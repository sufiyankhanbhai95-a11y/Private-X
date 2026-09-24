/**
 * PrivateX — server.js
 * --------------------
 * Express HTTP API + Socket.io real-time gateway, served as ONE process
 * (single dyno / single instance friendly).
 *
 * Responsibilities:
 *   - Static hosting of the vanilla frontend in /public
 *   - Passwordless auth (VIP-code) REST API
 *   - Contacts, message history (paginated), media upload (Multer, 25MB)
 *   - Socket.io: presence, 1:1 chat, typing indicators, read receipts,
 *     delivered ticks, and WebRTC call signaling (STUN-based P2P)
 *
 * Memory-safety notes (no listener leaks):
 *   - All `socket.on(...)` handlers are registered once per connection and die
 *     with the socket. Nothing is ever re-subscribed inside handlers.
 *   - Presence/call state lives in Maps keyed by userId / callId and is fully
 *     pruned on `disconnect`.
 *   - Every setTimeout/setInterval created for a call is cleared on every
 *     possible exit path (accept, reject, end, disconnect).
 */

'use strict';

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const { Server } = require('socket.io');

const db = require('./database');

// ----------------------------------------------------------------------------
// App setup
// ----------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT, 10) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
const MAX_UPLOAD_BYTES = 25 * 1024 * 1024; // 25 MB

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.set('trust proxy', 1); // correct client IPs behind Render/Koyeb proxies
app.disable('x-powered-by');

const server = http.createServer(app);

const io = new Server(server, {
  // Guard against oversized socket payloads (files go through HTTP multipart).
  maxHttpBufferSize: 1e6, // 1 MB
  serveClient: true,      // serves /socket.io/socket.io.js for the frontend
});

// ----------------------------------------------------------------------------
// Tiny in-memory rate limiter (per IP + path) for sensitive auth endpoints
// ----------------------------------------------------------------------------
const rateBuckets = new Map();
function rateLimit({ windowMs = 60_000, max = 40 } = {}) {
  return (req, res, next) => {
    const key = `${req.ip}|${req.path}`;
    const now = Date.now();
    let b = rateBuckets.get(key);
    if (!b || now > b.reset) {
      b = { count: 0, reset: now + windowMs };
      rateBuckets.set(key, b);
    }
    if (++b.count > max) {
      return res.status(429).json({ error: 'rate_limited', message: 'Too many requests, slow down.' });
    }
    next();
  };
}
// Periodically purge expired buckets so the limiter never grows unboundedly.
const rateSweeper = setInterval(() => {
  const now = Date.now();
  for (const [k, b] of rateBuckets) if (now > b.reset) rateBuckets.delete(k);
}, 60_000);
rateSweeper.unref();

// ----------------------------------------------------------------------------
// HTTP middleware
// ----------------------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Uploads are content-addressed by random name → safe to cache aggressively.
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d', immutable: true }));
app.use(express.static(PUBLIC_DIR, { maxAge: '1h', index: 'index.html' }));

// ----------------------------------------------------------------------------
// Auth helpers
// ----------------------------------------------------------------------------
/** Normalize "vip-xxxx", "XXXX", " VIP-XXXX " → "VIP-XXXX" (or null if invalid). */
function normalizeCode(raw) {
  if (!raw) return null;
  const core = String(raw).trim().toUpperCase().replace(/^VIP-?/, '');
  return /^[A-Z2-9]{4,8}$/.test(core) ? `VIP-${core}` : null;
}

/** Extract the bearer token from the Authorization header. */
function bearerToken(req) {
  const h = String(req.get('authorization') || '');
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

/** Express middleware: requires a valid login session (`Authorization: Bearer <token>`). */
async function requireAuth(req, res, next) {
  try {
    const token = bearerToken(req);
    if (!token) return res.status(401).json({ error: 'unauthorized', message: 'Please log in first.' });
    const user = await db.getUserByToken(token);
    if (!user) return res.status(401).json({ error: 'unauthorized', message: 'Session expired. Please log in again.' });
    req.user = user;
    req.sessionToken = token;
    next();
  } catch (err) {
    next(err);
  }
}

// ----------------------------------------------------------------------------
// REST API
// ----------------------------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'privatex', uptime: Math.round(process.uptime()), time: new Date().toISOString() });
});

// -- Auth: register (display name + mobile number + password → VIP code) -----
app.post('/api/auth/register', rateLimit({ windowMs: 60_000, max: 20 }), async (req, res, next) => {
  try {
    const { username, phone, password } = req.body || {};
    if (typeof username !== 'string' || username.trim().length < 2 || username.trim().length > 64) {
      return res.status(400).json({ error: 'invalid_username', message: 'Display name must be 2–64 characters.' });
    }
    if (!db.normalizePhone(phone)) {
      return res.status(400).json({ error: 'invalid_phone', message: 'Enter a valid mobile number with country code (7–15 digits).' });
    }
    if (typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'weak_password', message: 'Password must be at least 6 characters.' });
    }
    // One account per number — enforced inside createUser + unique index.
    const user = await db.createUser(username, phone, password);
    const token = await db.createSession(user.id);
    res.status(201).json({ user: db.publicUser(user), token });
  } catch (err) { next(err); }
});

// -- Auth: login with mobile number + password -------------------------------
app.post('/api/auth/login', rateLimit({ windowMs: 60_000, max: 30 }), async (req, res, next) => {
  try {
    const { phone, password } = req.body || {};
    if (!phone || !password) {
      return res.status(400).json({ error: 'missing_fields', message: 'Enter your mobile number and password.' });
    }
    const user = await db.verifyLogin(phone, password);
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials', message: 'Wrong number or password. Please try again.' });
    }
    const token = await db.createSession(user.id);
    res.json({ user: db.publicUser(user), token });
  } catch (err) { next(err); }
});

// -- Auth: logout (revoke the current session) --------------------------------
app.post('/api/auth/logout', requireAuth, async (req, res, next) => {
  try {
    await db.deleteSession(req.sessionToken);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// -- Me ----------------------------------------------------------------------
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: db.publicUser(req.user) });
});

app.patch('/api/me', requireAuth, async (req, res, next) => {
  try {
    const patch = {};
    if (req.body && typeof req.body.username === 'string' && req.body.username.trim().length >= 2) {
      patch.username = req.body.username;
    }
    if (req.body && typeof req.body.avatar === 'string' && /^\/uploads\/[\w.-]+$/.test(req.body.avatar)) {
      patch.avatar = req.body.avatar;
    }
    const user = await db.updateProfile(req.user.id, patch);
    res.json({ user: db.publicUser(user) });
  } catch (err) { next(err); }
});

// -- Lookup a user by VIP code (add-contact preview) --------------------------
app.get('/api/users/lookup/:code', requireAuth, async (req, res, next) => {
  try {
    const code = normalizeCode(req.params.code);
    if (!code) return res.status(400).json({ error: 'invalid_code', message: 'Enter a valid code like VIP-7K2Q.' });
    const user = await db.getUserByCode(code);
    if (!user) return res.status(404).json({ error: 'not_found', message: 'No PrivateX user with that code.' });
    const pub = db.publicUser(user);
    if (pub.id === req.user.id) {
      return res.status(400).json({ error: 'self_contact', message: 'That is your own code.' });
    }
    res.json({ user: pub });
  } catch (err) { next(err); }
});

// -- Contacts ------------------------------------------------------------------
app.get('/api/contacts', requireAuth, async (req, res, next) => {
  try {
    const contacts = await db.getContacts(req.user.id);
    res.json({ contacts });
  } catch (err) { next(err); }
});

app.post('/api/contacts', requireAuth, async (req, res, next) => {
  try {
    const code = normalizeCode(req.body && req.body.code);
    if (!code) return res.status(400).json({ error: 'invalid_code', message: 'Enter a valid code like VIP-7K2Q.' });
    const target = await db.getUserByCode(code);
    if (!target) return res.status(404).json({ error: 'not_found', message: 'No PrivateX user with that code.' });
    if (target.id === req.user.id) {
      return res.status(400).json({ error: 'self_contact', message: 'You cannot add yourself.' });
    }
    const contact = await db.addContact(req.user.id, target.id);
    const pub = db.publicUser(contact);
    // If the new contact is online, let them know their related list changed
    // (so I appear online-state-correct on their side too if they re-fetch).
    io.to(`user:${target.id}`).emit('contacts:refresh');
    res.status(201).json({ contact: { ...pub, unread: 0 } });
  } catch (err) { next(err); }
});

app.delete('/api/contacts/:id', requireAuth, async (req, res, next) => {
  try {
    const contactId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(contactId)) return res.status(400).json({ error: 'invalid_id' });
    await db.removeContact(req.user.id, contactId);
    res.status(204).end();
  } catch (err) { next(err); }
});

// -- Message history (paginated) ----------------------------------------------
app.get('/api/messages/:peerId', requireAuth, async (req, res, next) => {
  try {
    const peerId = Number.parseInt(req.params.peerId, 10);
    if (!Number.isSafeInteger(peerId)) return res.status(400).json({ error: 'invalid_peer' });
    const before = req.query.before ? Number.parseInt(req.query.before, 10) : null;
    const limit = req.query.limit ? Number.parseInt(req.query.limit, 10) : 50;
    const messages = await db.getMessages(req.user.id, peerId, {
      before: Number.isSafeInteger(before) ? before : null,
      limit,
    });
    res.json({ messages });
  } catch (err) { next(err); }
});

// -- Media upload (Multer, local disk, max 25MB) --------------------------------
const MIME_EXT = {
  'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif', 'image/avif': '.avif',
  'video/mp4': '.mp4', 'video/webm': '.webm', 'video/quicktime': '.mov',
  'audio/mpeg': '.mp3', 'audio/ogg': '.ogg', 'audio/wav': '.wav',
  'application/pdf': '.pdf', 'text/plain': '.txt', 'application/zip': '.zip',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    // Never trust the uploader's filename for the on-disk path.
    const mapped = MIME_EXT[file.mimetype];
    const rawExt = path.extname(file.originalname || '').toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
    const ext = mapped || rawExt || '';
    cb(null, `px_${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
});

function classifyMedia(mimetype) {
  if (mimetype.startsWith('image/')) return 'image';
  if (mimetype.startsWith('video/')) return 'video';
  return 'file';
}

app.post('/api/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({ error: 'file_too_large', message: 'File exceeds the 25 MB limit.' });
      }
      return res.status(400).json({ error: 'upload_failed', message: 'Upload failed.' });
    }
    if (!req.file) return res.status(400).json({ error: 'no_file', message: 'Attach a file as form field "file".' });
    res.status(201).json({
      url: `/uploads/${req.file.filename}`,
      mediaType: classifyMedia(req.file.mimetype),
      name: (req.file.originalname || 'file').slice(0, 120),
      size: req.file.size,
    });
  });
});

// Download page — serves the install/app-store page
app.get('/download', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'download.html'));
});

// SPA-ish fallback: anything that is not api/socket/uploads/download serves the app shell.
app.get(/^(?!\/(api|socket\.io|uploads|download)\b).*/, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// JSON 404 for unknown API routes
app.use('/api', (req, res) => res.status(404).json({ error: 'not_found', message: 'Unknown API route.' }));

// Central error handler — never leak internals to clients.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[http] error:', err.message);
  res.status(err.status || 500).json({ error: err.code || 'server_error', message: err.status ? err.message : 'Something went wrong.' });
});

// ----------------------------------------------------------------------------
// Socket.io real-time layer
// ----------------------------------------------------------------------------

/** userId → Set<socketId> (a user may have several tabs/devices open). */
const onlineSockets = new Map();

/** callId → { a, b, media, phase: 'ringing'|'active', startedAt, ringTimeout } */
const activeCalls = new Map();

const roomOf = (userId) => `user:${userId}`;

function isUserOnline(userId) {
  return onlineSockets.has(userId) && onlineSockets.get(userId).size > 0;
}

function isUserInCall(userId) {
  for (const call of activeCalls.values()) {
    if (call.a === userId || call.b === userId) return true;
  }
  return false;
}

/** Tell everyone related to `userId` (both directions) about a presence change. */
async function broadcastPresence(userId, online, lastSeen) {
  try {
    const related = await db.getRelatedUserIds(userId);
    const payload = { userId, online, lastSeen };
    for (const rid of related) io.to(roomOf(rid)).emit('presence', payload);
    io.to(roomOf(userId)).emit('presence', payload); // own other tabs
  } catch (err) {
    console.error('[ws] presence broadcast failed:', err.message);
  }
}

/** Fully tear down a call record: clear timers, notify the other peer, delete. */
function destroyCall(callId, notifyUserId, reason) {
  const call = activeCalls.get(callId);
  if (!call) return;
  if (call.ringTimeout) clearTimeout(call.ringTimeout);
  activeCalls.delete(callId);
  if (notifyUserId) {
    io.to(roomOf(notifyUserId)).emit('call:ended', { callId, reason });
  }
}

// -- Socket auth middleware: handshake must carry a valid session token -------
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error('unauthorized'));
    const user = await db.getUserByToken(token);
    if (!user) return next(new Error('unauthorized'));
    socket.data.userId = user.id;
    socket.data.user = db.publicUser(user);
    next();
  } catch (err) {
    next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  const me = socket.data.user;
  const myId = me.id;

  // ---- presence bookkeeping -------------------------------------------------
  let set = onlineSockets.get(myId);
  if (!set) { set = new Set(); onlineSockets.set(myId, set); }
  set.add(socket.id);
  socket.join(roomOf(myId));

  if (set.size === 1) {
    // First socket for this user → mark online (DB is the source of truth).
    db.setOnline(myId, true)
      .then((row) => broadcastPresence(myId, true, row ? row.last_seen : null))
      .catch((err) => console.error('[ws] setOnline(true) failed:', err.message));
  }

  // ---- chat: send message ---------------------------------------------------
  socket.on('message:send', async (payload, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    try {
      const toId = Number(payload && payload.to);
      const body = typeof payload.body === 'string' ? payload.body.slice(0, 4000) : '';
      let mediaUrl = typeof payload.mediaUrl === 'string' ? payload.mediaUrl : '';
      let mediaType = typeof payload.mediaType === 'string' ? payload.mediaType : '';

      // Media URLs must point at files THIS server produced.
      if (mediaUrl && !/^\/uploads\/[\w.-]+$/.test(mediaUrl)) { mediaUrl = ''; mediaType = ''; }
      if (!['image', 'video', 'file'].includes(mediaType)) mediaType = mediaUrl ? 'file' : '';

      if (!Number.isSafeInteger(toId)) return done({ ok: false, error: 'invalid_recipient' });
      if (toId === myId) return done({ ok: false, error: 'cannot_message_self' });
      if (!body.trim() && !mediaUrl) return done({ ok: false, error: 'empty_message' });

      const recipient = await db.getUserById(toId);
      if (!recipient) return done({ ok: false, error: 'recipient_not_found' });

      const message = await db.saveMessage({
        senderId: myId,
        receiverId: toId,
        body: body.trim(),
        mediaUrl,
        mediaType,
      });

      // Push to the recipient (all their tabs) and to MY other tabs — not back
      // to this sending socket (it reconciles via the ack).
      io.to(roomOf(toId)).emit('message:new', message);
      socket.to(roomOf(myId)).emit('message:new', message);

      done({ ok: true, message });
    } catch (err) {
      console.error('[ws] message:send failed:', err.message);
      done({ ok: false, error: 'send_failed' });
    }
  });

  // ---- chat: device acknowledged visual delivery (✓✓ grey) -------------------
  socket.on('message:ack', (payload) => {
    try {
      const messageId = Number(payload && payload.id);
      const senderId = Number(payload && payload.senderId);
      if (!Number.isSafeInteger(messageId) || !Number.isSafeInteger(senderId)) return;
      io.to(roomOf(senderId)).emit('message:delivered', { id: messageId, to: myId });
    } catch (err) {
      console.error('[ws] message:ack failed:', err.message);
    }
  });

  // ---- chat: typing indicator -------------------------------------------------
  socket.on('typing', (payload) => {
    try {
      const toId = Number(payload && payload.to);
      if (!Number.isSafeInteger(toId)) return;
      io.to(roomOf(toId)).emit('typing', { from: myId, isTyping: !!payload.isTyping });
    } catch (err) {
      console.error('[ws] typing failed:', err.message);
    }
  });

  // ---- chat: read receipts -----------------------------------------------------
  socket.on('messages:read', async (payload) => {
    try {
      const peerId = Number(payload && payload.peerId);
      if (!Number.isSafeInteger(peerId)) return;
      const ids = await db.markMessagesRead(myId, peerId);
      if (!ids.length) return;
      const event = { by: myId, peer: peerId, ids, at: new Date().toISOString() };
      io.to(roomOf(peerId)).emit('messages:read', event); // sender's ticks turn blue
      io.to(roomOf(myId)).emit('messages:read', event);   // my other tabs stay in sync
    } catch (err) {
      console.error('[ws] messages:read failed:', err.message);
    }
  });

  // ---- calls: WebRTC signaling ------------------------------------------------
  socket.on('call:request', (payload, ack) => {
    const done = typeof ack === 'function' ? ack : () => {};
    try {
      const calleeId = Number(payload && payload.to);
      const media = payload && payload.media === 'video' ? 'video' : 'audio';
      if (!Number.isSafeInteger(calleeId) || calleeId === myId) return done({ ok: false, reason: 'invalid' });
      if (!isUserOnline(calleeId)) return done({ ok: false, reason: 'offline' });
      if (isUserInCall(calleeId) || isUserInCall(myId)) return done({ ok: false, reason: 'busy' });

      const callId = crypto.randomUUID();
      const call = { a: myId, b: calleeId, media, phase: 'ringing', startedAt: null, ringTimeout: null };

      // Ring timeout: if nobody picks up in 45s, end it cleanly on both sides.
      call.ringTimeout = setTimeout(() => {
        if (activeCalls.get(callId) === call && call.phase === 'ringing') {
          io.to(roomOf(call.a)).emit('call:ended', { callId, reason: 'no-answer' });
          io.to(roomOf(call.b)).emit('call:ended', { callId, reason: 'no-answer' });
          activeCalls.delete(callId);
        }
      }, 45_000);
      call.ringTimeout.unref();

      activeCalls.set(callId, call);
      io.to(roomOf(calleeId)).emit('call:incoming', { callId, media, from: me });
      done({ ok: true, callId });
    } catch (err) {
      console.error('[ws] call:request failed:', err.message);
      done({ ok: false, reason: 'error' });
    }
  });

  socket.on('call:accept', (payload) => {
    try {
      const call = activeCalls.get(String(payload && payload.callId));
      if (!call || call.b !== myId) return; // only the callee may accept
      call.phase = 'active';
      call.startedAt = Date.now();
      if (call.ringTimeout) { clearTimeout(call.ringTimeout); call.ringTimeout = null; }
      io.to(roomOf(call.a)).emit('call:accepted', { callId: String(payload.callId) });
      socket.to(roomOf(call.b)).emit('call:ended', { callId: String(payload.callId), reason: 'answered-elsewhere' });
    } catch (err) {
      console.error('[ws] call:accept failed:', err.message);
    }
  });

  socket.on('call:reject', (payload) => {
    try {
      const callId = String(payload && payload.callId);
      const call = activeCalls.get(callId);
      if (!call || (call.a !== myId && call.b !== myId)) return;
      const other = call.a === myId ? call.b : call.a;
      destroyCall(callId, other, payload.reason === 'busy' ? 'busy' : 'rejected');
    } catch (err) {
      console.error('[ws] call:reject failed:', err.message);
    }
  });

  socket.on('call:end', (payload) => {
    try {
      const callId = String(payload && payload.callId);
      const call = activeCalls.get(callId);
      if (!call || (call.a !== myId && call.b !== myId)) return;
      const other = call.a === myId ? call.b : call.a;
      const duration = call.startedAt ? Math.round((Date.now() - call.startedAt) / 1000) : 0;
      destroyCall(callId, other, 'ended');
      socket.emit('call:ended', { callId, reason: 'ended', duration }); // confirm to self
    } catch (err) {
      console.error('[ws] call:end failed:', err.message);
    }
  });

  // WebRTC relay: offer / answer / ICE candidates between the two call parties.
  socket.on('rtc:signal', (payload) => {
    try {
      const callId = String(payload && payload.callId);
      const call = activeCalls.get(callId);
      if (!call || (call.a !== myId && call.b !== myId)) return;
      const data = payload.data;
      if (!data || typeof data !== 'object') return;
      const other = call.a === myId ? call.b : call.a;
      io.to(roomOf(other)).emit('rtc:signal', { callId, from: myId, data });
    } catch (err) {
      console.error('[ws] rtc:signal failed:', err.message);
    }
  });

  // ---- disconnect --------------------------------------------------------------
  socket.on('disconnect', () => {
    const bucket = onlineSockets.get(myId);
    if (bucket) {
      bucket.delete(socket.id);
      if (bucket.size === 0) {
        onlineSockets.delete(myId);
        db.setOnline(myId, false)
          .then((row) => broadcastPresence(myId, false, row ? row.last_seen : new Date().toISOString()))
          .catch((err) => console.error('[ws] setOnline(false) failed:', err.message));
      }
    }
    // Hanging up: end any call this user was part of, on every exit path.
    for (const [callId, call] of [...activeCalls]) {
      if (call.a === myId || call.b === myId) {
        const other = call.a === myId ? call.b : call.a;
        destroyCall(callId, other, 'disconnected');
      }
    }
  });
});

// ----------------------------------------------------------------------------
// Boot
// ----------------------------------------------------------------------------
async function main() {
  await db.init();
  server.listen(PORT, () => {
    console.log(`[privatex] listening on http://localhost:${PORT} (env: ${process.env.NODE_ENV || 'development'})`);
  });
}

// Graceful shutdown → free-tier platforms send SIGTERM on deploy/restart.
function shutdown(signal) {
  console.log(`[privatex] ${signal} received, shutting down…`);
  server.close(() => {
    db.pool.end().then(() => process.exit(0)).catch(() => process.exit(0));
  });
  // Hard timeout in case connections linger.
  setTimeout(() => process.exit(0), 8_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

main().catch((err) => {
  console.error('[privatex] fatal boot error:', err);
  process.exit(1);
});
