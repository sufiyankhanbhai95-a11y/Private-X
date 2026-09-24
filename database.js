/**
 * PrivateX — database.js
 * ----------------------
 * PostgreSQL connection pool + schema bootstrap + all data-access queries.
 *
 * Auth model (mobile-number based):
 *   - users register with phone + password (password = scrypt hash, salted)
 *   - ONE account per phone number (unique partial index — the number can
 *     only ever be registered once, and its VIP code is permanent)
 *   - login issues a random session token; only its SHA-256 hash is stored
 *     in the `sessions` table (stateful, revocable, no expiry on free tier)
 *
 * Connection:
 *   - Reads DATABASE_URL from the environment (Neon / Supabase / Render / local).
 *   - SSL with `rejectUnauthorized: false` for remote hosted databases; SSL off
 *     for localhost automatically.
 *
 * Schema is created/updated automatically on boot (idempotent DDL), so a fresh
 * Neon/Supabase database needs zero manual migration steps. Data is never
 * dropped or truncated by this code.
 */

'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');

// ---------- Types -----------------------------------------------------------
// pg returns BIGINT (int8) as strings; our ids are < 2^53 so parse to numbers.
const pgTypes = require('pg').types;
pgTypes.setTypeParser(20, (v) => (v === null ? null : parseInt(v, 10))); // int8 → number

// ---------- Pool ------------------------------------------------------------
const DATABASE_URL = process.env.DATABASE_URL || '';
const isLocalDb =
  !DATABASE_URL ||
  DATABASE_URL.includes('localhost') ||
  DATABASE_URL.includes('127.0.0.1');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isLocalDb ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on('error', (err) => {
  console.error('[db] idle client error:', err.message);
});

// ---------- Schema (idempotent — never destructive) -------------------------
async function init() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            BIGSERIAL PRIMARY KEY,
        code          VARCHAR(16)  UNIQUE NOT NULL,          -- permanent VIP code, e.g. "VIP-7K2Q"
        username      VARCHAR(64)  NOT NULL,
        avatar        TEXT         NOT NULL DEFAULT '',
        online        BOOLEAN      NOT NULL DEFAULT FALSE,
        last_seen     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );
    `);
    // Mobile-number auth columns (added idempotently for existing databases).
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(20)`);
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT`);
    // ONE account per phone number — forever. NULLs allowed for legacy rows.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique
        ON users (phone) WHERE phone IS NOT NULL;
    `);

    // Login sessions — only token hashes are stored, never raw tokens.
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        id         BIGSERIAL PRIMARY KEY,
        token_hash CHAR(64)  UNIQUE NOT NULL,
        user_id    BIGINT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id)`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id         BIGSERIAL PRIMARY KEY,
        user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        contact_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (user_id, contact_id),
        CHECK (user_id <> contact_id)
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id          BIGSERIAL PRIMARY KEY,
        sender_id   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        body        TEXT        NOT NULL DEFAULT '',
        media_url   TEXT        NOT NULL DEFAULT '',
        media_type  VARCHAR(16) NOT NULL DEFAULT '',
        read        BOOLEAN     NOT NULL DEFAULT FALSE,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_pair
        ON messages (sender_id, receiver_id, id DESC);
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_messages_receiver_unread
        ON messages (receiver_id, read) WHERE read = FALSE;
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts (user_id);
    `);

    await client.query('COMMIT');
    console.log('[db] schema ready');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ---------- Passwords (scrypt, built into Node) ------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(String(password), salt, 64);
  const good = Buffer.from(hash, 'hex');
  return good.length === test.length && crypto.timingSafeEqual(good, test);
}

// ---------- Phone numbers -----------------------------------------------------
/**
 * Normalize a phone number: keep digits + optional leading '+'.
 * Accept 7–15 digits (E.164 range). Returns null when invalid.
 */
function normalizePhone(raw) {
  const s = String(raw || '').trim();
  const plus = s.startsWith('+');
  const digits = s.replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return null;
  return (plus ? '+' : '') + digits;
}

// ---------- VIP codes --------------------------------------------------------
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no ambiguous chars

/** Generate a human-friendly VIP code like "VIP-7K2Q". */
function generateVipCode() {
  const bytes = crypto.randomBytes(4);
  let core = '';
  for (let i = 0; i < 4; i++) core += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return `VIP-${core}`;
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id,
    code: u.code,
    phone: maskPhone(u.phone),
    username: u.username,
    avatar: u.avatar || '',
    online: !!u.online,
    last_seen: u.last_seen,
    created_at: u.created_at,
  };
}

/** Show the number to its owner semi-masked in API responses. */
function maskPhone(phone) {
  if (!phone) return '';
  if (phone.length <= 5) return phone;
  return phone.slice(0, phone.length - 4).replace(/\d/g, '•') + phone.slice(-4);
}

// ---------- Users -------------------------------------------------------------

/**
 * Register a new account: username + phone (unique, ONE per number) + password.
 * Assigns a permanent VIP code. Returns the user row.
 */
async function createUser(username, phone, password) {
  const name = String(username || '').trim().slice(0, 64);
  if (name.length < 2) {
    const e = new Error('Display name must be at least 2 characters.');
    e.status = 400; e.code = 'invalid_username'; throw e;
  }
  const normalizedPhone = normalizePhone(phone);
  if (!normalizedPhone) {
    const e = new Error('Enter a valid mobile number with country code (7–15 digits).');
    e.status = 400; e.code = 'invalid_phone'; throw e;
  }
  if (String(password || '').length < 6) {
    const e = new Error('Password must be at least 6 characters.');
    e.status = 400; e.code = 'weak_password'; throw e;
  }
  // One number = one account. Check first for a friendly error message.
  const existing = await getUserByPhone(normalizedPhone);
  if (existing) {
    const e = new Error('This mobile number is already registered. Please log in.');
    e.status = 409; e.code = 'phone_taken'; throw e;
  }
  const pwHash = hashPassword(password);
  for (let attempt = 0; attempt < 8; attempt++) {
    const code = generateVipCode();
    try {
      const { rows } = await pool.query(
        'INSERT INTO users (code, username, phone, password_hash) VALUES ($1, $2, $3, $4) RETURNING *',
        [code, name, normalizedPhone, pwHash]
      );
      return rows[0];
    } catch (err) {
      if (err.code === '23505' && String(err.detail || '').includes('(code)')) continue; // code collision → retry
      if (err.code === '23505') { // phone unique index (race-safe second guard)
        const e = new Error('This mobile number is already registered. Please log in.');
        e.status = 409; e.code = 'phone_taken'; throw e;
      }
      throw err;
    }
  }
  const e = new Error('Could not allocate a VIP code, please retry.');
  e.status = 503; e.code = 'code_exhausted'; throw e;
}

async function getUserByPhone(phone) {
  const { rows } = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
  return rows[0] || null;
}

async function getUserByCode(code) {
  const { rows } = await pool.query('SELECT * FROM users WHERE code = $1', [code]);
  return rows[0] || null;
}

async function getUserById(id) {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return rows[0] || null;
}

/** Verify login credentials; returns the user row or null. */
async function verifyLogin(phone, password) {
  const normalized = normalizePhone(phone);
  if (!normalized) return null;
  const user = await getUserByPhone(normalized);
  if (!user || !user.password_hash) return null;
  return verifyPassword(password, user.password_hash) ? user : null;
}

async function updateProfile(id, { username, avatar }) {
  const fields = [];
  const values = [];
  let i = 1;
  if (username !== undefined) { fields.push(`username = $${i++}`); values.push(String(username).trim().slice(0, 64)); }
  if (avatar !== undefined)   { fields.push(`avatar = $${i++}`);   values.push(String(avatar).slice(0, 500)); }
  if (!fields.length) return getUserById(id);
  values.push(id);
  const { rows } = await pool.query(
    `UPDATE users SET ${fields.join(', ')} WHERE id = $${i} RETURNING *`,
    values
  );
  return rows[0] || null;
}

/** Set online flag; when going offline also stamps last_seen = now. */
async function setOnline(id, online) {
  const { rows } = await pool.query(
    `UPDATE users
        SET online = $2,
            last_seen = CASE WHEN $2 THEN last_seen ELSE NOW() END
      WHERE id = $1
      RETURNING *`,
    [id, online]
  );
  return rows[0] || null;
}

/** Ids of every user related to `id` (people I added + people who added me). */
async function getRelatedUserIds(id) {
  const { rows } = await pool.query(
    `SELECT contact_id AS id FROM contacts WHERE user_id = $1
     UNION
     SELECT user_id AS id FROM contacts WHERE contact_id = $1`,
    [id]
  );
  return rows.map((r) => r.id);
}

// ---------- Sessions ----------------------------------------------------------
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** Create a login session; returns the RAW token (only the hash is stored). */
async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)', [sha256(token), userId]);
  return token;
}

async function getUserByToken(token) {
  if (!token || typeof token !== 'string' || token.length < 20) return null;
  const { rows } = await pool.query(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1`,
    [sha256(token)]
  );
  return rows[0] || null;
}

async function deleteSession(token) {
  if (!token) return;
  await pool.query('DELETE FROM sessions WHERE token_hash = $1', [sha256(token)]);
}

// ---------- Contacts ----------------------------------------------------------

async function addContact(userId, contactId) {
  if (Number(userId) === Number(contactId)) {
    const e = new Error('You cannot add yourself.'); e.status = 400; e.code = 'self_contact'; throw e;
  }
  await pool.query(
    `INSERT INTO contacts (user_id, contact_id) VALUES ($1, $2)
     ON CONFLICT (user_id, contact_id) DO NOTHING`,
    [userId, contactId]
  );
  return getUserById(contactId);
}

async function removeContact(userId, contactId) {
  await pool.query(
    'DELETE FROM contacts WHERE user_id = $1 AND contact_id = $2',
    [userId, contactId]
  );
}

/**
 * Contact list for sidebar: profile + presence + last exchanged message
 * preview + unread counter, ordered most-recent-conversation first.
 */
async function getContacts(userId) {
  const { rows } = await pool.query(
    `SELECT u.id, u.code, u.username, u.avatar, u.online, u.last_seen,
            lm.id          AS last_message_id,
            lm.sender_id   AS last_message_sender,
            lm.body        AS last_message_body,
            lm.media_type  AS last_message_media,
            lm.read        AS last_message_read,
            lm.created_at  AS last_message_at,
            (SELECT COUNT(*)::int FROM messages m
              WHERE m.sender_id = u.id AND m.receiver_id = $1 AND m.read = FALSE) AS unread
       FROM contacts c
       JOIN users u ON u.id = c.contact_id
       LEFT JOIN LATERAL (
         SELECT * FROM messages m
          WHERE (m.sender_id = $1 AND m.receiver_id = c.contact_id)
             OR (m.sender_id = c.contact_id AND m.receiver_id = $1)
          ORDER BY m.id DESC
          LIMIT 1
       ) lm ON TRUE
      WHERE c.user_id = $1
      ORDER BY COALESCE(lm.created_at, c.created_at) DESC NULLS LAST, u.username ASC`,
    [userId]
  );
  return rows;
}

// ---------- Messages ----------------------------------------------------------

async function saveMessage({ senderId, receiverId, body = '', mediaUrl = '', mediaType = '' }) {
  const { rows } = await pool.query(
    `INSERT INTO messages (sender_id, receiver_id, body, media_url, media_type)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [senderId, receiverId, String(body).slice(0, 4000), mediaUrl, mediaType]
  );
  return rows[0];
}

/** Paginated history between two users, oldest→newest within the page. */
async function getMessages(userA, userB, { before = null, limit = 50 } = {}) {
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);
  const { rows } = await pool.query(
    `SELECT * FROM (
        SELECT * FROM messages
         WHERE ((sender_id = $1 AND receiver_id = $2)
             OR (sender_id = $2 AND receiver_id = $1))
           AND ($3::bigint IS NULL OR id < $3)
         ORDER BY id DESC
         LIMIT $4
     ) t ORDER BY id ASC`,
    [userA, userB, before, safeLimit]
  );
  return rows;
}

/** Mark every message from `peerId` → `readerId` as read; returns flipped ids. */
async function markMessagesRead(readerId, peerId) {
  const { rows } = await pool.query(
    `UPDATE messages SET read = TRUE
      WHERE receiver_id = $1 AND sender_id = $2 AND read = FALSE
      RETURNING id`,
    [readerId, peerId]
  );
  return rows.map((r) => r.id);
}

// ---------- Exports -----------------------------------------------------------

module.exports = {
  pool,
  init,
  publicUser,
  generateVipCode,
  normalizePhone,
  hashPassword,
  // users
  createUser,
  getUserByPhone,
  getUserByCode,
  getUserById,
  verifyLogin,
  updateProfile,
  setOnline,
  getRelatedUserIds,
  // sessions
  createSession,
  getUserByToken,
  deleteSession,
  // contacts
  addContact,
  removeContact,
  getContacts,
  // messages
  saveMessage,
  getMessages,
  markMessagesRead,
};
