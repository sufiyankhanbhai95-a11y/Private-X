/**
 * PrivateX end-to-end smoke test (mobile-number auth edition).
 *
 * Requires the server to be running (default http://localhost:3000, override
 * with SMOKE_BASE=http://host:port). Exercises the HTTP API and the full
 * Socket.io event loop: presence → send → delivered → read receipt → typing →
 * call signaling (request/accept/relay/end) → disconnect presence.
 *
 *   node test/smoke.js
 */
'use strict';

const BASE = process.env.SMOKE_BASE || 'http://localhost:3000';
const { io } = require('socket.io-client');

let failures = 0;
const ok = (name, cond) => {
  console.log(cond ? `  ok    ${name}` : `  FAIL  ${name}`);
  if (!cond) failures++;
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, { method = 'GET', token, body } = {}) {
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  let data = null;
  if (res.status !== 204) data = await res.json().catch(() => null);
  return { status: res.status, data };
}

function connect(token) {
  return new Promise((resolve, reject) => {
    const s = io(BASE, { auth: { token }, transports: ['websocket'] });
    const t = setTimeout(() => reject(new Error('socket connect timeout')), 5000);
    s.on('connect', () => { clearTimeout(t); resolve(s); });
    s.on('connect_error', (e) => { clearTimeout(t); reject(e); });
  });
}

function once(socket, event, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout waiting for "${event}"`)), timeoutMs);
    socket.once(event, (data) => { clearTimeout(t); resolve(data); });
  });
}

(async () => {
  console.log(`\nPrivateX smoke test → ${BASE}\n`);

  const PHONE_A = '+15551000001', PHONE_B = '+15551000002', PW = 'secret123';

  // ---- HTTP ----
  const health = await api('/api/health');
  ok('GET /api/health', health.status === 200 && health.data.ok === true);

  const regA = await api('/api/auth/register', { method: 'POST', body: { username: 'Smoke Alice', phone: PHONE_A, password: PW } });
  const regB = await api('/api/auth/register', { method: 'POST', body: { username: 'Smoke Bob', phone: PHONE_B, password: PW } });
  ok('register A (number + password → VIP code)', regA.status === 201 && /^VIP-[A-Z2-9]{4}$/.test(regA.data.user.code) && typeof regA.data.token === 'string');
  ok('register B', regB.status === 201 && regB.data.user.id !== regA.data.user.id);
  const A = regA.data.user, B = regB.data.user, tokA = regA.data.token, tokB = regB.data.token;

  const dup = await api('/api/auth/register', { method: 'POST', body: { username: 'Alice Clone', phone: PHONE_A, password: PW } });
  ok('duplicate number rejected (one account per number)', dup.status === 409);

  const weak = await api('/api/auth/register', { method: 'POST', body: { username: 'Weak Pw', phone: '+15551000003', password: '123' } });
  ok('weak password rejected', weak.status === 400);

  const badPhone = await api('/api/auth/register', { method: 'POST', body: { username: 'Bad Phone', phone: '12', password: PW } });
  ok('invalid number rejected', badPhone.status === 400);

  const loginBad = await api('/api/auth/login', { method: 'POST', body: { phone: PHONE_A, password: 'wrong-pass' } });
  ok('wrong password → 401', loginBad.status === 401);

  const login = await api('/api/auth/login', { method: 'POST', body: { phone: PHONE_A, password: PW } });
  ok('login with number + password', login.status === 200 && login.data.user.id === A.id && typeof login.data.token === 'string');

  const me = await api('/api/me', { token: tokA });
  ok('GET /api/me with session token', me.status === 200 && me.data.user.id === A.id);

  const noAuth = await api('/api/contacts');
  ok('auth required (401 without token)', noAuth.status === 401);

  const lookup = await api(`/api/users/lookup/${B.code}`, { token: tokA });
  ok('GET /api/users/lookup by VIP code', lookup.status === 200 && lookup.data.user.id === B.id);

  const addC = await api('/api/contacts', { method: 'POST', token: tokA, body: { code: B.code } });
  ok('POST /api/contacts', addC.status === 201 && addC.data.contact.id === B.id);
  await api('/api/contacts', { method: 'POST', token: tokB, body: { code: A.code } });

  // ---- Sockets ----
  const sa = await connect(tokA);
  const sb = await connect(tokB);
  ok('socket auth connects (A & B)', sa.connected && sb.connected);

  const badSock = await new Promise((r) => {
    const s = io(BASE, { auth: { token: 'invalid-token' }, transports: ['websocket'] });
    s.on('connect', () => { s.disconnect(); r('connected'); });
    s.on('connect_error', () => r('rejected'));
    setTimeout(() => r('timeout'), 4000);
  });
  ok('socket rejects invalid token', badSock === 'rejected');

  await wait(400); // let A's initial online broadcast flush through first
  let extraPresence = 0;
  sb.on('presence', (p) => { if (p.userId === A.id) extraPresence++; });
  const sa2 = await connect(tokA); // second tab → must NOT re-broadcast online
  await wait(800);
  ok('no duplicate presence burst for 2nd tab', extraPresence === 0);

  // message A → B
  const incomingB = once(sb, 'message:new');
  const deliveredA = once(sa, 'message:delivered');
  const sendAck = await new Promise((r) => sa.emit('message:send', { to: B.id, body: 'hello bob' }, r));
  ok('message:send ack', sendAck.ok === true && sendAck.message.body === 'hello bob');
  const gotB = await incomingB;
  ok('B receives message:new in real time', gotB.body === 'hello bob' && gotB.sender_id === A.id);
  sb.emit('message:ack', { id: gotB.id, senderId: gotB.sender_id });
  const del = await deliveredA;
  ok('A receives delivered tick', del.id === gotB.id);

  // history persisted
  const hist = await api(`/api/messages/${B.id}`, { token: tokA });
  ok('GET /api/messages history', hist.status === 200 && hist.data.messages.some((m) => m.id === gotB.id));

  // read receipt
  const readA = once(sa, 'messages:read');
  sb.emit('messages:read', { peerId: A.id });
  const read = await readA;
  ok('read receipt reaches sender', read.by === B.id && read.ids.includes(gotB.id));

  // typing indicator
  const typingB = once(sb, 'typing');
  sa.emit('typing', { to: B.id, isTyping: true });
  const typ = await typingB;
  ok('typing indicator relayed', typ.from === A.id && typ.isTyping === true);

  // ---- call signaling ----
  const incomingCall = once(sb, 'call:incoming');
  const callAck = await new Promise((r) => sa.emit('call:request', { to: B.id, media: 'audio' }, r));
  ok('call:request ack ok', callAck.ok === true && typeof callAck.callId === 'string');
  const ic = await incomingCall;
  ok('B receives call:incoming', ic.from.id === A.id && ic.media === 'audio');

  const acceptedA = once(sa, 'call:accepted');
  sb.emit('call:accept', { callId: ic.callId });
  await acceptedA;
  ok('A receives call:accepted', true);

  const relayB = once(sb, 'rtc:signal');
  sa.emit('rtc:signal', { callId: ic.callId, data: { kind: 'offer', sdp: { type: 'offer', sdp: 'fake' } } });
  const relay = await relayB;
  ok('rtc:signal relayed A→B', relay.data.kind === 'offer');

  const endedA = once(sa, 'call:ended');
  sb.emit('call:end', { callId: ic.callId });
  const end = await endedA;
  ok('call:end notified to peer', end.reason === 'ended');

  // uploads reject anon
  const upRes = await fetch(BASE + '/api/upload', { method: 'POST', body: new FormData() });
  ok('upload requires auth', upRes.status === 401);

  // logout revokes session
  sa.disconnect(); sb.disconnect(); sa2.disconnect();
  const lo = await api('/api/auth/logout', { method: 'POST', token: tokA });
  ok('logout ok', lo.status === 200 && lo.data.ok === true);
  const meAfter = await api('/api/me', { token: tokA });
  ok('session revoked after logout', meAfter.status === 401);

  await wait(300);

  console.log(failures === 0 ? '\nALL CHECKS PASSED\n' : `\n${failures} CHECK(S) FAILED\n`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('\nSMOKE ERROR:', e.message, '\n'); process.exit(1); });
