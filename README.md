# PrivateX — Private Real-Time Messenger

PrivateX is a **production-ready, real-time private messaging app** with **voice & video calls**. Log in from **any mobile or PC** with your **mobile number + password** — every account also gets a **permanent VIP code** (issued once per number) for adding friends.

| | |
|---|---|
| **Auth** | Mobile number (login ID) + password (scrypt-hashed). **One account per number, forever**, with server-side session tokens |
| **VIP code** | Every account gets a permanent `VIP-XXXX` code, issued exactly once — friends find & add you with it |
| **Chat** | 1-on-1 real-time messaging, typing indicators, read receipts (✓ sent / ✓✓ delivered / ✓✓ blue read) |
| **Presence** | Online/offline with "last seen" |
| **Calls** | Peer-to-peer **WebRTC** voice & video calls (Socket.io signaling, Google STUN) |
| **Media** | Image, video & file uploads up to **25 MB** (Multer, local disk) |
| **UI** | WhatsApp-inspired **dark mode (default)** + light toggle, fully mobile responsive |
| **Stack** | Node.js · Express · Socket.io · PostgreSQL · Vanilla HTML/CSS/JS (zero build step) |

---

## 1. Project structure

```
privatex/
├── package.json        # Exact dependencies + scripts
├── database.js         # PostgreSQL pool, schema bootstrap, queries
├── server.js           # Express API + Socket.io real-time gateway
├── public/
│   ├── index.html      # Complete frontend (CSS + JS inside, no build tools)
│   └── uploads/        # Media uploads land here (auto-created)
├── test/
│   └── smoke.js        # End-to-end API + Socket.io smoke test
├── .env.example        # Environment template
└── README.md
```

## 2. Database schema

Created/migrated automatically on boot (idempotent, non-destructive DDL — your data is never dropped by the app):

- **users** — `id, code (permanent VIP code), username, phone (unique), password_hash, avatar, online, last_seen, created_at`
- **sessions** — `id, token_hash, user_id, created_at` (login sessions; only SHA-256 hashes stored)
- **contacts** — `id, user_id, contact_id, created_at` (unique pair, FK cascade)
- **messages** — `id, sender_id, receiver_id, body, media_url, media_type, read, created_at`

Works with **Neon**, **Supabase**, Render Postgres, or any local PostgreSQL 13+.

## 3. Run locally

```bash
# 1. Install dependencies
npm install

# 2. Create your environment file
cp .env.example .env
#    → set DATABASE_URL to your PostgreSQL connection string

# 3. Start
npm start
# → http://localhost:3000
```

Open **two browser windows** (or one normal + one incognito), create two accounts, and add each other via VIP codes to chat/call.

### Handy scripts

| Command | Purpose |
|---|---|
| `npm start` | Production start (`node server.js`) |
| `npm run dev` | Dev mode with auto-reload (`node --watch`) |
| `npm run smoke` | End-to-end test (server must be running — set `SMOKE_BASE` to override URL) |

## 4. Environment variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | no (default `3000`) | HTTP port. Render/Koyeb inject this automatically. |
| `DATABASE_URL` | **yes** | PostgreSQL connection string. Remote hosts auto-use SSL with `rejectUnauthorized: false`; localhost auto-disables SSL. |

## 5. Deploy to Render.com (free, no credit card)

1. **Push this repo** to GitHub/GitLab.
2. **Create a free PostgreSQL** at [Neon.tech](https://neon.tech) (free, no card):
   - Sign up → *New Project* → copy the **connection string**
     (`postgresql://user:pass@ep-xxxx.aws.neon.tech/dbname?sslmode=require`).
   - (Supabase works too: *Project Settings → Database → Connection string → URI*.)
3. On [render.com](https://render.com): **New → Web Service** → connect your repo.
4. Settings:
   - **Runtime:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Instance type:** Free
5. **Environment → Add:**
   - `DATABASE_URL` = your Neon connection string
6. Deploy. Render assigns `PORT` automatically and provides **HTTPS** (required by browsers for mic/camera) — calls work out of the box.

## 6. Deploy to Koyeb (alternative, free)

1. Push the repo to GitHub.
2. [koyeb.com](https://www.koyeb.com) → **Create Service → GitHub** → pick the repo.
3. Builder: **Buildpack** (auto-detects Node; runs `npm install`, then `npm start`).
4. Add env var `DATABASE_URL` (Neon string from step 5.2).
5. Deploy — Koyeb exposes HTTPS and routes traffic to `$PORT` automatically.

## 7. Free-tier notes & production hardening

- **Ephemeral disk:** Render/Koyeb free tiers wipe local files on redeploy, so `/uploads` is **not permanent**. For durable media, swap the Multer `diskStorage` in `server.js` for S3/Cloudflare R2 (`multer-s3`) — the rest of the app is unchanged.
- **Sleep on free tiers:** Render free web services sleep after inactivity (first request takes ~30–60s to wake — including Socket.io reconnect, which the UI handles automatically).
- **TURN servers:** Google STUN covers most NATs. Symmetric NATs / strict corporate firewalls need a TURN relay (e.g. [Cloudflare Calls TURN](https://developers.cloudflare.com/calls/turn/) or [Metered.ca](https://www.metered.ca/stun-turn) free tiers) added to `RTC_CONFIG.iceServers` in `public/index.html`.
- **Scaling past one instance:** presence/call state is in-memory by design (single instance). To scale horizontally, add `@socket.io/redis-adapter` and move presence/calls maps to Redis.
- **Security model:** login requires the mobile number + password (scrypt-hashed with per-user salt). Sessions are revocable server-side tokens (SHA-256 hashed in the DB). The VIP code is only a *contact identifier* for adding friends — it cannot be used to log in. Auth endpoints are rate-limited; add CAPTCHA if you run a public instance. True SIM verification (SMS OTP) requires a paid SMS provider (e.g. Twilio) and can be layered onto `/api/auth/register` if needed.

## 8. API & socket reference (quick)

**REST** (authenticated routes expect `Authorization: Bearer <session-token>`):

| Method | Route | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/auth/register` | `{username, phone, password}` → `{user, token}` (201; 409 if number already registered) |
| POST | `/api/auth/login` | `{phone, password}` → `{user, token}` |
| POST | `/api/auth/logout` | Revokes the current session |
| GET/PATCH | `/api/me` | Read/update profile `{username?, avatar?}` |
| GET | `/api/users/lookup/:code` | Preview a user by VIP code |
| GET/POST | `/api/contacts` | List contacts / add `{code}` |
| DELETE | `/api/contacts/:id` | Remove contact |
| GET | `/api/messages/:peerId?limit&before` | Paginated history (asc within page) |
| POST | `/api/upload` | Multipart `file` ≤ 25 MB → `{url, mediaType, name, size}` |

**Socket.io** (handshake `auth.token`):

| Direction | Event | Payload |
|---|---|---|
| c→s | `message:send` | `{to, body, mediaUrl, mediaType}` (ack) |
| s→c | `message:new` | full message row |
| c→s | `message:ack` | `{id, senderId}` → `message:delivered` to sender |
| c→s | `typing` | `{to, isTyping}` |
| c→s | `messages:read` | `{peerId}` → `messages:read` to both |
| s→c | `presence` | `{userId, online, lastSeen}` |
| c→s | `call:request` | `{to, media}` (ack: `ok` / `offline` / `busy`) |
| s→c | `call:incoming` | `{callId, media, from}` |
| c→s | `call:accept` / `call:reject` / `call:end` | `{callId}` |
| c↔s | `rtc:signal` | `{callId, data}` = offer/answer/ICE relay |
| s→c | `call:accepted` / `call:ended` | `{callId[, reason]}` |

---

Built with Express + Socket.io + PostgreSQL. One process, one file frontend — deploy anywhere Node runs.
