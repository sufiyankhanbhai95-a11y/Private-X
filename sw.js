/**
 * PrivateX Service Worker v3 — Robust PWA caching
 * 
 * Strategy: Cache-first for app shell, network-only for API/sockets.
 * This ensures the app OPENS even on slow connections.
 */
'use strict';

const CACHE = 'px-v3';

// Critical files that must be cached for the app to open
const PRECACHE = [
  '/',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
];

// ---- Install: cache the shell ----
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(PRECACHE))
      .catch(() => {}) // Never fail install due to network
  );
  self.skipWaiting();
});

// ---- Activate: clean old caches ----
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))
      ))
      .catch(() => {})
  );
  self.clients.claim();
});

// ---- Fetch: smart routing ----
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);

  // NEVER intercept: API (live data), WebSocket transport, uploads, POST/PUT, external
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/uploads/') ||
    req.method !== 'GET' ||
    url.origin !== self.location.origin
  ) {
    return; // Let browser handle normally
  }
  // Socket.io transport requests should pass through
  if (url.pathname.startsWith('/socket.io/') && url.search.includes('transport=')) {
    return; // Don't cache WebSocket/polling transport
  }
  // BUT /socket.io/socket.io.js (the client library itself) SHOULD be cached

  // For app shell: Cache-first with network fallback
  e.respondWith(
    caches.match(req).then((cached) => {
      if (cached) {
        // Return cached version immediately, update cache in background
        fetch(req).then((fresh) => {
          if (fresh && fresh.status === 200) {
            caches.open(CACHE).then((c) => c.put(req, fresh));
          }
        }).catch(() => {});
        return cached;
      }
      // Not cached: fetch from network and cache it
      return fetch(req).then((res) => {
        if (res && res.status === 200 && res.type !== 'opaque') {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(req, clone));
        }
        return res;
      }).catch(() => {
        // Last resort: return cached home page for navigation requests
        if (req.mode === 'navigate') return caches.match('/');
        return new Response('Offline', { status: 503 });
      });
    })
  );
});
