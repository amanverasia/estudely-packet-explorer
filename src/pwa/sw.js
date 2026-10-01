// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Service worker: makes the app work offline after the first visit.
//
// The build (vite.config.ts, pwaPlugin) copies this file to dist/sw.js and
// fills in PRECACHE: every file of the built app, split into the app shell
// and the Wireshark engine, each named after a hash of its contents. A new
// deploy therefore changes sw.js, the browser installs the new worker, and the
// page offers to reload. The engine cache keeps its name while the engine is
// unchanged, so its tens of megabytes are downloaded once, not per deploy.
//
// Privacy: only the files listed in PRECACHE are ever cached. Captures and key
// files are read from the user's disk with the File API, never fetched, and
// this worker never stores a response it was not told to precache.

/* global self, caches, fetch, URL, Request */
const PRECACHE = /*__EPX_PRECACHE__*/ { shell: { name: 'epx-shell-dev', files: [] }, engine: { name: 'epx-engine-dev', files: [] } };

const CACHES = [PRECACHE.shell, PRECACHE.engine];
// Paths resolve against this script's directory, so the app works at a
// domain root or in any subdirectory.
const url = (path) => new URL(path, self.location.href).href;
const INDEX = url('index.html');
const SCOPE_ROOT = url('./');
const KNOWN = new Set(CACHES.flatMap((c) => c.files.map(url)));

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    for (const c of CACHES) {
      const cache = await caches.open(c.name);
      for (const path of c.files) {
        // Already cached: the engine cache is carried over from the previous
        // version when the engine did not change, or an earlier install of
        // this version was interrupted.
        if (await cache.match(url(path))) continue;
        // 'no-cache' revalidates with the server, so an HTTP-cached copy of a
        // file from an older deploy cannot end up in a new version's cache.
        const res = await fetch(new Request(url(path), { cache: 'no-cache' }));
        if (!res.ok) throw new Error(`precache failed: ${res.status} ${path}`);
        await cache.put(url(path), res);
      }
    }
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keep = new Set(CACHES.map((c) => c.name));
    for (const name of await caches.keys()) {
      if (name.startsWith('epx-') && !keep.has(name)) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

// The page asks the waiting worker to take over when the user accepts an update.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'skip-waiting') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const u = new URL(req.url);
  u.search = '';
  u.hash = '';
  let key = u.href;
  if (req.mode === 'navigate' && key === SCOPE_ROOT) key = INDEX;
  // Anything not in the precache list goes to the network untouched.
  if (!KNOWN.has(key)) return;
  event.respondWith((async () => {
    for (const c of CACHES) {
      const hit = await (await caches.open(c.name)).match(key);
      if (hit) return hit;
    }
    return fetch(req);
  })());
});
