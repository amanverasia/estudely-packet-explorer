// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Minimal static server for tests: serves dist/ under a subdirectory, the way
// a plain static host would (no rewrites). It applies dist/_headers like
// Cloudflare does, so header problems (such as CSP blocking the worker) fail
// the browser tests instead of only showing up in production.
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist/', import.meta.url));
const base = process.env.BASE ?? '/tools/packet-explorer/';
const port = Number(process.env.PORT ?? 4173);
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.gz': 'application/octet-stream', '.png': 'image/png', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json',
};

// dist/_headers: "path pattern" lines followed by indented "Name: value" or
// "! Name" (detach) lines. `*` matches any characters. Later rules add to or
// detach headers set by earlier ones, as on Cloudflare.
const rules = [];
const headersFile = join(root, '_headers');
if (existsSync(headersFile)) {
  let cur = null;
  for (const line of readFileSync(headersFile, 'utf8').split('\n')) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      const re = new RegExp('^' + line.trim().replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
      cur = { re, set: [], detach: [] };
      rules.push(cur);
    } else if (cur) {
      const t = line.trim();
      if (t.startsWith('!')) cur.detach.push(t.slice(1).trim().toLowerCase());
      else { const i = t.indexOf(':'); cur.set.push([t.slice(0, i).trim().toLowerCase(), t.slice(i + 1).trim()]); }
    }
  }
}
function headersFor(path) {
  const h = new Map();
  for (const r of rules) {
    if (!r.re.test(path)) continue;
    for (const d of r.detach) h.delete(d);
    for (const [k, v] of r.set) h.set(k, h.has(k) ? `${h.get(k)}, ${v}` : v);
  }
  return Object.fromEntries(h);
}

createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  if (!url.pathname.startsWith(base)) { res.writeHead(404).end('not found'); return; }
  // Test hook for offline tests in WebKit, where Playwright's setOffline and
  // routing also block requests the service worker would answer: a browser
  // context with this cookie finds the server unreachable (connection reset).
  if (/(?:^|;\s*)epx-test-offline=1(?:;|$)/.test(req.headers.cookie ?? '')) {
    req.socket.destroy();
    return;
  }
  let rel = decodeURIComponent(url.pathname.slice(base.length));
  // Cloudflare's static assets redirect an explicit index.html to its
  // directory (307), so the service worker must never depend on that URL.
  if (rel === 'index.html' || rel.endsWith('/index.html')) {
    res.writeHead(307, { Location: base + rel.slice(0, -'index.html'.length) }).end();
    return;
  }
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  rel = normalize(rel).replace(/^(\.\.[/\\])+/, '');
  const file = join(root, rel);
  // Test hook for the service worker update flow: a browser context with this
  // cookie sees sw.js as if a new version had been deployed, with a changed
  // app shell (new shell cache name) and an unchanged engine.
  const deploy = /(?:^|;\s*)epx-test-deploy=([0-9a-f]+)/.exec(req.headers.cookie ?? '')?.[1];
  if (rel === 'sw.js' && deploy && existsSync(file)) {
    const body = readFileSync(file, 'utf8').replace(/"(epx-shell-[0-9a-f]+)"/, `"$1${deploy}"`);
    res.writeHead(200, { ...headersFor('/sw.js'), 'Content-Type': types['.js'], 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  try {
    const st = statSync(file);
    if (!st.isFile()) throw new Error('not a file');
    res.writeHead(200, { ...headersFor('/' + rel.replace(/\\/g, '/')), 'Content-Type': types[extname(file)] ?? 'application/octet-stream', 'Content-Length': st.size });
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(port, () => console.log(`serving dist/ at http://localhost:${port}${base}`));
