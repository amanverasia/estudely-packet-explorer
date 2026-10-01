// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Minimal static server for tests: serves dist/ under a subdirectory, the way
// a plain static host would (no rewrites, no special headers).
import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist/', import.meta.url));
const base = process.env.BASE ?? '/tools/packet-explorer/';
const port = Number(process.env.PORT ?? 4173);
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.gz': 'application/octet-stream', '.txt': 'text/plain; charset=utf-8', '.map': 'application/json',
};

createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  if (!url.pathname.startsWith(base)) { res.writeHead(404).end('not found'); return; }
  let rel = decodeURIComponent(url.pathname.slice(base.length));
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  rel = normalize(rel).replace(/^(\.\.[/\\])+/, '');
  const file = join(root, rel);
  try {
    const st = statSync(file);
    if (!st.isFile()) throw new Error('not a file');
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream', 'Content-Length': st.size });
    createReadStream(file).pipe(res);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(port, () => console.log(`serving dist/ at http://localhost:${port}${base}`));
