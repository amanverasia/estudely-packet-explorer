/// <reference types="vitest/config" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';

// Build identity shown in the app's corner: version, commit and date.
// A build from uncommitted changes is marked "-dirty" so it can't pass for a release.
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
function gitCommit(): string {
  try {
    const sha = execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    const dirty = execSync('git status --porcelain', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim() !== '';
    return dirty ? `${sha}-dirty` : sha;
  } catch {
    return 'unknown';
  }
}

// Content-Security-Policy for the built page (dev mode needs inline scripts).
// connect-src 'self' means the page can only fetch the self-hosted engine
// files; capture data has no network destination. Workers take their policy
// from HTTP headers, so docs/DEPLOYMENT.md also lists a header to set.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "worker-src 'self' blob:",
  "connect-src 'self'",
  "img-src 'self' data: blob:",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ');

function cspPlugin(): Plugin {
  return {
    name: 'estudely-csp',
    apply: 'build',
    transformIndexHtml: (html) => html.replace('<meta name="referrer"', `<meta http-equiv="Content-Security-Policy" content="${CSP}" />\n    <meta name="referrer"`),
  };
}

// Writes dist/sw.js from src/pwa/sw.js with the list of files to cache for
// offline use. The app shell and the engine (public/wiregasm) get separate
// caches, each named after a hash of its files, so a deploy that leaves the
// engine unchanged does not download it again. Source maps, host config and
// the .woff font fallbacks (every browser with service workers takes .woff2)
// are left out.
function pwaPlugin(): Plugin {
  let outDir = 'dist';
  return {
    name: 'estudely-pwa',
    apply: 'build',
    configResolved: (c) => { outDir = c.build.outDir; },
    closeBundle() {
      const files = (readdirSync(outDir, { recursive: true, withFileTypes: true }) as import('node:fs').Dirent[])
        .filter((d) => d.isFile())
        .map((d) => relative(outDir, join(d.parentPath, d.name)).split(sep).join('/'))
        .filter((f) => !f.endsWith('.map') && !f.endsWith('.woff') && f !== '_headers' && f !== 'sw.js')
        .sort();
      const group = (prefix: string, list: string[]) => {
        const h = createHash('sha256');
        for (const f of list) h.update(f).update('\0').update(readFileSync(join(outDir, f)));
        return { name: `epx-${prefix}-${h.digest('hex').slice(0, 16)}`, files: list };
      };
      const precache = {
        shell: group('shell', files.filter((f) => !f.startsWith('wiregasm/'))),
        engine: group('engine', files.filter((f) => f.startsWith('wiregasm/'))),
      };
      const src = readFileSync(new URL('./src/pwa/sw.js', import.meta.url), 'utf8');
      const marker = /\/\*__EPX_PRECACHE__\*\/ .*;/;
      if (!marker.test(src)) throw new Error('src/pwa/sw.js: precache marker not found');
      writeFileSync(join(outDir, 'sw.js'), src.replace(marker, () => `${JSON.stringify(precache)};`));
    },
  };
}

// `base: './'` makes every asset URL relative, so the build works from a
// domain root or any subdirectory without rebuilding.
export default defineConfig({
  base: './',
  plugins: [react(), cspPlugin(), pwaPlugin()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __APP_COMMIT__: JSON.stringify(gitCommit()),
    __BUILD_DATE__: JSON.stringify(new Date().toISOString().slice(0, 10)),
  },
  worker: { format: 'es' },
  build: { target: 'es2022', sourcemap: true, chunkSizeWarningLimit: 900 },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});