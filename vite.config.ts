/// <reference types="vitest/config" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
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

// `base: './'` makes every asset URL relative, so the build works from a
// domain root or any subdirectory without rebuilding.
export default defineConfig({
  base: './',
  plugins: [react(), cspPlugin()],
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