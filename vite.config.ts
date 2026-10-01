/// <reference types="vitest/config" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { Plugin } from 'vite';

import { cloudflare } from "@cloudflare/vite-plugin";

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
  plugins: [react(), cspPlugin(), cloudflare()],
  worker: { format: 'es' },
  build: { target: 'es2022', sourcemap: true, chunkSizeWarningLimit: 900 },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});