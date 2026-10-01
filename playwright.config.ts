// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { defineConfig, devices } from '@playwright/test';

// Runs against the production build served from a subdirectory by a plain
// static server. Build first: `npm run e2e` does both.
// PORT lets several checkouts run the suite at once without sharing a server.
const port = Number(process.env.PORT ?? 4173);
const url = `http://localhost:${port}/tools/packet-explorer/`;

export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  expect: { timeout: 30_000 },
  fullyParallel: true,
  reporter: [['list']],
  use: { baseURL: url },
  // The same suite runs in all three engines. Pick one with --project.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    command: 'node scripts/serve-subdir.mjs',
    url,
    reuseExistingServer: !process.env.CI,
  },
});
