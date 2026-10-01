import { defineConfig, devices } from '@playwright/test';

// Runs against the production build served from a subdirectory by a plain
// static server. Build first: `npm run e2e` does both.
export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  expect: { timeout: 30_000 },
  fullyParallel: true,
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:4173/tools/packet-explorer/',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'node scripts/serve-subdir.mjs',
    url: 'http://localhost:4173/tools/packet-explorer/',
    reuseExistingServer: !process.env.CI,
  },
});
