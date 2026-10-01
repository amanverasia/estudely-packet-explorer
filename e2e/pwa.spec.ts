// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';

// Installable offline app: the service worker caches the app shell and the
// engine after the first visit, and never caches captures.

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

/** Waits until the service worker has finished caching and controls the page. */
async function waitForOffline(page: Page) {
  await page.evaluate(async () => {
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller) {
      await new Promise((r) => navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    }
  });
  await expect(page.getByTestId('offline-status')).toContainText('Available offline');
}

test('has a web app manifest with icons and a service worker scoped to the app directory', async ({ page, baseURL }) => {
  await page.goto('./');
  const href = await page.locator('link[rel=manifest]').getAttribute('href');
  expect(href).toBe('./manifest.webmanifest');
  const res = await page.request.get(new URL(href!, baseURL).href);
  expect(res.headers()['content-type']).toContain('application/manifest+json');
  const manifest = await res.json();
  expect(manifest.start_url).toBe('./');
  expect(manifest.scope).toBe('./');
  expect(manifest.display).toBe('standalone');
  for (const size of ['192x192', '512x512']) {
    const icon = manifest.icons.find((i: { sizes: string; type: string }) => i.sizes === size && i.type === 'image/png');
    expect(icon, `${size} PNG icon`).toBeTruthy();
    expect((await page.request.get(new URL(icon.src, baseURL).href)).ok()).toBe(true);
  }
  await waitForOffline(page);
  const scope = await page.evaluate(async () => (await navigator.serviceWorker.ready).scope);
  expect(scope).toBe(baseURL);
});

test('works offline after the first visit', async ({ page, context }) => {
  await page.goto('./');
  await waitForOffline(page);
  await expect(page.getByTestId('offline-status')).toContainText(/MiB/);

  await context.setOffline(true);
  await page.reload();
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('dns.pcap');
  await expect(page.locator('.facts').getByText('Packets', { exact: true }).locator('..')).toContainText('29');
  // Lazily loaded views come from the cache too.
  await page.evaluate(() => { location.hash = '#/http'; });
  await expect(page.getByText('No cleartext HTTP/1.x messages were decoded.')).toBeVisible();
  await context.setOffline(false);
});

test('only app files are cached; captures never are', async ({ page }) => {
  await page.goto('./');
  await waitForOffline(page);
  await page.locator('input[type=file]').first().setInputFiles(fixture('http.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  const cached = await page.evaluate(async () => {
    const urls: string[] = [];
    for (const name of await caches.keys()) {
      for (const req of await (await caches.open(name)).keys()) urls.push(`${name} ${req.url}`);
    }
    return urls;
  });
  expect(cached.some((u) => u.endsWith('/wiregasm/wiregasm.wasm.gz'))).toBe(true);
  expect(cached.some((u) => u.endsWith('/wiregasm/wiregasm.data.gz'))).toBe(true);
  expect(cached.some((u) => u.endsWith('/index.html'))).toBe(true);
  for (const u of cached) {
    expect(u).toMatch(/^epx-(shell|engine)-[0-9a-f]+ http:\/\/localhost:\d+\/tools\/packet-explorer\//);
    expect(u).not.toMatch(/\.pcap|\.map$|blob:/);
  }
  // Nothing else persisted for the capture: no IndexedDB databases.
  expect(await page.evaluate(async () => (await indexedDB.databases()).length)).toBe(0);
});

test('offers to reload when a new version is deployed', async ({ page, context, baseURL }) => {
  await page.goto('./');
  await waitForOffline(page);
  // A new deploy changes sw.js (its precache list carries content hashes).
  // The test server serves a changed sw.js to a context with this cookie.
  await context.addCookies([{ name: 'epx-test-deploy', value: '2', url: baseURL! }]);
  await page.evaluate(async () => { await (await navigator.serviceWorker.ready).update(); });
  const banner = page.getByRole('status').filter({ hasText: 'A new version is available' });
  await expect(banner).toBeVisible();
  expect(await page.evaluate(async () => !!(await navigator.serviceWorker.ready).waiting)).toBe(true);
  await banner.getByRole('button', { name: 'Reload to update' }).click();
  await page.waitForEvent('load');
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
  await expect(page.getByText('A new version is available')).toHaveCount(0);
  const waiting = await page.evaluate(async () => !!(await navigator.serviceWorker.ready).waiting);
  expect(waiting).toBe(false);
});
