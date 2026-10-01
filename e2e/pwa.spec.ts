// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
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

/**
 * Cuts the page off from the server. In WebKit, Playwright's setOffline (and
 * routing) block requests before the service worker sees them, so even cached
 * files fail there; the test server is made unreachable instead.
 */
async function goOffline(context: BrowserContext, browserName: string, baseURL: string) {
  if (browserName === 'webkit') await context.addCookies([{ name: 'epx-test-offline', value: '1', url: baseURL }]);
  else await context.setOffline(true);
}

test('works offline after the first visit', async ({ page, context, browserName, baseURL }) => {
  await page.goto('./');
  await waitForOffline(page);
  await expect(page.getByTestId('offline-status')).toContainText(/MiB/);

  await goOffline(context, browserName, baseURL!);
  // The server really is unreachable now (and not just slow).
  expect(await page.evaluate(() => fetch('./sw.js', { cache: 'no-store' }).then(() => 'reached', () => 'unreachable'))).toBe('unreachable');
  await page.reload();
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('dns.pcap');
  await expect(page.locator('.facts').getByText('Packets', { exact: true }).locator('..')).toContainText('29');
  // Lazily loaded views come from the cache too.
  await page.evaluate(() => { location.hash = '#/http'; });
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
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
  expect(cached.some((u) => u.endsWith('/packet-explorer/'))).toBe(true);
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
  const before = await page.evaluate(() => caches.keys());
  // Tag the cached engine so a second download (which would replace the entry)
  // shows: a deploy that leaves the engine unchanged must reuse it.
  await page.evaluate(async () => {
    const name = (await caches.keys()).find((n) => n.startsWith('epx-engine-'))!;
    const cache = await caches.open(name);
    const key = new URL('wiregasm/wiregasm.wasm.gz', document.baseURI).href;
    const old = (await cache.match(key))!;
    const headers = new Headers(old.headers);
    headers.set('x-epx-test', 'kept');
    await cache.put(key, new Response(await old.blob(), { status: old.status, headers }));
  });
  // A new deploy changes sw.js (its precache list carries content hashes).
  // The test server serves a changed sw.js to a context with this cookie.
  await context.addCookies([{ name: 'epx-test-deploy', value: '2', url: baseURL! }]);
  await page.evaluate(async () => { await (await navigator.serviceWorker.ready).update(); });
  const banner = page.getByRole('status').filter({ hasText: 'A new version is available' });
  await expect(banner).toBeVisible();
  expect(await page.evaluate(async () => !!(await navigator.serviceWorker.ready).waiting)).toBe(true);
  // The fixed update notice must not block controls behind its text. Keep
  // only its explicit Reload button interactive while the user decides.
  const point = await banner.evaluate((el) => {
    const probe = document.createElement('button');
    probe.id = 'update-banner-underlay';
    probe.setAttribute('aria-label', 'Underlying control');
    probe.style.cssText = 'position:fixed;inset:0;z-index:29;opacity:0';
    probe.addEventListener('click', () => { probe.dataset.clicked = 'true'; });
    document.body.append(probe);
    const text = el.firstElementChild!.getBoundingClientRect();
    return { x: text.left + text.width / 2, y: text.top + text.height / 2 };
  });
  await page.mouse.click(point.x, point.y);
  await expect(page.locator('#update-banner-underlay')).toHaveAttribute('data-clicked', 'true');
  await page.locator('#update-banner-underlay').evaluate((el) => el.remove());
  await banner.getByRole('button', { name: 'Reload to update' }).click();
  await page.waitForEvent('load');
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
  await expect(page.getByText('A new version is available')).toHaveCount(0);
  const waiting = await page.evaluate(async () => !!(await navigator.serviceWorker.ready).waiting);
  expect(waiting).toBe(false);
  // The old shell cache is gone, the engine cache is the same one, untouched.
  const after = await page.evaluate(() => caches.keys());
  const engine = before.filter((n) => n.startsWith('epx-engine-'));
  expect(engine).toHaveLength(1);
  expect(after.filter((n) => n.startsWith('epx-engine-'))).toEqual(engine);
  const shell = after.filter((n) => n.startsWith('epx-shell-'));
  expect(shell).toHaveLength(1);
  expect(before).not.toContain(shell[0]);
  expect(after).toHaveLength(2);
  const tag = await page.evaluate(async (name) => {
    const res = await (await caches.open(name)).match(new URL('wiregasm/wiregasm.wasm.gz', document.baseURI).href);
    return res?.headers.get('x-epx-test');
  }, engine[0]);
  expect(tag).toBe('kept');
});
