// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Cross-browser engine behaviour. These run in every Playwright project, so
// Chromium, Firefox and WebKit each prove they can hand the compiled engine
// to a new worker, and the fallbacks are exercised everywhere.
import { expect, test, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

/** Counts downloads of the compiled engine. */
function engineDownloads(page: Page) {
  let n = 0;
  page.on('request', (r) => { if (r.url().endsWith('wiregasm/wiregasm.wasm.gz')) n++; });
  return () => n;
}

async function openTwoCaptures(page: Page) {
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('dns.pcap');
  await expect(page.locator('.nav a[href="#/dns"] .nav-count')).toHaveText('13');
  await page.locator('input[type=file]').first().setInputFiles(fixture('http.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await expect(page.locator('.nav a[href="#/http"] .nav-count')).toHaveText('5');
}

test('the compiled engine is handed to the next capture\'s worker, not downloaded again', async ({ page }) => {
  const errs: string[] = [];
  page.on('pageerror', (e) => errs.push(e.message));
  const downloads = engineDownloads(page);
  await page.goto('./');
  await openTwoCaptures(page);
  expect(downloads()).toBe(1);
  expect(errs).toEqual([]);
});

test('if the browser refuses to post the compiled engine, the next worker compiles its own', async ({ page }) => {
  await page.addInitScript(() => {
    const post = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (this: Worker, msg: unknown, ...rest: unknown[]) {
      if (msg && typeof msg === 'object' && (msg as { wasmModule?: unknown }).wasmModule) throw new DOMException('refused for test', 'DataCloneError');
      return (post as (...a: unknown[]) => void).call(this, msg, ...rest);
    } as typeof post;
  });
  const downloads = engineDownloads(page);
  await page.goto('./');
  await openTwoCaptures(page);
  expect(downloads()).toBe(2);
});

test('a browser without DecompressionStream gets a plain explanation and no engine download', async ({ page }) => {
  await page.addInitScript(() => { delete (globalThis as { DecompressionStream?: unknown }).DecompressionStream; });
  const downloads = engineDownloads(page);
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('DecompressionStream');
  await expect(alert).toContainText('Firefox or Safari');
  expect(downloads()).toBe(0);
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
});

test('a browser that cannot start a module worker gets a plain explanation', async ({ page }) => {
  // Firefox before 114 throws like this for `new Worker(url, { type: 'module' })`.
  await page.addInitScript(() => {
    const Real = Worker;
    globalThis.Worker = function (url: string | URL, opts?: WorkerOptions) {
      if (opts?.type === 'module') throw new TypeError('Module scripts are not supported on DedicatedWorker yet.');
      return new Real(url, opts);
    } as unknown as typeof Worker;
  });
  const errs: string[] = [];
  page.on('pageerror', (e) => errs.push(e.message));
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('could not start the analysis worker');
  await expect(alert).toContainText('Firefox or Safari');
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
  expect(errs).toEqual([]);
});

test('a worker can grow WebAssembly memory to the engine\'s 2 GiB ceiling', async ({ page }) => {
  // wiregasm.wasm declares 2048 pages (128 MiB) initially and grows to at most
  // 32768 pages (2 GiB), the wasm32 limit. Large captures need most of that.
  await page.goto('./');
  const result = await page.evaluate(() => new Promise<string>((resolve) => {
    const src = `
      const m = new WebAssembly.Memory({ initial: 2048, maximum: 32768 });
      try {
        m.grow(32768 - 2048);
        new Uint8Array(m.buffer)[m.buffer.byteLength - 1] = 1;
        postMessage(String(m.buffer.byteLength));
      } catch (e) { postMessage(e.name + ': ' + e.message); }`;
    const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
    w.onmessage = (e) => { w.terminate(); resolve(String(e.data)); };
    w.onerror = (e) => { w.terminate(); resolve(`worker error: ${e.message}`); };
  }));
  expect(result).toBe(String(2 ** 31));
});
