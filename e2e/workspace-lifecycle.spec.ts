// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
async function open(page: Page, name: string) {
  await page.locator('input[type=file]').first().setInputFiles(fixture(name));
  await expect(page.locator('.cap-title h1')).toHaveText(name);
}
async function openLargeFollow(page: Page) {
  const capture = readFileSync(fixture('follow.pcap'));
  // Repeat synthetic packet records under a single PCAP header: 894 packets.
  await page.locator('input[type=file]').first().setInputFiles({ name: 'follow.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: Buffer.concat([capture, capture.subarray(24)]) });
  await expect(page.locator('.cap-title h1')).toHaveText('follow.pcap');
}
async function compare(page: Page) {
  const actions = page.locator('summary').filter({ hasText: /^Capture actions$/ });
  if (await actions.count()) await actions.click();
  await page.getByRole('button', { name: 'Compare captures', exact: true }).click();
}
async function instrument(page: Page) {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    const control = window as unknown as { workers: TrackingWorker[]; failNextOpen: boolean; stallNextOpen: boolean; peakWorkers: number };
    control.workers = []; control.peakWorkers = 0;
    class TrackingWorker {
      native: Worker; terminated = false;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event: ErrorEvent) => void) | null = null;
      constructor(url: string | URL, options?: WorkerOptions) {
        this.native = new NativeWorker(url, options);
        this.native.onmessage = (event) => this.onmessage?.(event);
        this.native.onerror = (event) => this.onerror?.(event);
        control.workers.push(this);
        control.peakWorkers = Math.max(control.peakWorkers, control.workers.filter((worker) => !worker.terminated).length);
      }
      postMessage(message: { type: string }) {
        if (message.type === 'open' && control.failNextOpen) {
          control.failNextOpen = false;
          this.native.terminate(); // No engine download progress should follow the injected failure.
          queueMicrotask(() => this.onmessage?.({ data: { type: 'error', stage: 'open', message: 'Synthetic restore failure' } } as MessageEvent));
          return;
        }
        if (message.type === 'open' && control.stallNextOpen) { control.stallNextOpen = false; return; }
        this.native.postMessage(message);
      }
      terminate() { this.terminated = true; this.native.terminate(); }
    }
    window.Worker = TrackingWorker as unknown as typeof Worker;
  });
}

test('comparison Back restores original capture, route, shared filter and table state repeatedly', async ({ page }) => {
  await instrument(page); await page.goto(''); await open(page, 'http.pcap');
  await page.evaluate(() => { location.hash = '#/http?hf=10.0.0.5'; });
  const search = page.getByPlaceholder('Search hosts, paths, user agents, status');
  await search.fill('example');
  const hash = await page.evaluate(() => location.hash);
  for (const run of [false, true]) {
    await compare(page);
    await expect(page.locator('.compare-baseline')).toContainText('http.pcap');
    if (run) {
      await page.getByLabel('Choose capture B').setInputFiles(fixture('dns.pcap'));
      await compare(page);
      await expect(page.getByRole('heading', { name: 'Capture comparison' })).toBeVisible();
    }
    await page.getByRole('button', { name: 'Back', exact: true }).click();
    await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
    await expect.poll(() => page.evaluate(() => location.hash)).toBe(hash);
    await expect(search).toHaveValue('example');
  }
  await page.evaluate(() => { location.hash = '#/connections?hf=10.0.0.5'; });
  const conversations = page.getByRole('grid', { name: 'Conversations', exact: true });
  await conversations.getByRole('row').nth(1).click();
  await expect(conversations.locator('[aria-selected="true"]')).toHaveCount(1);
  await compare(page);
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await expect(conversations.locator('[aria-selected="true"]')).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'Packets', exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { peakWorkers: number }).peakWorkers)).toBe(1);
});

test('restoration failure retries and running comparison closes before restore; stale progress ignored', async ({ page }) => {
  await instrument(page); await page.goto(''); await open(page, 'http.pcap');
  await compare(page);
  await page.evaluate(() => { (window as unknown as { failNextOpen: boolean }).failNextOpen = true; });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Synthetic restore failure');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await compare(page);
  await page.getByLabel('Choose capture B').setInputFiles(fixture('dns.pcap'));
  await page.evaluate(() => { (window as unknown as { stallNextOpen: boolean }).stallNextOpen = true; });
  await compare(page);
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await page.evaluate(() => {
    const workers = (window as unknown as { workers: { onmessage: ((event: MessageEvent) => void) | null }[] }).workers;
    workers.at(-2)?.onmessage?.({ data: { type: 'progress', progress: { phase: 'extract', fraction: 0.5, message: 'Stale comparison' } } } as MessageEvent);
  });
  await expect(page.getByText('Stale comparison')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { peakWorkers: number }).peakWorkers)).toBe(1);
  await compare(page);
  await page.evaluate(() => { (window as unknown as { failNextOpen: boolean }).failNextOpen = true; });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByRole('button', { name: 'Return to start', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
});

test('current capture keys stage, apply, survive comparison, remove and isolate replacement', async ({ page }) => {
  await page.goto(''); await open(page, 'tls13-h2.pcap');
  await page.evaluate(() => { location.hash = '#/http'; });
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  await page.getByLabel('Choose current capture TLS key log').setInputFiles(fixture('tls13-h2.keys'));
  await expect(page.getByRole('status').filter({ hasText: 'Staged: tls13-h2.keys' })).toContainText('results unchanged');
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  await page.getByRole('button', { name: 'Apply keys to current capture' }).click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await page.locator('.tls-key-menu summary').click();
  await expect(page.getByText(/Active key log:/)).toContainText('tls13-h2.keys');
  await compare(page);
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await page.locator('.tls-key-menu summary').click();
  await page.getByRole('button', { name: 'Remove active keys' }).click();
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  await expect(page.locator('.tls-key-menu summary')).toContainText('None');
  await page.getByLabel('Choose current capture TLS key log').setInputFiles(fixture('tls13.keys'));
  await page.getByRole('button', { name: 'Apply keys to current capture' }).click();
  await page.locator('.tls-key-menu summary').click();
  await expect(page.getByText(/Active key log:/)).toContainText('no matching decrypted sessions');
  await page.getByLabel('Choose current capture TLS key log').setInputFiles(fixture('tls13-h2.keys'));
  await page.getByRole('button', { name: 'Apply keys to current capture' }).click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await open(page, 'tls13-h2.pcap');
  await expect(page.locator('.tls-key-menu summary')).toContainText('None');
  await page.evaluate(() => { location.hash = '#/http'; });
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
});

test('failed and cancelled key updates keep prior active keys and can restore their results', async ({ page }) => {
  await instrument(page); await page.goto('');
  await page.locator('input[type=file]').nth(1).setInputFiles(fixture('tls13-h2.keys'));
  await open(page, 'tls13-h2.pcap');
  await page.evaluate(() => { location.hash = '#/http'; });
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await page.getByLabel('Choose current capture TLS key log').setInputFiles(fixture('tls13.keys'));
  await page.evaluate(() => { (window as unknown as { failNextOpen: boolean }).failNextOpen = true; });
  await page.getByRole('button', { name: 'Apply keys to current capture' }).click();
  await expect(page.getByRole('alert')).toContainText('Synthetic restore failure');
  await page.getByRole('button', { name: 'Return to previous analysis' }).click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await expect(page.locator('.tls-key-menu summary')).toContainText('tls13-h2.keys');
  await page.getByLabel('Choose current capture TLS key log').setInputFiles(fixture('tls13.keys'));
  await page.evaluate(() => { (window as unknown as { stallNextOpen: boolean }).stallNextOpen = true; });
  await page.getByRole('button', { name: 'Apply keys to current capture' }).click();
  await expect(page.getByRole('heading', { name: 'Updating TLS decryption' })).toBeVisible();
  await page.getByRole('button', { name: 'Return to previous analysis' }).click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' })).toContainText('/decrypted-h2');
  await expect(page.locator('.tls-key-menu summary')).toContainText('tls13-h2.keys');
  expect(await page.evaluate(() => (window as unknown as { peakWorkers: number }).peakWorkers)).toBe(1);
});

test('comparison return restores packet-table scroll after asynchronous packet loading', async ({ page }) => {
  await page.goto(''); await openLargeFollow(page);
  await page.evaluate(() => { location.hash = '#/packets'; });
  const packets = page.getByRole('grid', { name: 'Packets', exact: true });
  await expect(packets).toHaveAttribute('aria-busy', 'false');
  await expect.poll(async () => Number(await packets.getAttribute('aria-rowcount'))).toBeGreaterThan(501);
  await expect(packets.getByRole('columnheader').first()).toBeVisible();
  await packets.evaluate((element) => { element.scrollTop = 16020; });
  const top = await packets.evaluate((element) => element.scrollTop);
  expect(top).toBeGreaterThan(15000);
  await compare(page);
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.locator('.cap-title h1')).toHaveText('follow.pcap');
  await expect(packets).toHaveAttribute('aria-busy', 'false');
  await expect.poll(() => packets.evaluate((element) => element.scrollTop)).toBe(top);
});

test('mobile comparison restores page scroll together with packet offset after async loading', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(''); await openLargeFollow(page);
  await page.evaluate(() => { location.hash = '#/packets'; });
  const packets = page.getByRole('grid', { name: 'Packets', exact: true });
  await expect(packets).toHaveAttribute('aria-busy', 'false');
  await expect.poll(async () => Number(await packets.getAttribute('aria-rowcount'))).toBeGreaterThan(501);
  await expect(packets.getByRole('columnheader').first()).toBeVisible();
  await packets.evaluate((element) => { element.scrollTop = 16020; });
  const top = await packets.evaluate((element) => element.scrollTop);
  expect(top).toBeGreaterThan(15000);
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  const pageTop = await page.evaluate(() => window.scrollY);
  expect(pageTop).toBeGreaterThan(0);
  // Dispatch the already-authorized action without Playwright scrolling the
  // toolbar into view first, so the lifecycle snapshots an actual page offset.
  await page.evaluate(() => {
    const button = Array.from(document.querySelectorAll('button')).find((element) => element.textContent === 'Compare captures');
    button?.click();
  });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(page.locator('.cap-title h1')).toHaveText('follow.pcap');
  await expect(packets).toHaveAttribute('aria-busy', 'false');
  await expect.poll(() => packets.evaluate((element) => element.scrollTop)).toBe(top);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(pageTop);
});
