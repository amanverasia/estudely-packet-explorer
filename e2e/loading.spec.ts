// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test } from '@playwright/test';
import { fileURLToPath } from 'node:url';

test('each analysis gets a fresh clock and phase progress survives cancel and retry', async ({ page }) => {
  await page.addInitScript(() => {
    const control = window as unknown as { runClock: number; analysisWorkers: FakeWorker[] };
    control.runClock = 1000;
    control.analysisWorkers = [];
    performance.now = () => control.runClock;
    class FakeWorker {
      onmessage: ((event: { data: unknown }) => void) | null = null;
      terminated = false;
      constructor() { control.analysisWorkers.push(this); }
      postMessage() {}
      terminate() { this.terminated = true; }
      emit(data: unknown) { this.onmessage?.({ data }); }
    }
    window.Worker = FakeWorker as unknown as typeof Worker;
  });
  await page.goto('');
  const open = () => page.locator('input[type=file]').first().setInputFiles({ name: 'clock.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: Buffer.from('test') });
  const tick = (value: number) => page.evaluate((clock) => { (window as unknown as { runClock: number }).runClock = clock; }, value);
  const progress = (phase: string, fraction: number | null, message: string) => page.evaluate((payload) => {
    const workers = (window as unknown as { analysisWorkers: { emit: (data: unknown) => void }[] }).analysisWorkers;
    workers.at(-1)!.emit({ type: 'progress', progress: payload });
  }, { phase, fraction, message });
  const elapsed = page.getByTestId('analysis-elapsed');
  await tick(301000); // The landing page has been idle for five minutes.
  await open();
  await expect(elapsed).toContainText('0 s elapsed');
  await tick(313000);
  await expect(elapsed).toContainText('12 s elapsed');
  await progress('engine', 1, 'Downloading engine data…');
  await expect(page.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '100');
  await expect(page.getByText('100% of current download', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeVisible();
  await progress('init', null, 'Starting Wireshark engine…');
  await expect(page.getByRole('progressbar')).toHaveAccessibleName('Initialize the Wireshark engine progress');
  await expect(page.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(elapsed).toHaveCount(0);
  await tick(900000);
  await open();
  await expect(elapsed).toContainText('0 s elapsed');
  // A cancelled worker cannot contaminate the new run's progress.
  await page.evaluate(() => {
    const workers = (window as unknown as { analysisWorkers: { emit: (data: unknown) => void; terminated: boolean }[] }).analysisWorkers;
    if (!workers[0].terminated) throw new Error('Cancelled worker was not terminated');
    workers[0].emit({ type: 'progress', progress: { phase: 'extract', fraction: 0.7, message: 'Stale progress' } });
  });
  await expect(page.getByText('Stale progress')).toHaveCount(0);
  await page.evaluate(() => {
    (window as unknown as { analysisWorkers: { emit: (data: unknown) => void }[] }).analysisWorkers.at(-1)!.emit({ type: 'error', stage: 'open', message: 'Synthetic failure' });
  });
  await expect(page.getByRole('alert')).toContainText('Synthetic failure');
  await tick(1200000);
  await open();
  await expect(elapsed).toContainText('0 s elapsed');
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('cold analysis and warm capture replacement complete only with ready results', async ({ page }) => {
  await page.goto('');
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/dns.pcap', import.meta.url)));
  await expect(page.locator('.cap-title h1')).toHaveText('dns.pcap');
  await expect(page.getByTestId('analysis-elapsed')).toHaveCount(0);
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/http.pcap', import.meta.url)));
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await expect(page.getByTestId('analysis-elapsed')).toHaveCount(0);
});
