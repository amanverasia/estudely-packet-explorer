// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Download, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

interface DownloadControl {
  holdNextDownload: boolean;
  failNextDownload: boolean;
  releaseDownload: (() => void) | null;
  blobTypes: string[];
}

async function instrument(page: Page) {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    const NativeBlob = window.Blob;
    const flags = window as unknown as DownloadControl;
    flags.holdNextDownload = false;
    flags.failNextDownload = false;
    flags.releaseDownload = null;
    flags.blobTypes = [];
    window.Blob = class RecordingBlob extends NativeBlob {
      constructor(parts?: BlobPart[], options?: BlobPropertyBag) {
        super(parts, options);
        if (options?.type) flags.blobTypes.push(options.type);
      }
    } as typeof Blob;
    class HoldingWorker {
      native: Worker;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event: ErrorEvent) => void) | null = null;
      constructor(url: string | URL, options?: WorkerOptions) {
        this.native = new NativeWorker(url, options);
        this.native.onmessage = (event) => this.onmessage?.(event);
        this.native.onerror = (event) => this.onerror?.(event);
      }
      postMessage(message: { type?: string; id?: number; req?: { kind?: string } }) {
        if (message?.type === 'request' && message.req?.kind === 'downloadObject') {
          if (flags.failNextDownload) {
            flags.failNextDownload = false;
            const id = message.id;
            queueMicrotask(() => this.onmessage?.({ data: { type: 'response', id, ok: false, error: 'synthetic failure' } } as MessageEvent));
            return;
          }
          if (flags.holdNextDownload) {
            flags.holdNextDownload = false;
            flags.releaseDownload = () => {
              flags.releaseDownload = null;
              this.native.postMessage(message);
            };
            return;
          }
        }
        this.native.postMessage(message);
      }
      terminate() { this.native.terminate(); }
    }
    window.Worker = HoldingWorker as unknown as typeof Worker;
  });
}

async function openFiles(page: Page) {
  await page.locator('input[type=file]').first().setInputFiles(fixture('http.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  const link = page.locator('.nav a[href="#/files"]');
  if (!(await link.isVisible())) await page.locator('.workspace-absent summary').click();
  await link.click();
  await expect(page.getByRole('grid', { name: 'Exported files' })).toBeVisible();
}

test('one file download does not disable the other Download button', async ({ page }) => {
  await instrument(page);
  await page.goto('./');
  await openFiles(page);
  const indexButton = page.getByRole('button', { name: /^Download index\.html/ });
  const loginButton = page.getByRole('button', { name: /^Download login/ });
  await expect(indexButton).toBeEnabled();
  await expect(loginButton).toBeEnabled();

  await page.evaluate(() => { (window as unknown as DownloadControl).holdNextDownload = true; });
  await indexButton.click();
  await expect(indexButton).toBeDisabled();
  await expect(indexButton).toHaveText('Saving…');
  await expect(loginButton).toBeEnabled();
  await expect(loginButton).toHaveText('Download');

  const loginDownload = page.waitForEvent('download');
  await loginButton.click();
  expect((await loginDownload).suggestedFilename()).toBe('login');
  await expect(loginButton).toBeEnabled();
  await expect(loginButton).toHaveText('Download');
  await expect(indexButton).toBeDisabled();
  await expect(indexButton).toHaveText('Saving…');
  await expect(page).not.toHaveURL(/^blob:/);

  const indexDownload: Promise<Download> = page.waitForEvent('download');
  await page.evaluate(() => (window as unknown as DownloadControl).releaseDownload?.());
  expect((await indexDownload).suggestedFilename()).toBe('index.html');
  await expect(indexButton).toBeEnabled();
  await expect(indexButton).toHaveText('Download');
  await expect(loginButton).toBeEnabled();
  expect(await page.evaluate(() => (window as unknown as DownloadControl).blobTypes)).toContain('application/octet-stream');

  await page.evaluate(() => { (window as unknown as DownloadControl).failNextDownload = true; });
  await indexButton.click();
  await expect(page.getByRole('alert')).toContainText('Could not save index.html: synthetic failure');
  await expect(indexButton).toBeEnabled();
  await expect(indexButton).toHaveText('Download');
  await expect(indexButton).toHaveAttribute('aria-invalid', 'true');
  await expect(loginButton).toBeEnabled();
  await expect(loginButton).toHaveText('Download');
  await expect(page).not.toHaveURL(/^blob:/);
});
