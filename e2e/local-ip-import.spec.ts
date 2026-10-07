// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test } from '@playwright/test';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

test('gzip import transfers typed ranges, persists offline, and failed replacement keeps installed data', async ({ page }, testInfo) => {
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
  await page.locator('a[href="#/hosts"]').click();
  const row = page.getByRole('grid', { name: 'Hosts' }).getByRole('row').filter({ hasText: '8.8.8.8' });
  await page.getByText('Add country/ASN data', { exact: false }).click();
  const asn = page.getByLabel('Import ASN CSV');
  const csv = '\uFEFFIP_START,IP_END,ASN,AS_NAME\r\n2001:4860::,2001:4860::ffff,15169,"Café, ""ISP""\nnetwork"\r\n8.8.8.0,8.8.8.255,15169,"Café, ""ISP""\nnetwork"';
  await asn.setInputFiles({ name: 'asn-2026-10.csv.gz', mimeType: 'application/gzip', buffer: gzipSync(csv) });
  await expect(row).toContainText('AS15169 Café, "ISP"');
  await expect(page.getByText('Ready offline · release 2026-10 · 2 ranges')).toBeVisible();
  const stored = await page.evaluate(async () => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('estudely-local-ip-data', 1);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const result = await new Promise<any>((resolve, reject) => {
      const request = db.transaction('databases').objectStore('databases').get('asn');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    db.close();
    return { typed: result.ipv4Start instanceof Uint32Array && result.ipv6End instanceof Uint32Array,
      rows: result.recordCount, label: result.values[0] };
  });
  expect(stored).toEqual({ typed: true, rows: 2, label: 'Café, "ISP"\nnetwork' });

  for (const buffer of [Buffer.from([0xff]), gzipSync(csv).subarray(0, 10), Buffer.from('8.8.8.0,8.8.8.255,1,"unclosed')]) {
    await asn.setInputFiles({ name: 'bad.csv.gz', mimeType: 'application/gzip', buffer });
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(row).toContainText('AS15169 Café, "ISP"');
    await expect(page.getByText('Ready offline · release 2026-10 · 2 ranges')).toBeVisible();
  }
  await testInfo.attach('hosts-imported', { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
  await page.reload();
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
  await page.locator('a[href="#/hosts"]').click();
  await expect(page.getByRole('grid', { name: 'Hosts' }).getByRole('row').filter({ hasText: '8.8.8.8' })).toContainText('AS15169 Café, "ISP"');
  await expect(page.getByText('ASN ready offline', { exact: false })).toBeVisible();
  await page.getByText('Manage country/ASN data', { exact: false }).click();
  await page.getByRole('button', { name: 'Remove ASN data' }).click();
  await expect(page.getByRole('columnheader', { name: 'Approx. network owner' })).toHaveCount(0);
  await expect(page.getByText('Not installed', { exact: true })).toHaveCount(2);
  await page.reload();
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
  await page.locator('a[href="#/hosts"]').click();
  await expect(page.getByRole('columnheader', { name: 'Approx. network owner' })).toHaveCount(0);
});

for (const viewport of [{ width: 1440, height: 900 }, { width: 960, height: 900 }, { width: 390, height: 844 }]) {
  test(`hosts foreground records and keyboard-accessible optional data at ${viewport.width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize(viewport);
    const externalRequests: string[] = [];
    page.on('request', (request) => {
      if (!request.url().startsWith('http://localhost:') && /^https?:/.test(request.url())) externalRequests.push(request.url());
    });
    await page.goto('./');
    await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
    await page.locator('a[href="#/hosts"]').click();
    const grid = page.getByRole('grid', { name: 'Hosts' });
    await expect(grid.getByRole('row').filter({ hasText: '8.8.8.8' })).toBeVisible();
    await expect(page.getByLabel('Import Country CSV')).toBeHidden();
    await expect(grid.getByRole('columnheader', { name: 'Approx. country' })).toHaveCount(0);
    await expect(grid.getByRole('columnheader', { name: 'Approx. network owner' })).toHaveCount(0);
    const bounds = await grid.boundingBox();
    const heading = await page.getByRole('heading', { name: 'Hosts', exact: true }).boundingBox();
    expect(bounds!.y - heading!.y).toBeLessThan(400);
    await testInfo.attach(`hosts-no-data-${viewport.width}`, { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
    const downloadReady = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export CSV', exact: true }).click();
    const download = await downloadReady;
    const stream = await download.createReadStream();
    let exported = '';
    for await (const chunk of stream!) exported += chunk.toString();
    expect(exported.split('\n')[0]).toContain('Approx. country,Approx. network owner');
    await page.getByLabel('Show country/ASN columns').check();
    await expect(grid.getByRole('columnheader', { name: 'Approx. country' })).toBeAttached();
    await page.getByLabel('Show country/ASN columns').uncheck();
    const disclosure = page.locator('summary').filter({ hasText: 'Add country/ASN data' });
    await disclosure.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Import Country CSV')).toBeVisible();
    await expect(page.getByRole('link', { name: 'CC BY 4.0' })).toBeVisible();
    await page.getByLabel('Import Country CSV').setInputFiles({ name: 'country-2026-10.csv', mimeType: 'text/csv', buffer: Buffer.from('8.8.8.0,8.8.8.255,US') });
    await expect(grid.getByRole('row').filter({ hasText: '8.8.8.8' })).toContainText('US');
    await expect(grid.getByRole('columnheader', { name: 'Approx. network owner' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Remove Country data' }).click();
    await expect(grid.getByRole('columnheader', { name: 'Approx. country' })).toHaveCount(0);
    await disclosure.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByLabel('Import Country CSV')).toBeHidden();
    await grid.getByRole('row').filter({ hasText: '8.8.8.8' }).click();
    await page.getByRole('button', { name: 'Filter all views to host' }).click();
    await expect(page.getByRole('button', { name: 'Remove host filter for 8.8.8.8' })).toBeVisible();
    await page.getByRole('button', { name: /^Connections \(/ }).click();
    await expect(page).toHaveURL(/connections/);
    await expect(page.getByRole('button', { name: 'Remove host filter for 8.8.8.8' })).toBeVisible();
    expect(externalRequests).toEqual([]);
  });
}
