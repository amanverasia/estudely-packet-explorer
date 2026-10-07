// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test } from '@playwright/test';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

test('gzip import transfers typed ranges, persists offline, and failed replacement keeps installed data', async ({ page }) => {
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
  await page.locator('a[href="#/hosts"]').click();
  const row = page.getByRole('grid', { name: 'Hosts' }).getByRole('row').filter({ hasText: '8.8.8.8' });
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
  await page.reload();
  await page.locator('input[type=file]').first().setInputFiles(fileURLToPath(new URL('../fixtures/ip-data.pcap', import.meta.url)));
  await page.locator('a[href="#/hosts"]').click();
  await expect(page.getByRole('grid', { name: 'Hosts' }).getByRole('row').filter({ hasText: '8.8.8.8' })).toContainText('AS15169 Café, "ISP"');
});
