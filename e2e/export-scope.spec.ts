// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Place each protocol fixture in its own ten-second window. HTTP is the
// second window and contributes exactly 31 of the combined 129 packets.
function mixedCapture(): Buffer {
  const names = ['dns', 'http', 'tls', 'protocols', 'http2', 'ip-data'];
  const captures = names.map((name) => readFileSync(fileURLToPath(new URL(`../fixtures/${name}.pcap`, import.meta.url))));
  const header = captures[0].subarray(0, 24);
  const records: Buffer[] = [];
  for (const [window, capture] of captures.entries()) {
    expect(capture.subarray(0, 24)).toEqual(header);
    let firstTime: bigint | undefined;
    for (let offset = 24; offset < capture.length;) {
      const time = BigInt(capture.readUInt32LE(offset)) * 1_000_000n + BigInt(capture.readUInt32LE(offset + 4));
      firstTime ??= time;
      const target = 1_700_000_000_000_000n + BigInt(window) * 10_000_000n + time - firstTime;
      const length = 16 + capture.readUInt32LE(offset + 8);
      const record = Buffer.from(capture.subarray(offset, offset + length));
      record.writeUInt32LE(Number(target / 1_000_000n), 0);
      record.writeUInt32LE(Number(target % 1_000_000n), 4);
      records.push(record);
      offset += length;
    }
  }
  return Buffer.concat([header, ...records]);
}

async function openMixed(page: Page) {
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles({ name: 'mixed.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: mixedCapture() });
  await expect(page.locator('.cap-title h1')).toHaveText('mixed.pcap');
}

async function download(page: Page, name: string, keyboard = false): Promise<{ text: string; filename: string }> {
  const menu = page.locator('.json-export-menu');
  await menu.locator('summary').click();
  const button = menu.getByRole('button', { name, exact: true });
  const pending = page.waitForEvent('download');
  if (keyboard) {
    await button.focus();
    await button.press('Enter');
  } else await button.click();
  const result = await pending;
  const path = await result.path();
  if (!path) throw new Error('Download path unavailable');
  await expect(menu).not.toHaveAttribute('open', '');
  await expect(menu.locator('summary')).toBeFocused();
  return { text: readFileSync(path, 'utf8'), filename: result.suggestedFilename() };
}

test('Export labels scope before download and preserves 31 selected versus 129 whole packets', async ({ page }) => {
  const outbound: string[] = [];
  page.on('request', (request) => {
    if (/^https?:/.test(request.url()) && new URL(request.url()).hostname !== 'localhost') outbound.push(request.url());
  });
  await openMixed(page);
  const menu = page.locator('.json-export-menu');
  await menu.locator('summary').click();
  await expect(menu.getByRole('button', { name: 'Download current selection HTML' })).toBeDisabled();
  await expect(menu).toContainText('Whole capture: 129 analyzed packets');
  await expect(menu).toContainText('current search and sort');
  await page.keyboard.press('Escape');
  await page.getByLabel('Time range start in seconds').fill('10');
  const end = page.getByLabel('Time range end in seconds');
  await end.fill('16');
  await end.press('Enter');
  await expect(page.locator('.cap-facts')).toContainText('31 / 129');
  await menu.locator('summary').click();
  await expect(menu).toContainText('31 of 129 packets');
  await expect(menu).toContainText('JSON downloads always cover the whole capture');
  await expect(menu).toContainText('including MAC vendor strings and ALPN values');
  await expect(menu).toContainText('ports, traffic sizes, protocol labels, and counts remain');
  await expect(menu.getByRole('checkbox')).toBeChecked();
  await expect(menu.getByRole('button', { name: 'Download current selection HTML' })).toBeEnabled();
  await page.keyboard.press('Escape');

  const selected = await download(page, 'Download current selection HTML', true);
  expect(selected.filename).toBe('mixed-filtered-report.html');
  expect(selected.text).toContain('Active shared-filter aggregates');
  expect(selected.text).toContain('<span>Matching packets</span><strong>31</strong>');
  expect(selected.text).toContain('10.000000–16.000000');
  const whole = await download(page, 'Download whole capture HTML', true);
  expect(whole.filename).toBe('mixed-report.html');
  expect(whole.text).toContain('Whole-capture aggregates');
  expect(whole.text).toContain('<span>Packets</span><strong>129</strong>');
  const aggregateDownload = await download(page, 'Download whole capture aggregate JSON', true);
  const aggregate = JSON.parse(aggregateDownload.text);
  expect(aggregateDownload.filename).toBe('mixed-summary.json');
  expect(aggregate.capture.packetCount).toBe(129);
  expect(aggregate.export.mode).toBe('aggregate');
  expect(aggregate).not.toHaveProperty('hosts');
  expect(aggregateDownload.text).not.toContain('mixed.pcap');
  const redactedDownload = await download(page, 'Download whole capture detailed JSON', true);
  const redactedText = redactedDownload.text;
  const redacted = JSON.parse(redactedText);
  expect(redactedDownload.filename).toBe('mixed-details.json');
  expect(redacted.capture.packetCount).toBe(129);
  expect(redacted.capture.fileName).toBe('[REDACTED]');
  expect(redacted.export.redaction).toBe('known sensitive fields replaced with [REDACTED]');
  expect(redactedText).not.toContain('mixed.pcap');
  expect(redactedText).not.toContain('fixture-agent/1.0');
  expect(redacted.export.neverIncluded).toContain('Reassembled TCP/UDP stream payloads');
  expect(redacted.export.sensitiveData.join('\n')).toContain('MAC vendor strings');
  expect(redacted.export.sensitiveData.join('\n')).toContain('ALPN');
  expect(outbound).toEqual([]);
});

test('Export dismisses on Escape and outside click and fits a narrow viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openMixed(page);
  const menu = page.locator('.json-export-menu');
  const trigger = menu.locator('summary');
  await trigger.focus();
  await trigger.press('Enter');
  await expect(menu).toHaveAttribute('open', '');
  await menu.getByRole('checkbox').focus();
  await page.keyboard.press('Escape');
  await expect(menu).not.toHaveAttribute('open', '');
  await expect(trigger).toBeFocused();
  await trigger.press('Space');
  const bounds = await menu.locator('.json-export-panel').boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  await page.mouse.click(4, 4);
  await expect(menu).not.toHaveAttribute('open', '');
  await expect(trigger).toBeFocused();
  await expect(menu.getByRole('button', { name: 'Close export menu' })).toHaveCount(0);
});
