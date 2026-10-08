// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
const routes = ['overview', 'hosts', 'connections', 'network', 'packets', 'dns', 'http', 'files', 'tls', 'quic', 'ssh', 'dhcp', 'arp', 'icmp'];

function mixedCapture() {
  const captures = ['dns.pcap', 'http.pcap', 'tls.pcap', 'protocols.pcap', 'http2.pcap', 'ip-data.pcap'].map((name) => readFileSync(fixture(name)));
  const header = captures[0].subarray(0, 24);
  const records: { time: bigint; bytes: Buffer }[] = [];
  for (const [window, capture] of captures.entries()) {
    if (!capture.subarray(0, 24).equals(header)) throw new Error('Mixed fixtures must share a PCAP header');
    let first: bigint | undefined;
    for (let offset = 24; offset < capture.length;) {
      const included = capture.readUInt32LE(offset + 8);
      const source = BigInt(capture.readUInt32LE(offset)) * 1_000_000n + BigInt(capture.readUInt32LE(offset + 4));
      first ??= source;
      const time = 1_700_000_000_000_000n + BigInt(window) * 10_000_000n + source - first;
      const bytes = Buffer.from(capture.subarray(offset, offset + 16 + included));
      bytes.writeUInt32LE(Number(time / 1_000_000n), 0);
      bytes.writeUInt32LE(Number(time % 1_000_000n), 4);
      records.push({ time, bytes });
      offset += 16 + included;
    }
  }
  records.sort((a, b) => a.time < b.time ? -1 : a.time > b.time ? 1 : 0);
  return Buffer.concat([header, ...records.map((record) => record.bytes)]);
}

async function openCapture(page: Page, name = 'dns.pcap') {
  await page.locator('input[type=file]').first().setInputFiles(fixture(name));
  await expect(page.locator('.cap-title h1')).toHaveText(name);
}

async function navigate(page: Page, route: string, narrow: boolean) {
  const sidebar = page.locator('.workspace-sidebar');
  if (narrow) await sidebar.getByLabel('Current view').selectOption(route);
  else {
    const link = sidebar.locator(`a[href="#/${route}"]`);
    if (!await link.isVisible()) {
      const details = sidebar.locator('details');
      if (!await details.getAttribute('open')) await details.locator('summary').click();
    }
    await link.click();
  }
  await expect.poll(() => page.evaluate(() => location.hash.split('?')[0])).toBe(`#/${route}`);
  if (narrow) await expect(sidebar.getByLabel('Current view')).toHaveValue(route);
  else await expect(sidebar.locator(`a[href="#/${route}"]`)).toHaveAttribute('aria-current', 'page');
}

for (const width of [390, 820, 1440]) {
  test(`all grouped routes are reachable without sidebar overflow at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.goto('./');
    await openCapture(page);
    const sidebar = page.locator('.workspace-sidebar');
    const narrow = width <= 860;
    if (narrow) {
      await expect(sidebar.getByLabel('Current view')).toBeVisible();
      await expect(sidebar.locator('option')).toHaveCount(routes.length);
      await expect(sidebar.locator('optgroup')).toHaveCount(2);
      await expect(sidebar.locator('.brand')).toBeHidden();
      await expect(sidebar.locator('option[value="http"]')).toContainText('absent');
      const select = sidebar.getByLabel('Current view');
      await select.focus();
      await expect(select).toBeFocused();
      await select.press('ArrowDown');
      await select.press('Enter');
      await expect.poll(() => page.evaluate(() => location.hash.split('?')[0])).toBe('#/hosts');
    } else {
      await expect(sidebar.getByRole('heading', { name: 'Investigation' })).toBeVisible();
      await expect(sidebar.getByRole('heading', { name: 'Protocols', exact: true })).toBeVisible();
      await expect(sidebar.locator('a[href="#/http"]')).toBeHidden();
      await sidebar.locator('summary').focus();
      await sidebar.locator('summary').press('Enter');
      await expect(sidebar.locator('a[href="#/http"]')).toBeVisible();
    }
    expect(await sidebar.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
    const titles = ['Overview', 'Hosts', 'Connections', 'Network', 'Packet list', 'Name resolution', 'HTTP', 'Files', 'TLS', 'QUIC', 'SSH', 'DHCP', 'ARP', 'ICMP'];
    for (const [index, route] of routes.entries()) {
      await navigate(page, route, narrow);
      await expect(page.locator('.view-head').getByRole('heading', { name: titles[index], exact: true })).toBeVisible();
    }
    // Absent destinations stay discoverable when reached directly.
    await page.evaluate(() => { location.hash = '#/tls'; });
    await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/tls');
    if (!narrow) await expect(sidebar.locator('a[href="#/tls"]')).toBeVisible();
    await navigate(page, 'overview', narrow);
    await page.locator('input[type=file]').first().setInputFiles({ name: 'mixed.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: mixedCapture() });
    await expect(page.locator('.cap-title h1')).toHaveText('mixed.pcap');
    await page.screenshot({ path: testInfo.outputPath(`navigation-${width}.png`), fullPage: true });
  });
}

test('navigation retains shared filters, keeps filtered zero protocols visible, and resets a replacement capture', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('./');
  await openCapture(page);
  await page.evaluate(() => { location.hash = '#/dns?hf=192.0.2.200&t0=0&t1=1'; });
  const sidebar = page.locator('.workspace-sidebar');
  // DNS exists in the full capture even when no packets match the shared filters.
  await expect(sidebar.locator('a[href="#/dns"]')).toBeVisible();
  for (const route of ['hosts', 'packets', 'dns']) {
    await navigate(page, route, false);
    await expect.poll(() => page.evaluate(() => {
      const params = new URLSearchParams(location.hash.split('?')[1]);
      return [params.get('hf'), params.get('t0'), params.get('t1')];
    })).toEqual(['192.0.2.200', '0', '1']);
  }
  await openCapture(page, 'http.pcap');
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/overview');
  await expect(sidebar.locator('a[href="#/http"]')).toBeVisible();
  await expect(sidebar.locator('a[href="#/dns"]')).toBeHidden();
});

test('the first capture from a deep link opens Overview with a clean hash', async ({ page }) => {
  await page.goto('./');
  await page.evaluate(() => { location.hash = '#/connections?conv=3&hf=10.0.0.9'; });
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/connections?conv=3&hf=10.0.0.9');
  await page.locator('input[type=file]').first().setInputFiles(fixture('dns.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('dns.pcap');
  await expect(page.locator('.view-head').getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/overview');
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.9' })).toHaveCount(0);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.locator('.workspace-sidebar a[href="#/dns"]').click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/dns');
  await expect(page.locator('.view-head').getByRole('heading', { name: 'Name resolution', exact: true })).toBeVisible();
});

test('an unmatched shared link is explained and a matching host filter still applies', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('./');
  await openCapture(page);
  await page.evaluate(() => { location.hash = '#/overview?hf=203.0.113.5'; });
  const unmatchedHost = page.getByRole('status').filter({ hasText: '203.0.113.5' });
  await expect(unmatchedHost).toBeVisible();
  await expect(unmatchedHost).toContainText('hf');
  await expect(page.getByRole('button', { name: 'Remove host filter for 203.0.113.5' })).toHaveCount(0);
  await expect(page.getByText(/Shared filter:/)).toHaveCount(0);
  await unmatchedHost.getByRole('button', { name: 'Dismiss' }).click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/overview');

  await page.evaluate(() => { location.hash = '#/overview?hf=10.0.0.5'; });
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.5' })).toBeVisible();
  await expect(page.getByRole('status').filter({ hasText: '203.0.113.5' })).toHaveCount(0);

  await page.evaluate(() => { location.hash = '#/connections?conv=999'; });
  await expect(page.getByRole('status').filter({ hasText: '999' })).toContainText('conv');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.evaluate(() => { location.hash = '#/connections?hf=10.0.0.9&conv=0'; });
  await expect(page.getByRole('status').filter({ hasText: 'outside the current filter' })).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove host filter for 10.0.0.9' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();

  await page.evaluate(() => { location.hash = '#/hosts?host=203.0.113.9'; });
  await expect(page.getByRole('status').filter({ hasText: '203.0.113.9' })).toContainText('host');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.evaluate(() => { location.hash = '#/hosts?host=10.0.0.5'; });
  await expect(page.getByRole('dialog')).toContainText('10.0.0.5');
});
