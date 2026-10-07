// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
function mixedCapture(): Buffer {
  const names = ['dns.pcap', 'http.pcap', 'tls.pcap', 'protocols.pcap', 'http2.pcap', 'ip-data.pcap'];
  const buffers = names.map((name) => readFileSync(fixture(name)));
  const header = buffers[0].subarray(0, 24);
  const records: { time: bigint; bytes: Buffer }[] = [];

  for (const [window, capture] of buffers.entries()) {
    if (capture.readUInt32LE(0) !== 0xa1b2c3d4 || !capture.subarray(0, 24).equals(header)) {
      throw new Error(`${names[window]} must use the same little-endian microsecond PCAP header`);
    }
    let offset = 24;
    let firstTime: bigint | null = null;
    while (offset < capture.length) {
      const seconds = capture.readUInt32LE(offset);
      const microseconds = capture.readUInt32LE(offset + 4);
      const included = capture.readUInt32LE(offset + 8);
      const original = capture.readUInt32LE(offset + 12);
      const sourceTime = BigInt(seconds) * 1_000_000n + BigInt(microseconds);
      firstTime ??= sourceTime;
      const targetTime = 1_700_000_000_000_000n + BigInt(window) * 10_000_000n + sourceTime - firstTime;
      const [targetSeconds, targetMicroseconds] = [targetTime / 1_000_000n, targetTime % 1_000_000n];
      const record = Buffer.alloc(16 + included);
      record.writeUInt32LE(Number(targetSeconds), 0);
      record.writeUInt32LE(Number(targetMicroseconds), 4);
      record.writeUInt32LE(included, 8);
      record.writeUInt32LE(original, 12);
      capture.copy(record, 16, offset + 16, offset + 16 + included);
      records.push({ time: targetTime, bytes: record });
      offset += 16 + included;
    }
  }
  records.sort((a, b) => a.time < b.time ? -1 : a.time > b.time ? 1 : 0);
  return Buffer.concat([header, ...records.map((record) => record.bytes)]);
}
async function network(page: Page, name: string) {
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(name === 'mixed.pcap'
    ? { name, mimeType: 'application/vnd.tcpdump.pcap', buffer: mixedCapture() } : fixture(name));
  await expect(page.locator('.cap-title h1')).toHaveText(name);
  await page.evaluate(() => { location.hash = '#/network'; });
  await expect(page.locator('.graph-node').first()).toBeVisible();
}
// ResizeObserver and React may finish the first layout on successive rendering
// frames. Wait for the rendered viewport/transform to agree across frames before
// recording the fitted baseline; a visible first node alone is too early.
async function settledGraph(page: Page) {
  await page.locator('.graph-wrap svg').evaluate(async (svg) => {
    let previous = '', stable = 0;
    for (let frame = 0; frame < 120; frame++) {
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      const bounds = svg.getBoundingClientRect();
      const current = `${bounds.width}:${bounds.height}:${svg.querySelector('g')?.getAttribute('transform')}`;
      stable = current === previous ? stable + 1 : 0;
      previous = current;
      if (stable >= 3) return;
    }
    throw new Error('Graph viewport did not settle');
  });
}
const transform = (page: Page) => page.locator('.graph-wrap svg > g').getAttribute('transform');
async function fittedBounds(page: Page) {
  return page.locator('.graph-wrap').evaluate((wrap) => {
    const svg = wrap.querySelector('svg')!, g = svg.querySelector('g')!;
    const bounds = svg.getBoundingClientRect();
    const k = g.getCTM()!.a;
    const circles = [...g.querySelectorAll('circle')].map((node) => node.getBoundingClientRect());
    return { k, inside: circles.every((r) => r.left >= bounds.left && r.right <= bounds.right && r.top >= bounds.top && r.bottom <= bounds.bottom) };
  });
}

test('graph viewport recovers from keyboard zoom and mouse pan while graph filters remain active', async ({ page }) => {
  await network(page, 'mixed.pcap');
  await expect(page.locator('.graph-node')).toHaveCount(30);
  await settledGraph(page);
  const initial = await transform(page);
  expect((await fittedBounds(page)).inside).toBe(true);
  await page.getByRole('button', { name: 'Zoom in graph' }).focus();
  await page.keyboard.press('Enter');
  await expect.poll(() => transform(page)).not.toBe(initial);
  const graph = await page.locator('.graph-wrap').boundingBox();
  if (!graph) throw new Error('Graph must be visible');
  await page.mouse.move(graph.x + 20, graph.y + 20);
  await page.mouse.down();
  await page.mouse.move(graph.x + 90, graph.y + 70, { steps: 4 });
  await page.mouse.up();
  await page.getByRole('button', { name: 'Fit graph', exact: true }).click();
  await expect.poll(() => transform(page)).toBe(initial);

  await page.getByRole('searchbox', { name: 'Search graph hosts' }).fill('10.0.0.5');
  await page.getByRole('combobox', { name: 'Focus on host', exact: true }).selectOption('10.0.0.5');
  await expect(page.getByRole('status', { name: 'Selected host label' })).toContainText('10.0.0.5');
  await page.getByRole('combobox', { name: 'Protocol filter' }).selectOption('HTTP');
  await expect(page.locator('.graph-node')).toHaveCount(2);
  await expect.poll(async () => (await fittedBounds(page)).k).toBeLessThanOrEqual(1.200001);
  await settledGraph(page);
  const focused = await transform(page);
  await page.getByRole('button', { name: 'Zoom out graph' }).click();
  await page.getByRole('button', { name: 'Reset viewport', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect.poll(() => transform(page)).toBe(focused);
  await expect(page.getByRole('combobox', { name: 'Focus on host', exact: true })).toHaveValue('10.0.0.5');
  await expect(page.getByRole('combobox', { name: 'Protocol filter' })).toHaveValue('HTTP');
  await page.locator('.network-list summary').click();
  await expect(page.getByRole('table', { name: 'Network graph links with endpoints, traffic totals, main protocol, and conversations' }).getByRole('row')).toHaveCount(2);
  await page.getByRole('button', { name: 'Clear host focus' }).click();
  await expect(page.getByRole('combobox', { name: 'Focus on host', exact: true })).toHaveValue('');
  await expect(page.getByRole('combobox', { name: 'Protocol filter' })).toHaveValue('HTTP');
});

for (const capture of ['mixed.pcap', 'dns.pcap', 'http.pcap']) {
  test(`${capture}: fit cap and framing remain useful through desktop and narrow resizes`, async ({ page }) => {
    await network(page, capture);
    for (const width of [1440, 960, 390]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
      await settledGraph(page);
      await expect.poll(async () => (await fittedBounds(page)).inside).toBe(true);
      expect((await fittedBounds(page)).k).toBeLessThanOrEqual(1.200001);
      const controls = page.getByRole('group', { name: 'Graph viewport controls' });
      await expect(controls).toBeVisible();
      const positions = await controls.getByRole('button').evaluateAll((buttons) => buttons.map((button) => {
        const rect = button.getBoundingClientRect();
        return { left: rect.left, right: rect.right };
      }));
      expect(positions.every((rect) => rect.left >= 0 && rect.right <= width)).toBe(true);
      await page.getByRole('button', { name: 'Zoom in graph' }).click();
      await page.getByRole('button', { name: 'Reset viewport', exact: true }).click();
      expect((await fittedBounds(page)).inside).toBe(true);
    }
  });
}
