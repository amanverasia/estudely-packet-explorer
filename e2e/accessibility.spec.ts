// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AxeResults } from 'axe-core';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
const axeScript = readFileSync(new URL('../node_modules/axe-core/axe.min.js', import.meta.url), 'utf8');

async function audit(page: Page) {
  const violations = await page.evaluate(async () => {
    const axe = (window as unknown as { axe: { run: (context: Document, options: unknown) => Promise<AxeResults> } }).axe;
    const result = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] } });
    return result.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) }));
  });
  expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
}

async function openCapture(page: Page, name: string) {
  await page.locator('input[type=file]').first().setInputFiles(fixture(name));
  await expect(page.locator('.cap-title h1')).toHaveText(name);
}

async function view(page: Page, id: string) {
  const link = page.locator(`.nav a[href="#/${id}"]`);
  if (!(await link.isVisible())) await page.locator('.workspace-absent summary').click();
  await link.click();
  await expect(page.locator(`.nav a[href="#/${id}"]`)).toHaveAttribute('aria-current', 'page');
}

test.beforeEach(async ({ page }) => {
  await page.route('**/axe-for-test.js', (route) => route.fulfill({ contentType: 'application/javascript', body: axeScript }));
  await page.goto('./');
  await page.addScriptTag({ url: './axe-for-test.js' });
});

test('chart data is readable without hover and selectable bars support Space', async ({ page }) => {
  await openCapture(page, 'dns.pcap');
  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    await view(page, 'overview');
    await page.getByRole('group', { name: 'Chart metric', exact: true }).getByRole('button', { name: 'Packets', exact: true }).click();
    const timeTable = page.locator('.chart-data').filter({ hasText: 'Traffic over time as a table' });
    await timeTable.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(timeTable.getByRole('columnheader', { name: 'Total' })).toBeVisible();
    const headers = await timeTable.locator('thead th').allTextContents();
    expect(headers).toContain('DNS');
    // Every interval is exposed, including zero-valued cells; totals match the capture.
    const total = await timeTable.locator('tbody tr').evaluateAll((rows) => rows.reduce((sum, row) => sum + Number(row.lastElementChild!.textContent!.replaceAll(',', '')), 0));
    const packetFact = page.locator('.fact').filter({ has: page.getByText('Packets', { exact: true }) });
    expect(total).toBe(Number((await packetFact.locator('dd').innerText()).replaceAll(',', '')));
    await audit(page);
    await timeTable.locator('summary').click();

    await view(page, 'dns');
    const charts = page.locator('.summary-fold');
    if (!(await charts.evaluate((el) => (el as HTMLDetailsElement).open))) await charts.locator('> summary').click();
    const pairTable = page.locator('.chart-data');
    await pairTable.locator('summary').focus();
    await page.keyboard.press('Space');
    await expect(pairTable.getByRole('columnheader', { name: 'Queries' })).toBeVisible();
    await expect(pairTable.locator('tbody')).toContainText('10.0.0.5');
    await audit(page);
    await pairTable.locator('summary').click();

    await view(page, 'network');
    const graphList = page.locator('.network-list');
    await graphList.locator('summary').focus();
    await page.keyboard.press('Enter');
    const inspectHost = graphList.getByRole('button', { name: /^Inspect host / }).first();
    await inspectHost.focus();
    await page.keyboard.press('Space');
    await expect(inspectHost).toHaveAttribute('aria-pressed', 'true');
    const details = page.getByRole('region', { name: 'Selected graph item details' });
    await expect(details.getByRole('button', { name: 'Host details', exact: true })).toBeVisible();
    const inspectLink = graphList.getByRole('button', { name: /^Inspect link between / }).first();
    await inspectLink.focus();
    await page.keyboard.press('Enter');
    await expect(inspectLink).toHaveAttribute('aria-pressed', 'true');
    await expect(details).toContainText('Protocols');
    await audit(page);
    await graphList.locator('summary').click();
  }

  await view(page, 'overview');
  const talker = page.locator('.panel').filter({ has: page.getByRole('heading', { name: 'Top talkers', exact: true }) }).getByRole('button').first();
  await talker.focus();
  await page.keyboard.press('Space');
  await expect(page.locator('.filter-chips')).toContainText('Host');
  await expect(page).toHaveURL(/hf=/);
});

test('Files and populated protocol dashboards pass axe in both themes', async ({ page }) => {
  await openCapture(page, 'http.pcap');
  await view(page, 'files');
  await expect(page.getByRole('grid', { name: 'Exported files' })).toBeVisible();
  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    await audit(page);
  }
  await openCapture(page, 'protocols.pcap');
  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    for (const id of ['quic', 'ssh', 'dhcp', 'arp', 'icmp']) {
      await view(page, id);
      await expect(page.getByRole('grid').first()).toBeVisible();
      await audit(page);
    }
  }
});

test('packet rows open with Space and the toolbar time range is keyboard accessible', async ({ page }) => {
  await openCapture(page, 'http.pcap');
  await view(page, 'packets');
  await expect(page.getByText('31 of 31 packets')).toBeVisible();
  const packetGrid = page.getByRole('grid', { name: 'Packets' });
  const packetRow = packetGrid.locator('[role="row"][tabindex="0"]').first();
  await packetRow.focus();
  const scrollBefore = await page.evaluate(() => ({
    grid: document.querySelector('.dt-scroll')?.scrollTop ?? null,
    main: document.querySelector('.main')?.scrollTop ?? null,
    win: window.scrollY,
  }));
  await page.keyboard.press('Space');
  await expect(page.getByRole('dialog', { name: /Packet details: Packet #/ })).toBeVisible();
  const scrollAfter = await page.evaluate(() => ({
    grid: document.querySelector('.dt-scroll')?.scrollTop ?? null,
    main: document.querySelector('.main')?.scrollTop ?? null,
    win: window.scrollY,
  }));
  expect(scrollAfter).toEqual(scrollBefore);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toBeHidden();

  await page.locator('.strip-range-menu > summary').click();
  const rangeStart = page.getByRole('spinbutton', { name: 'Traffic strip start in seconds' });
  const rangeEnd = page.getByRole('spinbutton', { name: 'Traffic strip end in seconds' });
  await rangeStart.fill('0');
  await rangeEnd.fill('0.5');
  await rangeEnd.press('Enter');
  await expect(page.locator('.nav a[href="#/packets"]')).toHaveAttribute('aria-current', 'page');
  const timeChip = page.getByRole('button', { name: 'Remove time range filter' });
  await expect(timeChip).toBeVisible();
  await expect(page.locator('.filter-chips')).toContainText('Time');
  await expect.poll(() => page.evaluate(() => location.hash)).toMatch(/[?&]t0=/);
  await expect.poll(() => page.evaluate(() => location.hash)).toMatch(/[?&]t1=/);
  await expect(page.getByRole('status').filter({ hasText: 'Shared filter:' })).toContainText(/of 31 packets/);
  await expect(page.getByRole('status').filter({ hasText: 'Shared filter:' })).not.toContainText('31 of 31 packets');
  await timeChip.click();
  await expect(timeChip).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => location.hash)).not.toMatch(/[?&]t0=/);
});
