// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
for (const width of [1440, 960, 390]) {
  test(`capture toolbar remains compact and usable at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.goto('./');
    const filename = 'long-capture-name-' + 'network-investigation-'.repeat(9) + '.pcap';
    await page.locator('input[type=file]').first().setInputFiles({ name: filename, mimeType: 'application/vnd.tcpdump.pcap', buffer: readFileSync(fixture('http.pcap')) });
    await expect(page.locator('.cap-title h1')).toHaveText(filename);
    await page.evaluate(() => document.fonts.ready);
    const toolbar = page.getByRole('banner', { name: 'Capture toolbar' });
    const box = await toolbar.boundingBox();
    expect(box!.height).toBeLessThan(width === 390 ? 180 : 140);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.locator('.capture-help summary').focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.capture-help .capture-action-panel')).toContainText(filename);
    await expect(page.locator('.capture-help')).toContainText('Your capture is processed locally');
    await page.getByRole('button', { name: 'Close help', exact: true }).click();
    await expect(page.locator('.capture-help summary')).toBeFocused();
    await page.locator('.capture-toolbar-actions > .capture-action-menu').filter({ hasText: 'Capture actions' }).locator('summary').click();
    await expect(page.getByRole('button', { name: 'Open another', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Compare captures', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Close', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: /Colour theme:/ }).click();
    await expect(page.getByRole('button', { name: /Colour theme: light/ })).toBeVisible();
    await page.evaluate(() => { location.hash = '#/overview?hf=10.0.0.5&t0=0.001&t1=0.05'; });
    await expect(page.getByRole('button', { name: 'Remove time range filter' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.5' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Clear filters', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Remove time range filter' })).toHaveCount(0);
    await page.locator('input[aria-label="Open another capture"]').setInputFiles(fixture('cut.pcap'));
    await expect(page.locator('.cap-title h1')).toHaveText('cut.pcap');
    await expect(toolbar).toContainText('incomplete file');
    expect(await toolbar.evaluate((element) => getComputedStyle(element).position)).toBe('static');
  });
}
