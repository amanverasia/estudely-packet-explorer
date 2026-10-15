// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

test('landing links to the About page and carries the credit line', async ({ page, context }) => {
  await page.goto('./');
  const popup = context.waitForEvent('page');
  await page.getByRole('link', { name: 'About', exact: true }).click();
  const about = await popup;
  await about.waitForLoadState();
  await expect(about).toHaveTitle('About and licences');
  await expect(about.getByRole('heading', { level: 1 })).toHaveText('About Estudely Packet Explorer');
  await expect(about.getByRole('heading', { name: 'What leaves your device' })).toBeVisible();
  await expect(about.getByRole('heading', { name: 'Known limitations' })).toBeVisible();
  const footer = page.locator('.landing-footer .credit');
  await expect(footer).toHaveText('made by Aman Verasia · estudely.com · github.com/amanverasia');
  await expect(footer.getByRole('link', { name: 'estudely.com' })).toHaveAttribute('href', 'https://estudely.com');
  await expect(footer.getByRole('link', { name: 'github.com/amanverasia' })).toHaveAttribute('rel', 'noopener noreferrer');
  // The header carries no estudely.com link.
  await expect(page.locator('.landing-header a[href*="estudely.com"]')).toHaveCount(0);
});

test('workspace sidebar links to About and licences with the credit line', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles({ name: 'dns.pcap', mimeType: 'application/vnd.tcpdump.pcap', buffer: readFileSync(fixture('dns.pcap')) });
  const foot = page.locator('.sidebar-foot');
  await expect(foot.getByRole('link', { name: 'About and licences' })).toHaveAttribute('href', './ABOUT.html');
  await expect(foot.locator('.credit')).toHaveText('made by Aman Verasia · estudely.com · github.com/amanverasia');
});

test('landing footer lines up with the page: credit on the left edge, source and version on the right', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('./');
  const box = async (sel: string) => (await page.locator(sel).first().boundingBox())!;
  const brand = await box('.landing-brand');
  const actions = await box('.landing-header button:has-text("Theme")');
  const credit = await box('.landing-footer .credit');
  const source = await box('.landing-footer .build-tag > a');
  // Credit starts at the same left edge as the brand; source link ends at the right edge of the header buttons.
  expect(Math.abs(credit.x - brand.x)).toBeLessThanOrEqual(2);
  expect(Math.abs(source.x + source.width - (actions.x + actions.width))).toBeLessThanOrEqual(2);
  expect(credit.x + credit.width).toBeLessThan(source.x);

  // Phone width: everything left-aligned in one column, no sideways scroll.
  await page.setViewportSize({ width: 390, height: 844 });
  const cr = await box('.landing-footer .credit');
  const sr = await box('.landing-footer .build-tag > a');
  expect(Math.abs(cr.x - sr.x)).toBeLessThanOrEqual(2);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
