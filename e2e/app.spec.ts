// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page, type Request } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
const axeScript = join(dirname(fileURLToPath(import.meta.url)), '../node_modules/axe-core/axe.min.js');

async function auditA11y(page: Page, label: string) {
  const violations = await page.evaluate(async (auditLabel) => {
    const axe = (window as unknown as { axe: { run: (target: Document, options: unknown) => Promise<{ violations: { id: string; impact: string; description: string; nodes: { target: string[] }[] }[] }> } }).axe;
    const { violations } = await axe.run(document, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
    });
    return violations.map((v) => ({ id: v.id, impact: v.impact, description: `${auditLabel}: ${v.description}`, targets: v.nodes.map((n) => n.target) }));
  }, label);
  expect(violations, JSON.stringify(violations, null, 2)).toEqual([]);
}

async function contrastFailures(page: Page) {
  return page.evaluate(() => {
    const styles = getComputedStyle(document.documentElement);
    const color = (name: string) => {
      const value = styles.getPropertyValue(`--${name}`).trim();
      const short = value.match(/^#([\da-f]{3})$/i)?.[1];
      const raw = short ? [...short].map((channel) => channel + channel).join('') : value.match(/^#([\da-f]{6})$/i)?.[1];
      if (!raw) throw new Error(`Expected --${name} to be a three- or six-digit hex color, got ${value}`);
      return [0, 2, 4].map((i) => Number.parseInt(raw.slice(i, i + 2), 16) / 255);
    };
    const luminance = (name: string) => {
      const [r, g, b] = color(name).map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const ratio = (foreground: string, background: string) => {
      const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
      return (values[0] + 0.05) / (values[1] + 0.05);
    };
    const failures: string[] = [];
    const check = (foreground: string, background: string, minimum: number, kind: string) => {
      const value = ratio(foreground, background);
      if (value < minimum) failures.push(`${kind} --${foreground} on --${background}: ${value.toFixed(2)}:1 (needs ${minimum}:1)`);
    };

    // Small text uses 4.5:1; focus indicators are non-text and use 3:1.
    for (const foreground of ['ink', 'ink-2', 'ink-3', 'accent']) {
      for (const background of ['bg', 'panel', 'panel-2']) check(foreground, background, 4.5, 'text');
    }
    check('ink', 'hover', 4.5, 'hover text');
    check('ink', 'select', 4.5, 'selected text');
    check('ink', 'accent-soft', 4.5, 'accent surface text');
    for (const background of ['bg', 'panel', 'panel-2', 'hover', 'select', 'accent-soft']) check('focus', background, 3, 'focus indicator');
    for (const background of ['panel', 'panel-2']) check('good', background, 4.5, 'status text');
    check('accent-ink', 'accent', 4.5, 'button text');
    check('warn-ink', 'warn-bg', 4.5, 'warning text');
    check('crit', 'crit-bg', 4.5, 'error text');
    check('info-ink', 'info-bg', 4.5, 'info text');

    // Protocol colors are graphical distinctions; require 3:1 against chart surfaces.
    for (const foreground of ['s1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's-other']) {
      for (const background of ['bg', 'panel', 'panel-2']) check(foreground, background, 3, 'chart color');
    }
    return failures;
  });
}

/** Records every request so tests can assert nothing leaves the origin. */
function watchRequests(page: Page) {
  const all: Request[] = [];
  page.on('request', (r) => all.push(r));
  return {
    all,
    offenders: () => all.filter((r) => {
      const u = new URL(r.url());
      return u.origin !== `http://localhost:${process.env.PORT ?? 4173}` || r.method() !== 'GET' || r.postDataBuffer() !== null;
    }).map((r) => `${r.method()} ${r.url()}`),
  };
}

async function openCapture(page: Page, name: string) {
  await page.locator('input[type=file]').first().setInputFiles(fixture(name));
  await expect(page.locator('.cap-title h1')).toHaveText(name);
}

async function installPacketPageRetryFault(page: Page) {
  await page.addInitScript(() => {
    const state = { calls: [] as number[], failed: new Set<number>(), sample: null as Record<string, any> | null };
    Object.defineProperty(window, '__packetPageRetryTest', { configurable: true, value: state });
    const pending = new WeakMap<Worker, Map<number, number>>();
    const proto = Worker.prototype as unknown as { postMessage: (message: unknown, transfer?: Transferable[]) => void };
    const original = proto.postMessage;
    proto.postMessage = function (this: Worker, message: unknown, transfer?: Transferable[]) {
      const msg = message as { type?: string; id?: number; req?: { kind?: string; skip?: number } };
      let requests = pending.get(this as unknown as Worker);
      if (!requests) {
        requests = new Map();
        pending.set(this as unknown as Worker, requests);
        this.addEventListener('message', (event) => {
          const response = (event as MessageEvent).data as { type?: string; id?: number; ok?: boolean; data?: { rows?: Record<string, any>[]; matched?: number } };
          const skip = response.id === undefined ? undefined : requests!.get(response.id);
          if (response.type !== 'response' || !response.ok || skip === undefined || !response.data) return;
          if (skip === 0) {
            state.sample = response.data.rows?.[0] ?? state.sample;
            response.data.matched = 1001;
          } else if (skip === 500) {
            response.data.matched = 1001;
            if (state.sample) {
              const columns = [...state.sample.columns];
              columns[0] = '501';
              response.data.rows = [{ ...state.sample, number: 501, columns }];
            }
          }
        });
      }
      if (msg.type === 'request' && msg.req?.kind === 'packetList' && typeof msg.req.skip === 'number' && typeof msg.id === 'number') {
        const skip = msg.req.skip;
        state.calls.push(skip);
        requests.set(msg.id, skip);
        if ((skip === 0 || skip === 500) && !state.failed.has(skip)) {
          state.failed.add(skip);
          setTimeout(() => this.dispatchEvent(new MessageEvent('message', {
            data: { type: 'response', id: msg.id, ok: false, error: `Injected transient failure at offset ${skip}` },
          })), 0);
          return;
        }
      }
      if (transfer) original.call(this, message, transfer);
      else original.call(this, message);
    };
  });
}

async function view(page: Page, id: string) {
  await page.evaluate((v) => { location.hash = '#/' + v; }, id);
  await expect(page.locator('.nav a[aria-current=page]').first()).toBeVisible();
}

const errors = (page: Page) => {
  const list: string[] = [];
  page.on('pageerror', (e) => list.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') list.push(m.text()); });
  return list;
};

test('shows the local-processing notice before any file is chosen', async ({ page }) => {
  await page.goto('./');
  await expect(page.getByText('Your capture is processed locally in your browser.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Choose TLS key log (optional)' })).toBeVisible();
});

test('compares two local captures sequentially and labels capture changes', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.route('**/axe-for-test.js', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: readFileSync(axeScript, 'utf8'),
  }));
  await page.goto('./');
  await page.addScriptTag({ url: './axe-for-test.js' });
  await page.getByRole('button', { name: 'Compare two captures' }).click();
  await page.getByLabel('Choose capture A').setInputFiles(fixture('http.pcap'));
  await page.getByLabel('Choose capture B').setInputFiles(fixture('dns.pcap'));
  await page.getByRole('button', { name: 'Compare captures' }).click();
  await expect(page.getByRole('heading', { name: 'Analyzing capture A of 2' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Capture comparison' })).toBeVisible();
  await expect(page.getByRole('grid', { name: 'Host and name changes' })).toBeVisible();
  await expect(page.getByRole('grid', { name: 'Protocol changes' })).toBeVisible();
  await expect(page.getByRole('grid', { name: 'Conversation changes' })).toBeVisible();
  await expect(page.locator('.compare-overview')).toContainText('A · http.pcap');
  await expect(page.locator('.compare-overview')).toContainText('B · dns.pcap');
  await auditA11y(page, 'capture comparison results');

  await page.getByRole('button', { name: 'Back' }).click();
  await openCapture(page, 'http.pcap');
  await page.getByRole('button', { name: 'Compare captures' }).click();
  await expect(page.locator('.compare-baseline')).toContainText('http.pcap');
  await page.getByLabel('Choose capture B').setInputFiles(fixture('dns.pcap'));
  await page.getByRole('button', { name: 'Compare captures' }).click();
  await expect(page.getByRole('heading', { name: 'Capture comparison' })).toBeVisible();
  expect(reqs.offenders()).toEqual([]);
});

test('axe WCAG 2.1 AA audit: start screen, every view and drawer in light and dark themes', async ({ page }) => {
  await page.route('**/axe-for-test.js', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: readFileSync(axeScript, 'utf8'),
  }));
  await page.goto('./');
  await page.addScriptTag({ url: './axe-for-test.js' });
  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    await auditA11y(page, `start screen (${theme})`);
  }
  await openCapture(page, 'http.pcap');

  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    for (const id of ['overview', 'dns', 'http', 'tls', 'quic', 'ssh', 'dhcp', 'arp', 'icmp', 'hosts', 'connections', 'network', 'packets']) {
      await view(page, id);
      await expect(page.locator('.view-head h2').first()).toBeVisible();
      await auditA11y(page, `${id} (${theme})`);
      if (id === 'network') {
        const list = page.locator('.network-list');
        await list.locator('summary').focus();
        await page.keyboard.press('Enter');
        await expect(list.locator('table')).toBeVisible();
        await auditA11y(page, `network host links list (${theme})`);
        await list.locator('summary').click();
      }
    }

    await view(page, 'http');
    await page.getByRole('grid', { name: 'HTTP messages' }).getByText('/index.html').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    const drawer = page.getByRole('dialog');
    const closeDrawer = drawer.getByRole('button', { name: 'Close' });
    await expect(closeDrawer).toBeFocused();
    // Wait until packet decoding has finished building the field tree.
    await expect(drawer.getByRole('heading', { name: 'Decoded fields' })).toBeVisible();
    const tree = drawer.getByRole('tree', { name: 'Decoded fields' });
    const firstTreeItem = tree.getByRole('treeitem').first();
    await firstTreeItem.focus();
    await expect(firstTreeItem).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('ArrowRight');
    await expect(firstTreeItem).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowRight');
    await expect(tree.getByRole('treeitem').nth(1)).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(firstTreeItem).toBeFocused();
    await page.keyboard.press('Space');
    await expect(firstTreeItem).toHaveAttribute('aria-selected', 'true');
    await closeDrawer.focus();
    await page.keyboard.press('Shift+Tab');
    expect(await page.evaluate(() => document.activeElement?.closest('[role="dialog"]') !== null)).toBe(true);
    await page.keyboard.press('Tab');
    await expect(closeDrawer).toBeFocused();
    await auditA11y(page, `packet drawer opened from an HTTP row (${theme})`);
    await page.keyboard.press('Escape');
  }
});

test('text and chart colors meet WCAG contrast thresholds in light and dark themes', async ({ page }) => {
  await page.goto('./');
  for (const theme of ['light', 'dark']) {
    await page.evaluate((value) => { document.documentElement.dataset.theme = value; }, theme);
    const failures = await contrastFailures(page);
    expect(failures, `${theme} theme contrast failures:\n${failures.join('\n')}`).toEqual([]);
  }
});

test('DNS capture: overview, DNS dashboard and packet drawer, with no uploads', async ({ page }) => {
  const reqs = watchRequests(page);
  const errs = errors(page);
  await page.goto('./');
  await openCapture(page, 'dns.pcap');

  const facts = page.locator('.facts');
  await expect(facts.getByText('Packets', { exact: true }).locator('..')).toContainText('29');
  await expect(page.getByText('Bytes on wire (original frame length)', { exact: false })).toBeVisible();

  await view(page, 'dns');
  await expect(page.getByRole('button', { name: 'DNS 10' })).toHaveAttribute('aria-pressed', 'true');
  const dnsFacts = page.locator('.facts');
  await expect(dnsFacts.getByText('Unanswered', { exact: true }).locator('..')).toContainText('1');
  await expect(dnsFacts.getByText('Repeated queries', { exact: true }).locator('..')).toContainText('1');
  const table = page.getByRole('grid', { name: 'DNS transactions' });
  await expect(table.getByRole('row')).toHaveCount(11);
  await expect(table).toContainText('NXDomain');
  await expect(table).toContainText('ServFail');
  await expect(table).toContainText('retransmitted');

  await page.getByRole('button', { name: /NBNS 1/ }).click();
  await expect(page.getByRole('grid', { name: 'NBNS transactions' })).toContainText('FILESERVER<00>');

  await page.getByRole('button', { name: /DNS 10/ }).click();
  await page.getByRole('grid', { name: 'DNS transactions' }).getByText('tcp.example').click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByRole('group', { name: 'Choose a source packet' }).getByRole('button')).toHaveText(['#20', '#21', '#22']);
  await expect(drawer.getByText(/^Domain Name System/).first()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();

  expect(reqs.offenders()).toEqual([]);
  expect(reqs.all.some((r) => r.url().endsWith('wiregasm/wiregasm.wasm.gz'))).toBe(true);
  expect(errs).toEqual([]);
});

test('packet-list pages can be retried after a transient worker request failure', async ({ page }) => {
  await installPacketPageRetryFault(page);
  await page.goto('./');
  await openCapture(page, 'http.pcap');
  await view(page, 'packets');

  await expect(page.getByText(/Could not load packet page 1/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry packet page 1' })).toBeVisible();
  await expect(page.getByText('Loading packet columns…')).toHaveCount(0);
  await page.waitForTimeout(200);
  const firstPageCalls = await page.evaluate(() => (window as unknown as { __packetPageRetryTest: { calls: number[] } }).__packetPageRetryTest.calls.filter((skip) => skip === 0).length);
  expect(firstPageCalls).toBe(1);

  await page.getByRole('button', { name: 'Retry packet page 1' }).click();
  await expect(page.getByRole('button', { name: 'Retry packet page 1' })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'No.' })).toBeVisible();

  const grid = page.getByRole('grid', { name: 'Packets' });
  await grid.evaluate((element) => { element.scrollTop = 15000; element.dispatchEvent(new Event('scroll')); });
  await expect(page.getByText(/Could not load packet page 2/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry packet page 2' })).toBeVisible();
  await page.waitForTimeout(200);
  const secondPageCalls = await page.evaluate(() => (window as unknown as { __packetPageRetryTest: { calls: number[] } }).__packetPageRetryTest.calls.filter((skip) => skip === 500).length);
  expect(secondPageCalls).toBe(1);

  await page.getByRole('button', { name: 'Retry packet page 2' }).click();
  await expect(page.getByRole('button', { name: 'Retry packet page 2' })).toHaveCount(0);
  await expect(grid.getByRole('row').filter({ hasText: '501' })).toBeVisible();
  const finalCalls = await page.evaluate(() => (window as unknown as { __packetPageRetryTest: { calls: number[] } }).__packetPageRetryTest.calls);
  expect(finalCalls.filter((skip) => skip === 0)).toHaveLength(2);
  expect(finalCalls.filter((skip) => skip === 500)).toHaveLength(2);
});

test('packet drawer copies Wireshark fields and opens matching packets with shared filters', async ({ page }) => {
  await page.addInitScript(() => {
    const harness = { copied: '', deny: false };
    Object.defineProperty(window, '__clipboardHarness', { configurable: true, value: harness });
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async (text: string) => {
        if (harness.deny) { harness.deny = false; throw new Error('Clipboard denied for test'); }
        harness.copied = text;
      } },
    });
    Object.defineProperty(document, 'execCommand', { configurable: true, value: () => false });
  });
  await page.goto('./');
  await openCapture(page, 'http.pcap');
  await page.evaluate(() => { location.hash = '#/http?hf=10.0.0.5'; });
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.5' })).toBeVisible();
  await page.getByRole('grid', { name: 'HTTP messages' }).getByText('/index.html').click();
  const drawer = page.getByRole('dialog');
  await expect(drawer.getByRole('heading', { name: 'Decoded fields' })).toBeVisible();
  const tree = drawer.getByRole('tree', { name: 'Decoded fields' });
  const first = tree.getByRole('treeitem').first();
  await first.focus();
  await page.keyboard.press('ArrowRight');
  const field = tree.getByRole('treeitem').nth(1);
  await field.focus();
  await page.keyboard.press('Space');

  await expect(drawer.getByRole('group', { name: 'Selected field actions' })).toBeVisible();
  await expect(drawer.getByRole('button', { name: 'Copy field value' })).toBeDisabled();
  await expect(drawer.getByRole('note')).toContainText('Typed field values are not exposed separately');
  await drawer.getByRole('button', { name: 'Copy field label' }).click();
  const copiedLabel = await page.evaluate(() => (window as unknown as { __clipboardHarness: { copied: string } }).__clipboardHarness.copied);
  expect(copiedLabel.trim()).not.toBe('');
  await drawer.getByRole('button', { name: 'Copy display filter' }).click();
  const copiedFilter = await page.evaluate(() => (window as unknown as { __clipboardHarness: { copied: string } }).__clipboardHarness.copied);
  expect(copiedFilter.trim()).not.toBe('');
  await page.evaluate(() => { (window as unknown as { __clipboardHarness: { deny: boolean } }).__clipboardHarness.deny = true; });
  await drawer.getByRole('button', { name: 'Copy display filter' }).click();
  await expect(drawer.getByRole('alert')).toContainText(/Could not copy/);
  await expect(drawer.getByLabel('Text to copy manually')).toHaveValue(copiedFilter);

  await drawer.getByRole('button', { name: 'Show matching packets' }).click();
  await expect(page.getByLabel('Wireshark display filter')).toHaveValue(copiedFilter);
  const route = await page.evaluate(() => {
    const query = location.hash.split('?')[1] ?? '';
    const params = new URLSearchParams(query);
    return { view: location.hash.split('?')[0], host: params.get('hf'), filter: params.get('filter') };
  });
  expect(route.view).toBe('#/packets');
  expect(route.host).toBe('10.0.0.5');
  expect(route.filter).toBe(copiedFilter);
});

test('JSON export offers an aggregate allowlist and redacted or unredacted detailed choices', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.route('**/axe-for-test.js', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: readFileSync(axeScript, 'utf8'),
  }));
  await page.goto('./');
  await page.addScriptTag({ url: './axe-for-test.js' });
  await openCapture(page, 'http.pcap');

  const menu = page.locator('.json-export-menu');
  await menu.locator('summary').click();
  await expect(page.getByRole('heading', { name: 'Choose JSON export detail' })).toBeVisible();
  await expect(menu).toContainText('HTTP paths and headers');
  await auditA11y(page, 'JSON export menu');
  const redaction = menu.getByRole('checkbox', { name: 'Redact known identifying and content-like values' });
  await expect(redaction).toBeChecked();

  const readDownloadedJson = async (buttonName: string) => {
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      menu.getByRole('button', { name: buttonName }).click(),
    ]);
    const path = await download.path();
    if (!path) throw new Error('Browser did not provide the JSON download path');
    return { name: download.suggestedFilename(), json: readFileSync(path, 'utf8') };
  };

  const aggregateDownload = await readDownloadedJson('Download aggregate JSON');
  const aggregate = JSON.parse(aggregateDownload.json);
  expect(aggregateDownload.name).toBe('capture-summary.json');
  expect(aggregate.export.mode).toBe('aggregate');
  expect(aggregate).not.toHaveProperty('hosts');
  expect(aggregateDownload.json).not.toContain('10.0.0.5');
  expect(aggregateDownload.json).not.toContain('/index.html');
  expect(aggregateDownload.json).not.toContain('captured content');

  await menu.locator('summary').click();
  const redactedDownload = await readDownloadedJson('Download detailed JSON');
  const redacted = JSON.parse(redactedDownload.json);
  expect(redacted.export.redaction).toBe('known sensitive fields replaced with [REDACTED]');
  expect(redactedDownload.json).not.toContain('10.0.0.5');
  expect(redactedDownload.json).not.toContain('fixture-agent/1.0');
  expect(redactedDownload.json).toContain('[REDACTED]');

  await menu.locator('summary').click();
  await redaction.uncheck();
  const detailedDownload = await readDownloadedJson('Download detailed JSON');
  const detailed = JSON.parse(detailedDownload.json);
  expect(detailed.export.redaction).toBe('not applied');
  expect(detailed.hosts.some((host: { addr: string }) => host.addr === '10.0.0.5')).toBe(true);
  expect(detailedDownload.json).toContain('fixture-agent/1.0');
  expect(detailedDownload.json).not.toContain('captured content');
  expect(detailed.export.neverIncluded).toContain('Reassembled TCP/UDP stream payloads');
  expect(reqs.offenders()).toEqual([]);
});

test('HTTP capture: requests, hosts, sessions, graph and packet list', async ({ page }) => {
  const reqs = watchRequests(page);
  const errs = errors(page);
  await page.goto('./');
  await openCapture(page, 'http.pcap');

  await view(page, 'http');
  const http = page.getByRole('grid', { name: 'HTTP messages' });
  await expect(http.getByRole('row')).toHaveCount(6);
  for (const s of ['200', '401', '404', '304']) await expect(http).toContainText(s);
  await expect(http).toContainText('no response seen');
  // Captured HTML in the response body is never rendered or executed.
  await http.getByText('/index.html').click();
  await expect(page.getByRole('dialog')).toContainText('User-Agent: fixture-agent/1.0');
  await expect(page.locator('script:has-text("captured content")')).toHaveCount(0);
  await page.keyboard.press('Escape');

  await view(page, 'connections');
  const conns = page.getByRole('grid', { name: 'Conversations' });
  await expect(conns.getByRole('row')).toHaveCount(5);
  await expect(conns.getByRole('row').filter({ hasText: '10.0.0.5:40000' })).toHaveCount(2);
  await conns.getByRole('row').filter({ hasText: '10.0.0.5:40001' }).click();
  await expect(page.getByRole('grid', { name: 'Conversation packets' }).getByRole('row')).toHaveCount(9);
  await expect(page.getByRole('button', { name: /HTTP GET \/missing/ })).toBeVisible();

  await view(page, 'hosts');
  await page.getByRole('grid', { name: 'Hosts' }).getByText('10.0.0.80').click();
  await expect(page.getByText('handshake completed; 3 conversations from 1 peer')).toBeVisible();

  await view(page, 'network');
  await expect(page.locator('.graph-node')).toHaveCount(4);
  const networkList = page.locator('.network-list');
  const networkSummary = networkList.locator('summary');
  await networkSummary.focus();
  await page.keyboard.press('Enter');
  const networkTable = page.getByRole('table', { name: 'Network graph links with endpoints, traffic totals, main protocol, and conversations' });
  await expect(networkTable).toBeVisible();
  await expect(networkTable.getByRole('columnheader')).toHaveText(['Hosts', 'Traffic', 'Packets', 'Main protocol', 'Conversations', 'Action']);
  const firstLink = networkTable.getByRole('button').first();
  await expect(firstLink).toHaveAttribute('aria-label', /^View conversations between /);
  await firstLink.focus();
  await page.keyboard.press('Enter');
  await view(page, 'connections');

  await view(page, 'packets');
  await expect(page.getByText('31 of 31 packets')).toBeVisible();
  await page.getByLabel('Wireshark display filter').fill('http.response.code == 404');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByText('1 of 31 packets')).toBeVisible();
  await page.getByLabel('Wireshark display filter').fill('not a filter ((');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByText(/Invalid display filter/)).toBeVisible();

  expect(reqs.offenders()).toEqual([]);
  expect(errs).toEqual([]);
});

test('shared filters brush traffic, round-trip in the URL, and apply from a host', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'http.pcap');
  const packetFact = page.locator('.cap-facts').getByText(/packets/).first();
  await expect(packetFact).toContainText('31 packets');

  const strip = page.getByRole('img', { name: 'Capture traffic strip. Drag to choose a time range.' });
  const box = await strip.boundingBox();
  expect(box).not.toBeNull();
  const y = box!.y + box!.height / 2;
  await page.mouse.move(box!.x + box!.width * 0.005, y);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width * 0.05, y, { steps: 4 });
  await page.mouse.up();
  await expect(page.getByRole('button', { name: 'Remove time range filter' })).toBeVisible();
  const rangeHash = await page.evaluate(() => location.hash);
  expect(rangeHash).toMatch(/[?&]t0=/);
  expect(rangeHash).toMatch(/[?&]t1=/);
  const filteredPacketFact = page.locator('.cap-facts').getByText(/packets/).first();
  const filteredCount = Number((await filteredPacketFact.innerText()).split('/')[0].trim());
  expect(filteredCount).toBeGreaterThan(0);
  expect(filteredCount).toBeLessThan(31);

  await page.locator('.nav a[href="#/http"]').click();
  await expect(page.getByRole('button', { name: 'Remove time range filter' })).toBeVisible();
  await expect(page.locator('.nav a[href="#/http"] .nav-count')).toHaveText('3/5');
  const filteredRows = page.getByRole('grid', { name: 'HTTP messages' }).getByRole('row');
  await expect(filteredRows).toHaveCount(4);
  await page.locator('.nav a[href="#/packets"]').click();
  await expect(page.getByText('19 of 31 packets')).toBeVisible();
  await page.locator('.nav a[href="#/http"]').click();

  await page.getByRole('button', { name: 'Remove time range filter' }).click();
  await expect(page.getByRole('button', { name: 'Remove time range filter' })).toHaveCount(0);
  await expect(page.getByRole('grid', { name: 'HTTP messages' }).getByRole('row')).toHaveCount(6);
  await page.locator('.nav a[href="#/overview"]').click();
  const rangeStart = page.getByLabel('Time range start in seconds');
  const rangeEnd = page.getByLabel('Time range end in seconds');
  await rangeStart.fill('0');
  await rangeEnd.fill('0.5');
  await rangeEnd.press('Enter');
  await expect(page.getByRole('button', { name: 'Remove time range filter' })).toBeVisible();
  await page.getByRole('button', { name: 'Remove time range filter' }).click();
  await page.evaluate((hash) => { location.hash = hash; }, rangeHash);
  await expect(page.getByRole('button', { name: 'Remove time range filter' })).toBeVisible();
  await page.locator('.nav a[href="#/http"]').click();
  await expect(page.getByRole('grid', { name: 'HTTP messages' }).getByRole('row')).toHaveCount(4);

  await page.locator('.nav a[href="#/hosts"]').click();
  await page.getByRole('grid', { name: 'Hosts' }).getByText('10.0.0.80').click();
  await page.getByRole('button', { name: 'Filter all views to host' }).click();
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.80' })).toBeVisible();
  await page.locator('.nav a[href="#/http"]').click();
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.80' })).toBeVisible();
  await page.getByRole('button', { name: 'Remove host filter for 10.0.0.80' }).click();
  await expect(page.getByRole('button', { name: 'Remove host filter for 10.0.0.80' })).toHaveCount(0);
});

test('HTTP/2 h2c capture: table rows and request/status aggregates', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'http2.pcap');
  await view(page, 'http');

  const facts = page.locator('.facts');
  await expect(facts.getByText('Requests', { exact: true }).locator('..')).toContainText('2');
  await expect(facts.getByText('Hosts requested', { exact: true }).locator('..')).toContainText('1');
  const methods = page.locator('.panel').filter({ has: page.getByRole('heading', { name: 'Methods' }) });
  await expect(methods).toContainText('GET');
  await expect(methods).toContainText('POST');
  const statuses = page.locator('.panel').filter({ has: page.getByRole('heading', { name: 'Status codes' }) });
  await expect(statuses).toContainText('200');
  await expect(statuses).toContainText('404');

  const table = page.getByRole('grid', { name: 'HTTP messages' });
  await expect(table.getByRole('row')).toHaveCount(3);
  await expect(table).toContainText('HTTP/2');
  await expect(table).toContainText('h2.example.test');
  await expect(table).toContainText('/first');
  await expect(table).toContainText('/second');
  await table.getByText('/second').click();
  await expect(page.getByRole('dialog')).toContainText('HTTP/2 stream');
  await expect(page.getByRole('dialog')).toContainText('3');
});

test('TLS capture: offered vs negotiated, certificates, and empty DNS/HTTP states', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'tls.pcap');
  await view(page, 'tls');
  const tls = page.getByRole('grid', { name: 'TLS handshakes' });
  await expect(tls.getByRole('row')).toHaveCount(4);
  await expect(tls).toContainText('no ServerHello');
  await tls.getByRole('gridcell', { name: 'www.example.com' }).first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('CN=www.example.com, O=Fixture Org');
  await expect(drawer).toContainText('www.example.com, example.com');
  await expect(drawer).toContainText('ServerHello version field');
  await page.keyboard.press('Escape');
  await tls.getByText('api.example.net').click();
  await expect(drawer).toContainText('supported_versions extension');
  await expect(drawer).toContainText('The certificate was sent encrypted');
  await page.keyboard.press('Escape');

  await view(page, 'dns');
  await expect(page.getByText('No DNS, mDNS, LLMNR or NBNS messages were decoded.')).toBeVisible();
  await view(page, 'http');
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  await expect(page.getByText(/3 conversations use TLS or QUIC/)).toBeVisible();
});

test('TLS 1.3 key log decrypts and marks records locally; a later capture has no reused keys', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.goto('./');
  await page.locator('input[type=file]').nth(1).setInputFiles(fixture('tls13.keys'));
  await openCapture(page, 'tls13.pcap');
  await expect(page.getByRole('status').filter({ hasText: 'TLS decryption:' })).toContainText('1 of 1 sessions decrypted');

  await view(page, 'http');
  const table = page.getByRole('grid', { name: 'HTTP messages' });
  await expect(table).toContainText('keylog.example.test');
  await expect(table).toContainText('/decrypted');
  await expect(table).toContainText('Decrypted');

  await page.getByRole('button', { name: 'Open another' }).click();
  await expect(page.getByRole('button', { name: 'Choose TLS key log (optional)' })).toBeVisible();
  await page.locator('input[type=file]').first().setInputFiles(fixture('tls13.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('tls13.pcap');
  await expect(page.getByRole('status').filter({ hasText: 'TLS decryption:' })).toContainText('0 of 1 sessions decrypted');
  await view(page, 'http');
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  expect(reqs.offenders()).toEqual([]);
});

test('TLS key logs expose decrypted HTTP/2 rows with version and stream ID', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.goto('./');
  await page.locator('input[type=file]').nth(1).setInputFiles(fixture('tls13-h2.keys'));
  await openCapture(page, 'tls13-h2.pcap');
  await expect(page.getByRole('status').filter({ hasText: 'TLS decryption:' })).toContainText('1 of 1 sessions decrypted');

  await view(page, 'http');
  const table = page.getByRole('grid', { name: 'HTTP messages' });
  await expect(table.getByRole('columnheader', { name: 'Version' })).toBeVisible();
  await expect(table).toContainText('HTTP/2');
  await expect(table).toContainText('1');
  await expect(table).toContainText('h2-keylog.example.test');
  await expect(table).toContainText('/decrypted-h2');
  await expect(table).toContainText('Decrypted');
  await table.getByRole('row').filter({ hasText: '/decrypted-h2' }).click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('fixture-h2-keylog/1.0');
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: 'Open another' }).click();
  await page.locator('input[type=file]').first().setInputFiles(fixture('tls13-h2.pcap'));
  await expect(page.getByRole('status').filter({ hasText: 'TLS decryption:' })).toContainText('0 of 1 sessions decrypted');
  await view(page, 'http');
  await expect(page.getByText('No cleartext HTTP/1.x or HTTP/2 messages were decoded.')).toBeVisible();
  expect(reqs.offenders()).toEqual([]);
});

test('edge cases: truncated/malformed notes, incomplete file, non-capture file', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'edge.pcap');
  await expect(page.getByText(/1 packet truncated/)).toBeVisible();
  await expect(page.getByText(/1 packet malformed/)).toBeVisible();

  await view(page, 'connections');
  const conversations = page.getByRole('grid', { name: 'Conversations' });
  const quality = page.getByRole('group', { name: 'Filter by connection quality observation' });
  await quality.getByRole('button', { name: 'Malformed (1)' }).click();
  await expect(quality.getByRole('button', { name: 'Malformed (1)' })).toHaveAttribute('aria-pressed', 'true');
  await expect(conversations.getByRole('row')).toHaveCount(2);
  await expect(conversations.getByRole('row').filter({ hasText: '10.0.0.5:50100' })).toHaveCount(1);
  await quality.getByRole('button', { name: 'Truncated (1)' }).click();
  await expect(conversations.getByRole('row')).toHaveCount(2);
  await expect(conversations.getByRole('row').filter({ hasText: '10.0.0.5:50102' })).toHaveCount(1);
  await quality.getByRole('button', { name: 'RST seen (0)' }).click();
  await expect(page.getByText('No matching conversations.')).toBeVisible();
  await page.getByRole('button', { name: 'Clear quality filter' }).click();
  await expect(conversations.getByRole('row')).toHaveCount(5);

  await page.locator('input[type=file]').first().setInputFiles(fixture('cut.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('cut.pcap');
  await expect(page.getByText('incomplete file')).toBeVisible();
  await view(page, 'overview');
  await expect(page.getByText(/cut short/)).toBeVisible();

  await page.locator('input[type=file]').first().setInputFiles(fixture('not-a-capture.pcap'));
  await expect(page.getByRole('alert')).toContainText('could not be opened as a packet capture');
  // The landing page is usable again afterwards.
  await openCapture(page, 'multi-iface.pcapng');
  await expect(page.getByText('Raw IP (7)')).toBeVisible();
  await expect(page.getByText(/nanoseconds \(9 decimal digits used\)/)).toBeVisible();
});

test('cancelling an analysis returns to the start and a later capture opens cleanly', async ({ page }) => {
  await page.goto('./');
  await page.locator('input[type=file]').first().setInputFiles(fixture('http.pcap'));
  await expect(page.getByRole('progressbar')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
  // A cancelled worker must not deliver a late result.
  await page.waitForTimeout(3000);
  await expect(page.locator('.cap-title')).toHaveCount(0);

  await openCapture(page, 'dns.pcap');
  await expect(page.locator('.nav a[href="#/dns"] .nav-count')).toHaveText('13');
});

test('opening another capture replaces the first one entirely', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'dns.pcap');
  await expect(page.locator('.nav a[href="#/dns"] .nav-count')).toHaveText('13');
  await page.locator('input[type=file]').first().setInputFiles(fixture('http.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('http.pcap');
  await expect(page.locator('.nav a[href="#/dns"] .nav-count')).toHaveText('0');
  await expect(page.locator('.nav a[href="#/http"] .nav-count')).toHaveText('5');
  // The replaced capture's session is gone: packet details come from the new file.
  await view(page, 'packets');
  await expect(page.getByText('31 of 31 packets')).toBeVisible();

  await page.getByRole('button', { name: 'Close', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Choose capture file' })).toBeVisible();
});

test('Follow stream: text and hex, directions distinguished, captured HTML inert, local save', async ({ page }) => {
  const reqs = watchRequests(page);
  const errs = errors(page);
  await page.goto('./');
  await openCapture(page, 'http.pcap');
  await view(page, 'connections');
  await page.getByRole('grid', { name: 'Conversations' }).getByRole('row').filter({ hasText: '10.0.0.5:40000' }).first().click();
  await page.getByRole('button', { name: 'Follow stream' }).click();

  const body = page.getByRole('region', { name: 'Stream content' });
  await expect(body.locator('.follow-run.client').first()).toContainText('GET /index.html HTTP/1.1\nHost: www.example.test');
  await expect(body.locator('.follow-run.client').first()).toContainText('Client → server, #4 to #5 (2 packets)');
  await expect(body.locator('.follow-run.server').first()).toContainText('HTTP/1.1 200 OK');
  await expect(body.locator('.follow-run')).toHaveCount(4);
  // Captured markup is shown as text and never becomes DOM.
  await expect(body).toContainText("<script>alert('captured content must not run')</script><b>hello</b>");
  await expect(body.locator('script, b')).toHaveCount(0);
  const [clientColor, serverColor] = await Promise.all(['client', 'server'].map((k) =>
    body.locator(`.follow-run.${k}`).first().evaluate((el) => getComputedStyle(el).borderLeftColor)));
  expect(clientColor).not.toBe(serverColor);

  await page.getByRole('group', { name: 'Directions shown' }).getByRole('button', { name: /Server → client/ }).click();
  await expect(body.locator('.follow-run.client')).toHaveCount(0);
  await page.getByRole('group', { name: 'Format' }).getByRole('button', { name: 'Hex' }).click();
  await expect(body.locator('.follow-run').first()).toContainText('00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.');

  const dl = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save raw' }).click();
  const d = await dl;
  expect(d.suggestedFilename()).toBe('http-tcp-stream-0-server.bin');
  const saved = Buffer.concat(await (await d.createReadStream()).toArray()).toString('latin1');
  expect(saved.startsWith('HTTP/1.1 200 OK\r\n')).toBe(true);
  expect(saved.endsWith('HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n')).toBe(true);

  // A large stream is capped in the view with a notice; the saved file is complete.
  await openCapture(page, 'follow.pcap');
  await view(page, 'connections');
  await page.getByRole('grid', { name: 'Conversations' }).getByRole('row').filter({ hasText: '10.0.0.5:41000' }).click();
  await page.getByRole('button', { name: 'Follow stream' }).click();
  await expect(page.getByText('Showing part of the stream.')).toBeVisible();
  await expect(page.getByRole('region', { name: 'Stream content' })).toContainText('line 00000 of the large');
  const big = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save raw' }).click();
  const bd = await big;
  expect(bd.suggestedFilename()).toBe('follow-tcp-stream-0.bin');
  const all = Buffer.concat(await (await bd.createReadStream()).toArray());
  expect(all.length).toBe(612069 + 51);

  await page.getByRole('grid', { name: 'Conversations' }).getByRole('row').filter({ hasText: '10.0.0.5:41001' }).click();
  await page.getByRole('button', { name: 'Follow stream' }).click();
  await expect(page.getByRole('region', { name: 'Stream content' })).toHaveText(/PING 1[^]*PONG 1/);

  expect(reqs.offenders()).toEqual([]);
  expect(errs).toEqual([]);
});

test('exports are local downloads', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.goto('./');
  await openCapture(page, 'dns.pcap');
  const menu = page.locator('.json-export-menu');
  await menu.locator('summary').click();
  const [jd] = await Promise.all([
    page.waitForEvent('download'),
    menu.getByRole('button', { name: 'Download aggregate JSON' }).click(),
  ]);
  expect(jd.suggestedFilename()).toBe('capture-summary.json');
  const jsonPath = await jd.path();
  if (!jsonPath) throw new Error('Browser did not provide the JSON download path');
  const summary = JSON.parse(readFileSync(jsonPath, 'utf8'));
  expect(summary.export.mode).toBe('aggregate');
  expect(summary.capture.packetCount).toBe(29);

  await view(page, 'dns');
  const csv = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export CSV' }).click();
  const cd = await csv;
  const text = Buffer.concat(await (await cd.createReadStream()).toArray()).toString('utf8');
  expect(text.split('\r\n')[0]).toContain('Queried name');
  expect(text).toContain('nonexistent.example');
  expect(reqs.offenders()).toEqual([]);
});

test('HTML report is a self-contained aggregate snapshot without captured payloads', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.goto('./');
  await openCapture(page, 'http.pcap');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download HTML report' }).click();
  const reportDownload = await download;
  expect(reportDownload.suggestedFilename()).toBe('http-report.html');
  const html = Buffer.concat(await (await reportDownload.createReadStream()).toArray()).toString('utf8');

  expect(html).toContain('<!doctype html>');
  expect(html).toContain('Whole-capture aggregates');
  expect(html).toContain('names and network addresses');
  expect(html).toContain('www.example.test');
  expect(html).toContain('10.0.0.5');
  expect(html).toContain('does not contain packet bytes, payloads');
  expect(html).not.toContain('captured content must not run');
  expect(html).not.toMatch(/<(?:script|link|img|iframe|source)\b[^>]*(?:src|href)\s*=/i);
  expect(html).not.toMatch(/url\(\s*['"]?(?:https?:)?\/\//i);

  // Parse the saved snapshot as a document too; any active content or external
  // asset accidentally added to the report would execute or issue a request.
  await page.setContent(html);
  await expect(page).toHaveTitle(/Packet capture report/);
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible();
  expect(reqs.offenders()).toEqual([]);
});

for (const vp of [{ name: 'tablet', width: 820, height: 1180 }, { name: 'phone', width: 390, height: 844 }]) {
  test(`${vp.name} layout has no horizontal page scroll`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.goto('./');
    const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    expect(await fits()).toBe(true);
    await openCapture(page, 'dns.pcap');
    for (const v of ['overview', 'dns', 'http', 'tls', 'hosts', 'connections', 'network', 'packets', 'dhcp', 'arp', 'icmp', 'ssh', 'quic']) {
      await view(page, v);
      await page.waitForTimeout(300);
      expect(await fits(), `${v} overflows at ${vp.width}px`).toBe(true);
      if (v === 'overview' || v === 'dns') await page.screenshot({ path: `test-results/${vp.name}-${v}.png`, fullPage: true });
    }
    if (vp.name === 'phone') await expect(page.locator('.mobile-local')).toBeVisible();

    // The conversation detail and the follow panel (long text lines, a max-content hex dump) stay within the page.
    await openCapture(page, 'follow.pcap');
    await view(page, 'connections');
    await page.getByRole('grid', { name: 'Conversations' }).getByRole('row').filter({ hasText: '10.0.0.5:41000' }).click();
    await page.getByRole('button', { name: 'Follow stream' }).click();
    await expect(page.getByRole('region', { name: 'Stream content' })).toContainText('line 00000 of the large');
    expect(await fits(), `follow text overflows at ${vp.width}px`).toBe(true);
    await page.getByRole('group', { name: 'Format' }).getByRole('button', { name: 'Hex' }).click();
    await expect(page.getByRole('region', { name: 'Stream content' })).toContainText('00000000  ');
    expect(await fits(), `follow hex overflows at ${vp.width}px`).toBe(true);
  });
}

test('shows version, build and a source link on the start screen and in the workspace', async ({ page }) => {
  const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
  await page.goto('./');
  const corner = page.locator('.build-tag.corner');
  await expect(corner.getByRole('link', { name: 'Source on GitHub' })).toHaveAttribute('href', 'https://github.com/amanverasia/estudely-packet-explorer');
  await expect(corner).toContainText(`Version ${version}, build`);
  await openCapture(page, 'dns.pcap');
  await expect(page.locator('.sidebar .build-tag')).toContainText(`Version ${version}`);
});

test('Hosts view shows registered MAC vendors and flags locally administered addresses', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'vendors.pcap');
  await view(page, 'hosts');
  const hosts = page.getByRole('grid', { name: 'Hosts' });
  await expect(hosts.getByRole('row').filter({ hasText: '10.0.1.10' })).toContainText('Intel Corporate');
  await expect(hosts.getByRole('row').filter({ hasText: '10.0.1.20' })).toContainText('Apple, Inc.');
  await expect(hosts.getByRole('row').filter({ hasText: '10.0.1.30' })).toContainText('locally administered');
  await expect(hosts).toContainText('00:1b:21:aa:bb:cc');
});

test('Hosts can use optional DB-IP CSV indexes locally and keep them for offline use', async ({ page }) => {
  const reqs = watchRequests(page);
  await page.goto('./');
  await openCapture(page, 'ip-data.pcap');
  await view(page, 'hosts');
  const hosts = page.getByRole('grid', { name: 'Hosts' });
  await page.getByLabel('Import Country CSV').setInputFiles({
    name: 'dbip-country-lite-2026-10.csv', mimeType: 'text/csv',
    buffer: Buffer.from('1.1.1.0,1.1.1.255,AU\n8.8.8.0,8.8.8.255,US\n10.0.0.0,10.255.255.255,ZZ\n2001:4860::,2001:4860::ffff,US\n2606:4700:4700::,2606:4700:4700::ffff,US\n'),
  });
  const google = hosts.getByRole('row').filter({ hasText: '8.8.8.8' });
  await expect(google).toContainText('US');
  await page.getByLabel('Import ASN CSV').setInputFiles({
    name: 'dbip-asn-lite-2026-10.csv', mimeType: 'text/csv',
    buffer: Buffer.from('8.8.8.0,8.8.8.255,15169,"Google, LLC"\n10.0.0.0,10.255.255.255,64500,Private owner\n2001:4860::,2001:4860::ffff,15169,"Google, LLC"\n2606:4700:4700::,2606:4700:4700::ffff,13335,Cloudflare\n'),
  });
  await expect(google).toContainText('AS15169 Google, LLC');
  await expect(hosts.getByRole('row').filter({ hasText: '2001:4860::1' })).toContainText('AS15169 Google, LLC');
  await expect(hosts.getByRole('row').filter({ hasText: '2606:4700:4700::1111' })).toContainText('AS13335 Cloudflare');
  const privateHost = hosts.getByRole('row').filter({ hasText: '10.0.0.5' });
  await expect(privateHost).not.toContainText('ZZ');
  await expect(privateHost).not.toContainText('AS64500');
  await google.click();
  await expect(page.getByText('Country (approx.)')).toBeVisible();
  await expect(page.getByText('Network owner (approx.)')).toBeVisible();
  await expect(page.getByText(/Ready offline · release 2026-10/).first()).toBeVisible();

  // The imported data survives a reload and is available with the next capture.
  await page.reload();
  await openCapture(page, 'ip-data.pcap');
  await view(page, 'hosts');
  await expect(page.getByRole('grid', { name: 'Hosts' }).getByRole('row').filter({ hasText: '8.8.8.8' })).toContainText('AS15169 Google, LLC');
  expect(reqs.offenders()).toEqual([]);
});

test('DHCP, ARP, ICMP, SSH and QUIC views', async ({ page }) => {
  const reqs = watchRequests(page);
  const errs = errors(page);
  await page.goto('./');
  await openCapture(page, 'protocols.pcap');
  const count = (id: string) => page.locator(`.nav a[href="#/${id}"] .nav-count`);
  for (const [id, n] of [['dhcp', '3'], ['arp', '5'], ['icmp', '8'], ['ssh', '1'], ['quic', '2']]) await expect(count(id)).toHaveText(n);

  await view(page, 'dhcp');
  const dhcp = page.getByRole('grid', { name: 'DHCP exchanges' });
  await expect(dhcp.getByRole('row')).toHaveCount(4);
  const dora = dhcp.getByRole('row').filter({ hasText: '02:00:00:00:00:a1' });
  for (const s of ['laptop-a1', 'Discover → Offer → Request → ACK', 'acknowledged', '10.0.2.50']) await expect(dora).toContainText(s);
  await expect(dhcp.getByRole('row').filter({ hasText: '02:00:00:00:00:a2' })).toContainText('refused (NAK)');
  await expect(dhcp.getByRole('row').filter({ hasText: '02:00:00:00:00:a3' })).toContainText('no server reply seen');
  await dora.click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('1 h 0 min (3,600 s)');
  await expect(drawer.getByRole('group', { name: 'Choose a source packet' }).getByRole('button')).toHaveText(['#1', '#2', '#3', '#4']);
  await expect(drawer.getByText(/^Dynamic Host Configuration Protocol/).first()).toBeVisible();
  await page.keyboard.press('Escape');

  await view(page, 'arp');
  const mappings = page.getByRole('grid', { name: 'ARP mappings' });
  await expect(mappings.getByRole('row')).toHaveCount(3);
  await expect(mappings.getByRole('row').filter({ hasText: '10.0.2.1' })).toContainText('02:00:00:00:00:01, 02:00:00:00:00:fe');
  await expect(page.getByRole('grid', { name: 'ARP messages' }).getByRole('row')).toHaveCount(6);

  await view(page, 'icmp');
  const icmp = page.getByRole('grid', { name: 'ICMP messages' });
  await expect(icmp.getByRole('row')).toHaveCount(9);
  const unreachable = icmp.getByRole('row').filter({ hasText: 'Port unreachable' }).filter({ hasText: '33434' });
  await expect(unreachable).toContainText('UDP 10.0.2.50:51000 → 198.51.100.9:33434');
  await expect(icmp.getByRole('row').filter({ hasText: 'seq 2' })).toContainText('no reply seen');
  await page.getByRole('button', { name: 'Errors 3' }).click();
  await expect(icmp.getByRole('row')).toHaveCount(4);
  await unreachable.getByRole('button', { name: 'Conversation' }).click();
  await expect(page.locator('.nav a[aria-current=page]')).toHaveAttribute('href', '#/connections');
  await expect(page.getByRole('grid', { name: 'Conversation packets' }).getByRole('row')).toHaveCount(2);

  await view(page, 'ssh');
  const ssh = page.getByRole('grid', { name: 'SSH sessions' });
  await expect(ssh).toContainText('SSH-2.0-OpenSSH_9.6');
  await expect(ssh).toContainText('SSH-2.0-fixture_client_1.0');

  await view(page, 'quic');
  const quic = page.getByRole('grid', { name: 'QUIC conversations' });
  await expect(quic.getByRole('row')).toHaveCount(3);
  await expect(quic.getByRole('row').filter({ hasText: 'quic.example.net' })).toContainText('1 (0x00000001)');
  await expect(quic).toContainText('lists 1 (0x00000001)');

  expect(reqs.offenders()).toEqual([]);
  expect(errs).toEqual([]);
});
