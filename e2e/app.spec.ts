// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { expect, test, type Page, type Request } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const fixture = (name: string) => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

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

test('HTTP capture: requests, hosts, sessions, graph and packet list', async ({ page }) => {
  const reqs = watchRequests(page);
  const errs = errors(page);
  await page.goto('./');
  await openCapture(page, 'http.pcap');

  await view(page, 'http');
  const http = page.getByRole('grid', { name: 'HTTP requests' });
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
  await expect(page.getByText('No cleartext HTTP/1.x messages were decoded.')).toBeVisible();
  await expect(page.getByText(/3 conversations use TLS or QUIC/)).toBeVisible();
});

test('edge cases: truncated/malformed notes, incomplete file, non-capture file', async ({ page }) => {
  await page.goto('./');
  await openCapture(page, 'edge.pcap');
  await expect(page.getByText(/1 packet truncated/)).toBeVisible();
  await expect(page.getByText(/1 packet malformed/)).toBeVisible();

  await page.locator('input[type=file]').first().setInputFiles(fixture('cut.pcap'));
  await expect(page.locator('.cap-title h1')).toHaveText('cut.pcap');
  await expect(page.getByText('incomplete file')).toBeVisible();
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
  await page.locator('input[type=file]').setInputFiles(fixture('http.pcap'));
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
  const json = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON summary' }).click();
  const jd = await json;
  expect(jd.suggestedFilename()).toBe('dns-summary.json');
  const summary = JSON.parse(await (await jd.createReadStream()).toArray().then((c) => Buffer.concat(c).toString('utf8')));
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

for (const vp of [{ name: 'tablet', width: 820, height: 1180 }, { name: 'phone', width: 390, height: 844 }]) {
  test(`${vp.name} layout has no horizontal page scroll`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.goto('./');
    const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    expect(await fits()).toBe(true);
    await openCapture(page, 'dns.pcap');
    for (const v of ['overview', 'dns', 'http', 'tls', 'hosts', 'connections', 'network', 'packets']) {
      await view(page, v);
      await page.waitForTimeout(300);
      expect(await fits(), `${v} overflows at ${vp.width}px`).toBe(true);
      if (v === 'overview' || v === 'dns') await page.screenshot({ path: `test-results/${vp.name}-${v}.png`, fullPage: true });
    }
    if (vp.name === 'phone') await expect(page.locator('.mobile-local')).toBeVisible();
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
