// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// End-to-end engine tests: real Wiregasm (Wireshark WASM) + the Lua extractor
// + the TypeScript aggregation, run against synthetic fixtures with known contents.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { CaptureSession, FOLLOW_MAX_BYTES, installExtractor, type WiregasmModule } from '../src/engine/session';
import type { AnalysisModel } from '../src/engine/types';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const distDir = join(dirname(require.resolve('@goodtools/wiregasm/package.json')), 'dist');

let lib: WiregasmModule;
const prints: string[] = [];
let current: CaptureSession | null = null;

beforeAll(async () => {
  const loadWiregasm = require(join(distDir, 'wiregasm.js'));
  lib = await loadWiregasm({
    locateFile: (p: string) => join(distDir, p),
    print: (s: string) => { prints.push(s); current?.handlePrint(s); },
    printErr: () => {},
  });
  installExtractor(lib, readFileSync(join(root, 'src/engine/extractor.lua'), 'utf8'));
  expect(lib.init()).toBe(true);
});

async function open(name: string): Promise<{ model: AnalysisModel; session: CaptureSession }> {
  const session = new CaptureSession(lib, 'test');
  current = session;
  const bytes = new Uint8Array(readFileSync(join(root, 'fixtures', name)));
  const model = await session.open(name, bytes, () => {});
  return { model, session };
}

describe('DNS fixture', () => {
  let m: AnalysisModel;
  let s: CaptureSession;
  beforeAll(async () => ({ model: m, session: s } = await open('dns.pcap')));

  it('reads capture metadata', () => {
    expect(m.capture.packetCount).toBe(29);
    expect(m.capture.startEpoch).toBe('1700000000.010000000');
    expect(m.capture.timestampDigits).toBe(2);
    expect(m.capture.duration).toBeCloseTo(1.28, 9);
    expect(m.capture.incomplete).toBeNull();
    expect(m.capture.warnings).toEqual([]);
  });

  it('correlates queries and responses by txid + endpoints + transport', () => {
    const dns = m.dns.filter((d) => d.proto === 'DNS');
    expect(dns).toHaveLength(10);
    const byQuery = (f: number) => dns.find((d) => d.queryFrame === f)!;
    expect(byQuery(1)).toMatchObject({ status: 'answered', responseFrame: 2, rcode: 'NoError', qname: 'example.com', qtype: 'A', txid: 0x1111, transport: 'UDP' });
    expect(byQuery(1).answers).toEqual([{ section: 'answer', name: 'example.com', type: 'A', ttl: 300, value: '93.184.216.34' }]);
    expect(byQuery(1).rtt).toBeCloseTo(0.01, 9);
    expect(byQuery(3)).toMatchObject({ status: 'answered', responseFrame: 4, rcode: 'NXDomain' });
    expect(byQuery(5)).toMatchObject({ status: 'unanswered', responseFrame: null, rcode: null });
    expect(byQuery(13)).toMatchObject({ rcode: 'ServFail', qtype: 'MX' });
  });

  it('preserves repeated queries instead of merging them', () => {
    const first = m.dns.find((d) => d.queryFrame === 6)!;
    const repeat = m.dns.find((d) => d.queryFrame === 7)!;
    expect(first).toMatchObject({ status: 'answered', responseFrame: 8 });
    expect(repeat).toMatchObject({ status: 'retransmitted', relatedTo: first.id, responseFrame: null });
  });

  it('treats a reused transaction id as a new transaction', () => {
    const reuse = m.dns.find((d) => d.queryFrame === 9)!;
    expect(reuse).toMatchObject({ txid: 0x1111, qname: 'other.example', status: 'answered', responseFrame: 10 });
    expect(m.dns.find((d) => d.queryFrame === 1)!.responseFrame).toBe(2);
  });

  it('handles IPv6, CNAME chains and DNS over TCP with reassembly provenance', () => {
    expect(m.dns.find((d) => d.queryFrame === 11)).toMatchObject({ client: 'fd00::5', server: 'fd00::53', qtype: 'AAAA', status: 'answered' });
    const cname = m.dns.find((d) => d.queryFrame === 15)!;
    expect(cname.answers.map((a) => `${a.type} ${a.value}`)).toEqual(['CNAME example.com', 'A 93.184.216.34']);
    const tcp = m.dns.find((d) => d.transport === 'TCP')!;
    expect(tcp).toMatchObject({ qname: 'tcp.example', qtype: 'TXT', queryFrame: 21, responseFrame: 22, status: 'answered' });
    expect(tcp.frames).toEqual([20, 21, 22]);
    expect(tcp.answers[0].value).toBe('hello\tworld');
  });

  it('separates mDNS and NBNS from DNS', () => {
    const mdns = m.dns.filter((d) => d.proto === 'mDNS');
    expect(mdns.map((d) => d.status)).toEqual(['multicast query', 'multicast response']);
    const nbns = m.dns.filter((d) => d.proto === 'NBNS');
    expect(nbns).toHaveLength(1);
    expect(nbns[0]).toMatchObject({ status: 'answered', queryFrame: 28, responseFrame: 29, server: '10.0.0.20', qname: 'FILESERVER<00>' });
  });

  it('marks a subnet broadcast address as broadcast when sent to the Ethernet broadcast MAC', () => {
    expect(m.hosts.find((h) => h.addr === '10.0.0.255')?.scope).toBe('broadcast');
    expect(m.hosts.find((h) => h.addr === '10.0.0.20')?.scope).toBe('private');
  });

  it('records names with their source', () => {
    const printer = m.hosts.find((h) => h.addr === '10.0.0.9')!;
    expect(printer.names).toEqual([{ name: 'printer.local', source: 'mDNS', kind: 'observed', frame: 27 }]);
    const fs = m.hosts.find((h) => h.addr === '10.0.0.20')!;
    expect(fs.names[0]).toMatchObject({ name: 'FILESERVER<00>', source: 'NBNS' });
  });

  it('serves packet details and the packet list from the same session', () => {
    const d = s.frame(2);
    expect(d.epoch).toBe('1700000000.020000000');
    expect(d.tree.map((n) => n.filter)).toContain('dns');
    expect(d.sources[0].bytes.length).toBe(98);
    const page = s.packetList('dns.flags.rcode == 3', 0, 10);
    expect(page.matched).toBe(1);
    expect(page.rows[0].number).toBe(4);
    expect(page.columns).toContain('Info');
  });

  it('follows a UDP stream', () => {
    const f = s.follow('UDP', 1);
    expect(f.client).toEqual({ addr: '10.0.0.5', port: 50001 });
    expect(f.server).toEqual({ addr: '10.0.0.53', port: 53 });
    expect(f.segments.map((g) => [g.frame, g.fromServer])).toEqual([[3, false], [4, true]]);
    expect(Buffer.from(f.data).toString('latin1')).toContain('nonexistent');
  });
});

describe('HTTP fixture', () => {
  let m: AnalysisModel;
  let s: CaptureSession;
  beforeAll(async () => ({ model: m, session: s } = await open('http.pcap')));

  it('pairs requests and responses per TCP session', () => {
    expect(m.http.map((h) => [h.method, h.uri, h.status, h.state])).toEqual([
      ['GET', '/index.html', 200, 'complete'],
      ['POST', '/api/login', 401, 'complete'],
      ['GET', '/missing', 404, 'complete'],
      ['GET', '/again', 304, 'complete'],
      ['GET', '/v6', null, 'no response seen'],
    ]);
    const first = m.http[0];
    expect(first.host).toBe('www.example.test');
    expect(first.requestHeaders).toContain('User-Agent: fixture-agent/1.0');
    expect(first.frames).toEqual([4, 5, 6]);
    expect(m.http[4]).toMatchObject({ client: 'fd00::5', server: 'fd00::80', serverPort: 8080 });
  });

  it('keeps a reused 4-tuple as distinct TCP sessions', () => {
    const tcp = m.conversations.filter((c) => c.transport === 'TCP');
    expect(tcp).toHaveLength(4);
    const same = tcp.filter((c) => c.a === '10.0.0.5' && c.aPort === 40000 && c.bPort === 80);
    expect(same).toHaveLength(2);
    expect(same[0].stream).not.toBe(same[1].stream);
    expect(same.every((c) => c.initiator === 'SYN' && c.tcp!.synAckSeen)).toBe(true);
  });

  it('reports observed service ports and inferred names honestly', () => {
    const server = m.hosts.find((h) => h.addr === '10.0.0.80')!;
    expect(server.servicePorts).toEqual([{ transport: 'TCP', port: 80, evidence: 'handshake completed', conversations: 3, peers: 1 }]);
    expect(server.names.map((n) => [n.name, n.source, n.kind])).toEqual([
      ['www.example.test', 'HTTP Host header', 'inferred'],
      ['static.example.test', 'HTTP Host header', 'inferred'],
    ]);
    expect(server.macs[0].mac).toBe('02:00:00:00:00:80');
  });

  it('follows a TCP stream: reassembled payload in capture order, client and server separated', () => {
    const f = s.follow('TCP', 0);
    expect(f.client).toEqual({ addr: '10.0.0.5', port: 40000 });
    expect(f.server).toEqual({ addr: '10.0.0.80', port: 80 });
    expect(f.segments.map((g) => [g.frame, g.fromServer])).toEqual([[4, false], [5, false], [6, true], [7, false], [8, true]]);
    const text = (fromServer: boolean) => f.segments.filter((g) => g.fromServer === fromServer)
      .map((g) => Buffer.from(f.data.subarray(g.offset, g.offset + g.length)).toString('latin1')).join('');
    expect(text(false)).toMatch(/^GET \/index\.html HTTP\/1\.1\r\nHost: www\.example\.test\r\n[^]*POST \/api\/login[^]*\{"user":"alice"\}\n$/);
    expect(text(true)).toContain("<script>alert('captured content must not run')</script>");
    expect(text(true)).toMatch(/HTTP\/1\.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n$/);
    expect(f.clientBytes).toBe(text(false).length);
    expect(f.serverBytes).toBe(text(true).length);
    expect(f.data.length).toBe(f.clientBytes + f.serverBytes);
    expect(f).toMatchObject({ transport: 'TCP', stream: 0, totalSegments: 5, truncated: false });
  });

  it('caps a followed stream by bytes and by segments, and says so', () => {
    const bytesCap = s.follow('TCP', 0, { maxBytes: 30 });
    expect(bytesCap.truncated).toBe(true);
    expect(bytesCap.data.length).toBe(30);
    expect(bytesCap.segments.map((g) => [g.frame, g.offset, g.length])).toEqual([[4, 0, 20], [5, 20, 10]]);
    expect(bytesCap.totalSegments).toBe(5);
    expect(bytesCap.clientBytes + bytesCap.serverBytes).toBeGreaterThan(30);
    const segCap = s.follow('TCP', 0, { maxSegments: 2 });
    expect(segCap.truncated).toBe(true);
    expect(segCap.segments.map((g) => g.frame)).toEqual([4, 5]);
  });

  it('follows an IPv6 stream with no server data, and reports an unknown stream as empty', () => {
    const v6 = s.follow('TCP', 3);
    expect(v6.client).toEqual({ addr: 'fd00::5', port: 40002 });
    expect(v6.serverBytes).toBe(0);
    expect(v6.segments.map((g) => [g.frame, g.fromServer])).toEqual([[31, false]]);
    const none = s.follow('TCP', 99);
    expect(none).toMatchObject({ client: null, server: null, segments: [], totalSegments: 0, truncated: false });
  });
});

describe('HTTP pairing fixture', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('http-pairing.pcap')));

  it('keeps an orphan response from consuming the later linked exchange', () => {
    expect(m.http.map((h) => [h.method, h.uri, h.status, h.state])).toEqual([
      [null, null, 503, 'response without request'],
      ['GET', '/after-gap', 200, 'complete'],
      ['GET', '/pipeline-a', 201, 'complete'],
      ['GET', '/pipeline-b', 202, 'complete'],
    ]);
    expect(m.http.slice(1).every((h) => h.pairingWarning === null)).toBe(true);
  });

  it('continues pairing later messages on the same connection', () => {
    const [a, b] = m.http.slice(2);
    expect(a.requestFrame).not.toBe(b.requestFrame);
    expect(a.responseFrame).not.toBe(b.responseFrame);
    expect(a).toMatchObject({ uri: '/pipeline-a', status: 201, state: 'complete' });
    expect(b).toMatchObject({ uri: '/pipeline-b', status: 202, state: 'complete' });
  });
});

describe('HTTP/2 fixture', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('http2.pcap')));

  it('extracts cleartext h2c headers and pairs concurrent streams', () => {
    expect(m.capture.packetCount).toBe(9);
    expect(m.http).toHaveLength(2);
    expect(m.http.map((h) => [h.http2StreamId, h.method, h.host, h.uri, h.status, h.version, h.state])).toEqual([
      [1, 'GET', 'h2.example.test', '/first', 200, 'HTTP/2', 'complete'],
      [3, 'POST', 'h2.example.test', '/second', 404, 'HTTP/2', 'complete'],
    ]);
    expect(m.http[0].userAgent).toBe('fixture-h2/1.0');
    expect(m.http[0].contentType).toBe('text/plain');
    expect(m.http[1].requestContentType).toBe('application/json');
    expect(m.http[1].serverHeader).toBe('h2-fixture');
    expect(m.unsupported.http2Packets).toBeGreaterThan(0);
    expect(m.hosts.find((h) => h.addr === '10.0.0.80')?.names).toContainEqual(
      expect.objectContaining({ name: 'h2.example.test', source: 'HTTP Host header', kind: 'inferred' }),
    );
  });
});

describe('separate DNS and HTTP reassembly sources fixture', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('sources.pcap')));

  it('keeps decoded fields attached to their own reassembled messages', () => {
    expect(m.dns).toContainEqual(expect.objectContaining({
      qname: 'source-dns.example', qtype: 'A', status: 'answered', responseFrame: 6,
    }));
    expect(m.http).toHaveLength(1);
    expect(m.http[0]).toMatchObject({
      method: 'GET', uri: '/source-http', host: 'source-http.example', status: 200,
      state: 'complete', requestFrame: 14, responseFrame: 15,
    });
    expect(m.http[0].frames).toEqual([13, 14, 15]);
  });
});

describe('Follow stream fixture', () => {
  let s: CaptureSession;
  beforeAll(async () => ({ session: s } = await open('follow.pcap')));

  it('caps a large stream at the default view size and still counts the whole stream', () => {
    const f = s.follow('TCP', 0);
    expect(f).toMatchObject({ truncated: true, clientBytes: 51, serverBytes: 612069, totalSegments: 439 });
    expect(f.data.length).toBe(FOLLOW_MAX_BYTES);
    expect(f.segments.reduce((n, g) => n + g.length, 0)).toBe(FOLLOW_MAX_BYTES);
    const full = s.follow('TCP', 0, { maxBytes: Infinity, maxSegments: Infinity });
    expect(full).toMatchObject({ truncated: false });
    expect(full.data.length).toBe(612069 + 51);
    expect(Buffer.from(full.data.subarray(full.data.length - 51)).toString('latin1')).toBe('line 11999 of the large follow-stream fixture body\n');
  });

  it('follows a UDP exchange', () => {
    const f = s.follow('UDP', 0);
    expect(f.client).toEqual({ addr: '10.0.0.5', port: 41001 });
    expect(Buffer.from(f.data).toString('latin1')).toBe('PING 1\nPONG 1\n');
    expect(f.segments.map((g) => g.fromServer)).toEqual([false, true]);
  });
});

describe('TLS fixture', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('tls.pcap')));

  it('separates advertised from negotiated parameters', () => {
    expect(m.tls).toHaveLength(3);
    const [t12, t13, noReply] = m.tls;
    expect(t12.sni).toBe('www.example.com');
    expect(t12.offered!.alpn).toEqual(['h2', 'http/1.1']);
    expect(t12.offered!.cipherSuites).toHaveLength(3);
    expect(t12.negotiated).toEqual({
      version: 'TLS 1.2 (0x0303)', versionSource: 'ServerHello version field', alpn: 'h2',
      cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)',
    });
    expect(t13.offered!.supportedVersions).toEqual(['TLS 1.3 (0x0304)', 'TLS 1.2 (0x0303)']);
    expect(t13.negotiated).toMatchObject({ version: 'TLS 1.3 (0x0304)', versionSource: 'supported_versions extension' });
    expect(t13.certificateStatus).toBe('encrypted (TLS 1.3)');
    expect(t13.client).toBe('fd00::5');
    expect(noReply).toMatchObject({ sni: 'noreply.example.org', negotiated: null, serverHelloFrame: null, certificateStatus: 'not observed' });
  });

  it('decodes certificates only when present', () => {
    const [cert] = m.tls[0].certificates;
    expect(cert).toMatchObject({
      commonName: 'www.example.com', subject: 'CN=www.example.com, O=Fixture Org', issuer: 'CN=Fixture Test CA',
      serial: '1234abcd', notBefore: '2023-01-01 00:00:00 UTC', notAfter: '2024-01-01 00:00:00 UTC',
      san: ['www.example.com', 'example.com'], publicKeyAlgorithm: 'EC', signatureAlgorithm: 'ecdsa-with-SHA256', error: null,
    });
    expect(cert.sha256).toMatch(/^([0-9a-f]{2}:){31}[0-9a-f]{2}$/);
    expect(m.tls[0].certificateStatus).toBe('decoded');
  });

  it('learns SNI names as inferred', () => {
    const h = m.hosts.find((x) => x.addr === '198.51.100.10')!;
    expect(h.names).toEqual([{ name: 'www.example.com', source: 'TLS SNI', kind: 'inferred', frame: 4 }]);
    expect(m.unsupported.encryptedConversations).toBe(3);
  });
});

describe('edge cases', () => {
  it('flags malformed, fragmented and truncated packets', async () => {
    const { model: m } = await open('edge.pcap');
    expect(m.capture.packetCount).toBe(4);
    expect(m.capture.malformedPackets).toBe(1);
    expect(m.capture.fragmentPackets).toBe(2);
    expect(m.capture.truncatedPackets).toBe(1);
    expect(m.capture.wireBytes - m.capture.capturedBytes).toBe(442 - 60);
    const frag = m.dns.find((d) => d.qname === 'frag.example')!;
    expect(frag).toMatchObject({ status: 'response without query', responseFrame: 3 });
    expect(frag.frames).toEqual([2, 3]);
    expect(frag.answers).toHaveLength(2);
    expect(m.dns.find((d) => d.queryFrame === 1)!.malformed).toBe(true);
  });

  it('analyses the readable part of a cut-short file and says so', async () => {
    const { model: m } = await open('cut.pcap');
    expect(m.capture.packetCount).toBe(3);
    expect(m.capture.incomplete).toMatch(/cut short/);
  });

  it('rejects files that are not captures', async () => {
    await expect(open('not-a-capture.pcap')).rejects.toThrow(/could not be opened as a packet capture/);
  });

  it('handles pcapng with mixed link types and timestamp resolutions', async () => {
    const { model: m } = await open('multi-iface.pcapng');
    expect(m.capture.interfaces).toEqual([
      { id: 0, linkType: 'Ethernet (1)', name: 'eth0', packets: 1 },
      { id: 1, linkType: 'Raw IP (7)', name: 'tun0', packets: 1 },
    ]);
    expect(m.capture.timestampDigits).toBe(9);
    expect(m.capture.duration).toBeCloseTo(0.000000789, 12);
    expect(m.dns.map((d) => d.qname)).toEqual(['ng.example', 'tun.example']);
  });
});

describe('MAC vendors', () => {
  it('names registered prefix owners and flags locally administered addresses', async () => {
    const { model: m } = await open('vendors.pcap');
    const mac = (addr: string) => m.hosts.find((h) => h.addr === addr)!.macs[0];
    expect(mac('10.0.1.10')).toEqual({ mac: '00:1b:21:aa:bb:cc', packets: 1, vendor: 'Intel Corporate', locallyAdministered: false });
    expect(mac('10.0.1.20')).toMatchObject({ mac: 'f0:18:98:11:22:33', vendor: 'Apple, Inc.', locallyAdministered: false });
    expect(mac('10.0.1.30')).toMatchObject({ mac: '06:11:22:33:44:55', vendor: null, locallyAdministered: true });
  });
});

describe('protocols fixture (DHCP, ARP, ICMP, SSH, QUIC)', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('protocols.pcap')));

  it('groups DHCP messages into exchanges by transaction id and client MAC', () => {
    expect(m.capture.packetCount).toBe(34);
    expect(m.capture.warnings).toEqual([]);
    expect(m.dhcp.map((d) => [d.xid, d.clientMac, d.messages.map((x) => x.type), d.outcome])).toEqual([
      [0x1001, '02:00:00:00:00:a1', ['Discover', 'Offer', 'Request', 'ACK'], 'acknowledged'],
      [0x2002, '02:00:00:00:00:a2', ['Request', 'NAK'], 'refused (NAK)'],
      [0x3003, '02:00:00:00:00:a3', ['Discover'], 'no server reply seen'],
    ]);
    const [dora, nak, silent] = m.dhcp;
    expect(dora).toMatchObject({
      hostname: 'laptop-a1', requestedIp: '10.0.2.50', offeredIp: '10.0.2.50', assignedIp: '10.0.2.50', server: '10.0.2.1',
      leaseTime: 3600, subnetMask: '255.255.255.0', routers: ['10.0.2.1'], dnsServers: ['10.0.2.1'], frames: [1, 2, 3, 4],
    });
    expect(dora.messages[1]).toMatchObject({ frame: 2, type: 'Offer', src: '10.0.2.1', dst: '10.0.2.50' });
    expect(nak).toMatchObject({ hostname: 'phone-a2', requestedIp: '10.0.2.99', assignedIp: null, server: '10.0.2.1', frames: [5, 6] });
    expect(silent).toMatchObject({ hostname: null, offeredIp: null, assignedIp: null, server: null, leaseTime: null, frames: [7] });
    // The DHCP host name still feeds the host inventory.
    expect(m.hosts.find((h) => h.addr === '10.0.2.50')!.names).toContainEqual({ name: 'laptop-a1', source: 'DHCP host name', kind: 'observed', frame: 1 });
  });

  it('records ARP IP-to-MAC mappings over time without judging them', () => {
    expect(m.arp.map((a) => [a.frame, a.op, a.ip, a.mac, a.targetIp, a.gratuitous])).toEqual([
      [8, 'request', '10.0.2.50', '02:00:00:00:00:a1', '10.0.2.1', false],
      [9, 'reply', '10.0.2.1', '02:00:00:00:00:01', '10.0.2.50', false],
      [10, 'reply', '10.0.2.1', '02:00:00:00:00:fe', '10.0.2.1', true],
      [11, 'reply', '10.0.2.1', '02:00:00:00:00:01', '10.0.2.50', false],
      [12, 'request', '0.0.0.0', '02:00:00:00:00:a3', '10.0.2.77', false],
    ]);
    // The probe (sender 0.0.0.0) claims no address, so it creates no mapping.
    expect(m.arpBindings.map((b) => b.ip)).toEqual(['10.0.2.1', '10.0.2.50']);
    const gw = m.arpBindings[0];
    expect(gw).toMatchObject({ macs: ['02:00:00:00:00:01', '02:00:00:00:00:fe'], changes: 2, frames: [9, 10, 11] });
    expect(gw.periods.map((p) => [p.mac, p.firstFrame, p.lastFrame, p.messages])).toEqual([
      ['02:00:00:00:00:01', 9, 9, 1], ['02:00:00:00:00:fe', 10, 10, 1], ['02:00:00:00:00:01', 11, 11, 1],
    ]);
    expect(gw.periods[1].firstSeen - gw.periods[0].lastSeen).toBeCloseTo(1, 9);
    expect(m.arpBindings[1]).toMatchObject({ macs: ['02:00:00:00:00:a1'], changes: 0, frames: [8] });
  });

  it('pairs ICMP echoes and links errors to the conversation they quote', () => {
    expect(m.icmp.map((i) => [i.frame, i.version, i.type, i.code, i.kind])).toEqual([
      [13, 4, 8, 0, 'echo request'], [14, 4, 0, 0, 'echo reply'], [15, 4, 8, 0, 'echo request'],
      [17, 4, 3, 3, 'error'], [19, 4, 11, 0, 'error'],
      [20, 6, 128, 0, 'echo request'], [21, 6, 129, 0, 'echo reply'], [23, 6, 1, 4, 'error'],
    ]);
    const at = (f: number) => m.icmp.find((i) => i.frame === f)!;
    expect(at(13)).toMatchObject({ typeName: 'Echo (ping) request', echo: { ident: 1, seq: 1, status: 'replied', pairedFrame: 14 }, frames: [13, 14] });
    expect(at(14).echo).toEqual({ ident: 1, seq: 1, status: 'reply', pairedFrame: 13 });
    expect(at(15).echo).toEqual({ ident: 1, seq: 2, status: 'no reply seen', pairedFrame: null });
    expect(at(20).echo).toMatchObject({ ident: 7, seq: 1, status: 'replied', pairedFrame: 21 });

    const unreachable = at(17);
    expect(unreachable).toMatchObject({ src: '198.51.100.9', dst: '10.0.2.50', typeName: 'Destination unreachable', codeName: 'Port unreachable', echo: null });
    const quotedConv = m.conversations.find((c) => c.transport === 'UDP' && c.aPort === 51000)!;
    expect(unreachable.quoted).toEqual({ protocol: 'UDP', src: '10.0.2.50', srcPort: 51000, dst: '198.51.100.9', dstPort: 33434, convId: quotedConv.id });
    expect(at(19)).toMatchObject({ src: '10.0.2.1', typeName: 'Time-to-live exceeded', codeName: 'Time to live exceeded in transit' });
    expect(at(19).quoted).toMatchObject({ protocol: 'UDP', dst: '203.0.113.5', dstPort: 33435 });
    expect(at(23)).toMatchObject({ src: 'fd00::99', typeName: 'Destination Unreachable', codeName: 'Port unreachable' });
    expect(at(23).quoted).toMatchObject({ protocol: 'UDP', src: 'fd00::50', srcPort: 51002, dst: 'fd00::99', dstPort: 9999 });
    expect(at(23).quoted!.convId).toBe(m.conversations.find((c) => c.transport === 'UDP' && c.aPort === 51002)!.id);
  });

  it('reads SSH version strings per TCP session', () => {
    expect(m.ssh).toHaveLength(1);
    expect(m.ssh[0]).toMatchObject({
      client: '10.0.2.50', clientPort: 45000, server: '10.0.2.22', serverPort: 22,
      clientVersion: 'SSH-2.0-fixture_client_1.0', clientVersionFrame: 28,
      serverVersion: 'SSH-2.0-OpenSSH_9.6', serverVersionFrame: 27, frames: [27, 28],
    });
    expect(m.ssh[0].convId).toBe(m.conversations.find((c) => c.bPort === 22)!.id);
  });

  it('lists QUIC versions, version negotiation and the Initial SNI', () => {
    expect(m.quic.map((q) => [q.client, q.clientPort, q.server, q.serverPort, q.versions, q.versionNegotiation, q.sni, q.alpn, q.frames])).toEqual([
      ['10.0.2.50', 52000, '198.51.100.20', 443, ['1 (0x00000001)'], null, 'quic.example.net', ['h3'], [32]],
      ['10.0.2.50', 52001, '198.51.100.21', 443, ['Unknown (0x0a0a0a0a)'], ['1 (0x00000001)'], null, [], [33, 34]],
    ]);
  });
});

describe('protocols edge fixture (DHCP outcome order, tunnelled ICMP)', () => {
  let m: AnalysisModel;
  beforeAll(async () => ({ model: m } = await open('protocols-edge.pcap')));

  it('takes the DHCP outcome from the last message that decides it', () => {
    expect(m.capture.packetCount).toBe(12);
    expect(m.dhcp.map((d) => [d.xid, d.messages.map((x) => x.type), d.outcome, d.assignedIp])).toEqual([
      // The client declined the address the server ACKed, so the exchange ends declined.
      [0x4004, ['Discover', 'Offer', 'Request', 'ACK', 'Decline'], 'declined', '10.0.2.60'],
      [0x5005, ['Request', 'NAK', 'Request', 'ACK'], 'acknowledged', '10.0.2.61'],
    ]);
  });

  it('reads the quoted packet after the ICMP header, not a tunnel header', () => {
    expect(m.icmp.map((i) => [i.frame, i.type, i.kind])).toEqual([[11, 3, 'error'], [12, 8, 'echo request']]);
    expect(m.icmp[0].quoted).toMatchObject({ protocol: 'UDP', src: '10.0.2.50', srcPort: 51000, dst: '198.51.100.9', dstPort: 33434 });
    expect(m.icmp[1].quoted).toBeNull();
  });
});
