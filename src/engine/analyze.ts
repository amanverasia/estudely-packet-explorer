// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Aggregates raw extractor records into the shared AnalysisModel.
// Pure TypeScript: runs in the Web Worker and in Node tests.
import type {
  AnalysisModel, CaptureInfo, Conversation, DnsAnswer, DnsProto, DnsTransaction, Host, HttpExchange, LearnedName,
  NameSource, ProtoStat, ServicePort, Timeline, TlsSession, Transport,
} from './types';
import type { RawDns, RawNbns, RawPacket, RawRecords } from './records';
import { buildArp, buildDhcp, buildIcmp, buildQuic, buildSsh, type ProtoCtx } from './protocols';
import { fingerprint, hexToBytes, parseCertificate } from './x509';

export interface CaptureMeta {
  fileName: string;
  fileSize: number;
  fileType: string;
  linkType: string;
  incomplete: string | null;
  engine: { wireshark: string; wiregasm: string };
  warnings: string[];
}

/** Worker-side packet index used for drill-downs; never sent wholesale to the UI. */
export interface PacketIndex {
  packets: RawPacket[];
  convOf: Int32Array; // per packet index -> conversation id (or -1)
}

const PAYLOAD_PROTOS = new Set([
  'data', 'data-text-lines', 'media', 'png', 'image-gif', 'image-jfif', 'json', 'xml', 'urlencoded-form',
  'mime_multipart', 'ethertype', 'pkt_comment', 'tcp.segments', 'ip.fragments', 'ipv6.fragments', 'x509sat', 'x509af',
  'x509ce', 'pkcs-1', 'pkix1explicit', 'pkix1implicit', 'ber', 'cms', 'http-urlencoded', 'json.object',
]);

const PROTO_NAMES: Record<string, string> = {
  eth: 'Ethernet', ip: 'IPv4', ipv6: 'IPv6', tcp: 'TCP', udp: 'UDP', dns: 'DNS', mdns: 'mDNS', llmnr: 'LLMNR',
  http: 'HTTP', http2: 'HTTP/2', tls: 'TLS', quic: 'QUIC', arp: 'ARP', icmp: 'ICMP', icmpv6: 'ICMPv6', nbns: 'NBNS',
  dhcp: 'DHCP', dhcpv6: 'DHCPv6', ssdp: 'SSDP', ntp: 'NTP', sll: 'Linux cooked', raw: 'Raw IP', vlan: '802.1Q VLAN',
  igmp: 'IGMP', stp: 'STP', lldp: 'LLDP', cdp: 'CDP', smb: 'SMB', smb2: 'SMB2', nbss: 'NBSS', ssh: 'SSH',
  ftp: 'FTP', smtp: 'SMTP', imap: 'IMAP', pop: 'POP', sip: 'SIP', rtp: 'RTP', snmp: 'SNMP', kerberos: 'Kerberos',
  ldap: 'LDAP', 'data': 'Data', gre: 'GRE', esp: 'ESP', isakmp: 'ISAKMP', wg: 'WireGuard', dtls: 'DTLS',
  frame: 'Frame', null: 'Null/Loopback', loop: 'Loopback', ppp: 'PPP', pppoes: 'PPPoE', mpls: 'MPLS',
};

export function protoName(p: string): string {
  return PROTO_NAMES[p] ?? p.toUpperCase();
}


export function topProtocol(protos: string): string {
  const stack = protos.split(':');
  for (let i = stack.length - 1; i >= 0; i--) {
    const p = stack[i];
    if (!PAYLOAD_PROTOS.has(p) && p !== 'frame') return p;
  }
  return stack[stack.length - 1] || 'unknown';
}

function hasProto(protos: string, name: string): boolean {
  return (':' + protos + ':').includes(':' + name + ':');
}

const DNS_RCODES = ['NoError', 'FormErr', 'ServFail', 'NXDomain', 'NotImp', 'Refused', 'YXDomain', 'YXRRSet', 'NXRRSet', 'NotAuth', 'NotZone', 'DSOTYPENI'];
const NBNS_RCODES = ['OK', 'FMT_ERR', 'SRV_ERR', 'NAM_ERR', 'IMP_ERR', 'RFS_ERR', 'ACT_ERR', 'CFT_ERR'];

function rcodeName(proto: DnsProto, code: number | null): string | null {
  if (code === null) return null;
  const table = proto === 'NBNS' ? NBNS_RCODES : DNS_RCODES;
  return table[code] ?? `RCODE ${code}`;
}

/** "A (1)" -> "A" */
function shortType(t: string | null): string | null {
  if (!t) return t;
  return t.replace(/\s*\(\d+\)$/, '');
}

// --------------------------------------------------------------- addresses
function ipv4ToInt(a: string): number | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(a);
  if (!m) return null;
  return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4];
}

function inV4(n: number, base: string, bits: number): boolean {
  const b = ipv4ToInt(base)!;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((n & mask) >>> 0) === ((b & mask) >>> 0);
}

export function addressScope(a: string): string {
  if (a.includes(':')) {
    const l = a.toLowerCase();
    if (l === '::1') return 'loopback';
    if (l === '::') return 'unspecified';
    if (/^fe[89ab]/.test(l)) return 'link-local';
    if (/^f[cd]/.test(l)) return 'unique local';
    if (l.startsWith('ff')) return 'multicast';
    if (l.startsWith('2001:db8:') || l === '2001:db8::' || l.startsWith('2001:0db8')) return 'documentation';
    return 'global';
  }
  const n = ipv4ToInt(a);
  if (n === null) return 'unknown';
  if (a === '255.255.255.255') return 'broadcast';
  if (a === '0.0.0.0') return 'unspecified';
  if (inV4(n, '127.0.0.0', 8)) return 'loopback';
  if (inV4(n, '10.0.0.0', 8) || inV4(n, '172.16.0.0', 12) || inV4(n, '192.168.0.0', 16)) return 'private';
  if (inV4(n, '169.254.0.0', 16)) return 'link-local';
  if (inV4(n, '224.0.0.0', 4)) return 'multicast';
  if (inV4(n, '100.64.0.0', 10)) return 'shared (CGNAT)';
  if (inV4(n, '192.0.2.0', 24) || inV4(n, '198.51.100.0', 24) || inV4(n, '203.0.113.0', 24)) return 'documentation';
  return 'public';
}

function isGroupAddress(a: string): boolean {
  const s = addressScope(a);
  return s === 'multicast' || s === 'broadcast' || /\.255$/.test(a);
}

// ---------------------------------------------------------------- timeline
const NICE_BINS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400];

function pickBin(duration: number, target = 150): number {
  const want = duration / target;
  for (const b of NICE_BINS) if (b >= want) return b;
  return Math.ceil(want / 86400) * 86400;
}

// ----------------------------------------------------------------- analyze
export async function analyze(raw: RawRecords, meta: CaptureMeta, onProgress?: (msg: string) => void): Promise<{ model: AnalysisModel; index: PacketIndex }> {
  const t0 = performance.now();
  const packets = raw.packets;
  const byFrame = new Map<number, number>();
  packets.forEach((p, i) => byFrame.set(p.frame, i));
  const pkt = (frame: number): RawPacket | undefined => {
    const i = byFrame.get(frame);
    return i === undefined ? undefined : packets[i];
  };
  const segs = (frame: number): number[] => raw.segments.get(frame) ?? [frame];

  // ---- capture counters, protocol hierarchy
  onProgress?.('Counting protocols');
  const hier = new Map<string, ProtoStat>();
  const top = new Map<string, ProtoStat>();
  const topOf: string[] = new Array(packets.length);
  const ifaceCount = new Map<number | null, number>();
  let backwards = 0;
  let wire = 0, captured = 0, truncated = 0, malformed = 0, expert = 0, frags = 0, retrans = 0, ooo = 0, lost = 0, dupack = 0, http2 = 0;
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    if (i > 0 && p.t < packets[i - 1].t) backwards++;
    wire += p.len;
    captured += p.caplen;
    if (p.caplen < p.len) truncated++;
    const f = p.flags;
    if (f) {
      if (f.includes('M')) malformed++;
      if (f.includes('E')) expert++;
      if (f.includes('F')) frags++;
      if (f.includes('R')) retrans++;
      if (f.includes('O')) ooo++;
      if (f.includes('L')) lost++;
      if (f.includes('D')) dupack++;
    }
    ifaceCount.set(p.iface, (ifaceCount.get(p.iface) ?? 0) + 1);
    const stack = p.protos.split(':');
    const seen = new Set<string>();
    for (const s of stack) {
      if (PAYLOAD_PROTOS.has(s) || s === 'frame' || seen.has(s)) continue;
      seen.add(s);
      const name = protoName(s);
      const h = hier.get(name) ?? { proto: name, packets: 0, bytes: 0 };
      h.packets++;
      h.bytes += p.len;
      hier.set(name, h);
    }
    if (seen.has('http2')) http2++;
    const tp = protoName(topProtocol(p.protos));
    topOf[i] = tp;
    const ts = top.get(tp) ?? { proto: tp, packets: 0, bytes: 0 };
    ts.packets++;
    ts.bytes += p.len;
    top.set(tp, ts);
  }

  // ---- conversations
  onProgress?.('Grouping conversations');
  const convs: Conversation[] = [];
  const convKey = new Map<string, number>();
  const convOf = new Int32Array(packets.length).fill(-1);
  const convTop: Map<string, number>[] = [];
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    const quoted = hasProto(p.protos, 'icmp') || hasProto(p.protos, 'icmpv6');
    let transport: Transport;
    let key: string;
    let stream: number | null = null;
    if (!quoted && p.tcpStream !== null && hasProto(p.protos, 'tcp')) {
      transport = 'TCP';
      stream = p.tcpStream;
      key = 'T' + stream;
    } else if (!quoted && p.udpStream !== null && hasProto(p.protos, 'udp')) {
      transport = 'UDP';
      stream = p.udpStream;
      key = 'U' + stream;
    } else if (p.src && p.dst) {
      transport = 'IP';
      const [x, y] = p.src < p.dst ? [p.src, p.dst] : [p.dst, p.src];
      key = 'I' + topOf[i] + '|' + x + '|' + y;
    } else {
      transport = 'Non-IP';
      const s = p.ethSrc || '?', d = p.ethDst || '?';
      const [x, y] = s < d ? [s, d] : [d, s];
      key = 'N' + topOf[i] + '|' + x + '|' + y;
    }
    let id = convKey.get(key);
    const ported = transport === 'TCP' || transport === 'UDP';
    const src = p.src || p.ethSrc || '?';
    const dst = p.dst || p.ethDst || '?';
    if (id === undefined) {
      id = convs.length;
      convKey.set(key, id);
      const isSyn = transport === 'TCP' && p.tcpFlags !== null && (p.tcpFlags & 0x12) === 0x02;
      convs.push({
        id, transport, stream, a: src, aPort: ported ? p.sport : null, b: dst, bPort: ported ? p.dport : null,
        initiator: isSyn ? 'SYN' : 'first packet', packetsAB: 0, bytesAB: 0, packetsBA: 0, bytesBA: 0,
        start: p.t, end: p.t, firstFrame: p.frame, lastFrame: p.frame, protocols: [], appProtocol: '',
        tcp: transport === 'TCP' ? { synSeen: false, synAckSeen: false, finSeen: false, rstSeen: false, retransmissions: 0, outOfOrder: 0, lostSegments: 0, payloadBytesAB: 0, payloadBytesBA: 0 } : null,
        truncatedPackets: 0, malformedPackets: 0, records: { dns: 0, http: 0, tls: 0 },
      });
      convTop.push(new Map());
    }
    const c = convs[id];
    convOf[i] = id;
    const ab = src === c.a && (!ported || p.sport === c.aPort);
    if (ab) { c.packetsAB++; c.bytesAB += p.len; } else { c.packetsBA++; c.bytesBA += p.len; }
    if (p.t < c.start) c.start = p.t;
    if (p.t > c.end) c.end = p.t;
    c.lastFrame = p.frame;
    if (p.caplen < p.len) c.truncatedPackets++;
    if (p.flags.includes('M')) c.malformedPackets++;
    const tc = convTop[id];
    tc.set(topOf[i], (tc.get(topOf[i]) ?? 0) + 1);
    if (c.tcp && p.tcpFlags !== null) {
      const fl = p.tcpFlags;
      if ((fl & 0x12) === 0x02) c.tcp.synSeen = true;
      if ((fl & 0x12) === 0x12) c.tcp.synAckSeen = true;
      if (fl & 0x01) c.tcp.finSeen = true;
      if (fl & 0x04) c.tcp.rstSeen = true;
      if (p.flags.includes('R')) c.tcp.retransmissions++;
      if (p.flags.includes('O')) c.tcp.outOfOrder++;
      if (p.flags.includes('L')) c.tcp.lostSegments++;
      if (ab) c.tcp.payloadBytesAB += p.tcpLen ?? 0; else c.tcp.payloadBytesBA += p.tcpLen ?? 0;
    }
  }
  convs.forEach((c, id) => {
    const entries = [...convTop[id].entries()].sort((x, y) => y[1] - x[1]);
    c.protocols = entries.map((e) => e[0]);
    const app = entries.find((e) => !['TCP', 'UDP', 'IPv4', 'IPv6'].includes(e[0]));
    c.appProtocol = app ? app[0] : c.transport === 'Non-IP' ? entries[0]?.[0] ?? 'Non-IP' : c.transport;
  });
  const convOfFrame = (frame: number): number | null => {
    const i = byFrame.get(frame);
    if (i === undefined) return null;
    const c = convOf[i];
    return c < 0 ? null : c;
  };

  // ---- DNS / mDNS / LLMNR / NBNS transactions
  onProgress?.('Correlating DNS transactions');
  const dns = correlateDns(raw.dns, raw.nbns, pkt, segs, convOfFrame);
  for (const d of dns) if (d.convId !== null) convs[d.convId].records.dns++;

  // ---- HTTP
  onProgress?.('Pairing HTTP requests and responses');
  const http: HttpExchange[] = [];
  const pendingHttp = new Map<number, HttpExchange[]>();
  const pendingHttp2 = new Map<string, HttpExchange[]>();
  const requestExchangeByFrame = new Map<number, HttpExchange[]>();
  const requestByResponseFrame = new Map<number, number[]>();
  const http2Key = (stream: number, id: number) => `${stream}:${id}`;
  for (const h of raw.http) {
    if (h.kind === 'req' && h.responseIn !== null) {
      const frames = requestByResponseFrame.get(h.responseIn) ?? [];
      if (!frames.includes(h.frame)) frames.push(h.frame);
      requestByResponseFrame.set(h.responseIn, frames);
    }
  }
  for (const h of raw.http) {
    const p = pkt(h.frame);
    if (!p) continue;
    const convId = convOfFrame(h.frame);
    const stream = p.tcpStream;
    const frames = segs(h.frame);
    if (h.kind === 'req') {
      const ex: HttpExchange = {
        id: http.length, stream, http2StreamId: h.http2StreamId, convId, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        method: h.method, host: h.host, uri: h.uri, version: h.version, userAgent: h.userAgent, requestHeaders: h.headers,
        requestFrame: h.frame, requestTime: p.t, requestContentType: h.contentType, status: null, phrase: null,
        responseVersion: null, responseHeaders: [], contentType: null, contentLength: null, serverHeader: null,
        location: null, responseFrame: null, responseTime: null, state: 'no response seen', pairingWarning: null, frames: [...frames],
      };
      http.push(ex);
      const sameFrame = requestExchangeByFrame.get(h.frame) ?? [];
      sameFrame.push(ex);
      requestExchangeByFrame.set(h.frame, sameFrame);
      if (stream !== null) {
        const q = h.http2StreamId === null
          ? pendingHttp.get(stream) ?? []
          : pendingHttp2.get(http2Key(stream, h.http2StreamId)) ?? [];
        q.push(ex);
        if (h.http2StreamId === null) pendingHttp.set(stream, q);
        else pendingHttp2.set(http2Key(stream, h.http2StreamId), q);
      }
    } else {
      // 1xx interim responses (except 101 Switching Protocols) do not complete a request.
      const interim = h.code !== null && h.code >= 100 && h.code < 200 && h.code !== 101;
      const q = stream === null ? undefined : h.http2StreamId === null
        ? pendingHttp.get(stream)
        : pendingHttp2.get(http2Key(stream, h.http2StreamId));
      const fifoCandidate = q?.[0];
      const reverseLinks = requestByResponseFrame.get(h.frame) ?? [];
      const linkedFrames = h.requestIn === null ? reverseLinks : [h.requestIn];
      const linkedExchange = linkedFrames
        .flatMap((frame) => requestExchangeByFrame.get(frame) ?? [])
        .find((candidate) => candidate.responseFrame === null
          && (stream === null || candidate.stream === stream)
          && candidate.http2StreamId === h.http2StreamId);
      const linkedFrame = h.requestIn ?? linkedExchange?.requestFrame ?? reverseLinks[0] ?? null;
      let ex: HttpExchange | undefined = linkedFrame === null ? fifoCandidate : linkedExchange;
      const pairingWarnings: string[] = [];
      if (h.requestIn !== null && reverseLinks.length > 0 && !reverseLinks.includes(h.requestIn)) {
        pairingWarnings.push(`Wireshark's request_in link points to packet ${h.requestIn}, but the request's response_in link points to packet${reverseLinks.length === 1 ? '' : 's'} ${reverseLinks.join(', ')}.`);
      }
      if (linkedFrame !== null && !ex) {
        pairingWarnings.push(`Wireshark links this response to request packet ${linkedFrame}, which is not an available request in the matching stream.`);
      }
      if (linkedFrame !== null && ex && fifoCandidate && ex !== fifoCandidate) {
        pairingWarnings.push(`Wireshark links this response to request packet ${ex.requestFrame}, while stream-order pairing would use packet ${fifoCandidate.requestFrame}.`);
      }
      if (ex && pairingWarnings.length) {
        ex.pairingWarning = [...new Set([...(ex.pairingWarning ? [ex.pairingWarning] : []), ...pairingWarnings])].join(' ');
      }
      if (!ex || interim) {
        if (interim && ex) {
          ex.frames.push(...frames);
          continue;
        }
        ex = {
          id: http.length, stream, http2StreamId: h.http2StreamId, convId, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
          method: null, host: null, uri: null, version: null, userAgent: null, requestHeaders: [], requestFrame: null,
          requestTime: null, requestContentType: null, status: null, phrase: null, responseVersion: null, responseHeaders: [],
          contentType: null, contentLength: null, serverHeader: null, location: null, responseFrame: null, responseTime: null,
          state: 'response without request', pairingWarning: pairingWarnings.length ? pairingWarnings.join(' ') : null, frames: [],
        };
        http.push(ex);
      } else {
        ex.state = 'complete';
        if (q) {
          const pairedIndex = q.indexOf(ex);
          if (pairedIndex >= 0) q.splice(pairedIndex, 1);
        }
      }
      ex.status = h.code;
      ex.phrase = h.phrase;
      ex.responseVersion = h.version;
      ex.responseHeaders = h.headers;
      ex.contentType = h.contentType;
      ex.contentLength = h.contentLength;
      ex.serverHeader = h.server;
      ex.location = h.location;
      ex.responseFrame = h.frame;
      ex.responseTime = p.t;
      ex.frames.push(...frames);
    }
  }
  for (const h of http) {
    h.frames = [...new Set(h.frames)].sort((a, b) => a - b);
    if (h.convId !== null) convs[h.convId].records.http++;
  }

  // ---- TLS
  onProgress?.('Reading TLS handshakes');
  const tls: TlsSession[] = [];
  const tlsByConv = new Map<number, TlsSession>();
  for (const t of raw.tls) {
    const p = pkt(t.frame);
    if (!p) continue;
    const convId = convOfFrame(t.frame);
    const frames = segs(t.frame);
    const carrier = t.carrier === 'quic' ? 'QUIC' : 'TCP';
    const stream = carrier === 'QUIC' ? p.udpStream : p.tcpStream;
    let s = convId !== null ? tlsByConv.get(convId) : undefined;
    if (t.type === 1) {
      s = {
        id: tls.length, carrier, stream, convId, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        sni: t.sni, clientHelloFrame: t.frame, clientHelloTime: p.t,
        offered: { legacyVersion: t.version, supportedVersions: t.supportedVersions, alpn: t.alpn, cipherSuites: t.ciphers },
        serverHelloFrame: null, negotiated: null, certificates: [], certificateStatus: 'not observed', frames: [...frames],
      };
      tls.push(s);
      if (convId !== null) tlsByConv.set(convId, s);
      continue;
    }
    if (!s) {
      s = {
        id: tls.length, carrier, stream, convId, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
        sni: null, clientHelloFrame: null, clientHelloTime: null, offered: null, serverHelloFrame: null, negotiated: null,
        certificates: [], certificateStatus: 'not observed', frames: [],
      };
      tls.push(s);
      if (convId !== null) tlsByConv.set(convId, s);
    }
    s.frames.push(...frames);
    if (t.type === 2) {
      const viaExt = t.supportedVersions.length > 0;
      s.serverHelloFrame = t.frame;
      s.negotiated = {
        version: viaExt ? t.supportedVersions[0] : t.version,
        versionSource: viaExt ? 'supported_versions extension' : 'ServerHello version field',
        alpn: t.alpn[0] ?? null,
        cipherSuite: t.ciphers[0] ?? null,
      };
    } else if (t.type === 11) {
      for (const hex of t.certs) {
        const der = hexToBytes(hex);
        const cert = parseCertificate(der, t.frame, s.certificates.length);
        cert.sha256 = await fingerprint(der);
        s.certificates.push(cert);
      }
    }
  }
  for (const s of tls) {
    s.frames = [...new Set(s.frames)].sort((a, b) => a - b);
    if (s.certificates.length) s.certificateStatus = 'decoded';
    else if (s.negotiated?.version?.includes('1.3') || s.carrier === 'QUIC') s.certificateStatus = 'encrypted (TLS 1.3)';
    if (s.convId !== null) convs[s.convId].records.tls++;
  }

  // ---- hosts
  onProgress?.('Building host inventory');
  interface HostAcc extends Host { _peers: Set<string>; _macs: Map<string, number>; _protos: Set<string>; _clientPorts: Set<number>; _convs: Set<number> }
  const hosts = new Map<string, HostAcc>();
  const host = (addr: string, t: number): HostAcc => {
    let h = hosts.get(addr);
    if (!h) {
      h = {
        addr, ipVersion: addr.includes(':') ? 6 : 4, scope: addressScope(addr), macs: [], arpMacs: [], txPackets: 0,
        txBytes: 0, rxPackets: 0, rxBytes: 0, peers: 0, conversations: 0, firstSeen: t, lastSeen: t, names: [],
        servicePorts: [], clientPortCount: 0, protocols: [],
        _peers: new Set(), _macs: new Map(), _protos: new Set(), _clientPorts: new Set(), _convs: new Set(),
      };
      hosts.set(addr, h);
    }
    if (t < h.firstSeen) h.firstSeen = t;
    if (t > h.lastSeen) h.lastSeen = t;
    return h;
  };
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    if (!p.src || !p.dst) continue;
    const s = host(p.src, p.t);
    const d = host(p.dst, p.t);
    s.txPackets++; s.txBytes += p.len;
    d.rxPackets++; d.rxBytes += p.len;
    s._peers.add(p.dst); d._peers.add(p.src);
    if (p.ethSrc) s._macs.set(p.ethSrc, (s._macs.get(p.ethSrc) ?? 0) + 1);
    s._protos.add(topOf[i]); d._protos.add(topOf[i]);
    // The subnet is not in the capture, but an IPv4 packet sent to the Ethernet
    // broadcast MAC shows its destination is a (subnet) broadcast address.
    if (p.ethDst === 'ff:ff:ff:ff:ff:ff' && d.ipVersion === 4 && d.scope !== 'unspecified') d.scope = 'broadcast';
    const c = convOf[i];
    if (c >= 0) { s._convs.add(c); d._convs.add(c); }
  }
  const svc = new Map<string, ServicePort & { _peers: Set<string> }>();
  for (const c of convs) {
    if (c.transport !== 'TCP' && c.transport !== 'UDP') continue;
    if (c.aPort === null || c.bPort === null) continue;
    let server = c.b, serverPort = c.bPort, client = c.a, clientPort = c.aPort;
    let evidence: ServicePort['evidence'];
    if (c.tcp) {
      if (c.initiator === 'SYN') {
        evidence = c.tcp.synAckSeen ? (c.packetsAB >= 2 ? 'handshake completed' : 'SYN-ACK sent') : 'SYN received, no SYN-ACK seen';
      } else {
        evidence = 'mid-stream traffic';
        if (c.aPort < c.bPort) { server = c.a; serverPort = c.aPort; client = c.b; clientPort = c.bPort; }
      }
    } else {
      evidence = 'UDP traffic received';
    }
    if (isGroupAddress(server)) continue;
    const h = hosts.get(server);
    if (!h) continue;
    const key = server + '|' + c.transport + '|' + serverPort;
    let sp = svc.get(key);
    if (!sp) {
      sp = { transport: c.transport, port: serverPort, evidence, conversations: 0, peers: 0, _peers: new Set() };
      svc.set(key, sp);
      h.servicePorts.push(sp);
    }
    const rank = ['handshake completed', 'SYN-ACK sent', 'UDP traffic received', 'mid-stream traffic', 'SYN received, no SYN-ACK seen'];
    if (rank.indexOf(evidence) < rank.indexOf(sp.evidence)) sp.evidence = evidence;
    sp.conversations++;
    sp._peers.add(client);
    hosts.get(client)?._clientPorts.add(clientPort);
  }

  // ---- learned names
  onProgress?.('Collecting names learned from the capture');
  const addName = (addr: string, name: string, source: NameSource, kind: LearnedName['kind'], frame: number) => {
    const h = hosts.get(addr);
    if (!h || !name) return;
    const clean = name.replace(/\.$/, '');
    if (h.names.some((n) => n.name === clean && n.source === source)) return;
    h.names.push({ name: clean, source, kind, frame });
  };
  for (const d of dns) {
    if (d.proto === 'NBNS') {
      if (d.responseFrame !== null) {
        for (const a of d.answers) if (a.value) for (const ip of a.value.split(', ')) addName(ip, a.name, 'NBNS', 'observed', d.responseFrame);
      }
      continue;
    }
    const frame = d.responseFrame;
    if (frame === null) continue;
    const src: NameSource = d.proto === 'mDNS' ? 'mDNS' : d.proto === 'LLMNR' ? 'LLMNR' : 'DNS answer';
    for (const a of d.answers) {
      if (a.type !== 'A' && a.type !== 'AAAA') continue;
      addName(a.value, a.name, src, 'observed', frame);
      if (src === 'DNS answer' && d.qname && d.qname !== a.name && a.section === 'answer') addName(a.value, d.qname, 'DNS answer (CNAME alias)', 'observed', frame);
    }
  }
  const macToIps = new Map<string, Set<string>>();
  for (const h of hosts.values()) for (const m of h._macs.keys()) {
    const s = macToIps.get(m) ?? new Set();
    s.add(h.addr);
    macToIps.set(m, s);
  }
  for (const d of raw.dhcp) {
    if (!d.hostname) continue;
    const ip = d.yourIp && d.yourIp !== '0.0.0.0' ? d.yourIp : d.requestedIp;
    if (ip) addName(ip, d.hostname, 'DHCP host name', 'observed', d.frame);
    else for (const a of macToIps.get(d.mac) ?? []) addName(a, d.hostname, 'DHCP host name', 'observed', d.frame);
  }
  for (const s of tls) if (s.sni && s.clientHelloFrame !== null) addName(s.server, s.sni, 'TLS SNI', 'inferred', s.clientHelloFrame);
  for (const h of http) if (h.host && h.requestFrame !== null) addName(h.server, h.host.replace(/:\d+$/, ''), 'HTTP Host header', 'inferred', h.requestFrame);

  // ---- DHCP, ARP, ICMP, SSH, QUIC
  onProgress?.('Reading DHCP, ARP, ICMP, SSH and QUIC');
  const pctx: ProtoCtx = { packets, convOf, pkt, convOfFrame, conversations: convs, tls };
  const { arp, bindings: arpBindings } = buildArp(raw.arp, pctx);
  const dhcp = buildDhcp(raw.dhcp, pctx);
  const icmp = buildIcmp(raw.icmp, pctx);
  const ssh = buildSsh(raw.ssh, pctx);
  const quic = buildQuic(raw.quic, pctx);
  for (const a of arp) {
    if (a.ip === '0.0.0.0') continue;
    const h = hosts.get(a.ip);
    if (h && a.mac && !h.arpMacs.includes(a.mac)) h.arpMacs.push(a.mac);
  }

  const hostList: Host[] = [...hosts.values()].map((h) => {
    const { _peers, _macs, _protos, _clientPorts, _convs, ...rest } = h;
    return {
      ...rest,
      peers: _peers.size,
      conversations: _convs.size,
      macs: [..._macs.entries()].sort((a, b) => b[1] - a[1]).map(([mac, packets]) => {
        const v = raw.macVendors.get(mac);
        return { mac, packets, vendor: v?.vendor ?? null, locallyAdministered: v?.locallyAdministered ?? false };
      }),
      protocols: [..._protos].sort(),
      clientPortCount: _clientPorts.size,
      servicePorts: rest.servicePorts
        .map((sp) => {
          const { _peers: peers, ...r } = sp as ServicePort & { _peers: Set<string> };
          return { ...r, peers: peers.size };
        })
        .sort((a, b) => a.port - b.port),
    };
  });
  hostList.sort((a, b) => b.txBytes + b.rxBytes - (a.txBytes + a.rxBytes));

  // ---- timeline
  onProgress?.('Building timeline');
  // Timestamps are not guaranteed to be monotonic, so bin from the earliest one.
  let minT = 0, maxT = 0;
  for (const p of packets) { if (p.t < minT) minT = p.t; if (p.t > maxT) maxT = p.t; }
  const duration = maxT - minT;
  const binSeconds = pickBin(Math.max(duration, 1e-3));
  const bins = Math.max(1, Math.floor(duration / binSeconds) + 1);
  const topList = [...top.values()].sort((a, b) => b.bytes - a.bytes);
  const seriesKeys = topList.slice(0, 6).map((s) => s.proto);
  const seriesIdx = new Map(seriesKeys.map((k, i) => [k, i]));
  const series = [...seriesKeys, 'Other'].map((key) => ({ key, packets: new Array(bins).fill(0), bytes: new Array(bins).fill(0) }));
  const total = { key: 'All', packets: new Array(bins).fill(0), bytes: new Array(bins).fill(0) };
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    const b = Math.min(bins - 1, Math.max(0, Math.floor((p.t - minT) / binSeconds)));
    const si = seriesIdx.get(topOf[i]) ?? seriesKeys.length;
    series[si].packets[b]++;
    series[si].bytes[b] += p.len;
    total.packets[b]++;
    total.bytes[b] += p.len;
  }
  const timeline: Timeline = { origin: minT, binSeconds, bins, series: [total, ...series.filter((s) => s.packets.some((x) => x > 0))] };

  // ---- unsupported / encrypted context
  const HTTP_PORTS = new Set([80, 8080, 8000, 8008, 8888, 3128]);
  const unsupported = {
    httpPortsUndecoded: convs.filter((c) => c.tcp && c.records.http === 0 && (HTTP_PORTS.has(c.bPort ?? -1) || HTTP_PORTS.has(c.aPort ?? -1))
      && c.tcp.payloadBytesAB + c.tcp.payloadBytesBA > 0 && !c.protocols.includes('TLS')).map((c) => c.id),
    encryptedConversations: convs.filter((c) => c.protocols.includes('TLS') || c.protocols.includes('QUIC')).length,
    quicConversations: convs.filter((c) => c.protocols.includes('QUIC')).length,
    http2Packets: http2,
    httpWithGaps: convs.filter((c) => c.records.http > 0 && ((c.tcp?.lostSegments ?? 0) > 0 || c.truncatedPackets > 0)).map((c) => c.id),
  };

  const ifaceInfo = raw.ifaces.map((f) => ({ id: f.id, linkType: f.linkType, name: f.name, packets: ifaceCount.get(f.id) ?? 0 }));
  const capture: CaptureInfo = {
    fileName: meta.fileName, fileSize: meta.fileSize, fileType: meta.fileType, linkType: meta.linkType,
    packetCount: packets.length, startEpoch: raw.startEpoch, duration, timestampDigits: raw.timestampDigits, nonMonotonicTimestamps: backwards,
    interfaces: ifaceInfo, wireBytes: wire, capturedBytes: captured, truncatedPackets: truncated,
    malformedPackets: malformed, expertErrorPackets: expert, fragmentPackets: frags, retransmissions: retrans,
    outOfOrder: ooo, lostSegments: lost, duplicateAcks: dupack, incomplete: meta.incomplete,
    warnings: [...meta.warnings, ...raw.warnings], engine: meta.engine, analysisMs: 0,
  };
  const model: AnalysisModel = {
    capture,
    protocolHierarchy: [...hier.values()].sort((a, b) => b.packets - a.packets),
    topProtocols: topList,
    timeline, hosts: hostList, conversations: convs, dns, http, tls, arp, arpBindings, dhcp, icmp, ssh, quic, unsupported,
  };
  capture.analysisMs = Math.round(performance.now() - t0);
  return { model, index: { packets, convOf } };
}

// ------------------------------------------------------- DNS correlation
interface DnsMsg {
  proto: DnsProto;
  frame: number;
  isResponse: boolean;
  txid: number | null;
  opcode: number | null;
  rcode: number | null;
  qname: string | null;
  qtype: string | null;
  answers: DnsAnswer[];
  truncatedFlag: boolean;
}

/** A response is matched to a query only within this window (seconds). */
export const DNS_MATCH_WINDOW = 60;

function correlateDns(
  rawDns: RawDns[], rawNbns: RawNbns[], pkt: (f: number) => RawPacket | undefined, segs: (f: number) => number[],
  convOfFrame: (f: number) => number | null,
): DnsTransaction[] {
  const msgs: DnsMsg[] = [];
  const sectionName = (s: string): DnsAnswer['section'] => (s === 'an' ? 'answer' : s === 'ns' ? 'authority' : 'additional');
  for (const d of rawDns) {
    msgs.push({
      proto: d.proto === 'mdns' ? 'mDNS' : d.proto === 'llmnr' ? 'LLMNR' : 'DNS',
      frame: d.frame, isResponse: d.isResponse, txid: d.id, opcode: d.opcode, rcode: d.isResponse ? d.rcode : null,
      qname: d.qname, qtype: shortType(d.qtype),
      answers: d.rrs.filter((r) => !/^OPT\b/.test(r.type)).map((r) => ({ section: sectionName(r.section), name: r.name, type: shortType(r.type) ?? '', ttl: r.ttl, value: r.value })),
      truncatedFlag: d.truncated,
    });
  }
  for (const n of rawNbns) {
    const name = n.names[0]?.replace(/\s*\(.*\)$/, '') ?? null;
    msgs.push({
      proto: 'NBNS', frame: n.frame, isResponse: n.isResponse, txid: n.id, opcode: n.opcode,
      rcode: n.isResponse ? n.rcode : null, qname: name, qtype: shortType(n.qtype),
      answers: n.isResponse && n.addrs.length ? [{ section: 'answer', name: name ?? '', type: 'NB', ttl: null, value: n.addrs.join(', ') }] : [],
      truncatedFlag: false,
    });
  }
  msgs.sort((a, b) => a.frame - b.frame);

  const out: DnsTransaction[] = [];
  const pending = new Map<string, DnsTransaction[]>();
  const answered = new Map<string, DnsTransaction>();
  for (const m of msgs) {
    const p = pkt(m.frame);
    if (!p) continue;
    const transport: 'UDP' | 'TCP' = hasProto(p.protos, 'tcp') ? 'TCP' : 'UDP';
    const malformed = p.flags.includes('M');
    const base = {
      proto: m.proto, transport, convId: convOfFrame(m.frame), txid: m.txid, qname: m.qname, qtype: m.qtype,
      opcode: m.opcode, truncatedFlag: m.truncatedFlag, malformed,
    };
    if (m.proto === 'mDNS') {
      out.push({
        ...base, id: out.length, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        queryFrame: m.isResponse ? null : m.frame, queryTime: m.isResponse ? null : p.t,
        responseFrame: m.isResponse ? m.frame : null, responseTime: m.isResponse ? p.t : null, rtt: null,
        rcode: rcodeName(m.proto, m.rcode), answers: m.answers, status: m.isResponse ? 'multicast response' : 'multicast query',
        relatedTo: null, frames: segs(m.frame),
      });
      continue;
    }
    if (!m.isResponse) {
      const key = [m.proto, transport, p.src, p.sport, m.txid].join('|');
      const list = pending.get(key) ?? [];
      const original = list.find((q) => q.qname === m.qname && q.qtype === m.qtype && q.server === p.dst && q.status === 'unanswered');
      const tx: DnsTransaction = {
        ...base, id: out.length, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        queryFrame: m.frame, queryTime: p.t, responseFrame: null, responseTime: null, rtt: null, rcode: null,
        answers: [], status: original ? 'retransmitted' : 'unanswered', relatedTo: original ? original.id : null,
        frames: segs(m.frame),
      };
      out.push(tx);
      if (!original) {
        list.push(tx);
        pending.set(key, list);
      }
      continue;
    }
    // response: the client is the destination
    const key = [m.proto, transport, p.dst, p.dport, m.txid].join('|');
    const list = pending.get(key);
    let idx = -1;
    if (list) {
      idx = list.findIndex((q) => (q.server === p.src || isGroupAddress(q.server))
        && q.queryTime !== null && q.queryTime <= p.t && p.t - q.queryTime <= DNS_MATCH_WINDOW);
    }
    if (idx >= 0) {
      const tx = list![idx];
      list!.splice(idx, 1);
      tx.responseFrame = m.frame;
      tx.responseTime = p.t;
      tx.rtt = p.t - (tx.queryTime ?? p.t);
      tx.rcode = rcodeName(m.proto, m.rcode);
      tx.answers = m.answers;
      tx.status = 'answered';
      tx.malformed = tx.malformed || malformed;
      tx.truncatedFlag = m.truncatedFlag;
      if (isGroupAddress(tx.server)) { tx.server = p.src; tx.serverPort = p.sport; }
      tx.frames = [...new Set([...tx.frames, ...segs(m.frame)])].sort((a, b) => a - b);
      answered.set(key, tx);
      continue;
    }
    const prev = answered.get(key);
    const dup = prev && prev.qname === m.qname && prev.server === p.src && prev.responseTime !== null && p.t - prev.responseTime <= DNS_MATCH_WINDOW;
    out.push({
      ...base, id: out.length, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
      queryFrame: null, queryTime: null, responseFrame: m.frame, responseTime: p.t, rtt: null,
      rcode: rcodeName(m.proto, m.rcode), answers: m.answers,
      status: dup ? 'duplicate response' : 'response without query', relatedTo: dup ? prev!.id : null,
      frames: segs(m.frame),
    });
  }
  return out;
}
