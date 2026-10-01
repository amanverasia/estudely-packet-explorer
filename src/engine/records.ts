// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Parses the tab-separated output of extractor.lua into typed raw records.
// Lines are decoded incrementally from the byte buffer so a large output
// never has to exist as one giant JS string.

export interface RawPacket {
  frame: number;
  /** seconds relative to the first packet */
  t: number;
  len: number;
  caplen: number;
  iface: number | null;
  protos: string;
  ethSrc: string;
  ethDst: string;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  tcpStream: number | null;
  udpStream: number | null;
  tcpFlags: number | null;
  tcpLen: number | null;
  flags: string;
}

export interface RawDns {
  frame: number;
  proto: 'dns' | 'mdns' | 'llmnr';
  id: number | null;
  isResponse: boolean;
  opcode: number | null;
  rcode: number | null;
  qname: string | null;
  qtype: string | null;
  qclass: string | null;
  ancount: number | null;
  rrs: { section: string; name: string; type: string; ttl: number | null; value: string }[];
  truncated: boolean;
}

export interface RawNbns {
  frame: number;
  id: number | null;
  isResponse: boolean;
  opcode: number | null;
  rcode: number | null;
  names: string[];
  addrs: string[];
  qtype: string | null;
}

export interface RawHttp {
  frame: number;
  kind: 'req' | 'resp';
  method: string | null;
  uri: string | null;
  version: string | null;
  host: string | null;
  userAgent: string | null;
  code: number | null;
  phrase: string | null;
  contentType: string | null;
  contentLength: string | null;
  headers: string[];
  server: string | null;
  location: string | null;
}

export interface RawTls {
  frame: number;
  carrier: 'tcp' | 'quic';
  type: number;
  version: string | null;
  sni: string | null;
  alpn: string[];
  supportedVersions: string[];
  ciphers: string[];
  certs: string[];
  recordVersion: string | null;
}

export interface RawArp {
  frame: number;
  opcode: number | null;
  srcMac: string;
  srcIp: string;
  dstMac: string;
  dstIp: string;
}

export interface RawDhcp {
  frame: number;
  msgType: number | null;
  mac: string;
  hostname: string | null;
  yourIp: string | null;
  requestedIp: string | null;
  xid: number | null;
  serverId: string | null;
  leaseTime: number | null;
  subnetMask: string | null;
  routers: string[];
  dnsServers: string[];
}

export interface RawIcmp {
  frame: number;
  version: 4 | 6;
  type: number;
  code: number | null;
  typeName: string | null;
  codeName: string | null;
  ident: number | null;
  seq: number | null;
  /** The packet quoted by an error message (from its inner IP header), when present. */
  quoted: { protocol: string | null; src: string; dst: string; srcPort: number | null; dstPort: number | null } | null;
}

export interface RawSsh {
  frame: number;
  version: string;
  /** From Wireshark's ssh.direction; null when it was not determined. */
  fromClient: boolean | null;
}

export interface RawQuic {
  frame: number;
  versions: string[];
  /** Versions listed by a Version Negotiation packet. */
  supported: string[];
}

export interface RawIface {
  id: number | null;
  linkType: string;
  name: string;
}

export interface RawRecords {
  packets: RawPacket[];
  segments: Map<number, number[]>;
  dns: RawDns[];
  nbns: RawNbns[];
  http: RawHttp[];
  tls: RawTls[];
  arp: RawArp[];
  dhcp: RawDhcp[];
  icmp: RawIcmp[];
  ssh: RawSsh[];
  quic: RawQuic[];
  ifaces: RawIface[];
  /** Source MAC -> registered vendor (Wireshark's OUI table) and locally-administered bit. */
  macVendors: Map<string, { vendor: string | null; locallyAdministered: boolean }>;
  warnings: string[];
  startEpoch: string | null;
  timestampDigits: number;
}

const UNESC: Record<string, string> = { '\\': '\\', t: '\t', n: '\n', r: '\r', u: '\x1f' };

export function unescapeField(s: string): string {
  if (s.indexOf('\\') < 0) return s;
  return s.replace(/\\(.)/g, (_m, c: string) => UNESC[c] ?? c);
}

function str(s: string | undefined): string | null {
  if (s === undefined || s === '') return null;
  return unescapeField(s);
}

function int(s: string | undefined): number | null {
  if (s === undefined || s === '') return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function list(s: string | undefined): string[] {
  if (!s) return [];
  return s.split('\x1f').map(unescapeField);
}

function bool(s: string | undefined): boolean {
  return s === 'true' || s === '1';
}

/** Splits "1700000000.123456789" into integer seconds and the fractional digits. */
function splitEpoch(e: string): [number, string] {
  const dot = e.indexOf('.');
  if (dot < 0) return [Number(e), ''];
  return [Number(e.slice(0, dot)), e.slice(dot + 1)];
}

/** Calls fn for each line in the buffer without materialising one huge string. */
export function forEachLine(buf: Uint8Array, fn: (line: string) => void, onProgress?: (fraction: number) => void): void {
  const decoder = new TextDecoder('utf-8');
  const CHUNK = 4 * 1024 * 1024;
  let pos = 0;
  let carry = '';
  let lastReport = 0;
  while (pos < buf.length) {
    const end = Math.min(buf.length, pos + CHUNK);
    const text = carry + decoder.decode(buf.subarray(pos, end), { stream: end < buf.length });
    pos = end;
    const lines = text.split('\n');
    carry = lines.pop() ?? '';
    for (const l of lines) if (l) fn(l);
    if (onProgress && pos - lastReport > CHUNK) {
      lastReport = pos;
      onProgress(pos / buf.length);
    }
  }
  if (carry) fn(carry);
}

export function parseRecords(buf: Uint8Array, onProgress?: (fraction: number) => void): RawRecords {
  const out: RawRecords = {
    packets: [], segments: new Map(), dns: [], nbns: [], http: [], tls: [], arp: [], dhcp: [], icmp: [], ssh: [], quic: [], ifaces: [],
    macVendors: new Map(), warnings: [], startEpoch: null, timestampDigits: 0,
  };
  let baseSec = 0;
  let baseFrac = 0;
  let digits = 0;
  // Interning keeps one copy of repeated strings (addresses, protocol stacks).
  const pool = new Map<string, string>();
  const intern = (v: string | undefined): string => {
    if (!v) return '';
    const u = v.indexOf('\\') >= 0 ? unescapeField(v) : v;
    const hit = pool.get(u);
    if (hit !== undefined) return hit;
    pool.set(u, u);
    return u;
  };

  forEachLine(buf, (line) => {
    const c = line.split('\t');
    switch (c[0]) {
      case 'P': {
        const epoch = c[2];
        const [sec, fracDigits] = splitEpoch(epoch);
        const trimmed = fracDigits.replace(/0+$/, '');
        if (trimmed.length > digits) digits = trimmed.length;
        const frac = fracDigits ? Number('0.' + fracDigits) : 0;
        if (out.startEpoch === null) {
          out.startEpoch = epoch;
          baseSec = sec;
          baseFrac = frac;
        }
        out.packets.push({
          frame: Number(c[1]),
          t: sec - baseSec + (frac - baseFrac),
          len: Number(c[3]) || 0,
          caplen: Number(c[4]) || 0,
          iface: int(c[5]),
          protos: intern(c[6]),
          ethSrc: intern(c[7]),
          ethDst: intern(c[8]),
          src: intern(c[9]),
          dst: intern(c[10]),
          sport: int(c[11]),
          dport: int(c[12]),
          tcpStream: int(c[13]),
          udpStream: int(c[14]),
          tcpFlags: int(c[15]),
          tcpLen: int(c[16]),
          flags: intern(c[17]),
        });
        break;
      }
      case 'S':
        out.segments.set(Number(c[1]), list(c[2]).map(Number).filter(Number.isFinite));
        break;
      case 'D': {
        const rrs = list(c[13]).map((r) => {
          const [section, name, type, ttl, ...rest] = r.split('|');
          return { section, name, type, ttl: ttl === '' ? null : Number(ttl), value: rest.join('|') };
        });
        out.dns.push({
          frame: Number(c[1]),
          proto: (c[2] as RawDns['proto']) || 'dns',
          id: int(c[3]),
          isResponse: bool(c[4]),
          opcode: int(c[5]),
          rcode: int(c[6]),
          qname: str(c[7]),
          qtype: str(c[8]),
          qclass: str(c[9]),
          ancount: int(c[10]),
          rrs,
          truncated: bool(c[14]),
        });
        break;
      }
      case 'N':
        out.nbns.push({
          frame: Number(c[1]), id: int(c[2]), isResponse: bool(c[3]), opcode: int(c[4]), rcode: int(c[5]),
          names: list(c[6]), addrs: list(c[7]), qtype: str(c[8]),
        });
        break;
      case 'H':
        out.http.push({
          frame: Number(c[1]), kind: c[2] === 'req' ? 'req' : 'resp', method: str(c[3]), uri: str(c[4]), version: str(c[5]),
          host: str(c[6]), userAgent: str(c[7]), code: int(c[8]), phrase: str(c[9]), contentType: str(c[10]),
          contentLength: str(c[11]), headers: list(c[12]).map((h) => h.replace(/\r?\n$/, '')), server: str(c[13]),
          location: str(c[14]),
        });
        break;
      case 'T':
        out.tls.push({
          frame: Number(c[1]), carrier: c[2] === 'quic' ? 'quic' : 'tcp', type: Number(c[3]), version: str(c[4]),
          sni: str(c[5]), alpn: list(c[6]), supportedVersions: list(c[7]), ciphers: list(c[8]), certs: list(c[9]),
          recordVersion: str(c[10]),
        });
        break;
      case 'A':
        out.arp.push({ frame: Number(c[1]), opcode: int(c[2]), srcMac: c[3] ?? '', srcIp: c[4] ?? '', dstMac: c[5] ?? '', dstIp: c[6] ?? '' });
        break;
      case 'C':
        out.dhcp.push({
          frame: Number(c[1]), msgType: int(c[2]), mac: c[3] ?? '', hostname: str(c[4]), yourIp: str(c[5]), requestedIp: str(c[6]),
          xid: int(c[7]), serverId: str(c[8]), leaseTime: int(c[9]), subnetMask: str(c[10]), routers: list(c[11]), dnsServers: list(c[12]),
        });
        break;
      case 'K':
        out.icmp.push({
          frame: Number(c[1]), version: c[2] === '6' ? 6 : 4, type: Number(c[3]), code: int(c[4]), typeName: str(c[5]),
          codeName: str(c[6]), ident: int(c[7]), seq: int(c[8]),
          quoted: c[10] ? { protocol: str(c[9]), src: unescapeField(c[10]), dst: unescapeField(c[11] ?? ''), srcPort: int(c[12]), dstPort: int(c[13]) } : null,
        });
        break;
      case 'X':
        out.ssh.push({ frame: Number(c[1]), version: unescapeField(c[2] ?? ''), fromClient: c[3] === '0' ? true : c[3] === '1' ? false : null });
        break;
      case 'Q':
        out.quic.push({ frame: Number(c[1]), versions: list(c[2]), supported: list(c[3]) });
        break;
      case 'I':
        out.ifaces.push({ id: int(c[1]), linkType: str(c[2]) ?? 'unknown', name: str(c[3]) ?? '' });
        break;
      case 'V':
        out.macVendors.set(unescapeField(c[1] ?? ''), { vendor: str(c[2]), locallyAdministered: c[3] === '1' });
        break;
      case 'W':
        out.warnings.push(unescapeField(c.slice(1).join('\t')));
        break;
    }
  }, onProgress);
  out.timestampDigits = digits;
  return out;
}
