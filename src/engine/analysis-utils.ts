// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Shared helpers used by the focused aggregation modules.
import { addressScope } from './address-scope';

export const PAYLOAD_PROTOS = new Set([
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
  ldap: 'LDAP', data: 'Data', gre: 'GRE', esp: 'ESP', isakmp: 'ISAKMP', wg: 'WireGuard', dtls: 'DTLS',
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

export function hasProto(protos: string, name: string): boolean {
  return (':' + protos + ':').includes(':' + name + ':');
}

export function isGroupAddress(addr: string): boolean {
  const scope = addressScope(addr);
  return scope === 'multicast' || scope === 'broadcast' || /\.255$/.test(addr);
}

const NICE_BINS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400];

export function pickBin(duration: number, target = 150): number {
  const want = duration / target;
  for (const bin of NICE_BINS) if (bin >= want) return bin;
  return Math.ceil(want / 86400) * 86400;
}
