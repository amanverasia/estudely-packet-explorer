// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Builds host inventory and the protocol records associated with each host.
import type {
  ArpBinding, ArpRecord, Conversation, DnsTransaction, DhcpExchange, Host, HttpExchange, IcmpMessage, LearnedName, NameSource,
  QuicConnection, SshSession, TlsSession,
} from './types';
import type { RawPacket, RawRecords } from './records';
import { addressScope, isGloballyReachable } from './address-scope';
import { buildArp, buildDhcp, buildIcmp, buildQuic, buildSsh, type ProtoCtx } from './protocols';
import { isGroupAddress } from './analysis-utils';

export interface HostAggregation {
  hosts: Host[];
  arp: ArpRecord[];
  arpBindings: ArpBinding[];
  dhcp: DhcpExchange[];
  icmp: IcmpMessage[];
  ssh: SshSession[];
  quic: QuicConnection[];
}

export function aggregateHosts(
  raw: RawRecords, packets: RawPacket[], topOf: string[], convOf: Int32Array, convOfFrame: (frame: number) => number | null,
  conversations: Conversation[], dns: DnsTransaction[], http: HttpExchange[], tls: TlsSession[],
  pkt: (frame: number) => RawPacket | undefined, onProgress?: (message: string) => void,
): HostAggregation {
  onProgress?.('Building host inventory');
  interface HostAcc extends Host { _peers: Set<string>; _macs: Map<string, number>; _protos: Set<string>; _clientPorts: Set<number>; _convs: Set<number> }
  const hosts = new Map<string, HostAcc>();
  const host = (addr: string, t: number): HostAcc => {
    let h = hosts.get(addr);
    if (!h) {
      h = {
        addr, ipVersion: addr.includes(':') ? 6 : 4, scope: addressScope(addr), globallyReachable: isGloballyReachable(addr),
        macs: [], arpMacs: [], txPackets: 0,
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
    if (p.ethDst === 'ff:ff:ff:ff:ff:ff' && d.ipVersion === 4 && d.scope !== 'unspecified') {
      d.scope = 'broadcast';
      d.globallyReachable = false;
    }
    const c = convOf[i];
    if (c >= 0) { s._convs.add(c); d._convs.add(c); }
  }
  const svc = new Map<string, import('./types').ServicePort & { _peers: Set<string> }>();
  for (const c of conversations) {
    if (c.transport !== 'TCP' && c.transport !== 'UDP') continue;
    if (c.aPort === null || c.bPort === null) continue;
    let server = c.b, serverPort = c.bPort, client = c.a, clientPort = c.aPort;
    let evidence: import('./types').ServicePort['evidence'];
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
    const source: NameSource = d.proto === 'mDNS' ? 'mDNS' : d.proto === 'LLMNR' ? 'LLMNR' : 'DNS answer';
    for (const a of d.answers) {
      if (a.type !== 'A' && a.type !== 'AAAA') continue;
      addName(a.value, a.name, source, 'observed', frame);
      if (source === 'DNS answer' && d.qname && d.qname !== a.name && a.section === 'answer') addName(a.value, d.qname, 'DNS answer (CNAME alias)', 'observed', frame);
    }
  }
  const macToIps = new Map<string, Set<string>>();
  for (const h of hosts.values()) for (const mac of h._macs.keys()) {
    const addresses = macToIps.get(mac) ?? new Set();
    addresses.add(h.addr);
    macToIps.set(mac, addresses);
  }
  for (const d of raw.dhcp) {
    if (!d.hostname) continue;
    const ip = d.yourIp && d.yourIp !== '0.0.0.0' ? d.yourIp : d.requestedIp;
    if (ip) addName(ip, d.hostname, 'DHCP host name', 'observed', d.frame);
    else for (const addr of macToIps.get(d.mac) ?? []) addName(addr, d.hostname, 'DHCP host name', 'observed', d.frame);
  }
  for (const session of tls) if (session.sni && session.clientHelloFrame !== null) addName(session.server, session.sni, 'TLS SNI', 'inferred', session.clientHelloFrame);
  for (const exchange of http) if (exchange.host && exchange.requestFrame !== null) addName(exchange.server, exchange.host.replace(/:\d+$/, ''), 'HTTP Host header', 'inferred', exchange.requestFrame);

  onProgress?.('Reading DHCP, ARP, ICMP, SSH and QUIC');
  const pctx: ProtoCtx = { packets, convOf, pkt, convOfFrame, conversations, tls };
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
      macs: [..._macs.entries()].sort((a, b) => b[1] - a[1]).map(([mac, packetsSeen]) => {
        const vendor = raw.macVendors.get(mac);
        return { mac, packets: packetsSeen, vendor: vendor?.vendor ?? null, locallyAdministered: vendor?.locallyAdministered ?? false };
      }),
      protocols: [..._protos].sort(),
      clientPortCount: _clientPorts.size,
      servicePorts: rest.servicePorts
        .map((sp) => {
          const { _peers: peers, ...servicePort } = sp as import('./types').ServicePort & { _peers: Set<string> };
          return { ...servicePort, peers: peers.size };
        })
        .sort((a, b) => a.port - b.port),
    };
  });
  hostList.sort((a, b) => b.txBytes + b.rxBytes - (a.txBytes + a.rxBytes));
  return { hosts: hostList, arp, arpBindings, dhcp, icmp, ssh, quic };
}
