// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Aggregates the smaller protocols (DHCP, ARP, ICMP/ICMPv6, SSH, QUIC) into
// model records. Called from analyze(); pure TypeScript like the rest of it.
// Every record states what the capture showed and where; nothing is judged.
import type {
  ArpBinding, ArpRecord, Conversation, DhcpExchange, IcmpMessage, QuicConnection, SshSession, TlsSession,
} from './types';
import type { RawArp, RawDhcp, RawIcmp, RawPacket, RawQuic, RawSsh } from './records';

export interface ProtoCtx {
  packets: RawPacket[];
  convOf: Int32Array;
  pkt: (frame: number) => RawPacket | undefined;
  convOfFrame: (frame: number) => number | null;
  conversations: Conversation[];
  tls: TlsSession[];
}

const sorted = (frames: number[]) => [...new Set(frames)].sort((a, b) => a - b);

// -------------------------------------------------------------------- DHCP
const DHCP_TYPES = ['', 'Discover', 'Offer', 'Request', 'Decline', 'ACK', 'NAK', 'Release', 'Inform'];
const SERVER_TYPES = new Set([2, 5, 6]);

export function buildDhcp(raw: RawDhcp[], ctx: ProtoCtx): DhcpExchange[] {
  const out: DhcpExchange[] = [];
  const byKey = new Map<string, DhcpExchange>();
  const types = new Map<DhcpExchange, Set<string>>();
  for (const d of raw) {
    const p = ctx.pkt(d.frame);
    if (!p) continue;
    const type = d.msgType === null ? 'BOOTP' : DHCP_TYPES[d.msgType] || `type ${d.msgType}`;
    // Plain BOOTP has no message type: a reply comes from the server port.
    const fromServer = d.msgType === null ? p.sport === 67 : SERVER_TYPES.has(d.msgType);
    const key = `${d.xid}|${d.mac}`;
    let ex = byKey.get(key);
    if (!ex) {
      ex = {
        id: out.length, xid: d.xid, clientMac: d.mac, hostname: null, requestedIp: null, offeredIp: null, assignedIp: null,
        server: null, leaseTime: null, subnetMask: null, routers: [], dnsServers: [], start: p.t, messages: [],
        outcome: 'no server reply seen', frames: [],
      };
      out.push(ex);
      byKey.set(key, ex);
      types.set(ex, new Set());
    }
    ex.messages.push({ frame: d.frame, t: p.t, type, src: p.src, dst: p.dst });
    ex.frames.push(d.frame);
    types.get(ex)!.add(type);
    if (!fromServer) {
      ex.hostname = d.hostname ?? ex.hostname;
      ex.requestedIp = d.requestedIp ?? ex.requestedIp;
      continue;
    }
    ex.server = d.serverId ?? (p.src || ex.server);
    const yi = d.yourIp && d.yourIp !== '0.0.0.0' ? d.yourIp : null;
    if (type === 'Offer') ex.offeredIp = yi ?? ex.offeredIp;
    if (type === 'ACK' || type === 'BOOTP') ex.assignedIp = yi ?? ex.assignedIp;
    // Lease parameters: an ACK states what was granted, so it overrides an OFFER.
    if (type === 'ACK' || ex.leaseTime === null) ex.leaseTime = d.leaseTime ?? ex.leaseTime;
    if (type === 'ACK' || ex.subnetMask === null) ex.subnetMask = d.subnetMask ?? ex.subnetMask;
    if (type === 'ACK' || !ex.routers.length) ex.routers = d.routers.length ? d.routers : ex.routers;
    if (type === 'ACK' || !ex.dnsServers.length) ex.dnsServers = d.dnsServers.length ? d.dnsServers : ex.dnsServers;
  }
  for (const ex of out) {
    const t = types.get(ex)!;
    ex.outcome = t.has('ACK') || (t.has('BOOTP') && ex.server !== null) ? 'acknowledged'
      : t.has('NAK') ? 'refused (NAK)'
        : t.has('Offer') ? 'offered, no ACK seen'
          : t.has('Release') ? 'released'
            : t.has('Decline') ? 'declined'
              : 'no server reply seen';
    ex.frames = sorted(ex.frames);
  }
  return out;
}

// --------------------------------------------------------------------- ARP
export function buildArp(raw: RawArp[], ctx: ProtoCtx): { arp: ArpRecord[]; bindings: ArpBinding[] } {
  const arp: ArpRecord[] = raw.map((a) => ({
    frame: a.frame, t: ctx.pkt(a.frame)?.t ?? 0,
    op: a.opcode === 1 ? 'request' : a.opcode === 2 ? 'reply' : String(a.opcode),
    mac: a.srcMac, ip: a.srcIp, targetMac: a.dstMac, targetIp: a.dstIp,
    gratuitous: a.srcIp !== '' && a.srcIp === a.dstIp,
  }));
  const byIp = new Map<string, ArpBinding & { _first: number }>();
  for (const a of arp) {
    // A sender address of 0.0.0.0 (an ARP probe) states no mapping.
    if (!a.ip || a.ip === '0.0.0.0' || !a.mac) continue;
    let b = byIp.get(a.ip);
    if (!b) {
      b = { ip: a.ip, macs: [], changes: 0, periods: [], frames: [], _first: a.frame };
      byIp.set(a.ip, b);
    }
    const last = b.periods[b.periods.length - 1];
    if (last && last.mac === a.mac) {
      last.lastFrame = a.frame;
      last.lastSeen = a.t;
      last.messages++;
    } else {
      if (last) b.changes++;
      b.periods.push({ mac: a.mac, firstFrame: a.frame, lastFrame: a.frame, firstSeen: a.t, lastSeen: a.t, messages: 1 });
      if (!b.macs.includes(a.mac)) b.macs.push(a.mac);
    }
    b.frames.push(a.frame);
  }
  // Addresses whose stated MAC changed come first, then first appearance.
  const bindings = [...byIp.values()]
    .sort((x, y) => y.changes - x.changes || x._first - y._first)
    .map(({ _first, ...b }) => ({ ...b, frames: sorted(b.frames) }));
  return { arp, bindings };
}

// -------------------------------------------------------------------- ICMP
const ICMP_ERRORS: Record<4 | 6, Set<number>> = { 4: new Set([3, 4, 5, 11, 12]), 6: new Set([1, 2, 3, 4]) };
const ECHO: Record<4 | 6, [number, number]> = { 4: [8, 0], 6: [128, 129] };

// Registered type and code names (wording as in Wireshark's dissectors). The
// field displays in Lua carry only the number for ICMPv4 types and all codes.
const ICMP_TYPES: Record<4 | 6, Record<number, string>> = {
  4: {
    0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench (flow control)', 5: 'Redirect',
    8: 'Echo (ping) request', 9: 'Router advertisement', 10: 'Router solicitation', 11: 'Time-to-live exceeded',
    12: 'Parameter problem', 13: 'Timestamp request', 14: 'Timestamp reply',
  },
  6: {
    1: 'Destination Unreachable', 2: 'Packet Too Big', 3: 'Time Exceeded', 4: 'Parameter Problem',
    128: 'Echo (ping) request', 129: 'Echo (ping) reply', 133: 'Router Solicitation', 134: 'Router Advertisement',
    135: 'Neighbor Solicitation', 136: 'Neighbor Advertisement', 137: 'Redirect',
  },
};
const ICMP_CODES: Record<4 | 6, Record<number, string[]>> = {
  4: {
    3: ['Network unreachable', 'Host unreachable', 'Protocol unreachable', 'Port unreachable', 'Fragmentation needed',
      'Source route failed', 'Destination network unknown', 'Destination host unknown', 'Source host isolated',
      'Network administratively prohibited', 'Host administratively prohibited', 'Network unreachable for TOS',
      'Host unreachable for TOS', 'Communication administratively filtered', 'Host precedence violation', 'Precedence cutoff in effect'],
    5: ['Redirect for network', 'Redirect for host', 'Redirect for TOS and network', 'Redirect for TOS and host'],
    11: ['Time to live exceeded in transit', 'Fragment reassembly time exceeded'],
    12: ['Pointer indicates the error', 'Required option missing', 'Bad length'],
  },
  6: {
    1: ['No route to destination', 'Communication with destination administratively prohibited', 'Beyond scope of source address',
      'Address unreachable', 'Port unreachable', 'Source address failed ingress/egress policy', 'Reject route to destination'],
    3: ['Hop limit exceeded in transit', 'Fragment reassembly time exceeded'],
    4: ['Erroneous header field encountered', 'Unrecognized Next Header type encountered', 'Unrecognized IPv6 option encountered'],
  },
};

/** Wireshark's name when it gave one, else the registered name, else null. */
const named = (s: string | null, fallback: string | undefined) => (s && !/^\d+$/.test(s) ? s : fallback ?? null);

export function buildIcmp(raw: RawIcmp[], ctx: ProtoCtx): IcmpMessage[] {
  // Conversations by unordered 5-tuple, to link a quoted packet to its flow.
  const convIndex = new Map<string, Conversation[]>();
  const tuple = (proto: string, a: string, ap: number | null, b: string, bp: number | null) => {
    const x = `${a}|${ap}`, y = `${b}|${bp}`;
    return proto + '|' + (x < y ? x + '|' + y : y + '|' + x);
  };
  for (const c of ctx.conversations) {
    if (c.transport !== 'TCP' && c.transport !== 'UDP') continue;
    const k = tuple(c.transport, c.a, c.aPort, c.b, c.bPort);
    const l = convIndex.get(k) ?? [];
    l.push(c);
    convIndex.set(k, l);
  }
  const out: IcmpMessage[] = [];
  const pending = new Map<string, IcmpMessage[]>();
  for (const r of raw) {
    const p = ctx.pkt(r.frame);
    if (!p) continue;
    const [req, rep] = ECHO[r.version];
    const kind: IcmpMessage['kind'] = ICMP_ERRORS[r.version].has(r.type) ? 'error' : r.type === req ? 'echo request' : r.type === rep ? 'echo reply' : 'other';
    let quoted: IcmpMessage['quoted'] = null;
    if (kind === 'error' && r.quoted) {
      const q = r.quoted;
      const proto = q.protocol === 'TCP' || q.protocol === 'UDP' ? q.protocol : null;
      // The latest conversation with this 5-tuple that started before the error.
      const cands = proto ? (convIndex.get(tuple(proto, q.src, q.srcPort, q.dst, q.dstPort)) ?? []).filter((c) => c.start <= p.t) : [];
      const conv = cands.length ? cands.reduce((x, y) => (y.start >= x.start ? y : x)) : null;
      quoted = { protocol: q.protocol, src: q.src, srcPort: q.srcPort, dst: q.dst, dstPort: q.dstPort, convId: conv ? conv.id : null };
    }
    const m: IcmpMessage = {
      id: out.length, version: r.version, frame: r.frame, t: p.t, src: p.src, dst: p.dst, type: r.type, code: r.code,
      typeName: named(r.typeName, ICMP_TYPES[r.version][r.type]),
      codeName: named(r.codeName, r.code === null ? undefined : ICMP_CODES[r.version][r.type]?.[r.code]),
      kind, quoted, frames: [r.frame],
      echo: kind === 'echo request' || kind === 'echo reply'
        ? { ident: r.ident, seq: r.seq, status: kind === 'echo request' ? 'no reply seen' : 'reply without request', pairedFrame: null }
        : null,
    };
    out.push(m);
    if (kind === 'echo request') {
      const key = [r.version, p.src, p.dst, r.ident, r.seq].join('|');
      const l = pending.get(key) ?? [];
      l.push(m);
      pending.set(key, l);
    } else if (kind === 'echo reply') {
      const l = pending.get([r.version, p.dst, p.src, r.ident, r.seq].join('|'));
      const q = l?.shift();
      if (q && q.echo && m.echo) {
        q.echo.status = 'replied';
        q.echo.pairedFrame = r.frame;
        m.echo.status = 'reply';
        m.echo.pairedFrame = q.frame;
        q.frames = sorted([q.frame, r.frame]);
        m.frames = q.frames;
      }
    }
  }
  return out;
}

// --------------------------------------------------------------------- SSH
export function buildSsh(raw: RawSsh[], ctx: ProtoCtx): SshSession[] {
  const out: SshSession[] = [];
  const byConv = new Map<number | string, SshSession>();
  for (const r of raw) {
    const p = ctx.pkt(r.frame);
    if (!p) continue;
    const convId = ctx.convOfFrame(r.frame);
    const conv = convId !== null ? ctx.conversations[convId] : null;
    // Wireshark's direction; otherwise the SYN sender, otherwise the higher port, is the client.
    const fromClient = r.fromClient ?? (conv?.initiator === 'SYN' ? p.src === conv.a && p.sport === conv.aPort : (p.sport ?? 0) > (p.dport ?? 0));
    const key = convId ?? `f${r.frame}`;
    let s = byConv.get(key);
    if (!s) {
      s = {
        id: out.length, convId, stream: p.tcpStream,
        client: fromClient ? p.src : p.dst, clientPort: fromClient ? p.sport : p.dport,
        server: fromClient ? p.dst : p.src, serverPort: fromClient ? p.dport : p.sport,
        start: conv?.start ?? p.t, clientVersion: null, clientVersionFrame: null, serverVersion: null, serverVersionFrame: null, frames: [],
      };
      out.push(s);
      byConv.set(key, s);
    }
    if (fromClient && s.clientVersion === null) { s.clientVersion = r.version; s.clientVersionFrame = r.frame; }
    if (!fromClient && s.serverVersion === null) { s.serverVersion = r.version; s.serverVersionFrame = r.frame; }
    s.frames = sorted([...s.frames, r.frame]);
  }
  return out;
}

// -------------------------------------------------------------------- QUIC
/** "1 (0x00000001)" stays; Version Negotiation packets carry version 0 and are not a version in use. */
const isVersionNegotiation = (v: string) => /^Version Negotiation\b/.test(v) || /\(0x00000000\)/.test(v);

export function buildQuic(raw: RawQuic[], ctx: ProtoCtx): QuicConnection[] {
  const out: QuicConnection[] = [];
  const byConv = new Map<number | string, QuicConnection>();
  const quicPackets = new Map<number, number>();
  for (let i = 0; i < ctx.packets.length; i++) {
    const c = ctx.convOf[i];
    if (c >= 0 && (':' + ctx.packets[i].protos + ':').includes(':quic:')) quicPackets.set(c, (quicPackets.get(c) ?? 0) + 1);
  }
  for (const r of raw) {
    const p = ctx.pkt(r.frame);
    if (!p) continue;
    const convId = ctx.convOfFrame(r.frame);
    const conv = convId !== null ? ctx.conversations[convId] : null;
    const key = convId ?? `f${r.frame}`;
    let q = byConv.get(key);
    if (!q) {
      const hello = convId !== null ? ctx.tls.find((t) => t.carrier === 'QUIC' && t.convId === convId && t.clientHelloFrame !== null) : undefined;
      // The ClientHello sender is the client; without one, the conversation's first sender.
      const client = hello ? { a: hello.client, ap: hello.clientPort, b: hello.server, bp: hello.serverPort }
        : conv ? { a: conv.a, ap: conv.aPort, b: conv.b, bp: conv.bPort }
          : { a: p.src, ap: p.sport, b: p.dst, bp: p.dport };
      q = {
        id: out.length, convId, stream: p.udpStream, client: client.a, clientPort: client.ap, server: client.b, serverPort: client.bp,
        start: conv?.start ?? p.t, versions: [], versionNegotiation: null, sni: hello?.sni ?? null, alpn: hello?.offered?.alpn ?? [],
        clientHelloFrame: hello?.clientHelloFrame ?? null, packets: convId !== null ? quicPackets.get(convId) ?? 0 : 1, frames: [],
      };
      out.push(q);
      byConv.set(key, q);
    }
    for (const v of r.versions) if (!isVersionNegotiation(v) && !q.versions.includes(v)) q.versions.push(v);
    if (r.supported.length) q.versionNegotiation = [...new Set([...(q.versionNegotiation ?? []), ...r.supported])];
    q.frames.push(r.frame);
  }
  for (const q of out) q.frames = sorted(q.frames);
  return out;
}
