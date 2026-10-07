// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Packet-level counters and conversation grouping.
import type { Conversation, ProtoStat, Transport } from './types';
import type { RawPacket } from './records';
import { hasProto, PAYLOAD_PROTOS, protoName, topProtocol } from './analysis-utils';

export interface PacketSummary {
  hierarchy: Map<string, ProtoStat>;
  top: Map<string, ProtoStat>;
  topOf: string[];
  ifaceCount: Map<number | null, number>;
  backwards: number;
  wire: number;
  captured: number;
  truncated: number;
  malformed: number;
  expert: number;
  fragments: number;
  retransmissions: number;
  outOfOrder: number;
  lost: number;
  duplicateAcks: number;
  http2: number;
}

export function summarizePackets(packets: RawPacket[]): PacketSummary {
  const hierarchy = new Map<string, ProtoStat>();
  const top = new Map<string, ProtoStat>();
  const topOf: string[] = new Array(packets.length);
  const ifaceCount = new Map<number | null, number>();
  let backwards = 0;
  let wire = 0, captured = 0, truncated = 0, malformed = 0, expert = 0, fragments = 0, retransmissions = 0, outOfOrder = 0, lost = 0, duplicateAcks = 0, http2 = 0;
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    if (i > 0 && p.t < packets[i - 1].t) backwards++;
    wire += p.len;
    captured += p.caplen;
    if (p.caplen < p.len) truncated++;
    const flags = p.flags;
    if (flags) {
      if (flags.includes('M')) malformed++;
      if (flags.includes('E')) expert++;
      if (flags.includes('F')) fragments++;
      if (flags.includes('R')) retransmissions++;
      if (flags.includes('O')) outOfOrder++;
      if (flags.includes('L')) lost++;
      if (flags.includes('D')) duplicateAcks++;
    }
    ifaceCount.set(p.iface, (ifaceCount.get(p.iface) ?? 0) + 1);
    const stack = p.protos.split(':');
    const seen = new Set<string>();
    for (const protocol of stack) {
      if (PAYLOAD_PROTOS.has(protocol) || protocol === 'frame' || seen.has(protocol)) continue;
      seen.add(protocol);
      const name = protoName(protocol);
      const stat = hierarchy.get(name) ?? { proto: name, packets: 0, bytes: 0 };
      stat.packets++;
      stat.bytes += p.len;
      hierarchy.set(name, stat);
    }
    if (seen.has('http2')) http2++;
    const protocol = protoName(topProtocol(p.protos));
    topOf[i] = protocol;
    const stat = top.get(protocol) ?? { proto: protocol, packets: 0, bytes: 0 };
    stat.packets++;
    stat.bytes += p.len;
    top.set(protocol, stat);
  }
  return { hierarchy, top, topOf, ifaceCount, backwards, wire, captured, truncated, malformed, expert, fragments, retransmissions, outOfOrder, lost, duplicateAcks, http2 };
}

export interface ConversationSummary {
  conversations: Conversation[];
  convOf: Int32Array;
  convOfFrame: (frame: number) => number | null;
}

export function groupConversations(packets: RawPacket[], topOf: string[], byFrame: Map<number, number>): ConversationSummary {
  const conversations: Conversation[] = [];
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
      id = conversations.length;
      convKey.set(key, id);
      const isSyn = transport === 'TCP' && p.tcpFlags !== null && (p.tcpFlags & 0x12) === 0x02;
      conversations.push({
        id, transport, stream, a: src, aPort: ported ? p.sport : null, b: dst, bPort: ported ? p.dport : null,
        initiator: isSyn ? 'SYN' : 'first packet', packetsAB: 0, bytesAB: 0, packetsBA: 0, bytesBA: 0,
        start: p.t, end: p.t, firstFrame: p.frame, lastFrame: p.frame, protocols: [], appProtocol: '',
        tcp: transport === 'TCP' ? { synSeen: false, synAckSeen: false, finSeen: false, rstSeen: false, retransmissions: 0, outOfOrder: 0, lostSegments: 0, payloadBytesAB: 0, payloadBytesBA: 0 } : null,
        truncatedPackets: 0, malformedPackets: 0, records: { dns: 0, http: 0, tls: 0 },
      });
      convTop.push(new Map());
    }
    const conversation = conversations[id];
    convOf[i] = id;
    const ab = src === conversation.a && (!ported || p.sport === conversation.aPort);
    if (ab) { conversation.packetsAB++; conversation.bytesAB += p.len; } else { conversation.packetsBA++; conversation.bytesBA += p.len; }
    if (p.t < conversation.start) conversation.start = p.t;
    if (p.t > conversation.end) conversation.end = p.t;
    conversation.lastFrame = p.frame;
    if (p.caplen < p.len) conversation.truncatedPackets++;
    if (p.flags.includes('M')) conversation.malformedPackets++;
    const protocolCounts = convTop[id];
    protocolCounts.set(topOf[i], (protocolCounts.get(topOf[i]) ?? 0) + 1);
    if (conversation.tcp && p.tcpFlags !== null) {
      const flags = p.tcpFlags;
      if ((flags & 0x12) === 0x02) conversation.tcp.synSeen = true;
      if ((flags & 0x12) === 0x12) conversation.tcp.synAckSeen = true;
      if (flags & 0x01) conversation.tcp.finSeen = true;
      if (flags & 0x04) conversation.tcp.rstSeen = true;
      if (p.flags.includes('R')) conversation.tcp.retransmissions++;
      if (p.flags.includes('O')) conversation.tcp.outOfOrder++;
      if (p.flags.includes('L')) conversation.tcp.lostSegments++;
      if (ab) conversation.tcp.payloadBytesAB += p.tcpLen ?? 0; else conversation.tcp.payloadBytesBA += p.tcpLen ?? 0;
    }
  }
  conversations.forEach((conversation, id) => {
    const entries = [...convTop[id].entries()].sort((x, y) => y[1] - x[1]);
    conversation.protocols = entries.map((entry) => entry[0]);
    const app = entries.find((entry) => !['TCP', 'UDP', 'IPv4', 'IPv6'].includes(entry[0]));
    conversation.appProtocol = app ? app[0] : conversation.transport === 'Non-IP' ? entries[0]?.[0] ?? 'Non-IP' : conversation.transport;
  });
  const convOfFrame = (frame: number): number | null => {
    const i = byFrame.get(frame);
    if (i === undefined) return null;
    const conversation = convOf[i];
    return conversation < 0 ? null : conversation;
  };
  return { conversations, convOf, convOfFrame };
}
