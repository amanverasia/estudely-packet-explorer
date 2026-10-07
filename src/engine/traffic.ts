// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Builds timeline bins, the compact packet filter index, and protocol coverage summaries.
import type { Conversation, FilterIndex, Host, ProtoStat, Timeline } from './types';
import type { RawPacket } from './records';
import { pickBin } from './analysis-utils';

export function buildTimeline(packets: RawPacket[], top: Map<string, ProtoStat>, topOf: string[]): { timeline: Timeline; topList: ProtoStat[] } {
  // Timestamps are not guaranteed to be monotonic, so bin from the earliest one.
  let minT = 0, maxT = 0;
  for (const packet of packets) { if (packet.t < minT) minT = packet.t; if (packet.t > maxT) maxT = packet.t; }
  const duration = maxT - minT;
  const binSeconds = pickBin(Math.max(duration, 1e-3));
  const bins = Math.max(1, Math.floor(duration / binSeconds) + 1);
  const topList = [...top.values()].sort((a, b) => b.bytes - a.bytes);
  const seriesKeys = topList.slice(0, 6).map((stat) => stat.proto);
  const seriesIdx = new Map(seriesKeys.map((key, id) => [key, id]));
  const series = [...seriesKeys, 'Other'].map((key) => ({ key, packets: new Array(bins).fill(0), bytes: new Array(bins).fill(0) }));
  const total = { key: 'All', packets: new Array(bins).fill(0), bytes: new Array(bins).fill(0) };
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    const bin = Math.min(bins - 1, Math.max(0, Math.floor((packet.t - minT) / binSeconds)));
    const seriesId = seriesIdx.get(topOf[i]) ?? seriesKeys.length;
    series[seriesId].packets[bin]++;
    series[seriesId].bytes[bin] += packet.len;
    total.packets[bin]++;
    total.bytes[bin] += packet.len;
  }
  const timeline: Timeline = { origin: minT, end: maxT, binSeconds, bins, series: [total, ...series.filter((entry) => entry.packets.some((count) => count > 0))] };
  return { timeline, topList };
}

export function buildFilterIndex(
  packets: RawPacket[], convOf: Int32Array, conversations: Conversation[], hosts: Host[], topList: ProtoStat[], topOf: string[],
): FilterIndex {
  // Keep a small, columnar packet index in the shared model. It lets the UI
  // apply time/host filters and recompute traffic totals without retaining or
  // exposing decoded packet payloads.
  const hostAddresses = hosts.map((host) => host.addr);
  const hostIds = new Map(hostAddresses.map((addr, id) => [addr, id]));
  const protocolNames = topList.map((stat) => stat.proto);
  const protocolIds = new Map(protocolNames.map((name, id) => [name, id]));
  const maxFrame = packets.reduce((max, packet) => Math.max(max, packet.frame), 0);
  const frameTimes = new Float64Array(maxFrame + 1);
  const lengths = new Uint32Array(packets.length);
  const capturedLengths = new Uint32Array(packets.length);
  const sourceHosts = new Int32Array(packets.length).fill(-1);
  const destinationHosts = new Int32Array(packets.length).fill(-1);
  const conversationsByPacket = new Int32Array(convOf);
  const topProtocols = new Uint32Array(packets.length);
  const directionAB = new Uint8Array(packets.length);
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    frameTimes[packet.frame] = packet.t;
    lengths[i] = packet.len;
    capturedLengths[i] = packet.caplen;
    sourceHosts[i] = hostIds.get(packet.src) ?? -1;
    destinationHosts[i] = hostIds.get(packet.dst) ?? -1;
    topProtocols[i] = protocolIds.get(topOf[i]) ?? 0;
    const conversation = convOf[i] >= 0 ? conversations[convOf[i]] : null;
    directionAB[i] = conversation && (packet.src || packet.ethSrc || '?') === conversation.a
      && ((conversation.transport !== 'TCP' && conversation.transport !== 'UDP') || packet.sport === conversation.aPort) ? 1 : 0;
  }
  return { frameTimes, lengths, capturedLengths, sourceHosts, destinationHosts, conversations: conversationsByPacket, topProtocols, directionAB, hostAddresses, protocolNames };
}

export interface UnsupportedSummary {
  httpPortsUndecoded: number[];
  encryptedConversations: number;
  quicConversations: number;
  http2Packets: number;
  httpWithGaps: number[];
}

export function summarizeUnsupported(conversations: Conversation[], http2Packets: number): UnsupportedSummary {
  const httpPorts = new Set([80, 8080, 8000, 8008, 8888, 3128]);
  return {
    httpPortsUndecoded: conversations.filter((conversation) => conversation.tcp && conversation.records.http === 0
      && (httpPorts.has(conversation.bPort ?? -1) || httpPorts.has(conversation.aPort ?? -1))
      && conversation.tcp.payloadBytesAB + conversation.tcp.payloadBytesBA > 0 && !conversation.protocols.includes('TLS')).map((conversation) => conversation.id),
    encryptedConversations: conversations.filter((conversation) => conversation.protocols.includes('TLS') || conversation.protocols.includes('QUIC')).length,
    quicConversations: conversations.filter((conversation) => conversation.protocols.includes('QUIC')).length,
    http2Packets,
    httpWithGaps: conversations.filter((conversation) => conversation.records.http > 0
      && ((conversation.tcp?.lostSegments ?? 0) > 0 || conversation.truncatedPackets > 0)).map((conversation) => conversation.id),
  };
}
