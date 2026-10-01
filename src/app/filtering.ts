// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { AnalysisModel, ArpBinding, Conversation, Host } from '../engine/types';

export interface SharedFilter {
  start: number | null;
  end: number | null;
  host: string | null;
}

export interface FilterStats {
  packets: number;
  wireBytes: number;
  capturedBytes: number;
  hosts: number;
  conversations: number;
  allHosts: number;
  allConversations: number;
  start: number | null;
  end: number | null;
}

export function applySharedFilter(source: AnalysisModel, filter: SharedFilter): { model: AnalysisModel; stats: FilterStats } {
  const { capture, filterIndex: index } = source;
  const hasTime = filter.start !== null && filter.end !== null;
  const hasHost = Boolean(filter.host);
  if (!hasTime && !hasHost) return { model: source, stats: {
    packets: capture.packetCount, wireBytes: capture.wireBytes, capturedBytes: capture.capturedBytes,
    hosts: source.hosts.length, conversations: source.conversations.length,
    allHosts: source.hosts.length, allConversations: source.conversations.length,
    start: source.timeline.origin, end: source.timeline.origin + capture.duration,
  } };

  const hostId = hasHost ? index.hostAddresses.indexOf(filter.host!) : -1;
  const hostTraffic = index.hostAddresses.map(() => ({ txPackets: 0, txBytes: 0, rxPackets: 0, rxBytes: 0, first: Infinity, last: -Infinity }));
  const convTraffic = source.conversations.map(() => ({ packetsAB: 0, bytesAB: 0, packetsBA: 0, bytesBA: 0, first: Infinity, last: -Infinity }));
  const topPackets = new Float64Array(index.protocolNames.length);
  const topBytes = new Float64Array(index.protocolNames.length);
  const seriesByName = new Map(source.timeline.series.map((s, i) => [s.key, i]));
  const timeline = source.timeline.series.map((s) => ({ key: s.key, packets: new Array(source.timeline.bins).fill(0), bytes: new Array(source.timeline.bins).fill(0) }));
  let packets = 0, wireBytes = 0, capturedBytes = 0, first = Infinity, last = -Infinity;
  let http2Packets = 0;

  for (let i = 0; i < source.capture.packetCount; i++) {
    const t = index.frameTimes[i + 1];
    if (hasTime && (t < filter.start! || t > filter.end!)) continue;
    const src = index.sourceHosts[i], dst = index.destinationHosts[i];
    if (hasHost && src !== hostId && dst !== hostId) continue;
    packets++;
    wireBytes += index.lengths[i];
    capturedBytes += index.capturedLengths[i];
    first = Math.min(first, t); last = Math.max(last, t);

    if (src >= 0) {
      const h = hostTraffic[src]; h.txPackets++; h.txBytes += index.lengths[i]; h.first = Math.min(h.first, t); h.last = Math.max(h.last, t);
    }
    if (dst >= 0) {
      const h = hostTraffic[dst]; h.rxPackets++; h.rxBytes += index.lengths[i]; h.first = Math.min(h.first, t); h.last = Math.max(h.last, t);
    }
    const convId = index.conversations[i];
    if (convId >= 0) {
      const c = convTraffic[convId];
      if (index.directionAB[i]) { c.packetsAB++; c.bytesAB += index.lengths[i]; }
      else { c.packetsBA++; c.bytesBA += index.lengths[i]; }
      c.first = Math.min(c.first, t); c.last = Math.max(c.last, t);
    }
    const protocolId = index.topProtocols[i];
    topPackets[protocolId]++;
    topBytes[protocolId] += index.lengths[i];
    const bin = Math.min(source.timeline.bins - 1, Math.max(0, Math.floor((t - source.timeline.origin) / source.timeline.binSeconds)));
    const name = index.protocolNames[protocolId];
    const seriesId = seriesByName.get(name) ?? seriesByName.get('Other') ?? 0;
    timeline[0].packets[bin]++; timeline[0].bytes[bin] += index.lengths[i];
    timeline[seriesId].packets[bin]++; timeline[seriesId].bytes[bin] += index.lengths[i];
    if (name === 'HTTP/2') http2Packets++;
  }

  const timeMatch = (frames: number[] | undefined, frame: number | undefined) => {
    if (!hasTime) return true;
    const candidates = frames?.length ? frames : frame !== undefined ? [frame] : [];
    return candidates.some((n) => {
      const t = index.frameTimes[n];
      return Number.isFinite(t) && t >= filter.start! && t <= filter.end!;
    });
  };
  const addressMatch = (value: unknown): boolean => {
    if (typeof value === 'string') return value === filter.host;
    if (Array.isArray(value)) return value.some(addressMatch);
    return false;
  };
  const hostMatch = (row: Record<string, unknown>): boolean => {
    if (!hasHost) return true;
    if (Object.values(row).some(addressMatch)) return true;
    const convId = row.convId;
    if (typeof convId === 'number') {
      const c = source.conversations[convId];
      return c?.a === filter.host || c?.b === filter.host;
    }
    const messages = row.messages;
    return Array.isArray(messages) && messages.some((m) => m && typeof m === 'object' && Object.values(m as Record<string, unknown>).some(addressMatch));
  };
  const filterRows = <T extends { frames?: number[]; frame?: number }>(rows: T[]): T[] => rows.filter((row) =>
    timeMatch(row.frames, row.frame) && hostMatch(row as Record<string, unknown>));

  const dns = filterRows(source.dns);
  const http = filterRows(source.http);
  const tls = filterRows(source.tls);
  const arp = filterRows(source.arp);
  const dhcp = filterRows(source.dhcp);
  const icmp = filterRows(source.icmp);
  const ssh = filterRows(source.ssh);
  const quic = filterRows(source.quic);
  const arpBindings = filterRows(source.arpBindings).map((binding) => filterBinding(binding, index.frameTimes, filter));

  const hosts: Host[] = source.hosts.flatMap((host, id) => {
    if (hostId >= 0 && hostId !== id) return [];
    const traffic = hostTraffic[id];
    if (!traffic.txPackets && !traffic.rxPackets) return [];
    return [{ ...host, txPackets: traffic.txPackets, txBytes: traffic.txBytes, rxPackets: traffic.rxPackets, rxBytes: traffic.rxBytes,
      firstSeen: Math.min(traffic.first, traffic.last), lastSeen: traffic.last }];
  }).sort((a, b) => b.txBytes + b.rxBytes - (a.txBytes + a.rxBytes));

  const conversations: Conversation[] = source.conversations.flatMap((conv, id) => {
    const traffic = convTraffic[id];
    if (!traffic.packetsAB && !traffic.packetsBA) return [];
    return [{ ...conv, packetsAB: traffic.packetsAB, bytesAB: traffic.bytesAB, packetsBA: traffic.packetsBA, bytesBA: traffic.bytesBA,
      start: traffic.first, end: traffic.last,
      records: { dns: 0, http: 0, tls: 0 } }];
  });
  for (const d of dns) if (d.convId !== null) { const c = conversations.find((row) => row.id === d.convId); if (c) c.records.dns++; }
  for (const h of http) if (h.convId !== null) { const c = conversations.find((row) => row.id === h.convId); if (c) c.records.http++; }
  for (const t of tls) if (t.convId !== null) { const c = conversations.find((row) => row.id === t.convId); if (c) c.records.tls++; }

  const topProtocols = index.protocolNames.map((proto, i) => ({ proto, packets: topPackets[i], bytes: topBytes[i] }))
    .filter((s) => s.packets > 0).sort((a, b) => b.bytes - a.bytes);
  const filtered: AnalysisModel = {
    ...source,
    // Retain zeroed protocol series so surviving protocols keep their stable colors.
    timeline: { ...source.timeline, series: timeline },
    topProtocols, hosts, conversations, dns, http, tls, arp, arpBindings, dhcp, icmp, ssh, quic,
    unsupported: {
      ...source.unsupported,
      httpPortsUndecoded: source.unsupported.httpPortsUndecoded.filter((id) => conversations.some((c) => c.id === id)),
      encryptedConversations: conversations.filter((c) => c.protocols.includes('TLS') || c.protocols.includes('QUIC')).length,
      quicConversations: conversations.filter((c) => c.protocols.includes('QUIC')).length,
      http2Packets,
      httpWithGaps: source.unsupported.httpWithGaps.filter((id) => conversations.some((c) => c.id === id)),
    },
  };
  return { model: filtered, stats: {
    packets, wireBytes, capturedBytes, hosts: hosts.length, conversations: conversations.length,
    allHosts: source.hosts.length, allConversations: source.conversations.length,
    start: packets ? first : null, end: packets ? last : null,
  } };
}

function filterBinding(binding: ArpBinding, frameTimes: Float64Array, filter: SharedFilter): ArpBinding {
  if (filter.start === null || filter.end === null) return binding;
  const inRange = (frame: number) => frameTimes[frame] >= filter.start! && frameTimes[frame] <= filter.end!;
  const periods = binding.periods.filter((p) => {
    return binding.frames.some((frame) => frame >= p.firstFrame && frame <= p.lastFrame && inRange(frame));
  });
  return { ...binding, periods, macs: [...new Set(periods.map((p) => p.mac))], changes: Math.max(0, periods.length - 1), frames: binding.frames.filter(inRange) };
}
