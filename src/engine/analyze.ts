// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Orchestrates the protocol-focused aggregation modules into the shared model.
import type { AnalysisModel, CaptureInfo } from './types';
import type { RawPacket, RawRecords } from './records';
import { summarizePackets, groupConversations } from './conversations';
import { correlateDns, DNS_MATCH_WINDOW } from './dns';
import { correlateHttp } from './http';
import { correlateTls } from './tls';
import { aggregateHosts } from './hosts';
import { buildFilterIndex, buildTimeline, summarizeUnsupported } from './traffic';

export { addressScope, isGloballyReachable } from './address-scope';
export { protoName, topProtocol } from './analysis-utils';
export { DNS_MATCH_WINDOW };

export interface CaptureMeta {
  fileName: string;
  fileSize: number;
  analyzedBytes?: number;
  partial?: boolean;
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

export async function analyze(
  raw: RawRecords, meta: CaptureMeta, onProgress?: (message: string) => void,
): Promise<{ model: AnalysisModel; index: PacketIndex }> {
  const t0 = performance.now();
  const packets = raw.packets;
  const byFrame = new Map<number, number>();
  packets.forEach((packet, index) => byFrame.set(packet.frame, index));
  const pkt = (frame: number): RawPacket | undefined => {
    const index = byFrame.get(frame);
    return index === undefined ? undefined : packets[index];
  };
  const segs = (frame: number): number[] => raw.segments.get(frame) ?? [frame];

  onProgress?.('Counting protocols');
  const packetSummary = summarizePackets(packets);

  onProgress?.('Grouping conversations');
  const { conversations, convOf, convOfFrame } = groupConversations(packets, packetSummary.topOf, byFrame);

  onProgress?.('Correlating DNS transactions');
  const dns = correlateDns(raw.dns, raw.nbns, pkt, segs, convOfFrame);
  for (const transaction of dns) if (transaction.convId !== null) conversations[transaction.convId].records.dns++;

  onProgress?.('Pairing HTTP requests and responses');
  const http = correlateHttp(raw.http, pkt, segs, convOfFrame, conversations);

  onProgress?.('Reading TLS handshakes');
  const tls = await correlateTls(raw, packets, convOf, pkt, segs, convOfFrame, conversations, http);

  const hostAggregation = aggregateHosts(
    raw, packets, packetSummary.topOf, convOf, convOfFrame, conversations, dns, http, tls, pkt, onProgress,
  );

  onProgress?.('Building timeline');
  const { timeline, topList } = buildTimeline(packets, packetSummary.top, packetSummary.topOf);
  const filterIndex = buildFilterIndex(packets, convOf, conversations, hostAggregation.hosts, topList, packetSummary.topOf);
  const unsupported = summarizeUnsupported(conversations, packetSummary.http2);

  const interfaces = raw.ifaces.map((iface) => ({
    id: iface.id, linkType: iface.linkType, name: iface.name, packets: packetSummary.ifaceCount.get(iface.id) ?? 0,
  }));
  const capture: CaptureInfo = {
    fileName: meta.fileName, fileSize: meta.fileSize, analyzedBytes: meta.analyzedBytes ?? meta.fileSize,
    partial: meta.partial ?? false, fileType: meta.fileType, linkType: meta.linkType,
    packetCount: packets.length, startEpoch: raw.startEpoch, duration: timeline.end - timeline.origin,
    timestampDigits: raw.timestampDigits, nonMonotonicTimestamps: packetSummary.backwards,
    interfaces, wireBytes: packetSummary.wire, capturedBytes: packetSummary.captured, truncatedPackets: packetSummary.truncated,
    malformedPackets: packetSummary.malformed, expertErrorPackets: packetSummary.expert, fragmentPackets: packetSummary.fragments,
    retransmissions: packetSummary.retransmissions, spuriousRetransmissions: packetSummary.spuriousRetransmissions, outOfOrder: packetSummary.outOfOrder, lostSegments: packetSummary.lost,
    duplicateAcks: packetSummary.duplicateAcks, incomplete: meta.incomplete,
    warnings: [...meta.warnings, ...raw.warnings], engine: meta.engine, analysisMs: 0,
  };
  const model: AnalysisModel = {
    capture, filterIndex,
    protocolHierarchy: [...packetSummary.hierarchy.values()].sort((a, b) => b.packets - a.packets),
    topProtocols: topList,
    timeline, hosts: hostAggregation.hosts, conversations, dns, http, tls,
    arp: hostAggregation.arp, arpBindings: hostAggregation.arpBindings, dhcp: hostAggregation.dhcp,
    icmp: hostAggregation.icmp, ssh: hostAggregation.ssh, quic: hostAggregation.quic, unsupported,
  };
  capture.analysisMs = Math.round(performance.now() - t0);
  return { model, index: { packets, convOf } };
}
