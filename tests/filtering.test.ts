// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { applySharedFilter } from '../src/app/filtering';
import type { AnalysisModel, Conversation } from '../src/engine/types';

function conversation(id: number, protocols: string[] = []): Conversation {
  return { id, protocols, records: { dns: 0, http: 0, tls: 0 } } as unknown as Conversation;
}

function model(conversations: Conversation[], packetConversations: number[], packetTimes?: number[]): AnalysisModel {
  const packetCount = packetConversations.length;
  const times = new Float64Array(packetCount + 1);
  packetConversations.forEach((_, i) => { times[i + 1] = packetTimes?.[i] ?? i; });
  return {
    capture: { packetCount, wireBytes: packetCount * 100, capturedBytes: packetCount * 100, duration: packetCount } as AnalysisModel['capture'],
    filterIndex: {
      frameTimes: times,
      lengths: new Uint32Array(packetCount).fill(100),
      capturedLengths: new Uint32Array(packetCount).fill(100),
      sourceHosts: new Int32Array(packetCount).fill(-1),
      destinationHosts: new Int32Array(packetCount).fill(-1),
      conversations: new Int32Array(packetConversations),
      topProtocols: new Uint32Array(packetCount),
      directionAB: new Uint8Array(packetCount),
      hostAddresses: [],
      protocolNames: ['TCP'],
    },
    protocolHierarchy: [],
    topProtocols: [],
    timeline: {
      origin: 0,
      end: packetCount,
      binSeconds: 1,
      bins: Math.max(packetCount, 1),
      series: [
        { key: 'All', packets: Array(Math.max(packetCount, 1)).fill(0), bytes: Array(Math.max(packetCount, 1)).fill(0) },
        { key: 'Other', packets: Array(Math.max(packetCount, 1)).fill(0), bytes: Array(Math.max(packetCount, 1)).fill(0) },
      ],
    },
    hosts: [],
    conversations,
    dns: [], http: [], tls: [], arp: [], arpBindings: [], dhcp: [], icmp: [], ssh: [], quic: [],
    unsupported: { httpPortsUndecoded: [], encryptedConversations: 0, quicConversations: 0, http2Packets: 0, httpWithGaps: [] },
  } as AnalysisModel;
}

describe('shared filter conversation record indexing', () => {
  it('counts records by original conversation ID and ignores filtered, missing, and null IDs', () => {
    const source = model([conversation(41), conversation(900)], [0, 1], [0.25, 2]);
    source.dns = [
      { convId: 41, frames: [1] }, { convId: 41, frames: [1] },
      { convId: 900, frames: [1] }, { convId: 12345, frames: [1] }, { convId: null, frames: [1] },
      { convId: 41, frames: [2] },
    ] as unknown as AnalysisModel['dns'];
    source.http = [
      { convId: 41, frames: [1] }, { convId: 900, frames: [1] }, { convId: 12345, frames: [1] }, { convId: null, frames: [1] },
    ] as unknown as AnalysisModel['http'];
    source.tls = [
      { convId: 41, frames: [1] }, { convId: 41, frames: [1] }, { convId: 900, frames: [1] }, { convId: null, frames: [1] },
    ] as unknown as AnalysisModel['tls'];
    source.unsupported.httpPortsUndecoded = [900, 41, 12345, 41];
    source.unsupported.httpWithGaps = [12345, 41, 900];
    const sourceConversations = source.conversations.slice();
    const sourceRecords = source.conversations.map(({ records }) => ({ ...records }));
    const sourceDns = source.dns.slice();
    const sourceHttp = source.http.slice();
    const sourceTls = source.tls.slice();

    const { model: filtered } = applySharedFilter(source, { start: 0, end: 1, host: null });

    expect(filtered.conversations.map(({ id, records }) => [id, records])).toEqual([
      [41, { dns: 2, http: 1, tls: 2 }],
    ]);
    expect(filtered.unsupported.httpPortsUndecoded).toEqual([41, 41]);
    expect(filtered.unsupported.httpWithGaps).toEqual([41]);

    applySharedFilter(source, { start: 0, end: 2, host: null });
    expect(source.conversations).toEqual(sourceConversations);
    expect(source.conversations.map(({ records }) => records)).toEqual(sourceRecords);
    expect(source.dns).toEqual(sourceDns);
    expect(source.http).toEqual(sourceHttp);
    expect(source.tls).toEqual(sourceTls);
  });

  it('correlates records across a generated model with many conversations', () => {
    const count = 2500;
    const source = model(
      Array.from({ length: count }, (_, id) => conversation(id * 3 + 7, id % 2 ? ['TLS'] : [])),
      Array.from({ length: count }, (_, id) => id),
    );
    source.dns = source.conversations.map(({ id }, frame) => ({ convId: id, frames: [frame + 1] })) as unknown as AnalysisModel['dns'];
    source.http = source.conversations.map(({ id }, frame) => ({ convId: id, frames: [frame + 1] })) as unknown as AnalysisModel['http'];
    source.tls = source.conversations.map(({ id }, frame) => ({ convId: id, frames: [frame + 1] })) as unknown as AnalysisModel['tls'];
    source.unsupported.httpPortsUndecoded = source.conversations.filter((_, i) => i % 2 === 0).map(({ id }) => id);
    source.unsupported.httpWithGaps = source.conversations.filter((_, i) => i % 2 === 1).map(({ id }) => id);

    const { model: filtered } = applySharedFilter(source, { start: 0, end: count, host: null });

    expect(filtered.conversations).toHaveLength(count);
    expect(filtered.conversations.every(({ records }) => records.dns === 1 && records.http === 1 && records.tls === 1)).toBe(true);
    expect(filtered.unsupported.httpPortsUndecoded).toEqual(source.unsupported.httpPortsUndecoded);
    expect(filtered.unsupported.httpWithGaps).toEqual(source.unsupported.httpWithGaps);
  });
});
