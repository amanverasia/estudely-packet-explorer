// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { compareCaptures, countChanges, type ComparisonSource } from '../src/engine/compare';

function source(patch: Partial<ComparisonSource> = {}): ComparisonSource {
  return {
    capture: { fileName: 'capture.pcap', analyzedBytes: 100, partial: false, packetCount: 10, duration: 2 },
    hosts: [],
    topProtocols: [],
    conversations: [],
    ...patch,
  };
}

function host(addr: string, name: string, protocols: string[]) {
  return {
    addr,
    names: name ? [name] : [],
    protocols,
  };
}

function conversation(patch: Partial<ComparisonSource['conversations'][number]> = {}): ComparisonSource['conversations'][number] {
  return {
    transport: 'TCP',
    a: '10.0.0.1', aPort: 40000,
    b: '10.0.0.2', bPort: 80,
    packetsAB: 1, bytesAB: 60, packetsBA: 1, bytesBA: 60,
    start: 0, end: 2, firstFrame: 1,
    appProtocol: 'HTTP', protocols: ['TCP', 'HTTP'],
    ...patch,
  };
}

describe('capture comparison', () => {
  it('finds added, removed, and changed hosts, names, and protocol totals', () => {
    const before = source({
      hosts: [host('10.0.0.1', 'old.example', ['DNS', 'TCP']), host('10.0.0.2', '', ['UDP'])],
      topProtocols: [{ proto: 'DNS', packets: 4, bytes: 200 }, { proto: 'TCP', packets: 6, bytes: 600 }],
    });
    const after = source({
      hosts: [host('10.0.0.1', 'new.example', ['DNS', 'HTTP']), host('10.0.0.3', '', ['HTTP'])],
      topProtocols: [{ proto: 'DNS', packets: 5, bytes: 240 }, { proto: 'HTTP', packets: 1, bytes: 80 }],
    });

    const result = compareCaptures(before, after);
    expect(result.hosts.map(({ address, status }) => [address, status])).toEqual([
      ['10.0.0.1', 'changed'], ['10.0.0.2', 'missing'], ['10.0.0.3', 'new'],
    ]);
    expect(result.hosts[0]).toMatchObject({ beforeNames: ['old.example'], afterNames: ['new.example'], beforeProtocols: ['DNS', 'TCP'], afterProtocols: ['DNS', 'HTTP'] });
    expect(result.protocols.map(({ protocol, status }) => [protocol, status])).toEqual([
      ['DNS', 'changed'], ['HTTP', 'new'], ['TCP', 'missing'],
    ]);
    expect(result.protocols[0]).toMatchObject({ before: { packets: 4, bytes: 200 }, after: { packets: 5, bytes: 240 } });
    expect(countChanges(result.hosts)).toMatchObject({ changed: 1, missing: 1, new: 1, same: 0 });
  });

  it('matches reversed endpoints by exact protocol and address:port tuple', () => {
    const before = source({ conversations: [
      conversation(),
      conversation({ transport: 'UDP', aPort: 53000, bPort: 53, appProtocol: 'DNS', protocols: ['UDP', 'DNS'], firstFrame: 9 }),
    ] });
    const after = source({ conversations: [
      conversation({ a: '10.0.0.2', aPort: 80, b: '10.0.0.1', bPort: 40000, packetsAB: 2, packetsBA: 1, bytesAB: 120, bytesBA: 60, end: 3 }),
      conversation({ transport: 'UDP', aPort: 53001, bPort: 53, appProtocol: 'DNS', protocols: ['UDP', 'DNS'], firstFrame: 9 }),
    ] });

    const result = compareCaptures(before, after);
    expect(result.conversations.map(({ transport, status }) => [transport, status])).toEqual([
      ['TCP', 'changed'], ['UDP', 'missing'], ['UDP', 'new'],
    ]);
    expect(result.conversations[0]).toMatchObject({ endpointA: '10.0.0.1:40000', endpointB: '10.0.0.2:80', before: { packets: 2, bytes: 120 }, after: { packets: 3, bytes: 180 } });
  });
});
