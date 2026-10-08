// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import type { Conversation } from '../src/engine/types';
import { countConnectionQuality, filterConnectionsByQuality } from '../src/app/connectionQuality';

function conversation(id: number, patch: Partial<Conversation> = {}): Conversation {
  return {
    id,
    transport: 'TCP',
    stream: id,
    a: '10.0.0.1', aPort: 40000,
    b: '10.0.0.2', bPort: 443,
    initiator: 'SYN',
    packetsAB: 2, bytesAB: 120, packetsBA: 1, bytesBA: 60,
    start: 0, end: 2, firstFrame: 1, lastFrame: 3,
    protocols: ['TCP'], appProtocol: 'TCP',
    tcp: { synSeen: true, synAckSeen: true, finSeen: false, rstSeen: false, retransmissions: 0, spuriousRetransmissions: 0, outOfOrder: 0, lostSegments: 0, payloadBytesAB: 0, payloadBytesBA: 0 },
    truncatedPackets: 0,
    malformedPackets: 0,
    records: { dns: 0, http: 0, tls: 0 },
    ...patch,
  };
}

describe('connection quality filters', () => {
  it('counts distinct conversations with at least one full-conversation indicator', () => {
    const selectedTraffic = conversation(1, {
      packetsAB: 1,
      packetsBA: 0,
      tcp: { synSeen: true, synAckSeen: true, finSeen: false, rstSeen: true, retransmissions: 4, spuriousRetransmissions: 0, outOfOrder: 2, lostSegments: 3, payloadBytesAB: 0, payloadBytesBA: 0 },
    });
    const damagedUdp = conversation(2, { transport: 'UDP', tcp: null, truncatedPackets: 1, malformedPackets: 1 });
    const cleanTcp = conversation(3);

    expect(countConnectionQuality([selectedTraffic, damagedUdp, cleanTcp])).toEqual({
      all: 3,
      retransmissions: 1,
      spuriousRetransmissions: 0,
      outOfOrder: 1,
      gaps: 1,
      rstSeen: 1,
      truncated: 1,
      malformed: 1,
    });
  });

  it('filters by one observation and leaves All as a clear option', () => {
    const retransmitted = conversation(1, {
      tcp: { synSeen: true, synAckSeen: true, finSeen: false, rstSeen: false, retransmissions: 1, spuriousRetransmissions: 0, outOfOrder: 0, lostSegments: 0, payloadBytesAB: 0, payloadBytesBA: 0 },
    });
    const udp = conversation(2, { transport: 'UDP', tcp: null, truncatedPackets: 1 });
    const conversations = [retransmitted, udp];

    expect(filterConnectionsByQuality(conversations, 'retransmissions')).toEqual([retransmitted]);
    expect(filterConnectionsByQuality(conversations, 'truncated')).toEqual([udp]);
    expect(filterConnectionsByQuality(conversations, 'all')).toBe(conversations);
    expect(filterConnectionsByQuality(conversations, 'malformed')).toEqual([]);
  });

  it('keeps spurious retransmissions out of the ordinary retransmission filter', () => {
    const tcp = { synSeen: true, synAckSeen: true, finSeen: false, rstSeen: false, outOfOrder: 0, lostSegments: 0, payloadBytesAB: 0, payloadBytesBA: 0 };
    const ordinary = conversation(1, { tcp: { ...tcp, retransmissions: 1, spuriousRetransmissions: 0 } });
    const spuriousOnly = conversation(2, { tcp: { ...tcp, retransmissions: 0, spuriousRetransmissions: 2 } });
    const both = conversation(3, { tcp: { ...tcp, retransmissions: 1, spuriousRetransmissions: 1 } });
    const conversations = [ordinary, spuriousOnly, both];

    expect(filterConnectionsByQuality(conversations, 'retransmissions')).toEqual([ordinary, both]);
    expect(filterConnectionsByQuality(conversations, 'spuriousRetransmissions')).toEqual([spuriousOnly, both]);
    expect(countConnectionQuality(conversations)).toMatchObject({ retransmissions: 2, spuriousRetransmissions: 2 });
  });
});
