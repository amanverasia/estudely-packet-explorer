// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { groupConversations, summarizePackets } from '../src/engine/conversations';
import type { RawPacket } from '../src/engine/records';

function packet(frame: number, flags: string): RawPacket {
  return {
    frame,
    t: frame / 10,
    len: 100,
    caplen: 100,
    iface: 0,
    protos: 'eth:ip:tcp',
    ethSrc: '02:00:00:00:00:01',
    ethDst: '02:00:00:00:00:02',
    src: '10.0.0.1',
    dst: '10.0.0.2',
    sport: 40000,
    dport: 443,
    tcpStream: 1,
    udpStream: null,
    tcpFlags: 0x10,
    tcpLen: 20,
    flags,
    tlsAppData: false,
    quicStreamData: false,
    quicShort: false,
    decrypted: false,
  };
}

describe('TCP analysis flag counts', () => {
  it('counts r separately from R, including a packet flagged with both', () => {
    const packets = [
      packet(1, 'R'),
      packet(2, 'r'),
      packet(3, 'Rr'),
      packet(4, 'RO'),
      packet(5, ''),
    ];
    const summary = summarizePackets(packets);
    expect(summary.retransmissions).toBe(3);
    expect(summary.spuriousRetransmissions).toBe(2);
    expect(summary.outOfOrder).toBe(1);

    const byFrame = new Map(packets.map((p, index) => [p.frame, index]));
    const { conversations } = groupConversations(packets, summary.topOf, byFrame);
    expect(conversations).toHaveLength(1);
    expect(conversations[0].tcp).toMatchObject({ retransmissions: 3, spuriousRetransmissions: 2, outOfOrder: 1 });
  });

  it('does not treat a spurious-only flag string as an ordinary retransmission', () => {
    const packets = [packet(1, 'r')];
    const summary = summarizePackets(packets);
    expect(summary.retransmissions).toBe(0);
    expect(summary.spuriousRetransmissions).toBe(1);

    const { conversations } = groupConversations(packets, summary.topOf, new Map([[1, 0]]));
    expect(conversations[0].tcp).toMatchObject({ retransmissions: 0, spuriousRetransmissions: 1 });
  });
});
