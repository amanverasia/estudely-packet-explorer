// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { parseRecords } from '../src/engine/records';

function packetRecord(protos: string, tlsAppData: boolean, quicStreamData: boolean, quicShort: boolean, epoch = '1700000000.000000000', frame = 1): Uint8Array {
  return new TextEncoder().encode([
    'P', String(frame), epoch, '100', '100', '0', protos, '', '', '10.0.0.1', '10.0.0.2',
    '12345', '443', '', '0', '', '60', '', tlsAppData ? '1' : '0', quicStreamData ? '1' : '0', quicShort ? '1' : '0',
  ].join('\t') + '\n');
}

describe('decrypted application packet records', () => {
  it('marks decrypted QUIC stream data and tracks short-header packets', () => {
    const { packets } = parseRecords(packetRecord('eth:ip:udp:quic', false, true, true));
    expect(packets[0]).toMatchObject({ quicStreamData: true, quicShort: true, decrypted: true });
  });

  it('does not mistake encrypted TLS application data for decrypted content', () => {
    const { packets } = parseRecords(packetRecord('eth:ip:tcp:tls:data', true, false, false));
    expect(packets[0]).toMatchObject({ tlsAppData: true, decrypted: false });
  });
});

describe('relative packet timestamps', () => {
  it('preserves sub-microsecond gaps when subtracting epoch timestamps', () => {
    const decoder = new TextDecoder();
    const records = new TextEncoder().encode(
      decoder.decode(packetRecord('eth:ip:udp', false, false, false, '1700000000.123456000', 1))
      + decoder.decode(packetRecord('eth:ip:udp', false, false, false, '1700000000.123456789', 2)),
    );
    const { packets } = parseRecords(records);

    expect(packets.map((packet) => packet.t)).toEqual([0, 0.000000789]);
  });
});
