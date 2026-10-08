// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import type { RawPacket, RawRecords, RawTls } from '../src/engine/records';
import { correlateTls } from '../src/engine/tls';
import type { Conversation } from '../src/engine/types';

function packet(frame: number, decrypted: boolean, quicStreamData: boolean, protos: string): RawPacket {
  return {
    frame, t: frame, len: 100, caplen: 100, iface: 0, protos,
    ethSrc: '', ethDst: '', src: '10.0.0.5', dst: '10.0.0.8',
    sport: 44300, dport: 443, tcpStream: null, udpStream: 0,
    tcpFlags: null, tcpLen: null, flags: '',
    tlsAppData: false, quicStreamData, quicShort: quicStreamData, decrypted,
  };
}

function records(tls: RawTls[]): RawRecords {
  return {
    packets: [], segments: new Map(), dns: [], nbns: [], http: [], tls,
    arp: [], dhcp: [], icmp: [], ssh: [], quic: [], ifaces: [],
    macVendors: new Map(), warnings: [], startEpoch: null, timestampDigits: 0,
  };
}

const hello: RawTls = {
  frame: 1, carrier: 'quic', type: 1, version: 'TLS 1.3', sni: 'quic.example',
  alpn: ['h3'], supportedVersions: ['TLS 1.3'], ciphers: ['TLS_AES_128_GCM_SHA256'],
  certs: [], recordVersion: null,
};

async function status(packets: RawPacket[]): Promise<string> {
  const conversations = [{ records: { dns: 0, http: 0, tls: 0 } } as Conversation];
  const byFrame = new Map(packets.map((row) => [row.frame, row]));
  const sessions = await correlateTls(
    records([hello]), packets, Int32Array.from(packets.map(() => 0)),
    (frame) => byFrame.get(frame), (frame) => [frame], () => 0, conversations, [],
  );
  return sessions[0].decryptionStatus;
}

describe('QUIC session decryption status', () => {
  it('stays encrypted when packets carry stream data and no inner protocol', async () => {
    const packets = [
      packet(1, false, false, 'eth:ip:udp:quic'),
      packet(2, false, true, 'eth:ip:udp:quic'),
    ];
    expect(await status(packets)).toBe('encrypted');
  });

  it('is decrypted only when an inner protocol was dissected', async () => {
    const packets = [
      packet(1, false, false, 'eth:ip:udp:quic'),
      packet(2, true, true, 'eth:ip:udp:quic:http3'),
    ];
    expect(await status(packets)).toBe('decrypted');
  });

  it('reports no application data when the session has only the handshake', async () => {
    expect(await status([packet(1, false, false, 'eth:ip:udp:quic')])).toBe('no application data');
  });
});
