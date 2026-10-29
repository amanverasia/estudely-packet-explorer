// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { buildQuic, buildSsh, type ProtoCtx } from '../src/engine/protocols';
import type { RawPacket } from '../src/engine/records';
import type { Conversation, TlsSession } from '../src/engine/types';

function packet(frame: number, over: Partial<RawPacket> = {}): RawPacket {
  return {
    frame, t: frame, len: 100, caplen: 100, iface: 0, protos: 'eth:ip:tcp',
    ethSrc: '', ethDst: '', src: '10.0.0.5', dst: '10.0.0.8',
    sport: 44300, dport: 22, tcpStream: 0, udpStream: 0,
    tcpFlags: null, tcpLen: null, flags: '',
    tlsAppData: false, quicStreamData: false, quicShort: false, decrypted: false,
    ...over,
  };
}

function ctx(packets: RawPacket[], tls: TlsSession[] = []): ProtoCtx {
  const byFrame = new Map(packets.map((p) => [p.frame, p]));
  const conversations = [{ a: '10.0.0.5', aPort: 44300, b: '10.0.0.8', bPort: 22, initiator: 'SYN', start: 0 } as Conversation];
  return {
    packets, convOf: Int32Array.from(packets.map(() => 0)), pkt: (f) => byFrame.get(f),
    convOfFrame: () => 0, conversations, tls,
  };
}

describe('buildSsh', () => {
  it('records client and server banners with frames sorted and unique regardless of record order', () => {
    const packets = [1, 2, 3].map((f) => packet(f));
    const sessions = buildSsh([
      { frame: 3, version: 'SSH-2.0-server', fromClient: false },
      { frame: 1, version: 'SSH-2.0-client', fromClient: true },
      { frame: 3, version: 'SSH-2.0-server', fromClient: false },
    ], ctx(packets));
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      clientVersion: 'SSH-2.0-client', clientVersionFrame: 1, serverVersion: 'SSH-2.0-server', serverVersionFrame: 3, frames: [1, 3],
    });
  });
});

describe('buildQuic', () => {
  const hello = (convId: number, over: Partial<TlsSession>): TlsSession => ({
    id: 0, carrier: 'QUIC', stream: 0, convId, client: '10.0.0.5', clientPort: 50000, server: '10.0.0.8', serverPort: 443,
    sni: 'h3.example', clientHelloFrame: 1, clientHelloTime: 1, offered: null, serverHelloFrame: null, negotiated: null,
    certificates: [], certificateStatus: 'not observed', decryptionStatus: 'no application data', frames: [1],
    ...over,
  } as TlsSession);

  it('takes the client and SNI from the first QUIC TLS session that has a ClientHello', () => {
    const packets = [1, 2].map((f) => packet(f, { protos: 'eth:ip:udp:quic', sport: 50000, dport: 443, udpStream: 0 }));
    const tls = [
      hello(0, { carrier: 'TCP', sni: 'tcp.example' }),
      hello(0, { clientHelloFrame: null, sni: 'no-hello.example' }),
      hello(0, { sni: 'first.example' }),
      hello(0, { sni: 'second.example' }),
    ];
    const conns = buildQuic([
      { frame: 2, versions: ['1 (0x00000001)'], supported: [] },
      { frame: 1, versions: ['1 (0x00000001)'], supported: [] },
    ], ctx(packets, tls));
    expect(conns).toHaveLength(1);
    expect(conns[0]).toMatchObject({ sni: 'first.example', client: '10.0.0.5', clientPort: 50000, packets: 2, frames: [1, 2] });
    expect(conns[0].versions).toEqual(['1 (0x00000001)']);
  });
});
