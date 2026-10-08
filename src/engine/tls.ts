// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Aggregates TLS and QUIC-carried TLS handshakes and decryption status.
import type { Conversation, HttpExchange, TlsSession } from './types';
import type { RawPacket, RawRecords } from './records';
import { fingerprint, hexToBytes, parseCertificate } from './x509';

export async function correlateTls(
  raw: RawRecords, packets: RawPacket[], convOf: Int32Array, pkt: (frame: number) => RawPacket | undefined,
  segs: (frame: number) => number[], convOfFrame: (frame: number) => number | null,
  conversations: Conversation[], http: HttpExchange[],
): Promise<TlsSession[]> {
  const tls: TlsSession[] = [];
  const tlsByConv = new Map<number, TlsSession>();
  for (const t of raw.tls) {
    const p = pkt(t.frame);
    if (!p) continue;
    const convId = convOfFrame(t.frame);
    const frames = segs(t.frame);
    const carrier = t.carrier === 'quic' ? 'QUIC' : 'TCP';
    const stream = carrier === 'QUIC' ? p.udpStream : p.tcpStream;
    let session = convId !== null ? tlsByConv.get(convId) : undefined;
    if (t.type === 1) {
      session = {
        id: tls.length, carrier, stream, convId, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        sni: t.sni, clientHelloFrame: t.frame, clientHelloTime: p.t,
        offered: { legacyVersion: t.version, supportedVersions: t.supportedVersions, alpn: t.alpn, cipherSuites: t.ciphers },
        serverHelloFrame: null, negotiated: null, certificates: [], certificateStatus: 'not observed', decryptionStatus: 'no application data', frames: [...frames],
      };
      tls.push(session);
      if (convId !== null) tlsByConv.set(convId, session);
      continue;
    }
    if (!session) {
      session = {
        id: tls.length, carrier, stream, convId, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
        sni: null, clientHelloFrame: null, clientHelloTime: null, offered: null, serverHelloFrame: null, negotiated: null,
        certificates: [], certificateStatus: 'not observed', decryptionStatus: 'no application data', frames: [],
      };
      tls.push(session);
      if (convId !== null) tlsByConv.set(convId, session);
    }
    session.frames.push(...frames);
    if (t.type === 2) {
      const viaExt = t.supportedVersions.length > 0;
      session.serverHelloFrame = t.frame;
      session.negotiated = {
        version: viaExt ? t.supportedVersions[0] : t.version,
        versionSource: viaExt ? 'supported_versions extension' : 'ServerHello version field',
        alpn: t.alpn[0] ?? null,
        cipherSuite: t.ciphers[0] ?? null,
      };
    } else if (t.type === 11) {
      for (const hex of t.certs) {
        const der = hexToBytes(hex);
        const cert = parseCertificate(der, t.frame, session.certificates.length);
        cert.sha256 = await fingerprint(der);
        session.certificates.push(cert);
      }
    }
  }
  for (const session of tls) {
    session.frames = [...new Set(session.frames)].sort((a, b) => a - b);
    if (session.certificates.length) session.certificateStatus = 'decoded';
    else if (session.negotiated?.version?.includes('1.3') || session.carrier === 'QUIC') session.certificateStatus = 'encrypted (TLS 1.3)';
    if (session.convId !== null) conversations[session.convId].records.tls++;
  }

  // Decrypted follows the packet flag. That flag is set when Wireshark
  // dissected a protocol above TLS other than bare data, or a protocol above
  // QUIC other than the Initial TLS handshake and bare data. QUIC stream data
  // alone means the session still has encrypted application data.
  const tlsDataByConv = new Map<number, { hasAppData: boolean; frames: number[]; decryptedFrames: number[] }>();
  for (let i = 0; i < packets.length; i++) {
    const p = packets[i];
    if (!p.tlsAppData && !p.quicStreamData && !p.quicShort && !p.decrypted) continue;
    const convId = convOf[i];
    if (convId < 0) continue;
    let data = tlsDataByConv.get(convId);
    if (!data) tlsDataByConv.set(convId, data = { hasAppData: false, frames: [], decryptedFrames: [] });
    data.hasAppData ||= p.tlsAppData || p.quicStreamData || p.quicShort;
    if (p.tlsAppData || p.quicStreamData || p.quicShort) data.frames.push(p.frame);
    if (p.decrypted) data.decryptedFrames.push(p.frame);
  }
  for (const session of tls) {
    const data = session.convId === null ? undefined : tlsDataByConv.get(session.convId);
    session.decryptionStatus = data?.decryptedFrames.length ? 'decrypted' : data?.hasAppData ? 'encrypted' : 'no application data';
    if (data) session.frames = [...new Set([...session.frames, ...data.frames])].sort((a, b) => a - b);
  }
  const decryptedConvIds = new Set(tls.filter((session) => session.decryptionStatus === 'decrypted' && session.convId !== null).map((session) => session.convId!));
  for (const exchange of http) exchange.decrypted = exchange.convId !== null && decryptedConvIds.has(exchange.convId);
  return tls;
}
