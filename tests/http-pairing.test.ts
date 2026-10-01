// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { analyze } from '../src/engine/analyze';
import type { RawHttp, RawPacket, RawRecords } from '../src/engine/records';

const packet = (frame: number, clientToServer: boolean): RawPacket => ({
  frame,
  t: frame / 100,
  len: 100,
  caplen: 100,
  iface: 0,
  protos: 'eth:ip:tcp:http',
  ethSrc: clientToServer ? '02:00:00:00:00:05' : '02:00:00:00:00:80',
  ethDst: clientToServer ? '02:00:00:00:00:80' : '02:00:00:00:00:05',
  src: clientToServer ? '10.0.0.5' : '10.0.0.80',
  dst: clientToServer ? '10.0.0.80' : '10.0.0.5',
  sport: clientToServer ? 41000 : 80,
  dport: clientToServer ? 80 : 41000,
  tcpStream: 0,
  udpStream: null,
  tcpFlags: 0x18,
  tcpLen: 60,
  flags: '',
  tlsAppData: false,
  quicStreamData: false,
  quicShort: false,
  decrypted: false,
});

const request = (frame: number, responseIn: number, uri = `/request-${frame}`): RawHttp => ({
  frame, kind: 'req', method: 'GET', uri, version: 'HTTP/1.1', host: 'example.test',
  userAgent: null, code: null, phrase: null, contentType: null, contentLength: null, headers: [], server: null,
  location: null, requestIn: null, responseIn, http2StreamId: null,
});

const response = (frame: number, requestIn: number, code: number): RawHttp => ({
  frame, kind: 'resp', method: null, uri: null, version: 'HTTP/1.1', host: null,
  userAgent: null, code, phrase: 'OK', contentType: null, contentLength: null, headers: [], server: null,
  location: null, requestIn, responseIn: null, http2StreamId: null,
});

function records(http: RawHttp[]): RawRecords {
  return {
    packets: [packet(1, true), packet(2, true), packet(3, false), packet(4, false)],
    segments: new Map(), dns: [], nbns: [], http, tls: [], arp: [], dhcp: [], icmp: [], ssh: [], quic: [], ifaces: [],
    macVendors: new Map(), warnings: [], startEpoch: '1700000000.000000000', timestampDigits: 0,
  };
}

describe('HTTP frame-link reconciliation', () => {
  const meta = {
    fileName: 'links.pcap', fileSize: 1, fileType: 'pcap', linkType: 'Ethernet', incomplete: null,
    engine: { wireshark: 'test', wiregasm: 'test' }, warnings: [],
  };

  it('uses response links when they conflict with FIFO order and exposes both disagreements', async () => {
    const { model } = await analyze(records([
      request(1, 3), request(2, 4),
      response(3, 2, 201), response(4, 1, 202),
    ]), meta);

    expect(model.http.map((h) => [h.requestFrame, h.responseFrame, h.status, h.state])).toEqual([
      [1, 4, 202, 'complete'],
      [2, 3, 201, 'complete'],
    ]);
    expect(model.http[0].pairingWarning).toContain('request_in link points to packet 1');
    expect(model.http[1].pairingWarning).toContain('stream-order pairing would use packet 1');
  });

  it('keeps multiple messages from one request frame available to their linked responses', async () => {
    const { model } = await analyze(records([
      request(1, 3, '/first-in-frame'), request(1, 4, '/second-in-frame'),
      response(3, 1, 201), response(4, 1, 202),
    ]), meta);

    expect(model.http.map((h) => [h.requestFrame, h.uri, h.responseFrame, h.status, h.state])).toEqual([
      [1, '/first-in-frame', 3, 201, 'complete'],
      [1, '/second-in-frame', 4, 202, 'complete'],
    ]);
  });
});
