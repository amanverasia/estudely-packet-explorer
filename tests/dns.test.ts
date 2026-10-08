// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { correlateDns } from '../src/engine/dns';
import type { RawDns, RawPacket } from '../src/engine/records';

const CLIENT = '10.0.0.5';
const RESOLVER = '10.0.0.53';

function packet(frame: number, t: number, src: string, sport: number, dst: string, dport: number, protos = 'eth:ip:udp:dns'): RawPacket {
  return {
    frame, t, len: 80, caplen: 80, iface: 0, protos,
    ethSrc: '02:00:00:00:00:05', ethDst: '02:00:00:00:00:53',
    src, dst, sport, dport,
    tcpStream: null, udpStream: 0, tcpFlags: null, tcpLen: null, flags: '',
    tlsAppData: false, quicStreamData: false, quicShort: false, decrypted: false,
  };
}

function message(frame: number, isResponse: boolean, qname: string, qtype: string, proto: RawDns['proto'] = 'dns', answers: RawDns['rrs'] = []): RawDns {
  return {
    frame, proto, id: 0x1111, isResponse, opcode: 0, rcode: isResponse ? 0 : null,
    qname, qtype, qclass: 'IN', ancount: answers.length, rrs: answers, truncated: false,
  };
}

function correlate(rows: RawDns[], packets: RawPacket[], segs: (frame: number) => number[] = (frame) => [frame]) {
  const byFrame = new Map(packets.map((row) => [row.frame, row]));
  return correlateDns(rows, [], (frame) => byFrame.get(frame), segs, () => null);
}

describe('DNS transaction id reuse while two questions are outstanding', () => {
  it('attaches the first answer to the matching name and type', () => {
    const packets = [
      packet(1, 0, CLIENT, 41000, RESOLVER, 53),
      packet(2, 0.02, CLIENT, 41000, RESOLVER, 53),
      packet(3, 0.05, RESOLVER, 53, CLIENT, 41000),
    ];
    const answer = [{ section: 'an', name: 'two.example', type: 'AAAA', ttl: 60, value: '2001:db8::2' }];
    const rows = correlate([
      message(1, false, 'one.example', 'A'),
      message(2, false, 'two.example', 'AAAA'),
      message(3, true, 'two.example', 'AAAA', 'dns', answer),
    ], packets, (frame) => (frame === 3 ? [3, 7] : [frame]));

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      qname: 'one.example', qtype: 'A', txid: 0x1111, status: 'unanswered',
      queryFrame: 1, responseFrame: null, answers: [], frames: [1],
    });
    expect(rows[1]).toMatchObject({
      qname: 'two.example', qtype: 'AAAA', status: 'answered',
      client: CLIENT, clientPort: 41000, server: RESOLVER, serverPort: 53,
      queryFrame: 2, responseFrame: 3, rcode: 'NoError',
      answers: [{ section: 'answer', name: 'two.example', type: 'AAAA', ttl: 60, value: '2001:db8::2' }],
      frames: [2, 3, 7],
    });
    expect(rows[1].rtt).toBeCloseTo(0.03, 9);
  });

  it('leaves both questions unanswered when the answer names neither', () => {
    const packets = [
      packet(1, 0, CLIENT, 41000, RESOLVER, 53),
      packet(2, 0.02, CLIENT, 41000, RESOLVER, 53),
      packet(3, 0.05, RESOLVER, 53, CLIENT, 41000),
    ];
    const rows = correlate([
      message(1, false, 'one.example', 'A'),
      message(2, false, 'two.example', 'AAAA'),
      message(3, true, 'three.example', 'A'),
    ], packets);
    expect(rows.map((row) => [row.qname, row.status, row.queryFrame, row.responseFrame])).toEqual([
      ['one.example', 'unanswered', 1, null],
      ['two.example', 'unanswered', 2, null],
      ['three.example', 'response without query', null, 3],
    ]);
  });

  it('does not pair a response whose type differs from the outstanding query', () => {
    const packets = [
      packet(1, 0, CLIENT, 41000, RESOLVER, 53),
      packet(2, 0.01, RESOLVER, 53, CLIENT, 41000),
    ];
    const rows = correlate([
      message(1, false, 'one.example', 'A'),
      message(2, true, 'one.example', 'AAAA'),
    ], packets);
    expect(rows.map((row) => [row.qname, row.qtype, row.status])).toEqual([
      ['one.example', 'A', 'unanswered'],
      ['one.example', 'AAAA', 'response without query'],
    ]);
  });

  it('keeps a retransmission of the same question as one row', () => {
    const packets = [
      packet(1, 0, CLIENT, 41000, RESOLVER, 53),
      packet(2, 0.01, CLIENT, 41000, RESOLVER, 53),
      packet(3, 0.02, RESOLVER, 53, CLIENT, 41000),
    ];
    const rows = correlate([
      message(1, false, 'one.example', 'A'),
      message(2, false, 'one.example', 'A'),
      message(3, true, 'one.example', 'A'),
    ], packets);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ status: 'answered', queryFrame: 1, responseFrame: 3, frames: [1, 3] });
    expect(rows[1]).toMatchObject({ status: 'retransmitted', relatedTo: rows[0].id, queryFrame: 2, responseFrame: null, frames: [2] });
  });

  it('still marks a second answer for the same name as a duplicate response', () => {
    const packets = [
      packet(1, 0, CLIENT, 41000, RESOLVER, 53),
      packet(2, 0.01, RESOLVER, 53, CLIENT, 41000),
      packet(3, 0.02, RESOLVER, 53, CLIENT, 41000),
    ];
    const rows = correlate([
      message(1, false, 'one.example', 'A'),
      message(2, true, 'one.example', 'A'),
      message(3, true, 'one.example', 'A'),
    ], packets);
    expect(rows[0]).toMatchObject({ status: 'answered', responseFrame: 2 });
    expect(rows[1]).toMatchObject({ status: 'duplicate response', relatedTo: rows[0].id, qname: 'one.example', responseFrame: 3, frames: [3] });
  });

  it('leaves mDNS queries and responses unpaired', () => {
    const packets = [
      packet(1, 0, CLIENT, 5353, '224.0.0.251', 5353, 'eth:ip:udp:mdns'),
      packet(2, 0.01, CLIENT, 5353, '224.0.0.251', 5353, 'eth:ip:udp:mdns'),
    ];
    const rows = correlate([
      message(1, false, 'one.example', 'A', 'mdns'),
      message(2, true, 'one.example', 'A', 'mdns'),
    ], packets);
    expect(rows.map((row) => [row.proto, row.status, row.queryFrame, row.responseFrame])).toEqual([
      ['mDNS', 'multicast query', 1, null],
      ['mDNS', 'multicast response', null, 2],
    ]);
  });
});
