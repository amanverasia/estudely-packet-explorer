// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Correlates DNS-family packet records into query/response transactions.
import type { DnsAnswer, DnsProto, DnsTransaction } from './types';
import type { RawDns, RawNbns, RawPacket } from './records';
import { hasProto, isGroupAddress } from './analysis-utils';

interface DnsMsg {
  proto: DnsProto;
  frame: number;
  isResponse: boolean;
  txid: number | null;
  opcode: number | null;
  rcode: number | null;
  qname: string | null;
  qtype: string | null;
  answers: DnsAnswer[];
  truncatedFlag: boolean;
}

/** A response is matched to a query only within this window (seconds). */
export const DNS_MATCH_WINDOW = 60;

const DNS_RCODES = ['NoError', 'FormErr', 'ServFail', 'NXDomain', 'NotImp', 'Refused', 'YXDomain', 'YXRRSet', 'NXRRSet', 'NotAuth', 'NotZone', 'DSOTYPENI'];
const NBNS_RCODES = ['OK', 'FMT_ERR', 'SRV_ERR', 'NAM_ERR', 'IMP_ERR', 'RFS_ERR', 'ACT_ERR', 'CFT_ERR'];

function rcodeName(proto: DnsProto, code: number | null): string | null {
  if (code === null) return null;
  const table = proto === 'NBNS' ? NBNS_RCODES : DNS_RCODES;
  return table[code] ?? `RCODE ${code}`;
}

/** "A (1)" -> "A" */
function shortType(type: string | null): string | null {
  if (!type) return type;
  return type.replace(/\s*\(\d+\)$/, '');
}

export function correlateDns(
  rawDns: RawDns[], rawNbns: RawNbns[], pkt: (frame: number) => RawPacket | undefined, segs: (frame: number) => number[],
  convOfFrame: (frame: number) => number | null,
): DnsTransaction[] {
  const msgs: DnsMsg[] = [];
  const sectionName = (section: string): DnsAnswer['section'] => (section === 'an' ? 'answer' : section === 'ns' ? 'authority' : 'additional');
  for (const d of rawDns) {
    msgs.push({
      proto: d.proto === 'mdns' ? 'mDNS' : d.proto === 'llmnr' ? 'LLMNR' : 'DNS',
      frame: d.frame, isResponse: d.isResponse, txid: d.id, opcode: d.opcode, rcode: d.isResponse ? d.rcode : null,
      qname: d.qname, qtype: shortType(d.qtype),
      answers: d.rrs.filter((record) => !/^OPT\b/.test(record.type)).map((record) => ({ section: sectionName(record.section), name: record.name, type: shortType(record.type) ?? '', ttl: record.ttl, value: record.value })),
      truncatedFlag: d.truncated,
    });
  }
  for (const n of rawNbns) {
    const name = n.names[0]?.replace(/\s*\(.*\)$/, '') ?? null;
    msgs.push({
      proto: 'NBNS', frame: n.frame, isResponse: n.isResponse, txid: n.id, opcode: n.opcode,
      rcode: n.isResponse ? n.rcode : null, qname: name, qtype: shortType(n.qtype),
      answers: n.isResponse && n.addrs.length ? [{ section: 'answer', name: name ?? '', type: 'NB', ttl: null, value: n.addrs.join(', ') }] : [],
      truncatedFlag: false,
    });
  }
  msgs.sort((a, b) => a.frame - b.frame);

  const out: DnsTransaction[] = [];
  const pending = new Map<string, DnsTransaction[]>();
  const answered = new Map<string, DnsTransaction>();
  for (const m of msgs) {
    const p = pkt(m.frame);
    if (!p) continue;
    const transport: 'UDP' | 'TCP' = hasProto(p.protos, 'tcp') ? 'TCP' : 'UDP';
    const malformed = p.flags.includes('M');
    const base = {
      proto: m.proto, transport, convId: convOfFrame(m.frame), txid: m.txid, qname: m.qname, qtype: m.qtype,
      opcode: m.opcode, truncatedFlag: m.truncatedFlag, malformed,
    };
    if (m.proto === 'mDNS') {
      out.push({
        ...base, id: out.length, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        queryFrame: m.isResponse ? null : m.frame, queryTime: m.isResponse ? null : p.t,
        responseFrame: m.isResponse ? m.frame : null, responseTime: m.isResponse ? p.t : null, rtt: null,
        rcode: rcodeName(m.proto, m.rcode), answers: m.answers, status: m.isResponse ? 'multicast response' : 'multicast query',
        relatedTo: null, frames: segs(m.frame),
      });
      continue;
    }
    if (!m.isResponse) {
      const key = [m.proto, transport, p.src, p.sport, m.txid].join('|');
      const list = pending.get(key) ?? [];
      const original = list.find((query) => query.qname === m.qname && query.qtype === m.qtype && query.server === p.dst && query.status === 'unanswered');
      const tx: DnsTransaction = {
        ...base, id: out.length, client: p.src, clientPort: p.sport, server: p.dst, serverPort: p.dport,
        queryFrame: m.frame, queryTime: p.t, responseFrame: null, responseTime: null, rtt: null, rcode: null,
        answers: [], status: original ? 'retransmitted' : 'unanswered', relatedTo: original ? original.id : null,
        frames: segs(m.frame),
      };
      out.push(tx);
      if (!original) {
        list.push(tx);
        pending.set(key, list);
      }
      continue;
    }
    // response: the client is the destination
    const key = [m.proto, transport, p.dst, p.dport, m.txid].join('|');
    const list = pending.get(key);
    let idx = -1;
    if (list) {
      idx = list.findIndex((query) => (query.server === p.src || isGroupAddress(query.server))
        && query.queryTime !== null && query.queryTime <= p.t && p.t - query.queryTime <= DNS_MATCH_WINDOW);
    }
    if (idx >= 0) {
      const tx = list![idx];
      list!.splice(idx, 1);
      tx.responseFrame = m.frame;
      tx.responseTime = p.t;
      tx.rtt = p.t - (tx.queryTime ?? p.t);
      tx.rcode = rcodeName(m.proto, m.rcode);
      tx.answers = m.answers;
      tx.status = 'answered';
      tx.malformed = tx.malformed || malformed;
      tx.truncatedFlag = m.truncatedFlag;
      if (isGroupAddress(tx.server)) { tx.server = p.src; tx.serverPort = p.sport; }
      tx.frames = [...new Set([...tx.frames, ...segs(m.frame)])].sort((a, b) => a - b);
      answered.set(key, tx);
      continue;
    }
    const prev = answered.get(key);
    const dup = prev && prev.qname === m.qname && prev.server === p.src && prev.responseTime !== null && p.t - prev.responseTime <= DNS_MATCH_WINDOW;
    out.push({
      ...base, id: out.length, client: p.dst, clientPort: p.dport, server: p.src, serverPort: p.sport,
      queryFrame: null, queryTime: null, responseFrame: m.frame, responseTime: p.t, rtt: null,
      rcode: rcodeName(m.proto, m.rcode), answers: m.answers,
      status: dup ? 'duplicate response' : 'response without query', relatedTo: dup ? prev!.id : null,
      frames: segs(m.frame),
    });
  }
  return out;
}
