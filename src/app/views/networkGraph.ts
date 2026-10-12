// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Pure data-prep for the Network host graph. Extracted from Network.tsx so the
// ranking, Other-hosts folding and edge aggregation are unit-testable without
// rendering. Network.tsx remains the only caller; behaviour is unchanged.
import type { Conversation, Host } from '../../engine/types';

export const NETWORK_OTHER_NODE = 'Other hosts';

export interface NetworkGraphNode {
  id: string;
  bytes: number;
  packets: number;
  other: number;
  scope: string;
}

export interface NetworkGraphEdge {
  key: string;
  a: string;
  b: string;
  source: string;
  target: string;
  bytes: number;
  packets: number;
  convs: number[];
  protos: Map<string, number>;
  top: string;
}

export interface NetworkGraph {
  nodes: NetworkGraphNode[];
  edges: NetworkGraphEdge[];
  folded: number;
}

export interface NetworkGraphOptions {
  proto: string;
  focus: string;
  limit: number;
}

export function networkNodeRadius(b: number, max: number): number {
  return 5 + 15 * Math.sqrt(b / max);
}

export function networkProtoOptions(conversations: readonly Conversation[]): string[] {
  const m = new Map<string, number>();
  for (const c of conversations) {
    if (c.transport !== 'Non-IP') m.set(c.appProtocol, (m.get(c.appProtocol) ?? 0) + c.bytesAB + c.bytesBA);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
}

export function buildNetworkGraph(
  conversations: readonly Conversation[],
  hosts: readonly Host[],
  opts: NetworkGraphOptions,
): NetworkGraph {
  const proto = opts.proto;
  const focus = opts.focus;
  const limit = opts.limit;
  const convs = conversations.filter(
    (c) => c.transport !== 'Non-IP' && (proto === 'all' || c.appProtocol === proto)
      && (!focus || c.a === focus || c.b === focus),
  );
  const nodeAcc = new Map<string, { bytes: number; packets: number }>();
  for (const c of convs) {
    const v = c.bytesAB + c.bytesBA;
    const p = c.packetsAB + c.packetsBA;
    for (const h of [c.a, c.b]) {
      const n = nodeAcc.get(h) ?? { bytes: 0, packets: 0 };
      n.bytes += v;
      n.packets += p;
      nodeAcc.set(h, n);
    }
  }
  const ranked = [...nodeAcc.entries()].sort((a, b) => b[1].bytes - a[1].bytes);
  const keep = new Set(ranked.slice(0, limit).map((e) => e[0]));
  if (focus) keep.add(focus);
  const folded = ranked.length - [...keep].filter((k) => nodeAcc.has(k)).length;
  const nodes = new Map<string, NetworkGraphNode>();
  const scopeOf = new Map(hosts.map((h) => [h.addr, h.scope]));
  for (const [id, v] of ranked) {
    const target = keep.has(id) ? id : NETWORK_OTHER_NODE;
    const n = nodes.get(target) ?? {
      id: target, bytes: 0, packets: 0, other: 0,
      scope: target === NETWORK_OTHER_NODE ? 'aggregate' : (scopeOf.get(id) ?? 'unknown'),
    };
    n.bytes += v.bytes;
    n.packets += v.packets;
    if (target === NETWORK_OTHER_NODE) n.other++;
    nodes.set(target, n);
  }
  const edges = new Map<string, NetworkGraphEdge>();
  for (const c of convs) {
    const a = keep.has(c.a) ? c.a : NETWORK_OTHER_NODE;
    const b = keep.has(c.b) ? c.b : NETWORK_OTHER_NODE;
    if (a === b) continue;
    const pair = a < b ? [a, b] : [b, a];
    const x = pair[0];
    const y = pair[1];
    const key = x + '\u0000' + y;
    let e = edges.get(key);
    if (!e) {
      e = { key, a: x, b: y, source: x, target: y, bytes: 0, packets: 0, convs: [], protos: new Map(), top: '' };
      edges.set(key, e);
    }
    e.bytes += c.bytesAB + c.bytesBA;
    e.packets += c.packetsAB + c.packetsBA;
    e.convs.push(c.id);
    e.protos.set(c.appProtocol, (e.protos.get(c.appProtocol) ?? 0) + c.bytesAB + c.bytesBA);
    edges.set(key, e);
  }
  for (const e of edges.values()) e.top = [...e.protos.entries()].sort((a, b) => b[1] - a[1])[0][0];
  return { nodes: [...nodes.values()], edges: [...edges.values()], folded };
}
