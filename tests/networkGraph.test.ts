// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { buildNetworkGraph, networkNodeRadius, networkProtoOptions, NETWORK_OTHER_NODE } from '../src/app/views/networkGraph';
import type { Conversation, Host } from '../src/engine/types';

function conv(partial: Partial<Conversation> & { id: number; a: string; b: string }): Conversation {
  return {
    transport: 'TCP', appProtocol: 'TLS', packetsAB: 1, bytesAB: 100, packetsBA: 1, bytesBA: 100,
    ...partial,
  } as Conversation;
}

function host(addr: string, scope = 'unicast'): Host {
  return { addr, scope } as Host;
}

const hosts = [host('10.0.0.1'), host('10.0.0.2'), host('10.0.0.3'), host('10.0.0.4')];

describe('network graph data-prep', () => {
  it('excludes Non-IP traffic and filters by protocol and focus host', () => {
    const conversations = [
      conv({ id: 1, a: '10.0.0.1', b: '10.0.0.2', appProtocol: 'DNS' }),
      conv({ id: 2, a: '10.0.0.1', b: '10.0.0.3', appProtocol: 'TLS', transport: 'Non-IP' }),
      conv({ id: 3, a: '10.0.0.1', b: '10.0.0.4', appProtocol: 'TLS' }),
    ];
    const all = buildNetworkGraph(conversations, hosts, { proto: 'all', focus: '', limit: 60 });
    expect(all.nodes.map((n) => n.id).sort()).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.4']);
    const tls = buildNetworkGraph(conversations, hosts, { proto: 'TLS', focus: '', limit: 60 });
    expect(tls.nodes.map((n) => n.id).sort()).toEqual(['10.0.0.1', '10.0.0.4']);
    const focused = buildNetworkGraph(conversations, hosts, { proto: 'all', focus: '10.0.0.2', limit: 60 });
    expect(focused.nodes.map((n) => n.id).sort()).toEqual(['10.0.0.1', '10.0.0.2']);
    expect(focused.edges).toHaveLength(1);
  });

  it('folds smaller hosts into the Other node and skips self-folded edges', () => {
    const conversations = [
      conv({ id: 1, a: '10.0.0.1', b: '10.0.0.2', bytesAB: 5000, bytesBA: 5000 }),
      conv({ id: 2, a: '10.0.0.1', b: '10.0.0.3', bytesAB: 10, bytesBA: 10 }),
      conv({ id: 3, a: '10.0.0.3', b: '10.0.0.4', bytesAB: 5, bytesBA: 5 }),
    ];
    const graph = buildNetworkGraph(conversations, hosts, { proto: 'all', focus: '', limit: 2 });
    expect(graph.folded).toBe(2);
    const other = graph.nodes.find((n) => n.id === NETWORK_OTHER_NODE);
    expect(other?.other).toBe(2);
    expect(other?.scope).toBe('aggregate');
    // 10.0.0.3 <-> 10.0.0.4 both fold to Other, so that conversation contributes no edge.
    expect(graph.edges).toHaveLength(2);
    const totals = graph.nodes.reduce((n, node) => n + node.bytes, 0);
    const convTotal = conversations.reduce((n, c) => n + (c.bytesAB + c.bytesBA) * 2, 0);
    expect(totals).toBe(convTotal);
  });

  it('keeps a focused host outside the top limit', () => {
    const conversations = [
      conv({ id: 1, a: '10.0.0.1', b: '10.0.0.2', bytesAB: 9000, bytesBA: 0 }),
      conv({ id: 2, a: '10.0.0.3', b: '10.0.0.4', bytesAB: 1, bytesBA: 1 }),
    ];
    const graph = buildNetworkGraph(conversations, hosts, { proto: 'all', focus: '10.0.0.4', limit: 1 });
    // Focus also scopes the conversation list, so only the 10.0.0.3 link remains;
    // both of its hosts are kept and nothing folds.
    expect(graph.nodes.map((n) => n.id).sort()).toEqual(['10.0.0.3', '10.0.0.4']);
    expect(graph.folded).toBe(0);
  });

  it('merges parallel conversations into one edge with the top protocol', () => {
    const conversations = [
      conv({ id: 7, a: '10.0.0.2', b: '10.0.0.1', appProtocol: 'DNS', bytesAB: 100, bytesBA: 100 }),
      conv({ id: 8, a: '10.0.0.1', b: '10.0.0.2', appProtocol: 'TLS', bytesAB: 1000, bytesBA: 1000 }),
    ];
    const graph = buildNetworkGraph(conversations, hosts, { proto: 'all', focus: '', limit: 60 });
    expect(graph.edges).toHaveLength(1);
    const edge = graph.edges[0];
    expect(edge.a).toBe('10.0.0.1');
    expect(edge.b).toBe('10.0.0.2');
    expect(edge.bytes).toBe(2200);
    expect(edge.packets).toBe(4);
    expect(edge.convs.sort()).toEqual([7, 8]);
    expect(edge.top).toBe('TLS');
    expect(edge.protos.get('TLS')).toBe(2000);
    expect(edge.protos.get('DNS')).toBe(200);
  });

  it('maps host scopes and marks unknown hosts', () => {
    const conversations = [conv({ id: 1, a: '10.0.0.1', b: '9.9.9.9' })];
    const graph = buildNetworkGraph(conversations, [host('10.0.0.1', 'private')], { proto: 'all', focus: '', limit: 60 });
    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    expect(byId.get('10.0.0.1')?.scope).toBe('private');
    expect(byId.get('9.9.9.9')?.scope).toBe('unknown');
  });

  it('orders protocol options by bytes and skips Non-IP', () => {
    const conversations = [
      conv({ id: 1, a: 'a', b: 'b', appProtocol: 'DNS', bytesAB: 50, bytesBA: 50 }),
      conv({ id: 2, a: 'a', b: 'c', appProtocol: 'TLS', bytesAB: 500, bytesBA: 500 }),
      conv({ id: 3, a: 'a', b: 'd', appProtocol: 'ARP', transport: 'Non-IP' }),
    ];
    expect(networkProtoOptions(conversations)).toEqual(['TLS', 'DNS']);
  });

  it('scales node radius from 5px to 20px', () => {
    expect(networkNodeRadius(100, 100)).toBe(20);
    expect(networkNodeRadius(0, 100)).toBe(5);
    expect(networkNodeRadius(25, 100)).toBeCloseTo(12.5, 10);
  });
});
