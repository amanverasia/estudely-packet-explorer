// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import { select } from 'd3-selection';
import { zoom, zoomIdentity } from 'd3-zoom';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Legend, colorMap } from '../components/charts';
import { Panel, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { placeLabels, type LabelPlacement } from '../labels';
import { bytes, num, plural } from '../format';

interface GNode extends SimulationNodeDatum { id: string; bytes: number; packets: number; other: number; scope: string }
interface GEdge extends SimulationLinkDatum<GNode> { key: string; a: string; b: string; bytes: number; packets: number; convs: number[]; protos: Map<string, number>; top: string }

const OTHER_NODE = 'Other hosts';

export function Network() {
  const { model, sourceModel, params, go, nameOf, filter } = useApp();
  const [proto, setProto] = useViewState<string>('network.protocol', 'all', (value): value is string =>
    value === 'all' || (typeof value === 'string' && sourceModel.conversations.some((conversation) => conversation.transport !== 'Non-IP' && conversation.appProtocol === value)));
  const [focus, setFocus] = useViewState<string>('network.focus', '', (value): value is string => typeof value === 'string');
  const [limit, setLimit] = useViewState<number>('network.limit', 60, (value): value is number => value === 20 || value === 40 || value === 60 || value === 100 || value === 150 || value === 250);
  const [sel, setSel] = useViewState<{ kind: 'node'; id: string } | { kind: 'edge'; key: string } | null>('network.selection', null,
    (value): value is { kind: 'node'; id: string } | { kind: 'edge'; key: string } | null => value === null || (typeof value === 'object' && value !== null &&
      ((value as { kind?: unknown }).kind === 'node' && typeof (value as { id?: unknown }).id === 'string' ||
       (value as { kind?: unknown }).kind === 'edge' && typeof (value as { key?: unknown }).key === 'string')));
  const lastRouteHost = useRef<string | null>(null);
  useEffect(() => {
    if (!params.has('host')) { lastRouteHost.current = null; return; }
    const requested = params.get('host') || '';
    if (requested !== lastRouteHost.current) {
      lastRouteHost.current = requested;
      const host = requested && sourceModel.hosts.some((h) => h.addr === requested) ? requested : '';
      setFocus(host);
      setSel(host ? { kind: 'node', id: host } : null);
    }
  }, [params, sourceModel.hosts, setFocus, setSel]);
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  const protoOptions = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of sourceModel.conversations) if (c.transport !== 'Non-IP') m.set(c.appProtocol, (m.get(c.appProtocol) ?? 0) + c.bytesAB + c.bytesBA);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
  }, [sourceModel.conversations]);
  const colors = useMemo(() => colorMap([...protoOptions.slice(0, 7), 'Other']), [protoOptions]);
  const colorOf = (p: string) => colors.get(p) ?? colors.get('Other')!;

  const graph = useMemo(() => {
    const convs = model.conversations.filter((c) => c.transport !== 'Non-IP' && (proto === 'all' || c.appProtocol === proto)
      && (!focus || c.a === focus || c.b === focus));
    const nodeAcc = new Map<string, { bytes: number; packets: number }>();
    for (const c of convs) {
      const v = c.bytesAB + c.bytesBA, p = c.packetsAB + c.packetsBA;
      for (const h of [c.a, c.b]) {
        const n = nodeAcc.get(h) ?? { bytes: 0, packets: 0 };
        n.bytes += v; n.packets += p;
        nodeAcc.set(h, n);
      }
    }
    const ranked = [...nodeAcc.entries()].sort((a, b) => b[1].bytes - a[1].bytes);
    const keep = new Set(ranked.slice(0, limit).map((e) => e[0]));
    if (focus) keep.add(focus);
    const folded = ranked.length - [...keep].filter((k) => nodeAcc.has(k)).length;
    const nodes = new Map<string, GNode>();
    const scopeOf = new Map(model.hosts.map((h) => [h.addr, h.scope]));
    for (const [id, v] of ranked) {
      const target = keep.has(id) ? id : OTHER_NODE;
      const n = nodes.get(target) ?? { id: target, bytes: 0, packets: 0, other: 0, scope: target === OTHER_NODE ? 'aggregate' : scopeOf.get(id) ?? 'unknown' };
      n.bytes += v.bytes; n.packets += v.packets;
      if (target === OTHER_NODE) n.other++;
      nodes.set(target, n);
    }
    const edges = new Map<string, GEdge>();
    for (const c of convs) {
      const a = keep.has(c.a) ? c.a : OTHER_NODE;
      const b = keep.has(c.b) ? c.b : OTHER_NODE;
      if (a === b) continue;
      const [x, y] = a < b ? [a, b] : [b, a];
      const key = x + '\u0000' + y;
      const e: GEdge = edges.get(key) ?? { key, a: x, b: y, source: x, target: y, bytes: 0, packets: 0, convs: [], protos: new Map(), top: '' };
      e.bytes += c.bytesAB + c.bytesBA;
      e.packets += c.packetsAB + c.packetsBA;
      e.convs.push(c.id);
      e.protos.set(c.appProtocol, (e.protos.get(c.appProtocol) ?? 0) + c.bytesAB + c.bytesBA);
      edges.set(key, e);
    }
    for (const e of edges.values()) e.top = [...e.protos.entries()].sort((a, b) => b[1] - a[1])[0][0];
    return { nodes: [...nodes.values()], edges: [...edges.values()], folded };
  }, [model.conversations, model.hosts, proto, focus, limit]);

  const [layout, setLayout] = useState<{ nodes: GNode[]; edges: GEdge[]; w: number; h: number } | null>(null);
  useEffect(() => {
    const w = wrapRef.current?.clientWidth ?? 900;
    const h = wrapRef.current?.clientHeight ?? 600;
    const nodes = graph.nodes.map((n) => ({ ...n }));
    const edges = graph.edges.map((e) => ({ ...e }));
    const maxB = Math.max(1, ...nodes.map((n) => n.bytes));
    const sim = forceSimulation<GNode>(nodes)
      .force('link', forceLink<GNode, GEdge>(edges).id((d) => d.id).distance(70).strength(0.4))
      .force('charge', forceManyBody().strength(-260))
      .force('center', forceCenter(w / 2, h / 2))
      .force('collide', forceCollide<GNode>((d) => radius(d.bytes, maxB) + 6))
      .stop();
    // Settle the layout up front: no continuous motion on screen.
    for (let i = 0; i < 300; i++) sim.tick();
    setLayout({ nodes, edges, w, h });
  }, [graph]);

  useEffect(() => {
    if (!svgRef.current || !gRef.current || !layout) return;
    const svg = select(svgRef.current);
    const g = select(gRef.current);
    const z = zoom<SVGSVGElement, unknown>().scaleExtent([0.2, 6]).on('zoom', (ev) => g.attr('transform', ev.transform.toString()));
    svg.call(z);
    // Fit the settled layout into view.
    const xs = layout.nodes.map((n) => n.x ?? 0), ys = layout.nodes.map((n) => n.y ?? 0);
    if (xs.length) {
      const minX = Math.min(...xs) - 40, maxX = Math.max(...xs) + 40, minY = Math.min(...ys) - 40, maxY = Math.max(...ys) + 40;
      const k = Math.min(1.2, 0.95 / Math.max((maxX - minX) / layout.w, (maxY - minY) / layout.h));
      svg.call(z.transform, zoomIdentity.translate(layout.w / 2 - k * (minX + maxX) / 2, layout.h / 2 - k * (minY + maxY) / 2).scale(k));
    }
    return () => { svg.on('.zoom', null); };
  }, [layout]);

  const maxB = Math.max(1, ...graph.nodes.map((n) => n.bytes));
  const labelOf = (n: GNode) => (n.id === OTHER_NODE ? `${OTHER_NODE} (${n.other})` : nameOf(n.id) ?? n.id);
  const shortLabel = (l: string) => (l.length > 28 ? l.slice(0, 27) + '…' : l);
  const labels = useMemo(() => {
    if (!layout) return new Map<string, LabelPlacement>();
    const lmax = Math.max(1, ...layout.nodes.map((n) => n.bytes));
    return placeLabels(
      layout.nodes.map((n) => ({ id: n.id, x: n.x ?? 0, y: n.y ?? 0, r: radius(n.bytes, lmax), label: shortLabel(labelOf(n)) })),
      layout.edges.map((e) => { const s = e.source as GNode, t = e.target as GNode; return { x1: s.x ?? 0, y1: s.y ?? 0, x2: t.x ?? 0, y2: t.y ?? 0 }; }),
    );
  }, [layout]); // eslint-disable-line react-hooks/exhaustive-deps
  const maxE = Math.max(1, ...graph.edges.map((e) => e.bytes));
  const hosts = useMemo(() => [...model.hosts].sort((a, b) => a.addr.localeCompare(b.addr, undefined, { numeric: true })), [model.hosts]);
  const selNode = sel?.kind === 'node' ? graph.nodes.find((n) => n.id === sel.id) : null;
  const selEdge = sel?.kind === 'edge' ? graph.edges.find((e) => e.key === sel.key) : null;
  const orderedEdges = useMemo(() => [...graph.edges].sort((a, b) => b.bytes - a.bytes), [graph.edges]);
  const edgeLabel = (id: string) => id === OTHER_NODE
    ? `${OTHER_NODE} (${num(graph.nodes.find((n) => n.id === OTHER_NODE)?.other ?? 0)} hosts)`
    : nameOf(id) ? `${nameOf(id)} (${id})` : id;
  const openEdge = (e: GEdge) => {
    if (e.convs.length === 1) go('connections', { conv: String(e.convs[0]) });
    else if (e.a !== OTHER_NODE) go('connections', { host: e.a });
    else if (e.b !== OTHER_NODE) go('connections', { host: e.b });
    else go('connections');
  };

  return (
    <>
      <ViewHead title="Network">Hosts linked by the traffic between them. Line width scales with bytes on wire (log scale); line colour is the pair's main protocol by bytes. Node size scales with the host's total bytes.{filter.start !== null || filter.host ? ' Totals reflect the selected packets.' : ''}</ViewHead>
      <Panel title="Host graph" sub={`${plural(graph.nodes.length, 'node')}, ${plural(graph.edges.length, 'link')}${graph.folded ? `; ${num(graph.folded)} smaller hosts grouped as “${OTHER_NODE}”` : ''}`}
        right={<>
          <select className="select" value={proto} onChange={(e) => setProto(e.target.value)} aria-label="Protocol filter">
            <option value="all">All protocols</option>
            {protoOptions.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select className="select" value={focus} onChange={(e) => { setFocus(e.target.value); setSel(e.target.value ? { kind: 'node', id: e.target.value } : null); }} aria-label="Focus on host" style={{ maxWidth: 220 }}>
            <option value="">All hosts</option>
            {hosts.map((h) => <option key={h.addr} value={h.addr}>{h.addr}{nameOf(h.addr) ? ` (${nameOf(h.addr)})` : ''}</option>)}
          </select>
          <label className="muted" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12 }}>
            Max nodes
            <select className="select" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {[20, 40, 60, 100, 150, 250].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
        </>} flush>
        <div style={{ padding: '0 16px 10px' }}>
          <Legend items={[...protoOptions.slice(0, 7), ...(protoOptions.length > 7 ? ['Other'] : [])].map((k) => ({ key: k, color: colorOf(k) }))} />
        </div>
        <div className="graph-wrap" ref={wrapRef}>
          {!graph.nodes.length ? <div className="empty"><strong>No IP traffic matches these filters.</strong></div> : (
            <svg ref={svgRef} role="img" aria-label="Host-to-host traffic graph. A host link list follows the graph." onClick={(e) => { if (e.target === svgRef.current) setSel(null); }}>
              <g ref={gRef}>
                {layout?.edges.map((e) => {
                  const s = e.source as GNode, t = e.target as GNode;
                  return (
                    <g key={e.key} onClick={() => setSel({ kind: 'edge', key: e.key })} style={{ cursor: 'pointer' }}>
                      <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="transparent" strokeWidth={12} />
                      <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={colorOf(e.top)}
                        strokeWidth={1 + 7 * (Math.log1p(e.bytes) / Math.log1p(maxE))} strokeLinecap="round">
                        <title>{`${e.a} ↔ ${e.b}: ${bytes(e.bytes)}, ${e.top}`}</title>
                      </line>
                    </g>
                  );
                })}
                {layout?.nodes.map((n) => {
                  const r = radius(n.bytes, maxB);
                  const isSel = selNode?.id === n.id;
                  const label = labelOf(n);
                  const at = labels.get(n.id) ?? { x: r + 4, y: 0, anchor: 'start' };
                  return (
                    <g key={n.id} className="graph-node" transform={`translate(${n.x},${n.y})`}
                      onClick={(ev) => { ev.stopPropagation(); setSel({ kind: 'node', id: n.id }); }} style={{ cursor: 'pointer' }}>
                      <circle r={r} fill={n.id === OTHER_NODE ? 'var(--s-other)' : n.scope === 'multicast' || n.scope === 'broadcast' ? 'var(--panel)' : 'var(--accent)'}
                        stroke={isSel ? 'var(--ink)' : n.scope === 'multicast' || n.scope === 'broadcast' ? 'var(--ink-3)' : 'var(--panel)'} strokeWidth={isSel ? 2.5 : 2}
                        strokeDasharray={n.scope === 'multicast' || n.scope === 'broadcast' ? '3 2' : undefined} />
                      <text x={at.x} y={at.y} dy="0.32em" textAnchor={at.anchor}>{shortLabel(label)}</text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}
          {(selNode || selEdge) && (
            <div className="graph-side" role="region" aria-label="Selected graph item details" aria-live="polite">
              {selNode && <NodeDetail id={selNode.id} n={selNode} edges={graph.edges} onFocus={() => setFocus(selNode.id === OTHER_NODE ? '' : selNode.id)} go={go} />}
              {selEdge && (
                <>
                  <h3 className="mono" style={{ overflowWrap: 'anywhere' }}>{selEdge.a} ↔ {selEdge.b}</h3>
                  <dl className="kv">
                    <dt>Traffic</dt><dd>{bytes(selEdge.bytes)}, {plural(selEdge.packets, 'packet')}</dd>
                    <dt>Conversations</dt><dd>{num(selEdge.convs.length)}</dd>
                    <dt>Protocols</dt><dd>{[...selEdge.protos.entries()].sort((a, b) => b[1] - a[1]).map(([p, v]) => `${p} ${bytes(v)}`).join(', ')}</dd>
                  </dl>
                  {selEdge.convs.length === 1 ? (
                    <button className="btn small" onClick={() => go('connections', { conv: String(selEdge.convs[0]) })}>Open conversation</button>
                  ) : selEdge.a !== OTHER_NODE && (
                    <button className="btn small" onClick={() => go('connections', { host: selEdge.a })}>Conversations of {selEdge.a}</button>
                  )}
                </>
              )}
              <button className="btn small ghost" onClick={() => setSel(null)}>Close details</button>
            </div>
          )}
        </div>
      </Panel>
      <details className="panel network-list">
        <summary>Host links as a list ({num(orderedEdges.length)})</summary>
        <p className="muted">This list follows the graph’s protocol and host filters. Smaller hosts may be grouped under “{OTHER_NODE}”.</p>
        {graph.nodes.length > 0 && <div className="network-table-wrap">
          <table className="network-table">
            <caption>Graph hosts. Inspect a host to access its traffic details, focus and filter actions.</caption>
            <thead><tr><th scope="col">Host</th><th scope="col">Traffic</th><th scope="col">Packets</th><th scope="col">Action</th></tr></thead>
            <tbody>{graph.nodes.map((node) => (
              <tr key={node.id}>
                <th scope="row">{edgeLabel(node.id)}</th><td>{bytes(node.bytes)}</td><td>{num(node.packets)}</td>
                <td><button className="btn small" aria-label={`Inspect host ${edgeLabel(node.id)}`} aria-pressed={selNode?.id === node.id} onClick={() => setSel({ kind: 'node', id: node.id })}>Inspect host</button></td>
              </tr>
            ))}</tbody>
          </table>
        </div>}
        {orderedEdges.length ? (
          <div className="network-table-wrap">
            <table className="network-table">
              <caption className="sr-only">Network graph links with endpoints, traffic totals, main protocol, and conversations</caption>
              <thead><tr><th scope="col">Hosts</th><th scope="col">Traffic</th><th scope="col">Packets</th><th scope="col">Main protocol</th><th scope="col">Conversations</th><th scope="col">Action</th></tr></thead>
              <tbody>{orderedEdges.map((e) => (
                <tr key={e.key}>
                  <th scope="row">{edgeLabel(e.a)} ↔ {edgeLabel(e.b)}</th>
                  <td>{bytes(e.bytes)}</td><td>{num(e.packets)}</td><td>{e.top}</td><td>{num(e.convs.length)}</td>
                  <td><div className="actions">
                    <button className="btn small" aria-label={`View conversations between ${edgeLabel(e.a)} and ${edgeLabel(e.b)}`} onClick={() => openEdge(e)}>{e.convs.length === 1 ? 'View conversation' : 'View conversations'}</button>
                    <button className="btn small" aria-label={`Inspect link between ${edgeLabel(e.a)} and ${edgeLabel(e.b)}`} aria-pressed={selEdge?.key === e.key} onClick={() => setSel({ kind: 'edge', key: e.key })}>Inspect link</button>
                  </div></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <p className="muted">No host links match these filters.</p>}
      </details>
      <p className="muted" style={{ fontSize: 12 }}>Drag to pan, scroll or pinch to zoom. Dashed nodes are multicast or broadcast addresses. Non-IP traffic (such as ARP) is not shown.</p>
    </>
  );
}

function radius(b: number, max: number): number {
  return 5 + 15 * Math.sqrt(b / max);
}

function NodeDetail({ id, n, edges, onFocus, go }: { id: string; n: GNode; edges: GEdge[]; onFocus: () => void; go: (v: string, p?: Record<string, string>) => void }) {
  const { nameOf, setHostFilter, filter } = useApp();
  const mine = edges.filter((e) => e.a === id || e.b === id).sort((a, b) => b.bytes - a.bytes);
  return (
    <>
      <h3 className="mono" style={{ overflowWrap: 'anywhere' }}>{id === OTHER_NODE ? `${OTHER_NODE} (${n.other} hosts)` : id}</h3>
      {nameOf(id) && <p className="muted">{nameOf(id)}</p>}
      <dl className="kv">
        <dt>Traffic shown</dt><dd>{bytes(n.bytes)}, {plural(n.packets, 'packet')}</dd>
        <dt>Linked to</dt><dd>{plural(mine.length, 'node')}</dd>
      </dl>
      <div style={{ display: 'grid', gap: 2, fontSize: 12 }}>
        {mine.slice(0, 8).map((e) => <div key={e.key} className="mono" style={{ overflowWrap: 'anywhere' }}>{e.a === id ? e.b : e.a} <span className="muted">{bytes(e.bytes)}</span></div>)}
      </div>
      {id !== OTHER_NODE && (
        <div className="actions">
          <button className="btn small" onClick={onFocus}>Focus</button>
          <button className="btn small" onClick={() => go('hosts', { host: id })}>Host details</button>
          <button className="btn small" onClick={() => setHostFilter(id)} aria-pressed={filter.host === id}>{filter.host === id ? 'Filtered across views' : 'Filter all views'}</button>
        </div>
      )}
    </>
  );
}
