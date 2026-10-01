import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import { select } from 'd3-selection';
import { zoom, zoomIdentity } from 'd3-zoom';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Legend, colorMap } from '../components/charts';
import { Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { bytes, num, plural } from '../format';

interface GNode extends SimulationNodeDatum { id: string; bytes: number; packets: number; other: number; scope: string }
interface GEdge extends SimulationLinkDatum<GNode> { key: string; a: string; b: string; bytes: number; packets: number; convs: number[]; protos: Map<string, number>; top: string }

const OTHER_NODE = 'Other hosts';

export function Network() {
  const { model, params, go, nameOf } = useApp();
  const [proto, setProto] = useState('all');
  const [focus, setFocus] = useState<string>(params.get('host') ?? '');
  const [limit, setLimit] = useState(60);
  const [sel, setSel] = useState<{ kind: 'node'; id: string } | { kind: 'edge'; key: string } | null>(params.get('host') ? { kind: 'node', id: params.get('host')! } : null);
  const svgRef = useRef<SVGSVGElement>(null);
  const gRef = useRef<SVGGElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  const protoOptions = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of model.conversations) if (c.transport !== 'Non-IP') m.set(c.appProtocol, (m.get(c.appProtocol) ?? 0) + c.bytesAB + c.bytesBA);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
  }, [model.conversations]);
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
      const k = Math.min(2, 0.95 / Math.max((maxX - minX) / layout.w, (maxY - minY) / layout.h));
      svg.call(z.transform, zoomIdentity.translate(layout.w / 2 - k * (minX + maxX) / 2, layout.h / 2 - k * (minY + maxY) / 2).scale(k));
    }
    return () => { svg.on('.zoom', null); };
  }, [layout]);

  const maxB = Math.max(1, ...graph.nodes.map((n) => n.bytes));
  const maxE = Math.max(1, ...graph.edges.map((e) => e.bytes));
  const hosts = useMemo(() => [...model.hosts].sort((a, b) => a.addr.localeCompare(b.addr, undefined, { numeric: true })), [model.hosts]);
  const selNode = sel?.kind === 'node' ? graph.nodes.find((n) => n.id === sel.id) : null;
  const selEdge = sel?.kind === 'edge' ? graph.edges.find((e) => e.key === sel.key) : null;
  const neighbours = useMemo(() => {
    if (!selNode) return null;
    const s = new Set<string>([selNode.id]);
    for (const e of graph.edges) if (e.a === selNode.id || e.b === selNode.id) { s.add(e.a); s.add(e.b); }
    return s;
  }, [selNode, graph.edges]);

  return (
    <>
      <ViewHead title="Network">Hosts linked by the traffic between them. Line width scales with bytes on wire (log scale); line colour is the pair's main protocol by bytes. Node size scales with the host's total bytes.</ViewHead>
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
            <svg ref={svgRef} role="img" aria-label="Host-to-host traffic graph. Use the tables in Hosts and Connections for an accessible equivalent." onClick={(e) => { if (e.target === svgRef.current) setSel(null); }}>
              <g ref={gRef}>
                {layout?.edges.map((e) => {
                  const s = e.source as GNode, t = e.target as GNode;
                  const dim = neighbours ? !(neighbours.has(e.a) && neighbours.has(e.b) && (e.a === selNode!.id || e.b === selNode!.id)) : selEdge ? selEdge.key !== e.key : false;
                  return (
                    <g key={e.key} onClick={() => setSel({ kind: 'edge', key: e.key })} style={{ cursor: 'pointer' }}>
                      <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke="transparent" strokeWidth={12} />
                      <line x1={s.x} y1={s.y} x2={t.x} y2={t.y} stroke={colorOf(e.top)} strokeOpacity={dim ? 0.12 : 0.75}
                        strokeWidth={1 + 7 * (Math.log1p(e.bytes) / Math.log1p(maxE))} strokeLinecap="round">
                        <title>{`${e.a} ↔ ${e.b}: ${bytes(e.bytes)}, ${e.top}`}</title>
                      </line>
                    </g>
                  );
                })}
                {layout?.nodes.map((n) => {
                  const r = radius(n.bytes, maxB);
                  const dim = neighbours ? !neighbours.has(n.id) : false;
                  const isSel = selNode?.id === n.id;
                  const label = n.id === OTHER_NODE ? `${OTHER_NODE} (${n.other})` : nameOf(n.id) ?? n.id;
                  return (
                    <g key={n.id} className="graph-node" transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.25 : 1}
                      onClick={(ev) => { ev.stopPropagation(); setSel({ kind: 'node', id: n.id }); }} style={{ cursor: 'pointer' }}
                      tabIndex={0} role="button" aria-label={`${label}, ${bytes(n.bytes)}`}
                      onKeyDown={(ev) => { if (ev.key === 'Enter') setSel({ kind: 'node', id: n.id }); }}>
                      <circle r={r} fill={n.id === OTHER_NODE ? 'var(--s-other)' : n.scope === 'multicast' || n.scope === 'broadcast' ? 'var(--panel)' : 'var(--accent)'}
                        stroke={isSel ? 'var(--ink)' : n.scope === 'multicast' || n.scope === 'broadcast' ? 'var(--ink-3)' : 'var(--panel)'} strokeWidth={isSel ? 2.5 : 2}
                        strokeDasharray={n.scope === 'multicast' || n.scope === 'broadcast' ? '3 2' : undefined} />
                      <text x={r + 4} dy="0.32em">{label.length > 28 ? label.slice(0, 27) + '…' : label}</text>
                    </g>
                  );
                })}
              </g>
            </svg>
          )}
          {(selNode || selEdge) && (
            <div className="graph-side">
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
      <p className="muted" style={{ fontSize: 12 }}>Drag to pan, scroll or pinch to zoom. Dashed nodes are multicast or broadcast addresses. Non-IP traffic (such as ARP) is not shown.</p>
    </>
  );
}

function radius(b: number, max: number): number {
  return 5 + 15 * Math.sqrt(b / max);
}

function NodeDetail({ id, n, edges, onFocus, go }: { id: string; n: GNode; edges: GEdge[]; onFocus: () => void; go: (v: string, p?: Record<string, string>) => void }) {
  const { nameOf } = useApp();
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
        </div>
      )}
    </>
  );
}
