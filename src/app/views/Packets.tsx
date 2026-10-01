// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useVirtualizer } from '@tanstack/react-virtual';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Note, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { num } from '../format';

const PAGE = 500;
const ROW = 30;

export function Packets() {
  const { engine, params, openDrawer, model } = useApp();
  const [draft, setDraft] = useState(params.get('filter') ?? '');
  const [filter, setFilter] = useState(params.get('filter') ?? '');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [matched, setMatched] = useState<number | null>(null);
  const [columns, setColumns] = useState<string[]>([]);
  const pages = useRef(new Map<number, { number: number; columns: string[] }[]>());
  const inflight = useRef(new Set<number>());
  const [, force] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const gen = useRef(0);

  const loadPage = useCallback((p: number, g: number) => {
    if (pages.current.has(p) || inflight.current.has(p)) return;
    inflight.current.add(p);
    engine.request({ kind: 'packetList', filter, skip: p * PAGE, limit: PAGE }).then((res) => {
      if (g !== gen.current) return;
      pages.current.set(p, res.rows);
      inflight.current.delete(p);
      setColumns(res.columns);
      setMatched(res.matched);
      force((x) => x + 1);
    }).catch((e: Error) => { if (g === gen.current) setError(e.message); });
  }, [engine, filter]);

  useEffect(() => {
    gen.current++;
    pages.current = new Map();
    inflight.current = new Set();
    setMatched(null);
    setError(null);
    setBusy(true);
    const g = gen.current;
    engine.request({ kind: 'packetList', filter, skip: 0, limit: PAGE }).then((res) => {
      if (g !== gen.current) return;
      pages.current.set(0, res.rows);
      setColumns(res.columns);
      setMatched(res.matched);
      setBusy(false);
    }).catch((e: Error) => { if (g === gen.current) { setError(e.message); setBusy(false); } });
  }, [engine, filter]);

  const apply = async () => {
    const f = draft.trim();
    if (f) {
      const r = await engine.request({ kind: 'checkFilter', filter: f });
      if (!r.ok) { setError(`Invalid display filter: ${r.error}`); return; }
    }
    setFilter(f);
  };

  const virt = useVirtualizer({ count: matched ?? 0, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 20 });
  const items = virt.getVirtualItems();
  useEffect(() => {
    if (!items.length) return;
    const first = Math.floor(items[0].index / PAGE);
    const last = Math.floor(items[items.length - 1].index / PAGE);
    for (let p = first; p <= last; p++) loadPage(p, gen.current);
  }, [items, loadPage]);

  const widths: Record<string, string> = { 'No.': '80px', Time: '120px', Source: 'minmax(150px, 1fr)', Destination: 'minmax(150px, 1fr)', Protocol: '90px', Length: '76px', Info: 'minmax(320px, 4fr)' };
  const template = columns.map((c) => widths[c] ?? 'minmax(100px, 1fr)').join(' ');
  const rowAt = (i: number) => pages.current.get(Math.floor(i / PAGE))?.[i % PAGE];

  return (
    <>
      <ViewHead title="Packet list">Every packet with Wireshark's summary columns. Use a Wireshark display filter to narrow the list; filtering re-scans the capture, which takes a moment on large files.</ViewHead>
      <section className="panel">
        <form className="dt-tools" onSubmit={(e) => { e.preventDefault(); void apply(); }}>
          <input className="input mono" style={{ maxWidth: 520 }} value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Display filter, e.g. dns.flags.rcode != 0 or tcp.stream == 3" aria-label="Wireshark display filter" spellCheck={false} />
          <button className="btn primary" type="submit">Apply</button>
          {filter && <button className="btn" type="button" onClick={() => { setDraft(''); setFilter(''); }}>Clear</button>}
          <span className="dt-count">{busy ? 'Filtering…' : matched === null ? '' : `${num(matched)} of ${num(model.capture.packetCount)} packets`}</span>
        </form>
        {error && <div style={{ padding: '10px 16px' }}><Note kind="crit">{error}</Note></div>}
        <div className="dt-scroll" ref={scrollRef} style={{ maxHeight: '70vh' }} role="grid" tabIndex={0} aria-label="Packets" aria-busy={busy || columns.length === 0} aria-rowcount={matched === null ? -1 : matched + 1}>
          <div className="dt-grid" role="presentation">
            {columns.length > 0 && <div className="dt-row dt-head" role="row" style={{ gridTemplateColumns: template }}>
              {columns.map((c) => <div key={c} role="columnheader" className={c === 'No.' || c === 'Length' ? 'r' : undefined}>{c}</div>)}
            </div>}
            <div className="dt-body" role="rowgroup" style={{ height: virt.getTotalSize(), position: 'relative' }}>
              {columns.length === 0 && <div className="dt-row" role="row" style={{ gridTemplateColumns: '1fr' }}><div className="muted" role="gridcell">Loading packet columns…</div></div>}
              {matched === 0 && <div className="dt-row" role="row" style={{ gridTemplateColumns: '1fr' }}><div className="empty" role="gridcell">No packets match this filter.</div></div>}
              {items.map((vi) => {
                const r = rowAt(vi.index);
                return (
                  <div key={vi.index} role="row" className="dt-row clickable" tabIndex={0}
                    style={{ gridTemplateColumns: template, position: 'absolute', top: 0, left: 0, right: 0, height: ROW, transform: `translateY(${vi.start}px)`, minHeight: ROW, fontSize: 12.5 }}
                    onClick={() => r && openDrawer({ title: `Packet #${r.number}`, frames: [r.number] })}
                    onKeyDown={(e) => { if (r && e.key === 'Enter') openDrawer({ title: `Packet #${r.number}`, frames: [r.number] }); }}>
                    {r ? r.columns.map((c, i) => (
                      <div key={i} role="gridcell" className={columns[i] === 'No.' || columns[i] === 'Length' ? 'r' : columns[i] === 'Source' || columns[i] === 'Destination' ? 'mono' : undefined} title={c}>{c}</div>
                    )) : <div className="muted" role="gridcell">Loading…</div>}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
