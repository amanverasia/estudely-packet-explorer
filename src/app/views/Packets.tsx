// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useVirtualizer } from '@tanstack/react-virtual';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Note, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { decimalLiteral, num } from '../format';

const PAGE = 500;
const ROW = 30;

export function Packets({ captureSession }: { captureSession: number }) {
  const { engine, params, patchRouteParams, openDrawer, model, filter: sharedFilter } = useApp();
  const [draft, setDraft] = useViewState<string>('packets.filter.draft', params.get('filter') ?? '', (value): value is string => typeof value === 'string');
  const [filter, setFilter] = useViewState<string>('packets.filter.applied', params.get('filter') ?? '', (value): value is string => typeof value === 'string');
  const [restoredFilter, setRestoredFilter] = useViewState<string | null>('packets.filter.routeRestore', null, (value): value is string | null => value === null || typeof value === 'string');
  const [error, setError] = useState<string | null>(null);
  const [pageErrors, setPageErrors] = useState<Map<number, string>>(() => new Map());
  const [busy, setBusy] = useState(false);
  const [matched, setMatched] = useState<number | null>(null);
  const [columns, setColumns] = useState<string[]>([]);
  const pages = useRef(new Map<number, { number: number; columns: string[] }[]>());
  const pageErrorsRef = useRef(pageErrors);
  const inflight = useRef(new Map<number, number>());
  const [, force] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const gen = useRef(0);
  const validation = useRef(0);
  const lastRouteFilter = useRef<string | null>(null);
  const draftRevision = useRef(0);
  const routeRef = useRef(params.toString());
  const sharedRef = useRef('');
  const sessionRef = useRef(captureSession);
  routeRef.current = params.toString();
  sessionRef.current = captureSession;
  const sharedDisplay = useMemo(() => {
    const terms: string[] = [];
    if (sharedFilter.start !== null && sharedFilter.end !== null) {
      terms.push(`(frame.time_relative >= ${decimalLiteral(sharedFilter.start)} && frame.time_relative <= ${decimalLiteral(sharedFilter.end)})`);
    }
    if (sharedFilter.host) terms.push(`(${sharedFilter.host.includes(':') ? 'ipv6.addr' : 'ip.addr'} == ${sharedFilter.host})`);
    return terms.join(' && ');
  }, [sharedFilter.start, sharedFilter.end, sharedFilter.host]);
  sharedRef.current = sharedDisplay;
  const queryFilter = useMemo(() => [filter.trim() ? `(${filter.trim()})` : '', sharedDisplay].filter(Boolean).join(' && '), [filter, sharedDisplay]);

  const setPageError = useCallback((p: number, message: string | null) => {
    const next = new Map(pageErrorsRef.current);
    if (message === null) next.delete(p);
    else next.set(p, message);
    pageErrorsRef.current = next;
    setPageErrors(next);
  }, []);

  const fetchPage = useCallback((p: number, g: number) => {
    if (pages.current.has(p) || inflight.current.has(p)) return;
    inflight.current.set(p, g);
    void engine.request({ kind: 'packetList', filter: queryFilter, skip: p * PAGE, limit: PAGE }).then((res) => {
      if (g !== gen.current) return;
      pages.current.set(p, res.rows);
      setPageError(p, null);
      setColumns(res.columns);
      setMatched(res.matched);
      if (p === 0) setBusy(false);
      force((x) => x + 1);
    }).catch((e: unknown) => {
      if (g !== gen.current) return;
      setPageError(p, e instanceof Error ? e.message : String(e));
      if (p === 0) setBusy(false);
    }).finally(() => {
      // An older request must not clear a newer request for the same page.
      if (inflight.current.get(p) === g) inflight.current.delete(p);
    });
  }, [engine, queryFilter, setPageError]);

  const loadPage = useCallback((p: number, g: number) => {
    // A failed page remains dormant until the user explicitly retries it. Later
    // pages also wait for page 0 to establish the row count and columns.
    if (pageErrorsRef.current.has(p) || (p > 0 && !pages.current.has(0))) return;
    fetchPage(p, g);
  }, [fetchPage]);

  const retryPage = useCallback((p: number) => {
    const g = gen.current;
    setPageError(p, null);
    if (p === 0) setBusy(true);
    fetchPage(p, g);
  }, [fetchPage, setPageError]);

  useEffect(() => {
    const g = ++gen.current;
    pages.current = new Map();
    inflight.current = new Map();
    pageErrorsRef.current = new Map();
    setPageErrors(pageErrorsRef.current);
    setMatched(null);
    setError(null);
    setBusy(true);
    fetchPage(0, g);
    return () => {
      // Invalidate outstanding requests on query changes and unmount.
      if (gen.current === g) gen.current++;
    };
  }, [fetchPage]);

  useEffect(() => {
    if (!params.has('filter')) { lastRouteFilter.current = null; return; }
    const routeFilter = params.get('filter') ?? '';
    const routeFilterChanged = lastRouteFilter.current !== routeFilter;
    lastRouteFilter.current = routeFilter;
    const wasRestoredByNavigation = restoredFilter === routeFilter;
    if (wasRestoredByNavigation) setRestoredFilter(null);
    const routeText = params.toString();
    const sharedText = sharedDisplay;
    const session = captureSession;
    const draftVersion = draftRevision.current;
    const token = ++validation.current;
    const composed = [routeFilter.trim() ? `(${routeFilter.trim()})` : '', sharedText].filter(Boolean).join(' && ');
    let cancelled = false;
    const loadRouteFilter = async () => {
      try {
        if (composed) {
          const result = await engine.request({ kind: 'checkFilter', filter: composed });
          if (!result.ok) {
            if (!cancelled && token === validation.current) setError(`Invalid display filter: ${result.error}`);
            return;
          }
        }
        if (cancelled || token !== validation.current || routeRef.current !== routeText || sharedRef.current !== sharedText || sessionRef.current !== session) return;
        setFilter(routeFilter);
        if (routeFilterChanged && !wasRestoredByNavigation && draftRevision.current === draftVersion) setDraft(routeFilter);
        setError(null);
      } catch (e) {
        if (!cancelled && token === validation.current) setError(e instanceof Error ? e.message : String(e));
      }
    };
    void loadRouteFilter();
    return () => { cancelled = true; };
  }, [params, sharedDisplay, captureSession, engine, restoredFilter, setFilter, setDraft, setRestoredFilter]);

  const apply = async (candidate = draft) => {
    const f = candidate.trim();
    const composed = [f ? `(${f})` : '', sharedDisplay].filter(Boolean).join(' && ');
    const routeText = params.toString();
    const sharedText = sharedDisplay;
    const session = captureSession;
    const draftVersion = draftRevision.current;
    const token = ++validation.current;
    try {
      if (composed) {
        const result = await engine.request({ kind: 'checkFilter', filter: composed });
        if (token !== validation.current || draftRevision.current !== draftVersion || routeRef.current !== routeText || sharedRef.current !== sharedText || sessionRef.current !== session) return;
        if (!result.ok) { setError(`Invalid display filter: ${result.error}`); return; }
      }
    } catch (e) {
      if (token === validation.current && draftRevision.current === draftVersion && routeRef.current === routeText && sharedRef.current === sharedText && sessionRef.current === session) setError(e instanceof Error ? e.message : String(e));
      return;
    }
    if (token !== validation.current || draftRevision.current !== draftVersion || routeRef.current !== routeText || sharedRef.current !== sharedText || sessionRef.current !== session) return;
    setFilter(f);
    setDraft(f);
    setError(null);
    patchRouteParams({ filter: f });
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
  const orderedPageErrors = [...pageErrors.entries()].sort(([a], [b]) => a - b);

  return (
    <>
      <ViewHead title="Packet list">Every packet with Wireshark's summary columns. Use a Wireshark display filter to narrow the list; filtering re-scans the capture, which takes a moment on large files.</ViewHead>
      {sharedDisplay && <Note>Shared time and host filters are combined with the Wireshark display filter for this list.</Note>}
      <section className="panel">
        <form className="dt-tools" onSubmit={(e) => { e.preventDefault(); void apply(); }}>
          <input className="input mono" style={{ maxWidth: 520 }} value={draft} onChange={(e) => { draftRevision.current++; validation.current++; setDraft(e.target.value); }} placeholder="Display filter, e.g. dns.flags.rcode != 0 or tcp.stream == 3" aria-label="Wireshark display filter" spellCheck={false} />
          <button className="btn primary" type="submit">Apply</button>
          {(filter || draft) && <button className="btn" type="button" onClick={() => { void apply(''); }}>Clear</button>}
          <span className="dt-count">{busy ? 'Filtering…' : matched === null ? '' : `${num(matched)} of ${num(model.capture.packetCount)} packets`}</span>
        </form>
        {error && <div style={{ padding: '10px 16px' }}><Note kind="crit">{error}</Note></div>}
        {orderedPageErrors.length > 0 && <div style={{ padding: '10px 16px', display: 'grid', gap: 8 }}>
          {orderedPageErrors.map(([p, message]) => <div key={p} style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <Note kind="crit">Could not load packet page {p + 1}: {message}</Note>
            <button className="btn small" type="button" onClick={() => retryPage(p)} aria-label={`Retry packet page ${p + 1}`}>Retry page {p + 1}</button>
          </div>)}
        </div>}
        <div className="dt-scroll" ref={scrollRef} style={{ maxHeight: '70vh' }} role="grid" tabIndex={0} aria-label="Packets" aria-busy={busy} aria-rowcount={matched === null ? -1 : matched + 1}>
          <div className="dt-grid" role="presentation">
            {columns.length > 0 && <div className="dt-row dt-head" role="row" style={{ gridTemplateColumns: template }}>
              {columns.map((c) => <div key={c} role="columnheader" className={c === 'No.' || c === 'Length' ? 'r' : undefined}>{c}</div>)}
            </div>}
            <div className="dt-body" role="rowgroup" style={{ height: virt.getTotalSize(), position: 'relative' }}>
              {columns.length === 0 && !pageErrors.has(0) && <div className="dt-row" role="row" style={{ gridTemplateColumns: '1fr' }}><div className="muted" role="gridcell">Loading packet columns…</div></div>}
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
