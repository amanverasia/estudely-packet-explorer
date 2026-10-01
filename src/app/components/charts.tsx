// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useLayoutEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';
import type { Timeline } from '../../engine/types';
import { bytes, duration, num, pct } from '../format';

/** Categorical slots in fixed order (validated palette); "Other" is neutral. */
export const SERIES = ['var(--s1)', 'var(--s2)', 'var(--s3)', 'var(--s4)', 'var(--s5)', 'var(--s6)', 'var(--s7)', 'var(--s8)'];
export const OTHER = 'var(--s-other)';

/** Stable colour per entity name so a filter never repaints survivors. */
export function colorMap(keys: string[]): Map<string, string> {
  const m = new Map<string, string>();
  let i = 0;
  for (const k of keys) m.set(k, k === 'Other' ? OTHER : SERIES[i++] ?? OTHER);
  return m;
}

export function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((e) => setW(Math.floor(e[0].contentRect.width)));
    ro.observe(el);
    setW(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function shortNum(v: number, metric: 'packets' | 'bytes'): string {
  if (metric === 'bytes') return bytes(v).replace(' ', ' ');
  if (v >= 1e6) return `${+(v / 1e6).toFixed(1)}M`;
  if (v >= 1e3) return `${+(v / 1e3).toFixed(1)}k`;
  return String(v);
}

export function Legend({ items }: { items: { key: string; color: string; label?: ReactNode }[] }) {
  return (
    <div className="chart-legend" role="list">
      {items.map((i) => (
        <span key={i.key} role="listitem"><i className="dot" style={{ background: i.color }} />{i.label ?? i.key}</span>
      ))}
    </div>
  );
}

/** Stacked columns per time bin, one series per top protocol. */
export interface TimeSelection { start: number; end: number }

export function TimeChart({ timeline, metric, height = 220, colors, selection = null, onRangeChange }: {
  timeline: Timeline; metric: 'packets' | 'bytes'; height?: number; colors: Map<string, string>;
  selection?: TimeSelection | null; onRangeChange?: (start: number, end: number) => void;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const drag = useRef<{ start: number; end: number } | null>(null);
  const [dragRange, setDragRange] = useState<{ start: number; end: number } | null>(null);
  const series = timeline.series.filter((s) => s.key !== 'All');
  const total = timeline.series.find((s) => s.key === 'All')!;
  const values = metric === 'packets' ? total.packets : total.bytes;
  const max = niceMax(Math.max(0, ...values));
  const m = { l: 52, r: 8, t: 8, b: 24 };
  const iw = Math.max(10, width - m.l - m.r);
  const ih = height - m.t - m.b;
  const n = timeline.bins;
  const bw = iw / n;
  const gap = bw > 6 ? 1 : 0;
  const y = (v: number) => ih - (v / max) * ih;
  const ticks = [0, max / 2, max];
  const xTicks = useMemo(() => {
    const count = Math.max(2, Math.min(6, Math.floor(iw / 110)));
    return Array.from({ length: count + 1 }, (_, i) => (i / count) * n);
  }, [iw, n]);
  const pointerBin = (e: ReactPointerEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return Math.max(0, Math.min(n, Math.floor((e.clientX - rect.left - m.l) / bw)));
  };
  const finishBrush = (e: ReactPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const a = drag.current.start, b = pointerBin(e);
    drag.current = null; setDragRange(null);
    let lo = Math.min(a, b), hi = Math.max(a, b);
    if (lo === hi) hi = Math.min(n, lo + 1);
    if (hi <= lo) return;
    const start = timeline.origin + lo * timeline.binSeconds;
    const end = Math.min(timeline.end, timeline.origin + hi * timeline.binSeconds);
    if (end > start) onRangeChange?.(start, end);
  };
  const visibleSelection = dragRange ?? selection;
  const selectionStart = visibleSelection ? Math.max(0, Math.min(n, Math.floor((visibleSelection.start - timeline.origin) / timeline.binSeconds))) : 0;
  const selectionEnd = visibleSelection ? Math.max(selectionStart, Math.min(n, Math.ceil((visibleSelection.end - timeline.origin) / timeline.binSeconds))) : 0;

  return (
    <div className="chart-wrap" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={`${metric === 'packets' ? 'Packets' : 'Bytes'} per ${duration(timeline.binSeconds)} interval, stacked by protocol`}
          onMouseLeave={() => setHover(null)}
          style={{ touchAction: onRangeChange ? 'none' : undefined, cursor: onRangeChange ? 'crosshair' : undefined }}
          onPointerDown={(e) => {
            if (!onRangeChange || e.button !== 0) return;
            const start = pointerBin(e); drag.current = { start, end: start }; setDragRange({ start: timeline.origin + start * timeline.binSeconds, end: timeline.origin + (start + 1) * timeline.binSeconds });
            e.currentTarget.setPointerCapture(e.pointerId);
          }}
          onPointerMove={(e) => {
            if (drag.current) {
              const next = pointerBin(e); drag.current.end = next;
              const lo = Math.min(drag.current.start, next), hi = Math.min(n, Math.max(drag.current.start, next) || drag.current.start + 1);
              setDragRange({ start: timeline.origin + lo * timeline.binSeconds, end: Math.min(timeline.end, timeline.origin + Math.max(lo + 1, hi) * timeline.binSeconds) });
            }
            const i = pointerBin(e);
            setHover(i >= 0 && i < n ? i : null);
          }}
          onPointerUp={finishBrush}
          onPointerCancel={() => { drag.current = null; setDragRange(null); }}>
          <g transform={`translate(${m.l},${m.t})`}>
            <g className="axis">
              {ticks.map((t) => (
                <g key={t} transform={`translate(0,${y(t)})`}>
                  <line x1={0} x2={iw} strokeDasharray={t === 0 ? undefined : '2 3'} />
                  <text x={-8} dy="0.32em" textAnchor="end">{shortNum(t, metric)}</text>
                </g>
              ))}
              {xTicks.map((b) => (
                <text key={b} x={b * bw} y={ih + 16} textAnchor={b === 0 ? 'start' : b >= n ? 'end' : 'middle'}>
                  {duration(timeline.origin + b * timeline.binSeconds)}
                </text>
              ))}
            </g>
            {Array.from({ length: n }, (_, i) => {
              let acc = 0;
              return (
                <g key={i}>
                  {series.map((s) => {
                    const v = (metric === 'packets' ? s.packets : s.bytes)[i];
                    if (!v) return null;
                    const y0 = y(acc);
                    acc += v;
                    const y1 = y(acc);
                    return <rect key={s.key} x={i * bw + gap / 2} y={y1} width={Math.max(0.5, bw - gap)} height={Math.max(0.5, y0 - y1 - (bw > 6 ? 1 : 0))} fill={colors.get(s.key) ?? OTHER} />;
                  })}
                </g>
              );
            })}
            {visibleSelection && selectionEnd > selectionStart && <rect x={selectionStart * bw} y={0} width={(selectionEnd - selectionStart) * bw} height={ih} fill="var(--accent)" fillOpacity={0.12} stroke="var(--accent)" strokeOpacity={0.8} pointerEvents="none" />}
            {hover !== null && <line x1={hover * bw + bw / 2} x2={hover * bw + bw / 2} y1={0} y2={ih} stroke="var(--ink-3)" strokeDasharray="3 3" />}
          </g>
        </svg>
      )}
      {hover !== null && width > 0 && (
        <div className="chart-tip" style={{ left: Math.min(width - 200, Math.max(0, m.l + hover * bw + 12)), top: 8 }}>
          <div className="muted" style={{ marginBottom: 4 }}>
            {duration(timeline.origin + hover * timeline.binSeconds)} – {duration(timeline.origin + (hover + 1) * timeline.binSeconds)}
          </div>
          {series.map((s) => {
            const v = (metric === 'packets' ? s.packets : s.bytes)[hover];
            return v ? (
              <div className="row" key={s.key}><span><i className="dot" style={{ background: colors.get(s.key) }} />{s.key}</span><b className="num">{metric === 'packets' ? num(v) : bytes(v)}</b></div>
            ) : null;
          })}
          <div className="row" style={{ borderTop: '1px solid var(--rule)', marginTop: 4, paddingTop: 4 }}><span>Total</span><b className="num">{metric === 'packets' ? num(values[hover]) : bytes(values[hover])}</b></div>
        </div>
      )}
    </div>
  );
}

/** Capture-wide traffic strip shown under the header on every view. */
export function Strip({ timeline, selection = null, onRangeChange }: { timeline: Timeline; selection?: TimeSelection | null; onRangeChange?: (start: number, end: number) => void }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const drag = useRef<number | null>(null);
  const [dragRange, setDragRange] = useState<TimeSelection | null>(null);
  const total = timeline.series.find((s) => s.key === 'All')!.bytes;
  const max = Math.max(1, ...total);
  const h = 34;
  const bw = width / Math.max(1, total.length);
  // Short captures have few bins; cap the bar width so they stay bars, not blocks.
  const barW = Math.min(8, Math.max(0.6, bw - (bw > 4 ? 1 : 0)));
  const binAt = (e: ReactPointerEvent<SVGSVGElement>) => Math.max(0, Math.min(total.length, Math.floor((e.clientX - e.currentTarget.getBoundingClientRect().left) / Math.max(1, bw))));
  const visibleSelection = dragRange ?? selection;
  const selectionStart = visibleSelection ? Math.max(0, Math.min(total.length, Math.floor((visibleSelection.start - timeline.origin) / timeline.binSeconds))) : 0;
  const selectionEnd = visibleSelection ? Math.max(selectionStart, Math.min(total.length, Math.ceil((visibleSelection.end - timeline.origin) / timeline.binSeconds))) : 0;
  return (
    <div ref={ref} className="strip">
      {width > 0 && (
        <svg width={width} height={h} role="img" aria-label="Capture traffic strip. Drag to choose a time range."
          style={{ touchAction: 'none', cursor: 'crosshair' }}
          onPointerDown={(e) => { if (!onRangeChange || e.button !== 0) return; const i = binAt(e); drag.current = i; setDragRange({ start: timeline.origin + i * timeline.binSeconds, end: Math.min(timeline.end, timeline.origin + (i + 1) * timeline.binSeconds) }); e.currentTarget.setPointerCapture(e.pointerId); }}
          onPointerMove={(e) => { if (drag.current === null) return; const i = binAt(e); const lo = Math.min(drag.current, i), hi = Math.min(total.length, Math.max(drag.current, i) || drag.current + 1); setDragRange({ start: timeline.origin + lo * timeline.binSeconds, end: Math.min(timeline.end, timeline.origin + Math.max(lo + 1, hi) * timeline.binSeconds) }); }}
          onPointerUp={(e) => {
            if (drag.current === null) return;
            const a = drag.current, b = binAt(e); drag.current = null; setDragRange(null);
            const lo = Math.min(a, b), hi = Math.max(a, b) === lo ? Math.min(total.length, lo + 1) : Math.max(a, b);
            const start = timeline.origin + lo * timeline.binSeconds, end = Math.min(timeline.end, timeline.origin + hi * timeline.binSeconds);
            if (end > start) onRangeChange?.(start, end);
          }}
          onPointerCancel={() => { drag.current = null; setDragRange(null); }}>
          {/* Baseline across the whole capture, so quiet stretches read as "no traffic" rather than missing chart. */}
          <line x1={0} x2={width} y1={h - 0.5} y2={h - 0.5} stroke="var(--rule-strong)" />
          {total.map((v, i) => {
            const bh = v ? Math.max(1.5, (v / max) * (h - 4)) : 0;
            return <rect key={i} x={i * bw + (bw - barW) / 2} y={h - bh} width={barW} height={bh} rx={barW > 4 ? 1 : 0} fill="var(--accent)" opacity={0.75} />;
          })}
          {visibleSelection && selectionEnd > selectionStart && <rect x={selectionStart * bw} y={0} width={(selectionEnd - selectionStart) * bw} height={h} fill="var(--accent)" fillOpacity={0.18} stroke="var(--accent)" strokeOpacity={0.8} pointerEvents="none" />}
        </svg>
      )}
    </div>
  );
}

export interface BarItem { key: string; value: number; label?: ReactNode; detail?: string; color?: string }

/** Ranked horizontal bars with direct value labels. */
export function BarList({ items, total, format = num, onSelect, limit = 10, color = 'var(--s1)', emptyText = 'Nothing to show.' }: {
  items: BarItem[]; total?: number; format?: (v: number) => string; onSelect?: (key: string) => void; limit?: number; color?: string; emptyText?: string;
}) {
  const [all, setAll] = useState(false);
  if (!items.length) return <div className="empty" style={{ padding: 12 }}>{emptyText}</div>;
  const max = Math.max(...items.map((i) => i.value), 1);
  const shown = all ? items : items.slice(0, limit);
  const sum = total ?? items.reduce((a, b) => a + b.value, 0);
  return (
    <div className="barlist">
      {shown.map((i) => (
        <div key={i.key} className={`barlist-row${onSelect ? ' clickable' : ''}`}
          onClick={onSelect ? () => onSelect(i.key) : undefined}
          role={onSelect ? 'button' : undefined} tabIndex={onSelect ? 0 : undefined}
          onKeyDown={onSelect ? (e) => { if (e.key === 'Enter') onSelect(i.key); } : undefined}
          title={i.detail}>
          <span className="label">{i.label ?? i.key}</span>
          <span className="val">{format(i.value)} <span className="muted">{pct(i.value, sum)}</span></span>
          <div className="track"><div className="fill" style={{ width: `${(i.value / max) * 100}%`, background: i.color ?? color }} /></div>
        </div>
      ))}
      {items.length > limit && (
        <button className="btn ghost small" style={{ justifySelf: 'start' }} onClick={() => setAll(!all)}>
          {all ? 'Show fewer' : `Show all ${num(items.length)}`}
        </button>
      )}
    </div>
  );
}

/** Two-column flow: clients on the left, resolvers on the right, link width = queries. */
export function FlowChart({ links, leftLabel, rightLabel, onPick }: {
  links: { left: string; right: string; value: number }[]; leftLabel: string; rightLabel: string; onPick?: (l: string, r: string) => void;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<string | null>(null);
  const MAXN = 14;
  const lefts = useMemo(() => rank(links.map((l) => [l.left, l.value])), [links]);
  const rights = useMemo(() => rank(links.map((l) => [l.right, l.value])), [links]);
  const L = fold(lefts, MAXN);
  const R = fold(rights, MAXN);
  const merged = new Map<string, { left: string; right: string; value: number }>();
  for (const l of links) {
    const a = L.has(l.left) ? l.left : 'Other clients';
    const b = R.has(l.right) ? l.right : 'Other servers';
    const k = a + '\u0000' + b;
    const e = merged.get(k) ?? { left: a, right: b, value: 0 };
    e.value += l.value;
    merged.set(k, e);
  }
  const leftKeys = [...L.keys(), ...(lefts.length > MAXN ? ['Other clients'] : [])];
  const rightKeys = [...R.keys(), ...(rights.length > MAXN ? ['Other servers'] : [])];
  const rowH = 26;
  const h = Math.max(leftKeys.length, rightKeys.length) * rowH + 28;
  const colW = Math.min(220, width * 0.36);
  const maxV = Math.max(1, ...[...merged.values()].map((e) => e.value));
  const yL = (k: string) => 28 + leftKeys.indexOf(k) * rowH + rowH / 2;
  const yR = (k: string) => 28 + rightKeys.indexOf(k) * rowH + rowH / 2;
  if (!links.length) return <div className="empty">No client–server pairs to show.</div>;
  return (
    <div ref={ref} className="chart-wrap">
      {width > 0 && (
        <svg width={width} height={h} role="img" aria-label={`${leftLabel} to ${rightLabel} relationships; line width shows query count`}>
          <text x={0} y={14} fontSize={12} fill="var(--ink-3)">{leftLabel}</text>
          <text x={width} y={14} fontSize={12} fill="var(--ink-3)" textAnchor="end">{rightLabel}</text>
          {[...merged.values()].map((e) => {
            const x1 = colW, x2 = width - colW;
            const active = hover === null || hover === e.left || hover === e.right;
            return (
              <path key={e.left + e.right} d={`M${x1},${yL(e.left)} C${(x1 + x2) / 2},${yL(e.left)} ${(x1 + x2) / 2},${yR(e.right)} ${x2},${yR(e.right)}`}
                stroke="var(--s1)" fill="none" strokeWidth={active ? 1.5 + (e.value / maxV) * 10 : 1.5}
                style={{ cursor: onPick ? 'pointer' : undefined }} onClick={() => onPick?.(e.left, e.right)}>
                <title>{`${e.left} → ${e.right}: ${num(e.value)} queries`}</title>
              </path>
            );
          })}
          {leftKeys.map((k) => (
            <g key={k} onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)}>
              <rect x={colW - 4} y={yL(k) - 8} width={4} height={16} rx={2} fill="var(--ink-2)" />
              <text x={colW - 10} y={yL(k)} dy="0.32em" textAnchor="end" fontSize={12} fill="var(--ink)" fontFamily="var(--mono)">{trim(k, colW)}</text>
            </g>
          ))}
          {rightKeys.map((k) => (
            <g key={k} onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)}>
              <rect x={width - colW} y={yR(k) - 8} width={4} height={16} rx={2} fill="var(--ink-2)" />
              <text x={width - colW + 10} y={yR(k)} dy="0.32em" fontSize={12} fill="var(--ink)" fontFamily="var(--mono)">{trim(k, colW)}</text>
            </g>
          ))}
        </svg>
      )}
    </div>
  );
}

function rank(pairs: (string | number)[][]): [string, number][] {
  const m = new Map<string, number>();
  for (const [k, v] of pairs) m.set(k as string, (m.get(k as string) ?? 0) + (v as number));
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function fold(r: [string, number][], n: number): Map<string, number> {
  return new Map(r.slice(0, r.length > n ? n - 1 : n));
}

function trim(s: string, px: number): string {
  const max = Math.max(6, Math.floor(px / 7.4));
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}
