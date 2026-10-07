// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useVirtualizer } from '@tanstack/react-virtual';
import { useDeferredValue, useId, useMemo, useRef, type ReactNode } from 'react';
import { downloadCsv } from '../download';
import { num } from '../format';
import { useViewState } from '../context';

type SortState = { key: string; dir: 'asc' | 'desc' } | null;

export interface Column<T> {
  key: string;
  header: string;
  /** CSS grid track, e.g. '120px' or 'minmax(160px, 2fr)'. */
  width: string;
  /** Plain value used for sorting, searching and CSV export. */
  value: (row: T) => string | number | boolean | null | undefined;
  render?: (row: T) => ReactNode;
  align?: 'right';
  title?: string;
  /** Exclude from the free-text search (e.g. numeric columns). */
  noSearch?: boolean;
}

interface Props<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  exportName?: string;
  searchPlaceholder?: string;
  toolbar?: ReactNode;
  initialSort?: { key: string; dir: 'asc' | 'desc' };
  height?: number | string;
  empty?: ReactNode;
  label: string;
  /** Stable capture-local key for restoring this table's search and sort. */
  stateId?: string;
}

const ROW = 34;

export function DataTable<T>(props: Props<T>) {
  const { rows, columns, rowKey, onRowClick, selectedKey, exportName, toolbar, empty, label } = props;
  const localId = useId();
  const stateId = props.stateId ?? `local:${localId}`;
  const [query, setQuery] = useViewState<string>(`table:${stateId}:query`, '', (value): value is string => typeof value === 'string');
  const deferred = useDeferredValue(query);
  const [sort, setSort] = useViewState<SortState>(`table:${stateId}:sort`, props.initialSort ?? null, (value): value is SortState =>
    value === null || (typeof value === 'object' && value !== null && typeof (value as { key?: unknown }).key === 'string' &&
      ((value as { dir?: unknown }).dir === 'asc' || (value as { dir?: unknown }).dir === 'desc')));
  const scrollRef = useRef<HTMLDivElement>(null);

  const sortKeyExists = sort === null || columns.some((column) => column.key === sort.key);
  if (!sortKeyExists) setSort(props.initialSort ?? null);

  const view = useMemo(() => {
    let out = rows;
    const q = deferred.trim().toLowerCase();
    if (q) {
      const cols = columns.filter((c) => !c.noSearch);
      const terms = q.split(/\s+/);
      out = rows.filter((r) => {
        const hay = cols.map((c) => String(c.value(r) ?? '')).join('\u0000').toLowerCase();
        return terms.every((t) => hay.includes(t));
      });
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        const dir = sort.dir === 'asc' ? 1 : -1;
        out = [...out].sort((a, b) => {
          const x = col.value(a);
          const y = col.value(b);
          if (x === y) return 0;
          if (x === null || x === undefined || x === '') return 1;
          if (y === null || y === undefined || y === '') return -1;
          if (typeof x === 'number' && typeof y === 'number') return (x - y) * dir;
          return String(x).localeCompare(String(y), undefined, { numeric: true }) * dir;
        });
      }
    }
    return out;
  }, [rows, columns, deferred, sort]);

  const virt = useVirtualizer({ count: view.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 12 });
  const template = columns.map((c) => c.width).join(' ');

  const toggleSort = (key: string) => {
    setSort((s) => (s && s.key === key ? (s.dir === 'desc' ? { key, dir: 'asc' } : null) : { key, dir: 'desc' }));
  };

  const exportCsv = () => {
    downloadCsv(`${exportName ?? 'table'}.csv`, columns.map((c) => c.header), view.map((r) => columns.map((c) => c.value(r))));
  };

  const height = props.height ?? 'min(62vh, 640px)';
  return (
    <div className="dt">
      <div className="dt-tools">
        <input
          className="input"
          type="search"
          placeholder={props.searchPlaceholder ?? 'Search'}
          aria-label={`Search ${label}`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {toolbar}
        <span className="dt-count" aria-live="polite">
          {view.length === rows.length ? `${num(rows.length)} rows` : `${num(view.length)} of ${num(rows.length)} rows`}
        </span>
        {exportName && (
          <button className="btn small" onClick={exportCsv} disabled={!view.length} title="Save the rows shown (search and sort applied) as CSV">
            Export CSV
          </button>
        )}
      </div>
      {rows.length === 0 && empty ? (
        <div className="empty">{empty}</div>
      ) : (
        <div className="dt-scroll" ref={scrollRef} style={{ maxHeight: height }} role="grid" aria-label={label} aria-rowcount={view.length + 1}>
          <div className="dt-grid" role="presentation">
            <div className="dt-row dt-head" role="row" style={{ gridTemplateColumns: template }}>
              {columns.map((c) => (
                <div
                  key={c.key}
                  role="columnheader"
                  className={c.align === 'right' ? 'r' : undefined}
                  aria-sort={sort?.key === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                  title={c.title}
                >
                  <button onClick={() => toggleSort(c.key)}>
                    {c.header}
                    <span aria-hidden="true">{sort?.key === c.key ? (sort.dir === 'asc' ? '↑' : '↓') : ''}</span>
                  </button>
                </div>
              ))}
            </div>
            <div className="dt-body" role="rowgroup" style={{ height: virt.getTotalSize(), position: 'relative' }}>
              {view.length === 0 && (
                <div className="empty">No rows match “{deferred}”.</div>
              )}
              {virt.getVirtualItems().map((vi) => {
                const r = view[vi.index];
                const k = rowKey(r);
                return (
                  <div
                    key={k}
                    role="row"
                    aria-rowindex={vi.index + 2}
                    aria-selected={selectedKey === k}
                    tabIndex={onRowClick ? 0 : -1}
                    className={`dt-row${onRowClick ? ' clickable' : ''}`}
                    style={{ gridTemplateColumns: template, position: 'absolute', top: 0, left: 0, right: 0, height: ROW, transform: `translateY(${vi.start}px)` }}
                    onClick={onRowClick ? () => onRowClick(r) : undefined}
                    onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(r); } } : undefined}
                  >
                    {columns.map((c) => {
                      const content = c.render ? c.render(r) : c.value(r);
                      return (
                        <div key={c.key} role="gridcell" className={c.align === 'right' ? 'r' : undefined}
                          title={typeof content === 'string' || typeof content === 'number' ? String(content) : undefined}>
                          {content === null || content === undefined || content === '' ? <span className="muted">—</span> : content}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
