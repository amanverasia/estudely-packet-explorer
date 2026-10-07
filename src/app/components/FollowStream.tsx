// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Follow stream: a conversation's reassembled payload, as Wireshark's
// Follow TCP/UDP Stream shows it. Payload is rendered only as text nodes.
import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { Conversation, FollowStream as FollowData } from '../../engine/types';
import { downloadBlob, safeBase } from '../download';
import {
  directionBytes, findFollowByteMatches, findFollowTextMatches, FOLLOW_SAVE_BYTES, FOLLOW_SAVE_SEGMENTS, FOLLOW_SEARCH_MATCH_LIMIT,
  FOLLOW_VIEW_BYTES, FOLLOW_VIEW_SEGMENTS, followRuns, followSaveData, hexDump, mappedPayloadText, parseHexQuery, payloadText,
  type FollowDirection, type FollowRun, type FollowSearchMatch,
} from '../follow';
import { useApp } from '../context';
import { bytes, endpoint, num, plural } from '../format';
import { Note, Seg } from './bits';

function frameRange(frames: number[]): string {
  return frames.length === 1 ? `#${frames[0]}` : `#${frames[0]} to #${frames[frames.length - 1]} (${frames.length} packets)`;
}

interface HighlightRange { start: number; end: number; index: number }

/** Render coalesced text ranges as text and marks, never as captured HTML. */
function renderHighlightedText(text: string, ranges: HighlightRange[], activeIndex: number): ReactNode[] {
  const events: { at: number; index: number; start: boolean }[] = [];
  for (const r of ranges) {
    const start = Math.max(0, Math.min(text.length, r.start));
    const end = Math.max(start, Math.min(text.length, r.end));
    if (start === end) continue;
    events.push({ at: start, index: r.index, start: true }, { at: end, index: r.index, start: false });
  }
  events.sort((a, b) => a.at - b.at || Number(a.start) - Number(b.start));
  const out: ReactNode[] = [];
  const active = new Set<number>();
  let cursor = 0;
  let event = 0;
  while (event < events.length) {
    const at = events[event].at;
    if (cursor < at) {
      const value = text.slice(cursor, at);
      if (active.size === 0) out.push(value);
      else {
        const isActive = active.has(activeIndex);
        out.push(<mark key={`m${cursor}`} data-active-match={isActive ? 'true' : undefined}
          style={isActive ? { outline: '2px solid var(--focus)' } : undefined}>{value}</mark>);
      }
      cursor = at;
    }
    while (event < events.length && events[event].at === at && !events[event].start) {
      active.delete(events[event].index);
      event++;
    }
    while (event < events.length && events[event].at === at && events[event].start) {
      active.add(events[event].index);
      event++;
    }
  }
  if (cursor < text.length) {
    const value = text.slice(cursor);
    if (active.size === 0) out.push(value);
    else {
      const isActive = active.has(activeIndex);
      out.push(<mark key={`m${cursor}`} data-active-match={isActive ? 'true' : undefined}
        style={isActive ? { outline: '2px solid var(--focus)' } : undefined}>{value}</mark>);
    }
  }
  return out;
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** Format up to eight byte cells, coalescing adjacent highlights into one mark. */
function renderCellGroup(bytesValue: Uint8Array, mask: Uint8Array, activeMask: Uint8Array, start: number, end: number, ascii: boolean, width?: number): ReactNode[] {
  const out: ReactNode[] = [];
  let visibleLength = 0;
  let cursor = start;
  let part = 0;
  while (cursor < end) {
    const state = mask[cursor] ? (activeMask[cursor] ? 2 : 1) : 0;
    let next = cursor + 1;
    while (next < end && (mask[next] ? (activeMask[next] ? 2 : 1) : 0) === state) next++;
    let value = '';
    for (let i = cursor; i < next; i++) {
      if (ascii) value += bytesValue[i] >= 0x20 && bytesValue[i] < 0x7f ? String.fromCharCode(bytesValue[i]) : '.';
      else {
        if (i > cursor) value += ' ';
        value += HEX[bytesValue[i]];
      }
    }
    if (part > 0) { out.push(' '); visibleLength++; }
    if (state > 0) out.push(<mark key={`${start}-${part}`} data-active-match={state === 2 ? 'true' : undefined}
      style={state === 2 ? { outline: '2px solid var(--focus)' } : undefined}>{value}</mark>);
    else out.push(value);
    visibleLength += value.length;
    part++;
    cursor = next;
  }
  if (width && visibleLength < width) out.push(' '.repeat(width - visibleLength));
  return out;
}

function renderHexRow(run: FollowRun, mask: Uint8Array, activeMask: Uint8Array, start: number): ReactNode {
  const end = Math.min(start + 16, run.bytes.length);
  const leftEnd = Math.min(start + 8, end);
  const rightStart = Math.min(start + 8, end);
  const line: ReactNode[] = [
    `${(run.dirOffset + start).toString(16).padStart(8, '0')}  `,
    ...renderCellGroup(run.bytes, mask, activeMask, start, leftEnd, false, 23),
    '  ',
    ...renderCellGroup(run.bytes, mask, activeMask, rightStart, end, false, 23),
    '  ',
    ...renderCellGroup(run.bytes, mask, activeMask, start, end, true),
  ];
  return <Fragment key={start}>{line}{'\n'}</Fragment>;
}

function renderHexRun(run: FollowRun, mask: Uint8Array, activeMask: Uint8Array): ReactNode[] {
  const rows: ReactNode[] = [];
  let plainStart = 0;
  for (let start = 0; start < run.bytes.length; start += 16) {
    const end = Math.min(start + 16, run.bytes.length);
    let highlighted = false;
    for (let i = start; i < end; i++) {
      if (mask[i]) { highlighted = true; break; }
    }
    if (!highlighted) continue;
    if (plainStart < start) rows.push(`${hexDump(run.bytes.subarray(plainStart, start), run.dirOffset + plainStart)}\n`);
    rows.push(renderHexRow(run, mask, activeMask, start));
    plainStart = end;
  }
  if (plainStart < run.bytes.length) rows.push(`${hexDump(run.bytes.subarray(plainStart), run.dirOffset + plainStart)}\n`);
  return rows;
}

function directionName(fromServer: boolean): string {
  return fromServer ? 'Server → client' : 'Client → server';
}

function byteMasks(runs: FollowRun[], matches: FollowSearchMatch[], activeIndex: number): { all: Uint8Array[]; active: Uint8Array[] } {
  const all = runs.map((run) => new Uint8Array(run.bytes.length));
  const active = runs.map((run) => new Uint8Array(run.bytes.length));
  matches.forEach((match, index) => {
    all[match.runIndex].fill(1, match.byteStart, match.byteEnd);
    if (index === activeIndex) active[match.runIndex].fill(1, match.byteStart, match.byteEnd);
  });
  return { all, active };
}

export function FollowStream({ c }: { c: Conversation }) {
  const { model, engine, openDrawer } = useApp();
  const transport = c.transport as 'TCP' | 'UDP';
  const stream = c.stream!;
  const [request, setRequest] = useState<{
    engine: typeof engine; transport: 'TCP' | 'UDP'; stream: number; data: FollowData | null; error: string | null;
  } | null>(null);
  const [dir, setDir] = useState<FollowDirection>('both');
  const [format, setFormat] = useState<'text' | 'hex'>('text');
  const [searchMode, setSearchMode] = useState<'text' | 'bytes'>('text');
  const [query, setQuery] = useState('');
  const [activeResult, setActiveResult] = useState(0);
  const [saving, setSaving] = useState<string | null>(null);
  const queryRef = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setRequest({ engine, transport, stream, data: null, error: null });
    setDir('both');
    setFormat('text');
    setSearchMode('text');
    setQuery('');
    setActiveResult(0);
    engine.request({ kind: 'follow', transport, stream, maxBytes: FOLLOW_VIEW_BYTES, maxSegments: FOLLOW_VIEW_SEGMENTS })
      .then((data) => { if (!cancelled) setRequest({ engine, transport, stream, data, error: null }); })
      .catch((e: Error) => { if (!cancelled) setRequest({ engine, transport, stream, data: null, error: e.message }); });
    return () => { cancelled = true; };
  }, [engine, transport, stream]);

  const matchesRequest = request?.engine === engine && request.transport === transport && request.stream === stream;
  const data = matchesRequest ? request.data : null;
  const err = matchesRequest ? request.error : null;
  const runs = useMemo(() => (data ? followRuns(data, dir) : []), [data, dir]);
  const plainTexts = useMemo(() => runs.map((r) => payloadText(r.bytes)), [runs]);
  const mappedTexts = useMemo(() => query ? runs.map((r) => mappedPayloadText(r.bytes)) : [], [runs, query]);
  const search = useMemo(() => {
    if (!query) return { matches: [] as FollowSearchMatch[], capped: false, error: null as string | null };
    if (searchMode === 'text') return { ...findFollowTextMatches(runs, mappedTexts, query), error: null };
    try {
      return { ...findFollowByteMatches(runs, mappedTexts, parseHexQuery(query)), error: null };
    } catch (e) {
      return { matches: [] as FollowSearchMatch[], capped: false, error: e instanceof Error ? e.message : String(e) };
    }
  }, [runs, mappedTexts, searchMode, query]);
  const activeIndex = search.matches.length ? ((activeResult % search.matches.length) + search.matches.length) % search.matches.length : -1;
  const activeMatch = activeIndex >= 0 ? search.matches[activeIndex] : null;
  const masks = useMemo(() => search.matches.length ? byteMasks(runs, search.matches, activeIndex) : null,
    [runs, search.matches, activeIndex]);

  useEffect(() => {
    if (activeIndex >= 0) bodyRef.current?.querySelector('[data-active-match="true"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [activeIndex, search.matches, format]);

  const moveMatch = (delta: number) => {
    if (!search.matches.length) return;
    setActiveResult((index) => (index + delta + search.matches.length) % search.matches.length);
    queryRef.current?.focus();
  };

  if (err) return <div className="note crit">{err}</div>;
  if (!data) return <p className="muted">Reassembling the stream…</p>;
  if (!data.client || !data.server || data.totalSegments === 0) {
    return <p className="muted">This {transport} stream carries no payload (for example, only a handshake was captured).</p>;
  }

  const side = (fromServer: boolean) => {
    const e = fromServer ? data.server! : data.client!;
    return endpoint(e.addr, e.port);
  };
  const shownBytes = data.segments.reduce((n, g) => n + g.length, 0);
  const totalBytes = data.clientBytes + data.serverBytes;
  const dirSuffix = dir === 'both' ? '' : `-${dir}`;
  const fileName = `${safeBase(model.capture.fileName)}-${transport.toLowerCase()}-stream-${stream}${dirSuffix}.bin`;

  const save = async () => {
    setSaving('Preparing…');
    try {
      // Saving reassembles again with the larger cap, so the file is not limited to what is shown.
      const full = await engine.request({ kind: 'follow', transport, stream, maxBytes: FOLLOW_SAVE_BYTES, maxSegments: FOLLOW_SAVE_SEGMENTS });
      const out = followSaveData(full, dir);
      downloadBlob(fileName, new Blob([out], { type: 'application/octet-stream' }));
      // The cap counts both directions, so compare what was written with the selected directions' total.
      const wanted = directionBytes(full, dir);
      setSaving(out.length < wanted
        ? `Saved the first ${bytes(out.length)} of ${bytes(wanted)}. The combined stream reached the byte or segment save limit.`
        : full.truncated ? 'Saved all selected-direction bytes. The combined stream reached the byte or segment save limit.' : null);
    } catch (e) {
      setSaving(`Could not save: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const jumpToMatch = () => {
    if (!activeMatch?.frames.length) return;
    openDrawer({
      title: `${transport} stream ${stream} match`,
      frames: activeMatch.frames,
      focus: activeMatch.frames[0],
    });
  };

  const status = search.error
    ? `Invalid hex query: ${search.error}`
    : !query
      ? (searchMode === 'text' ? 'Enter a literal, case-sensitive text query.' : 'Enter hexadecimal byte pairs, such as 00 ff or 00ff.')
      : search.matches.length === 0
        ? 'No matches in the displayed runs.'
        : `Match ${activeIndex + 1} of ${search.matches.length}${search.capped ? ` (first ${num(FOLLOW_SEARCH_MATCH_LIMIT)} shown; more matches exist)` : ''} — ${directionName(activeMatch!.fromServer)}, byte offset ${num(runs[activeMatch!.runIndex].dirOffset + activeMatch!.byteStart)}.`;

  return (
    <div className="follow">
      <div className="follow-tools">
        <Seg label="Directions shown" value={dir} onChange={(value) => { setDir(value); setActiveResult(0); }} options={[
          { value: 'both', label: 'Both directions' },
          { value: 'client', label: <>Client → server <span className="num">({bytes(data.clientBytes)})</span></> },
          { value: 'server', label: <>Server → client <span className="num">({bytes(data.serverBytes)})</span></> },
        ]} />
        <Seg label="Format" value={format} onChange={(value) => { setFormat(value); setActiveResult(0); }} options={[{ value: 'text', label: 'Text' }, { value: 'hex', label: 'Hex' }]} />
        <button className="btn small" onClick={save} disabled={saving === 'Preparing…'}
          title="Download the reassembled payload of the selected directions as raw bytes. It is saved on this device only.">Save raw</button>
        {saving && <span className="muted" role="status">{saving}</span>}
      </div>
      <div className="follow-search" role="group" aria-label="Find in Follow Stream">
        <label htmlFor="follow-search-query">Find</label>
        <input ref={queryRef} id="follow-search-query" type="text" value={query} maxLength={1024 * 1024}
          placeholder={searchMode === 'text' ? 'Text to find' : '00 ff or 00ff'}
          onChange={(event) => { setQuery(event.target.value); setActiveResult(0); }}
          onKeyDown={(event) => {
            if (event.key === 'Enter') { event.preventDefault(); moveMatch(event.shiftKey ? -1 : 1); }
          }} />
        <label htmlFor="follow-search-mode">Search as</label>
        <select id="follow-search-mode" value={searchMode} onChange={(event) => {
          setSearchMode(event.target.value as 'text' | 'bytes');
          setActiveResult(0);
        }}>
          <option value="text">Text</option>
          <option value="bytes">Hex bytes</option>
        </select>
        <button type="button" className="btn small" onClick={() => moveMatch(-1)} disabled={!search.matches.length}>Previous</button>
        <button type="button" className="btn small" onClick={() => moveMatch(1)} disabled={!search.matches.length}>Next</button>
        <span className="muted" role="status" aria-live="polite">{status}</span>
      </div>
      <p className="muted follow-search-help">Searches each displayed run independently; it never joins opposite directions.</p>
      {data.truncated && <Note kind="warn">Searching displayed data only; unshown stream bytes are not searched.</Note>}
      {activeMatch && (
        <div className="follow-search-result">
          <span className="muted">{activeMatch.frames.length
            ? `Frame${activeMatch.frames.length === 1 ? '' : 's'} reported by Wireshark's follower: ${activeMatch.frames.map((frame) => `#${frame}`).join(', ')}. This may not identify the exact on-wire byte origin.`
            : 'The Wireshark follower did not report packet provenance for this match.'}</span>
          <button type="button" className="btn small" onClick={jumpToMatch} disabled={!activeMatch.frames.length}>
            {activeMatch.frames.length ? `Open packet${activeMatch.frames.length === 1 ? '' : 's'} ${activeMatch.frames.map((frame) => `#${frame}`).join(', ')}` : 'Packet source unavailable'}
          </button>
        </div>
      )}
      <div className="follow-legend">
        <span><i className="follow-swatch client" aria-hidden="true" />Client <span className="mono">{side(false)}</span></span>
        <span><i className="follow-swatch server" aria-hidden="true" />Server <span className="mono">{side(true)}</span></span>
        <span className="muted">{plural(data.totalSegments, 'segment')} with payload, {bytes(totalBytes)}. Wireshark's follower takes the first sender it sees as the client.</span>
      </div>
      {data.truncated && (
        <Note kind="warn">
          <b>Showing part of the stream.</b> The view is limited to the first {bytes(FOLLOW_VIEW_BYTES)} and {num(FOLLOW_VIEW_SEGMENTS)} segments; it shows {bytes(shownBytes)} in {num(data.segments.length)} of {num(data.totalSegments)} segments. "Save raw" writes up to {bytes(FOLLOW_SAVE_BYTES)} and {num(FOLLOW_SAVE_SEGMENTS)} segments across both directions.
        </Note>
      )}
      <div ref={bodyRef} className="follow-body" role="region" aria-label="Stream content" tabIndex={0}>
        {runs.length === 0 && <p className="muted">No payload in this direction.</p>}
        {runs.map((r, i) => {
          const highlights = search.matches.flatMap((match, index) => match.runIndex !== i ? [] : [{
            start: format === 'text' ? match.textStart : match.byteStart,
            end: format === 'text' ? match.textEnd : match.byteEnd,
            index,
          }]);
          return (
            <div key={i} className={`follow-run ${r.fromServer ? 'server' : 'client'}`}>
              <div className="follow-label">{directionName(r.fromServer)}, {frameRange(r.frames)}, {plural(r.bytes.length, 'byte')}</div>
              <pre className={format === 'hex' ? 'dump' : undefined}>{format === 'hex'
                ? masks ? renderHexRun(r, masks.all[i], masks.active[i]) : hexDump(r.bytes, r.dirOffset)
                : search.matches.length ? renderHighlightedText(plainTexts[i], highlights, activeIndex) : plainTexts[i]}</pre>
            </div>
          );
        })}
      </div>
    </div>
  );
}
