// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import type { FrameDetails, PacketRow, ProtoTreeNode } from '../../engine/types';
import { useApp, type DrawerSpec } from '../context';
import { absTime, bytes, decimalLiteral, endpoint, epochText, num, rel } from '../format';
import { SOURCE_PACKET_PAGE_SIZE, sourceFramePage } from '../sourceFrames';

export function Drawer({ spec, active, onClose }: { spec: DrawerSpec; active: boolean; onClose: () => void }) {
  const { engine, model, filter, go } = useApp();
  const frames = useMemo(() => [...new Set(spec.frames)].sort((a, b) => a - b), [spec.frames]);
  const initialFrame = spec.focus !== undefined && frames.includes(spec.focus) ? spec.focus : frames[0];
  const [current, setCurrent] = useState<number | undefined>(initialFrame);
  const [row, setRow] = useState<PacketRow | null>(null);
  const [details, setDetails] = useState<FrameDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<ProtoTreeNode | null>(null);
  const [actionFeedback, setActionFeedback] = useState<{ kind: 'status' | 'error'; message: string } | null>(null);
  const [copyFallback, setCopyFallback] = useState<{ description: string; text: string } | null>(null);
  const [showingMatches, setShowingMatches] = useState(false);
  const [activeTreePath, setActiveTreePath] = useState('');
  const [frameSearch, setFrameSearch] = useState('');
  const [framePage, setFramePage] = useState(() => {
    const index = initialFrame === undefined ? -1 : frames.indexOf(initialFrame);
    return index < 0 ? 0 : Math.floor(index / SOURCE_PACKET_PAGE_SIZE);
  });
  const closeRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const onCloseRef = useRef(onClose);
  const actionTokenRef = useRef(0);
  const returnFocusRef = useRef<HTMLElement | null>(document.activeElement instanceof HTMLElement ? document.activeElement : null);
  const sharedDisplay = useMemo(() => {
    const terms: string[] = [];
    if (filter.start !== null && filter.end !== null) {
      terms.push(`(frame.time_relative >= ${decimalLiteral(filter.start)} && frame.time_relative <= ${decimalLiteral(filter.end)})`);
    }
    if (filter.host) terms.push(`(${filter.host.includes(':') ? 'ipv6.addr' : 'ip.addr'} == ${filter.host})`);
    return terms.join(' && ');
  }, [filter.start, filter.end, filter.host]);

  useEffect(() => { onCloseRef.current = onClose; }, [onClose]);
  useEffect(() => {
    actionTokenRef.current++;
    const focused = spec.focus !== undefined && frames.includes(spec.focus) ? spec.focus : frames[0];
    const index = focused === undefined ? -1 : frames.indexOf(focused);
    setCurrent(focused);
    setFrameSearch('');
    setFramePage(index < 0 ? 0 : Math.floor(index / SOURCE_PACKET_PAGE_SIZE));
    setActionFeedback(null);
    setCopyFallback(null);
    setShowingMatches(false);
  }, [spec, frames]);
  useEffect(() => {
    const returnTo = returnFocusRef.current;
    return () => { if (returnTo?.isConnected) returnTo.focus(); };
  }, []);
  useEffect(() => {
    if (!active) return;
    const dialog = dialogRef.current;
    if (dialog && !dialog.contains(document.activeElement)) closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onCloseRef.current(); };
    const onTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;
      const dialog = dialogRef.current;
      if (!dialog) return;
      const items = [...dialog.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])')]
        .filter((el) => el.offsetParent !== null);
      if (!items.length) {
        e.preventDefault();
        dialog.focus();
        return;
      }
      const first = items[0], last = items[items.length - 1];
      if (!dialog.contains(document.activeElement)) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      } else if (e.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('keydown', onTab);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('keydown', onTab);
    };
  }, [active]);
  useEffect(() => {
    if (current === undefined) {
      setDetails(null);
      setRow(null);
      return;
    }
    actionTokenRef.current++;
    let live = true;
    setDetails(null);
    setRow(null);
    setSel(null);
    setActionFeedback(null);
    setCopyFallback(null);
    setShowingMatches(false);
    setActiveTreePath('');
    setError(null);
    engine.request({ kind: 'frame', number: current })
      .then((d) => { if (live) setDetails(d); })
      .catch((e: Error) => { if (live) setError(e.message); });
    engine.request({ kind: 'rows', frames: [current], limit: 1 })
      .then((result) => { if (live) setRow(result.rows.find((packet) => packet.frame === current) ?? null); })
      .catch(() => { if (live) setRow(null); });
    return () => { live = false; };
  }, [engine, current]);

  const selectNode = (node: ProtoTreeNode) => {
    actionTokenRef.current++;
    setSel(node);
    setActionFeedback(null);
    setCopyFallback(null);
    setShowingMatches(false);
  };

  const copyFieldText = async (kind: 'label' | 'filter') => {
    if (!sel) return;
    const text = kind === 'label' ? sel.label : sel.filter;
    const description = kind === 'label' ? 'field label' : 'display filter';
    setCopyFallback(null);
    if (!text.trim()) {
      setActionFeedback({ kind: 'error', message: `No ${description} is available for this field.` });
      return;
    }
    const actionToken = ++actionTokenRef.current;
    if (await copyText(text)) {
      if (actionToken === actionTokenRef.current) {
        setCopyFallback(null);
        setActionFeedback({ kind: 'status', message: `${kind === 'label' ? 'Field label' : 'Display filter'} copied.` });
      }
    } else {
      if (actionToken === actionTokenRef.current) {
        setCopyFallback({ description, text });
        setActionFeedback({ kind: 'error', message: `Could not copy the ${description}. Select the text below and copy it manually.` });
      }
    }
  };

  const showMatchingPackets = async () => {
    if (!sel?.filter.trim()) {
      setActionFeedback({ kind: 'error', message: 'This field does not provide a display filter.' });
      return;
    }
    const fieldFilter = sel.filter;
    const composed = [`(${fieldFilter.trim()})`, sharedDisplay].filter(Boolean).join(' && ');
    const actionToken = ++actionTokenRef.current;
    setShowingMatches(true);
    setActionFeedback({ kind: 'status', message: 'Checking the field filter…' });
    try {
      const result = await engine.request({ kind: 'checkFilter', filter: composed });
      if (actionToken !== actionTokenRef.current) return;
      if (!result.ok) {
        setActionFeedback({ kind: 'error', message: `Invalid display filter: ${result.error}` });
        return;
      }
      go('packets', { filter: fieldFilter });
      onClose();
    } catch (e) {
      if (actionToken === actionTokenRef.current) setActionFeedback({ kind: 'error', message: `Could not validate the display filter: ${e instanceof Error ? e.message : String(e)}` });
    } finally {
      if (actionToken === actionTokenRef.current) setShowingMatches(false);
    }
  };

  const sourcePage = useMemo(() => sourceFramePage(frames, frameSearch, framePage), [frameSearch, framePage, frames]);
  const { frames: pageFrames, page: visiblePage, pageCount, total: matchingFrameCount, firstShown, lastShown } = sourcePage;
  const digits = model.capture.timestampDigits;
  const selectSourceFrame = (frame: number) => {
    actionTokenRef.current++;
    setActionFeedback(null);
    setCopyFallback(null);
    setShowingMatches(false);
    setCurrent(frame);
  };
  const jumpToEdgeFrame = (last: boolean) => {
    const frame = last ? frames.at(-1) : frames[0];
    if (frame === undefined) return;
    setFrameSearch('');
    setFramePage(last ? Math.floor((frames.length - 1) / SOURCE_PACKET_PAGE_SIZE) : 0);
    selectSourceFrame(frame);
  };
  const showPackets = spec.showSourcePackets !== false;
  return (
    <>
      <div className="drawer-backdrop" hidden={!active} onClick={active ? onClose : undefined} />
      <aside ref={dialogRef} className="drawer" hidden={!active} role={active ? 'dialog' : undefined} aria-modal={active ? true : undefined} aria-label={`Packet details: ${spec.title}`} aria-describedby="drawer-description" tabIndex={-1}>
        <div className="drawer-head">
          <div style={{ minWidth: 0, flex: 1 }}>
            <h2 style={{ fontSize: 16, overflowWrap: 'anywhere' }}>{spec.title}</h2>
            <p id="drawer-description" className="muted" style={{ fontSize: 12, marginTop: 2 }}>
              Source packets this record was derived from. Fields below are Wireshark's decode of the selected packet.
            </p>
          </div>
          <button ref={closeRef} className="btn" onClick={onClose}>Close</button>
        </div>
        <div className="drawer-body">
          {spec.summary && (showPackets ? <section aria-label="Summary">{spec.summary}</section> : spec.summary)}
          {showPackets && (frames.length <= 1 ? (
            <section aria-label="Packets">
              <h3 style={{ marginBottom: 8 }}>Packet</h3>
              {frames.length === 1 ? (
                <button className="btn small" type="button" aria-pressed={frames[0] === current} onClick={() => selectSourceFrame(frames[0])}>Decode packet #{frames[0]}</button>
              ) : (
                <p className="muted">No source packet was recorded for this row.</p>
              )}
            </section>
          ) : (
          <section aria-label="Packets">
            <h3 style={{ marginBottom: 8 }}>Packets ({num(frames.length)})</h3>
            <label className="muted" style={{ display: 'block', fontSize: 12, marginBottom: 6 }}>
              Search source packets by frame number
              <input className="input mono" type="search" maxLength={20} value={frameSearch}
                onChange={(event) => { setFrameSearch(event.currentTarget.value); setFramePage(0); }}
                aria-label="Search source packets by frame number"
                style={{ display: 'block', width: '100%', marginTop: 4 }} />
            </label>
            <div className="actions" role="group" aria-label="Source packet pages" style={{ marginBottom: 8 }}>
              <button className="btn small" type="button" aria-label="First source packet page" disabled={visiblePage === 0} onClick={() => setFramePage(0)}>First</button>
              <button className="btn small" type="button" aria-label="Previous source packet page" disabled={visiblePage === 0} onClick={() => setFramePage((page) => Math.max(0, page - 1))}>Previous</button>
              <button className="btn small" type="button" aria-label="Next source packet page" disabled={visiblePage >= pageCount - 1} onClick={() => setFramePage((page) => Math.min(pageCount - 1, page + 1))}>Next</button>
              <button className="btn small" type="button" aria-label="Last source packet page" disabled={pageCount === 0 || visiblePage >= pageCount - 1} onClick={() => setFramePage(Math.max(0, pageCount - 1))}>Last</button>
              <span className="muted" role="status" aria-live="polite">
                {matchingFrameCount
                  ? `Showing ${num(firstShown)}–${num(lastShown)} of ${num(matchingFrameCount)}${frameSearch.trim() ? ' matching' : ''} packets${pageCount > 1 ? ` (page ${num(visiblePage + 1)} of ${num(pageCount)})` : ''}.`
                  : 'No source packets match this search.'}
              </span>
            </div>
            <p className="muted" role="status" aria-live="polite" style={{ fontSize: 12, margin: '0 0 8px' }}>
              Decoded packet: {current === undefined ? 'none' : `#${num(current)}`}. Browsing pages or search results keeps this packet selected.
            </p>
            {current !== undefined && !pageFrames.includes(current) && (
              <button className="btn small" type="button" style={{ marginBottom: 8 }} onClick={() => {
                const query = frameSearch.trim();
                const matchingIndex = (query ? frames.filter((frame) => String(frame).includes(query)) : frames).indexOf(current);
                if (matchingIndex >= 0) setFramePage(Math.floor(matchingIndex / SOURCE_PACKET_PAGE_SIZE));
                else {
                  const allFramesIndex = frames.indexOf(current);
                  setFrameSearch('');
                  setFramePage(Math.floor(Math.max(0, allFramesIndex) / SOURCE_PACKET_PAGE_SIZE));
                }
              }}>Show decoded packet in list</button>
            )}
            <div className="actions" role="group" aria-label="Jump to first or last source packet" style={{ marginBottom: 8 }}>
              <button className="btn small" type="button" disabled={!frames.length} onClick={() => jumpToEdgeFrame(false)}>Decode first source packet</button>
              <button className="btn small" type="button" disabled={!frames.length} onClick={() => jumpToEdgeFrame(true)}>Decode last source packet</button>
            </div>
            <div className="frames-pick" role="group" aria-label="Choose a source packet">
              {pageFrames.map((f) => (
                <button key={f} type="button" aria-label={`Decode source packet ${f}`} aria-pressed={f === current} onClick={() => selectSourceFrame(f)}>#{f}</button>
              ))}
            </div>
          </section>
          ))}
          {showPackets && current !== undefined && (
            <section>
              <dl className="kv">
                <dt>Packet</dt><dd className="mono">#{current}</dd>
                <dt>Timestamp</dt><dd className="mono">{details?.epoch ? epochText(details.epoch) : row ? absTime(model.capture.startEpoch, row.t, digits) + ' UTC' : '…'}</dd>
                {row && <><dt>Relative time</dt><dd className="mono">{rel(row.t, digits)} s</dd></>}
                {row && <><dt>Endpoints</dt><dd className="mono">{endpoint(row.src, row.sport)} → {endpoint(row.dst, row.dport)}</dd></>}
                {row && <><dt>Length</dt><dd>{bytes(row.len)} on wire{row.caplen < row.len ? <>, <b>{bytes(row.caplen)} captured (truncated)</b></> : ''}</dd></>}
                {row?.flags && <><dt>Flags</dt><dd>{flagText(row.flags)}</dd></>}
                {details?.comments.length ? <><dt>Comments</dt><dd>{details.comments.join('\n')}</dd></> : null}
              </dl>
            </section>
          )}
          {error && <div className="note crit" role="alert">{error}</div>}
          {!details && !error && <div className="muted" role="status">Decoding packet #{current}…</div>}
          {details && (
            <>
              <section className="tree" aria-label="Decoded fields">
                <h3 id="decoded-fields-title" style={{ marginBottom: 6 }}>Decoded fields</h3>
                <ul role="tree" aria-labelledby="decoded-fields-title" onKeyDown={moveTreeFocus}>
                  {details.tree.map((n, i) => <TreeNode key={i} node={n} path={String(i)} depth={0} sel={sel} onSel={selectNode} activePath={activeTreePath} onActive={setActiveTreePath} />)}
                </ul>
                {sel && (
                  <div className="panel" role="group" aria-label="Selected field actions" style={{ marginTop: 10, padding: 12 }}>
                    <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
                      Selected field: <span className="mono">{sel.label || 'label unavailable'}</span>
                    </div>
                    <div className="actions">
                      <button className="btn small" type="button" disabled={!sel.label} onClick={() => void copyFieldText('label')}>Copy field label</button>
                      <button className="btn small" type="button" disabled={!sel.filter.trim()} onClick={() => void copyFieldText('filter')}>Copy display filter</button>
                      <button className="btn small" type="button" disabled={!sel.filter.trim() || showingMatches} onClick={() => void showMatchingPackets()}>
                        {showingMatches ? 'Checking filter…' : 'Show matching packets'}
                      </button>
                    </div>
                    <div id="field-value-unavailable" className="muted" role="note" style={{ fontSize: 12, margin: '8px 0 0' }}>
                      Typed field values are not exposed separately by this decoder tree. Copying the field label copies only the displayed label; no value is inferred.
                    </div>
                    <button className="btn small" type="button" disabled aria-describedby="field-value-unavailable" style={{ marginTop: 8 }}>Copy field value</button>
                    {!sel.filter.trim() && <p className="muted" style={{ fontSize: 12, margin: '6px 0 0' }}>No display filter is available for this field.</p>}
                    {actionFeedback && <p className={actionFeedback.kind === 'error' ? 'note crit' : 'note info'} role={actionFeedback.kind === 'error' ? 'alert' : 'status'} aria-live={actionFeedback.kind === 'error' ? 'assertive' : 'polite'} style={{ margin: '8px 0 0' }}>{actionFeedback.message}</p>}
                    {copyFallback && <label className="muted" style={{ display: 'block', fontSize: 12, marginTop: 8 }}>
                      Copy the {copyFallback.description} manually
                      <textarea className="input mono" aria-label="Text to copy manually" readOnly rows={3} value={copyFallback.text}
                        onFocus={(event) => event.currentTarget.select()}
                        style={{ display: 'block', width: '100%', height: 'auto', minHeight: 56, marginTop: 4, padding: 6, resize: 'vertical' }} />
                    </label>}
                  </div>
                )}
                {details.truncatedTree && <p className="muted">The field tree was cut off at 20,000 entries.</p>}
              </section>
              {details.sources.map((s, i) => (
                <section key={i}>
                  <h3 style={{ marginBottom: 6 }}>{s.name || `Bytes (${i})`} <span className="muted" style={{ fontWeight: 400 }}>{num(s.bytes.length)} bytes</span></h3>
                  <HexDump data={s.bytes} hl={sel && sel.source === i ? [sel.start, sel.length] : null} />
                </section>
              ))}
            </>
          )}
        </div>
      </aside>
    </>
  );
}

export function flagText(f: string): string {
  const names: Record<string, string> = {
    R: 'retransmission', r: 'spurious retransmission', O: 'out of order', L: 'previous segment not captured',
    D: 'duplicate ACK', Z: 'zero window', F: 'IP fragment', f: 'reassembled from fragments', M: 'malformed', E: 'expert error',
  };
  return [...new Set(f.split(''))].map((c) => names[c] ?? c).join(', ');
}

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* Try the document copy fallback below. */ }

  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.setAttribute('aria-hidden', 'true');
  textarea.tabIndex = -1;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  textarea.style.pointerEvents = 'none';
  try {
    document.body.appendChild(textarea);
    textarea.select();
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textarea.remove();
    previous?.focus();
  }
}

function moveTreeFocus(event: ReactKeyboardEvent<HTMLUListElement>) {
  const tree = event.currentTarget;
  const current = (event.target as HTMLElement).closest<HTMLElement>('[role="treeitem"]');
  if (!current || !tree.contains(current)) return;
  const items = [...tree.querySelectorAll<HTMLElement>('[role="treeitem"]')];
  const index = items.indexOf(current);
  const next = event.key === 'ArrowDown' ? items[index + 1]
    : event.key === 'ArrowUp' ? items[index - 1]
      : event.key === 'Home' ? items[0]
        : event.key === 'End' ? items.at(-1)
          : undefined;
  if (next) {
    event.preventDefault();
    next.focus();
  }
}

function TreeNode({ node, path, depth, sel, onSel, activePath, onActive }: {
  node: ProtoTreeNode;
  path: string;
  depth: number;
  sel: ProtoTreeNode | null;
  onSel: (n: ProtoTreeNode) => void;
  activePath: string;
  onActive: (path: string) => void;
}) {
  const [open, setOpen] = useState(depth === 0 && node.children.length < 40 && !/^(Frame|Ethernet)/.test(node.label));
  const has = node.children.length > 0;
  return (
    <li role="treeitem" className="node" tabIndex={activePath === path || (!activePath && path === '0') ? 0 : -1}
      aria-expanded={has ? open : undefined} aria-selected={sel === node}
      onFocus={() => onActive(path)}
      onClick={(event) => {
        event.stopPropagation();
        event.currentTarget.focus();
        onSel(node);
        if (has) setOpen(!open);
      }}
      onKeyDown={(event) => {
        if (event.key === 'ArrowRight' && has) {
          event.preventDefault();
          if (!open) setOpen(true);
          else event.currentTarget.querySelector<HTMLElement>(':scope > ul[role="group"] > [role="treeitem"]')?.focus();
        } else if (event.key === 'ArrowLeft') {
          event.preventDefault();
          if (has && open) setOpen(false);
          else event.currentTarget.parentElement?.closest<HTMLElement>('[role="treeitem"]')?.focus();
        } else if (event.key === ' ' || event.key === 'Enter') {
          event.preventDefault();
          onSel(node);
        }
      }}>
        <span className="node-label">
          <span className="twisty" aria-hidden="true">{has ? (open ? '▾' : '▸') : ''}</span>
          <span>{node.label}</span>
        </span>
      {has && open && <ul role="group">{node.children.map((c, i) => <TreeNode key={i} node={c} path={`${path}.${i}`} depth={depth + 1} sel={sel} onSel={onSel} activePath={activePath} onActive={onActive} />)}</ul>}
    </li>
  );
}

function HexDump({ data, hl }: { data: Uint8Array; hl: [number, number] | null }) {
  const MAX = 16384;
  const shown = data.subarray(0, MAX);
  const lines = [];
  const inHl = (i: number) => hl !== null && hl[1] > 0 && i >= hl[0] && i < hl[0] + hl[1];
  for (let off = 0; off < shown.length; off += 16) {
    const hex = [];
    const asc = [];
    for (let i = off; i < off + 16; i++) {
      if (i < shown.length) {
        const b = shown[i];
        const h = b.toString(16).padStart(2, '0');
        const c = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
        hex.push(inHl(i) ? <mark key={i}>{h}</mark> : h, i === off + 7 ? '  ' : ' ');
        asc.push(inHl(i) ? <mark key={i}>{c}</mark> : c);
      } else hex.push('   ');
    }
    lines.push(<div key={off}>{off.toString(16).padStart(4, '0')}  {hex}  {asc}</div>);
  }
  return (
    <div className="hex" aria-label="Packet bytes">
      {lines}
      {data.length > MAX && <div className="muted">… {num(data.length - MAX)} more bytes not shown</div>}
    </div>
  );
}
