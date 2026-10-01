// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useRef, useState } from 'react';
import type { FrameDetails, PacketRow, ProtoTreeNode } from '../../engine/types';
import { useApp, type DrawerSpec } from '../context';
import { absTime, bytes, endpoint, epochText, num, rel } from '../format';

export function Drawer({ spec, onClose }: { spec: DrawerSpec; onClose: () => void }) {
  const { engine, model } = useApp();
  const frames = useMemo(() => [...new Set(spec.frames)].sort((a, b) => a - b), [spec.frames]);
  const [current, setCurrent] = useState<number>(spec.focus ?? frames[0]);
  const [rows, setRows] = useState<Map<number, PacketRow>>(new Map());
  const [details, setDetails] = useState<FrameDetails | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<ProtoTreeNode | null>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => { setCurrent(spec.focus ?? frames[0]); }, [spec, frames]);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  useEffect(() => {
    engine.request({ kind: 'rows', frames: frames.slice(0, 500) }).then((r) => setRows(new Map(r.rows.map((x) => [x.frame, x])))).catch(() => {});
  }, [engine, frames]);
  useEffect(() => {
    if (current === undefined) return;
    let live = true;
    setDetails(null);
    setSel(null);
    setError(null);
    engine.request({ kind: 'frame', number: current })
      .then((d) => { if (live) setDetails(d); })
      .catch((e: Error) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [engine, current]);

  const row = rows.get(current);
  const digits = model.capture.timestampDigits;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Packet details: ${spec.title}`}>
        <div className="drawer-head">
          <div style={{ minWidth: 0, flex: 1 }}>
            <h2 style={{ fontSize: 16, overflowWrap: 'anywhere' }}>{spec.title}</h2>
            <p className="muted" style={{ fontSize: 12, marginTop: 2 }}>
              Source packets this record was derived from. Fields below are Wireshark's decode of the selected packet.
            </p>
          </div>
          <button ref={closeRef} className="btn" onClick={onClose}>Close</button>
        </div>
        <div className="drawer-body">
          {spec.summary}
          <section>
            <h3 style={{ marginBottom: 8 }}>Packets ({num(frames.length)})</h3>
            <div className="frames-pick" role="group" aria-label="Choose a source packet">
              {frames.slice(0, 200).map((f) => (
                <button key={f} aria-pressed={f === current} onClick={() => setCurrent(f)}>#{f}</button>
              ))}
              {frames.length > 200 && <span className="muted">+{num(frames.length - 200)} more</span>}
            </div>
          </section>
          {current !== undefined && (
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
          {error && <div className="note crit">{error}</div>}
          {!details && !error && <div className="muted">Decoding packet #{current}…</div>}
          {details && (
            <>
              <section className="tree" aria-label="Decoded fields">
                <h3 style={{ marginBottom: 6 }}>Decoded fields</h3>
                <ul role="tree">
                  {details.tree.map((n, i) => <TreeNode key={i} node={n} depth={0} sel={sel} onSel={setSel} />)}
                </ul>
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

function TreeNode({ node, depth, sel, onSel }: { node: ProtoTreeNode; depth: number; sel: ProtoTreeNode | null; onSel: (n: ProtoTreeNode) => void }) {
  const [open, setOpen] = useState(depth === 0 && node.children.length < 40 && !/^(Frame|Ethernet)/.test(node.label));
  const has = node.children.length > 0;
  return (
    <li role="treeitem" aria-expanded={has ? open : undefined} aria-selected={sel === node}>
      <div className="node" aria-selected={sel === node} onClick={() => { onSel(node); if (has) setOpen(!open); }}
        tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSel(node); if (has) setOpen(!open); } }}>
        <span className="twisty" aria-hidden="true">{has ? (open ? '▾' : '▸') : ''}</span>
        <span>{node.label}</span>
      </div>
      {has && open && <ul role="group">{node.children.map((c, i) => <TreeNode key={i} node={c} depth={depth + 1} sel={sel} onSel={onSel} />)}</ul>}
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
