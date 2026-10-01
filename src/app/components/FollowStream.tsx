// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Follow stream: a conversation's reassembled payload, as Wireshark's
// Follow TCP/UDP Stream shows it. Payload is rendered only as text nodes.
import { useEffect, useMemo, useState } from 'react';
import type { Conversation, FollowStream as FollowData } from '../../engine/types';
import { downloadBlob, safeBase } from '../download';
import { directionBytes, FOLLOW_SAVE_BYTES, FOLLOW_VIEW_BYTES, FOLLOW_VIEW_SEGMENTS, followRuns, hexDump, joinRuns, payloadText, type FollowDirection } from '../follow';
import { useApp } from '../context';
import { bytes, endpoint, num, plural } from '../format';
import { Note, Seg } from './bits';

function frameRange(frames: number[]): string {
  return frames.length === 1 ? `#${frames[0]}` : `#${frames[0]} to #${frames[frames.length - 1]} (${frames.length} packets)`;
}

export function FollowStream({ c }: { c: Conversation }) {
  const { model, engine } = useApp();
  const transport = c.transport as 'TCP' | 'UDP';
  const stream = c.stream!;
  const [data, setData] = useState<FollowData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [dir, setDir] = useState<FollowDirection>('both');
  const [format, setFormat] = useState<'text' | 'hex'>('text');
  const [saving, setSaving] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    setErr(null);
    engine.request({ kind: 'follow', transport, stream, maxBytes: FOLLOW_VIEW_BYTES, maxSegments: FOLLOW_VIEW_SEGMENTS })
      .then(setData).catch((e: Error) => setErr(e.message));
  }, [engine, transport, stream]);

  const runs = useMemo(() => (data ? followRuns(data, dir) : []), [data, dir]);

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
      const full = await engine.request({ kind: 'follow', transport, stream, maxBytes: FOLLOW_SAVE_BYTES, maxSegments: Infinity });
      const out = joinRuns(followRuns(full, dir));
      downloadBlob(fileName, new Blob([out], { type: 'application/octet-stream' }));
      // The cap counts both directions, so compare what was written with the selected directions' total.
      const wanted = directionBytes(full, dir);
      setSaving(out.length < wanted ? `Saved the first ${bytes(out.length)} of ${bytes(wanted)}.` : null);
    } catch (e) {
      setSaving(`Could not save: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <div className="follow">
      <div className="follow-tools">
        <Seg label="Directions shown" value={dir} onChange={setDir} options={[
          { value: 'both', label: 'Both directions' },
          { value: 'client', label: <>Client → server <span className="num">({bytes(data.clientBytes)})</span></> },
          { value: 'server', label: <>Server → client <span className="num">({bytes(data.serverBytes)})</span></> },
        ]} />
        <Seg label="Format" value={format} onChange={setFormat} options={[{ value: 'text', label: 'Text' }, { value: 'hex', label: 'Hex' }]} />
        <button className="btn small" onClick={save} disabled={saving === 'Preparing…'}
          title="Download the reassembled payload of the selected directions as raw bytes. It is saved on this device only.">Save raw</button>
        {saving && <span className="muted" role="status">{saving}</span>}
      </div>
      <div className="follow-legend">
        <span><i className="follow-swatch client" aria-hidden="true" />Client <span className="mono">{side(false)}</span></span>
        <span><i className="follow-swatch server" aria-hidden="true" />Server <span className="mono">{side(true)}</span></span>
        <span className="muted">{plural(data.totalSegments, 'segment')} with payload, {bytes(totalBytes)}. Wireshark's follower takes the first sender it sees as the client.</span>
      </div>
      {data.truncated && (
        <Note kind="warn">
          <b>Showing part of the stream.</b> The view is limited to the first {bytes(FOLLOW_VIEW_BYTES)} and {num(FOLLOW_VIEW_SEGMENTS)} segments; it shows {bytes(shownBytes)} in {num(data.segments.length)} of {num(data.totalSegments)} segments. "Save raw" writes up to {bytes(FOLLOW_SAVE_BYTES)}.
        </Note>
      )}
      <div className="follow-body" role="region" aria-label="Stream content" tabIndex={0}>
        {runs.length === 0 && <p className="muted">No payload in this direction.</p>}
        {runs.map((r, i) => (
          <div key={i} className={`follow-run ${r.fromServer ? 'server' : 'client'}`}>
            <div className="follow-label">{r.fromServer ? 'Server → client' : 'Client → server'}, {frameRange(r.frames)}, {plural(r.bytes.length, 'byte')}</div>
            <pre className={format === 'hex' ? 'dump' : undefined}>{format === 'hex' ? hexDump(r.bytes, r.dirOffset) : payloadText(r.bytes)}</pre>
          </div>
        ))}
      </div>
    </div>
  );
}
