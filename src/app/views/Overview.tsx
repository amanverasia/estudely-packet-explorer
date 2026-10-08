// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo } from 'react';
import { BarList, Legend, TimeChart, colorMap } from '../components/charts';
import { DataTable } from '../components/DataTable';
import { Addr, Fact, Note, Panel, Seg, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { absTime, bytes, duration, editableSeconds, endpoint, num, parseEditableSeconds, pct, plural } from '../format';

export function Overview() {
  const { model, go, filter, stats, setTimeRange, setHostFilter } = useApp();
  const c = model.capture;
  const [metric, setMetric] = useViewState<'packets' | 'bytes'>('overview.time.metric', 'bytes', (value): value is 'packets' | 'bytes' => value === 'packets' || value === 'bytes');
  const [protoMetric, setProtoMetric] = useViewState<'packets' | 'bytes'>('overview.protocol.metric', 'packets', (value): value is 'packets' | 'bytes' => value === 'packets' || value === 'bytes');
  const keys = model.timeline.series.filter((s) => s.key !== 'All').map((s) => s.key);
  const colors = useMemo(() => colorMap(keys), [keys.join('|')]); // eslint-disable-line react-hooks/exhaustive-deps
  const end = c.startEpoch ? absTime(c.startEpoch, model.timeline.origin + c.duration, Math.min(c.timestampDigits, 6)) : null;
  const start = c.startEpoch ? absTime(c.startEpoch, model.timeline.origin, Math.min(c.timestampDigits, 6)) : null;
  const ip = model.conversations.filter((x) => x.transport === 'TCP' || x.transport === 'UDP');
  const selectedDuration = filter.start !== null && filter.end !== null ? filter.end - filter.start
    : stats.start !== null && stats.end !== null ? Math.max(0, stats.end - stats.start) : c.duration;

  const talkers = model.hosts.slice(0, 50).map((h) => ({ key: h.addr, value: h.txBytes + h.rxBytes, label: <Addr addr={h.addr} />, detail: `${bytes(h.txBytes)} sent, ${bytes(h.rxBytes)} received` }));
  const convs = [...model.conversations].sort((a, b) => b.bytesAB + b.bytesBA - (a.bytesAB + a.bytesBA)).slice(0, 50);
  const convItems = convs.map((x) => ({
    key: String(x.id), value: x.bytesAB + x.bytesBA,
    label: <span><span className="tag" style={{ marginRight: 6 }}>{x.appProtocol}</span><span className="mono">{endpoint(x.a, x.aPort)} ↔ {endpoint(x.b, x.bPort)}</span></span>,
    detail: `${num(x.packetsAB + x.packetsBA)} packets over ${duration(x.end - x.start)}`,
  }));
  const protoItems = [...model.topProtocols]
    .sort((a, b) => b[protoMetric] - a[protoMetric])
    .map((p) => ({ key: p.proto, value: p[protoMetric], color: colors.get(p.proto) ?? colors.get('Other'), label: p.proto }));

  return (
    <>
      <ViewHead title="Overview">{filter.start !== null || filter.host ? 'Filtered totals reflect the selected packets; capture-wide protocol hierarchy and metadata are labelled.' : 'What this capture contains, measured from every packet in the file.'}</ViewHead>
      <CaptureNotes />
      <TimeFilterControls />
      <dl className="facts" style={{ margin: 0 }}>
        <Fact label="Packets" value={num(stats.packets)} small={stats.packets !== c.packetCount ? `${num(c.packetCount)} in full capture` : undefined} />
        <Fact label="Duration" value={duration(selectedDuration)} small={filter.start !== null || filter.host ? 'selected traffic' : undefined} />
        <Fact label="Bytes on wire" value={bytes(stats.wireBytes)} title="Sum of original frame lengths" small={stats.wireBytes !== c.wireBytes ? `${bytes(c.wireBytes)} in full capture` : undefined} />
        <Fact label="Bytes captured" value={bytes(stats.capturedBytes)} small={stats.capturedBytes !== c.capturedBytes ? `${bytes(c.capturedBytes)} in full capture` : c.truncatedPackets ? `${num(c.truncatedPackets)} truncated` : undefined} />
        <Fact label="File size" value={bytes(c.fileSize)} />
        <Fact label="IP hosts" value={num(stats.hosts)} small={stats.hosts !== stats.allHosts ? `${num(stats.allHosts)} in full capture` : undefined} />
        <Fact label="TCP/UDP conversations" value={num(ip.length)} small={filter.start !== null || filter.host ? `${num(stats.allConversations)} total in full capture` : `${num(model.conversations.length)} total`} />
        <Fact label="Average rate" value={selectedDuration > 0 ? `${bytes(Math.round(stats.wireBytes / selectedDuration))}/s` : '—'} />
      </dl>
      <Panel title="Time range" sub="UTC, at the precision stored in the file">
        <dl className="kv">
          <dt>First packet</dt><dd className="mono">{start ?? '—'}</dd>
          <dt>Last packet</dt><dd className="mono">{end ?? '—'}</dd>
          <dt>Format</dt><dd>{c.fileType}; link type {c.linkType}</dd>
          <dt>Timestamp precision</dt><dd>{precisionText(c.timestampDigits)}</dd>
          <dt>Decoded by</dt><dd>Wireshark {c.engine.wireshark} (Wiregasm {c.engine.wiregasm}) in your browser, {duration(c.analysisMs / 1000)} aggregation</dd>
        </dl>
        {c.interfaces.length > 1 && (
          <div style={{ marginTop: 12 }}>
            <h3 style={{ marginBottom: 6 }}>Interfaces</h3>
            <dl className="kv">
              {c.interfaces.map((i) => (
                <div key={String(i.id)} style={{ display: 'contents' }}>
                  <dt className="mono">#{i.id ?? '—'} {i.name}</dt><dd>{i.linkType}, {plural(i.packets, 'packet')}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </Panel>
      <Panel
        title="Traffic over time"
        sub={metric === 'bytes' ? `Bytes on wire (original frame length) per ${duration(model.timeline.binSeconds)}` : `Packets per ${duration(model.timeline.binSeconds)}`}
        right={<Seg label="Chart metric" value={metric} onChange={setMetric} options={[{ value: 'bytes', label: 'Bytes' }, { value: 'packets', label: 'Packets' }]} />}
      >
        <div style={{ display: 'grid', gap: 10 }}>
          <Legend items={keys.map((k) => ({ key: k, color: colors.get(k)! }))} />
          <TimeChart timeline={model.timeline} metric={metric} colors={colors}
            selection={filter.start !== null && filter.end !== null ? { start: filter.start, end: filter.end } : null}
            onRangeChange={setTimeRange} />
          <p className="muted" style={{ fontSize: 12 }}>Series are each packet's highest decoded protocol. Times are relative to the first packet. Drag to apply this window to every view.</p>
        </div>
      </Panel>
      <div className="grid-2">
        <Panel title="Protocol distribution" sub={protoMetric === 'packets' ? 'Packets by highest decoded protocol' : 'Bytes on wire by highest decoded protocol'}
          right={<Seg label="Protocol metric" value={protoMetric} onChange={setProtoMetric} options={[{ value: 'packets', label: 'Packets' }, { value: 'bytes', label: 'Bytes' }]} />}>
          <BarList items={protoItems} format={protoMetric === 'bytes' ? bytes : num} limit={10} />
        </Panel>
        <Panel title="Top talkers" sub={filter.start !== null || filter.host ? 'Bytes sent + received in the selected traffic' : 'Bytes sent + received per IP address'}>
          <BarList items={talkers} format={bytes} limit={8} onSelect={(addr) => setHostFilter(addr)} emptyText="No IP traffic in this capture." />
        </Panel>
      </div>
      <Panel title="Largest conversations" sub="Bytes on wire in both directions">
        <BarList items={convItems} format={bytes} limit={8} onSelect={(id) => go('connections', { conv: id })} />
      </Panel>
      <Panel title="Protocol hierarchy" sub={`Packets containing each protocol at any layer; a packet counts once per protocol${filter.start !== null || filter.host ? ' · whole-capture totals' : ''}`} flush>
        <DataTable stateId="overview.protocol-hierarchy" label="Protocol hierarchy" exportName="protocol-hierarchy" rows={model.protocolHierarchy} rowKey={(r) => r.proto} height={360}
          initialSort={{ key: 'packets', dir: 'desc' }}
          columns={[
            { key: 'proto', header: 'Protocol', width: 'minmax(160px, 2fr)', value: (r) => r.proto },
            { key: 'packets', header: 'Packets', width: '120px', align: 'right', value: (r) => r.packets, render: (r) => num(r.packets) },
            { key: 'share', header: 'Share of packets', width: '130px', align: 'right', value: (r) => r.packets / Math.max(1, c.packetCount), render: (r) => pct(r.packets, c.packetCount) },
            { key: 'bytes', header: 'Bytes on wire', width: '130px', align: 'right', value: (r) => r.bytes, render: (r) => bytes(r.bytes) },
          ]} />
      </Panel>
    </>
  );
}

function TimeFilterControls() {
  const { model, filter, setTimeRange, setHostFilter, clearFilters } = useApp();
  const min = model.timeline.origin;
  const max = model.timeline.end;
  const digits = model.capture.timestampDigits;
  const exactStart = filter.start ?? min;
  const exactEnd = filter.end ?? max;
  const displayedStart = editableSeconds(exactStart, digits);
  const displayedEnd = editableSeconds(exactEnd, digits);
  const [start, setStart] = useViewState<string>('overview.time.start', displayedStart, (value): value is string => typeof value === 'string');
  const [end, setEnd] = useViewState<string>('overview.time.end', displayedEnd, (value): value is string => typeof value === 'string');
  useEffect(() => {
    setStart(displayedStart);
    setEnd(displayedEnd);
  }, [displayedStart, displayedEnd, setStart, setEnd]);
  const a = parseEditableSeconds(start, displayedStart, exactStart);
  const b = parseEditableSeconds(end, displayedEnd, exactEnd);
  const valid = Number.isFinite(a) && Number.isFinite(b) && a >= min && b <= max && a < b;
  return (
    <Panel title="Shared filters" sub="Choose a window here or drag across either traffic chart. Values are seconds relative to the first packet.">
      <form className="filter-controls" onSubmit={(e) => { e.preventDefault(); if (valid) setTimeRange(a, b); }}>
        <label>Start (s)<input className="input mono" type="number" step="any" min={min} max={max} value={start} onChange={(e) => setStart(e.target.value)} aria-label="Time range start in seconds" /></label>
        <label>End (s)<input className="input mono" type="number" step="any" min={min} max={max} value={end} onChange={(e) => setEnd(e.target.value)} aria-label="Time range end in seconds" /></label>
        <button className="btn primary" type="submit" disabled={!valid}>Apply time range</button>
        {filter.host && <span className="filter-detail">Host: <span className="mono">{filter.host}</span> <button type="button" className="btn small ghost" onClick={() => setHostFilter(null)}>Remove</button></span>}
        {(filter.start !== null || filter.host) && <button type="button" className="btn ghost" onClick={clearFilters}>Clear all filters</button>}
      </form>
      {!valid && <p className="note warn" style={{ marginTop: 10 }}>End must be later than start, within this capture.</p>}
      {(filter.start !== null || filter.host) && <p className="muted" style={{ fontSize: 12, margin: '10px 0 0' }}>Traffic and host packet/byte totals are recalculated for the filter. Host metadata and protocol hierarchy remain whole-capture values.</p>}
    </Panel>
  );
}

function precisionText(d: number): string {
  if (d <= 0) return 'whole seconds (or all timestamps fall on whole seconds)';
  if (d <= 3) return `milliseconds or coarser (${d} decimal digit${d > 1 ? 's' : ''} used)`;
  if (d <= 6) return `microseconds (${d} decimal digits used)`;
  return `nanoseconds (${d} decimal digits used)`;
}

/** Data-quality notes shared by the Overview. */
export function CaptureNotes() {
  const { model, filter } = useApp();
  const c = model.capture;
  const notes = [];
  if (c.incomplete) notes.push(<Note key="inc" kind="crit"><b>Incomplete capture.</b> {c.incomplete}</Note>);
  for (const w of c.warnings) notes.push(<Note key={w} kind="warn">{w}</Note>);
  if (c.truncatedPackets) notes.push(<Note key="tr" kind="warn"><b>{plural(c.truncatedPackets, 'packet')} truncated</b> by the capture's snapshot length. Protocol data beyond the captured bytes is missing, so some records may be partial or undecoded.</Note>);
  if (c.malformedPackets) notes.push(<Note key="mal" kind="warn"><b>{plural(c.malformedPackets, 'packet')} malformed</b> according to Wireshark. Fields after the damage point are unavailable.</Note>);
  if (c.lostSegments) notes.push(<Note key="lost" kind="info">Wireshark saw {plural(c.lostSegments, 'gap')} in TCP sequence numbers (segments not captured). Reassembled protocols in those streams may be partial.</Note>);
  if (c.nonMonotonicTimestamps) notes.push(<Note key="ts" kind="info">{plural(c.nonMonotonicTimestamps, 'packet')} have timestamps earlier than the packet before them. Durations use the earliest and latest timestamps.</Note>);
  if (c.retransmissions || c.spuriousRetransmissions || c.outOfOrder) notes.push(<Note key="re" kind="info">TCP analysis: {num(c.retransmissions)} retransmissions, {num(c.spuriousRetransmissions)} spurious retransmissions, {num(c.outOfOrder)} out-of-order segments, {num(c.duplicateAcks)} duplicate ACKs. Byte counts include retransmitted packets.</Note>);
  if (filter.start !== null || filter.host) notes.unshift(<Note key="capture-scope" kind="info">These data-quality notes and protocol counters describe the full capture.</Note>);
  if (!notes.length) return null;
  return <div className="notes">{notes}</div>;
}
