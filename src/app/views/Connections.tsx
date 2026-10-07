// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useRef, useState } from 'react';
import { PACKET_ROW_PAGE_SIZE, type Conversation, type PacketRow, type Transport } from '../../engine/types';
import { DataTable, type Column } from '../components/DataTable';
import { flagText } from '../components/Drawer';
import { Addr, Note, Panel, Seg, ViewHead } from '../components/bits';
import { FollowStream } from '../components/FollowStream';
import { useApp, useViewState } from '../context';
import { bytes, duration, endpoint, num, plural, rel } from '../format';
import { CONNECTION_TRANSPORTS, countConnectionTransports } from '../connectionCounts';
import {
  connectionQualityFilters,
  countConnectionQuality,
  filterConnectionsByQuality,
  type ConnectionQualityFilter,
} from '../connectionQuality';

export function tcpState(c: Conversation): string {
  if (!c.tcp) return '';
  const t = c.tcp;
  const parts = [];
  if (t.synSeen) parts.push('SYN');
  if (t.synAckSeen) parts.push('SYN-ACK');
  if (!t.synSeen && !t.synAckSeen) parts.push('started before capture');
  if (t.finSeen) parts.push('FIN');
  if (t.rstSeen) parts.push('RST');
  return parts.join(', ');
}

export function Connections() {
  const { model, sourceModel, params, go } = useApp();
  const [transport, setTransport] = useViewState<'all' | Transport>('connections.transport', 'all', (value): value is 'all' | Transport =>
    value === 'all' || value === 'TCP' || value === 'UDP' || value === 'IP' || value === 'Non-IP');
  const [app, setApp] = useViewState<string>('connections.protocol', 'all', (value): value is string =>
    value === 'all' || (typeof value === 'string' && sourceModel.conversations.some((conversation) => conversation.appProtocol === value)));
  const [qualityFilter, setQualityFilter] = useViewState<ConnectionQualityFilter>('connections.quality', 'all', (value): value is ConnectionQualityFilter =>
    value === 'all' || connectionQualityFilters.some((item) => item.value === value));
  const [hostFilter, setHostFilter] = useViewState<string | null>('connections.host', null, (value): value is string | null => value === null || typeof value === 'string');
  const lastRouteHost = useRef<string | null>(null);
  const [selected, setSelected] = useViewState<number | null>('connections.selected', null, (value): value is number | null => value === null || (typeof value === 'number' && Number.isInteger(value)));
  const lastRouteConversation = useRef<string | null>(null);
  useEffect(() => {
    if (params.has('host')) {
      const requested = params.get('host') || '';
      if (requested !== lastRouteHost.current) {
        lastRouteHost.current = requested;
        setHostFilter(requested && sourceModel.hosts.some((h) => h.addr === requested) ? requested : null);
      }
    } else {
      lastRouteHost.current = null;
      if (params.has('conv')) setHostFilter(null);
    }
  }, [params, sourceModel.hosts, setHostFilter]);
  useEffect(() => {
    if (!params.has('conv')) { lastRouteConversation.current = null; return; }
    const requested = params.get('conv') || '';
    if (requested !== lastRouteConversation.current) {
      lastRouteConversation.current = requested;
      const id = Number(requested);
      setSelected(requested && Number.isInteger(id) && sourceModel.conversations.some((c) => c.id === id) ? id : null);
    }
  }, [params, sourceModel.conversations, setSelected]);
  const apps = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of sourceModel.conversations) m.set(c.appProtocol, (m.get(c.appProtocol) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [sourceModel.conversations]);
  const transportScope = useMemo(() => model.conversations.filter((c) =>
    (app === 'all' || c.appProtocol === app) && (!hostFilter || c.a === hostFilter || c.b === hostFilter)),
  [model.conversations, app, hostFilter]);
  const unfilteredRows = useMemo(() => transportScope.filter((c) => transport === 'all' || c.transport === transport), [transportScope, transport]);
  const rows = useMemo(() => filterConnectionsByQuality(unfilteredRows, qualityFilter), [unfilteredRows, qualityFilter]);
  const qualityCounts = useMemo(() => countConnectionQuality(unfilteredRows), [unfilteredRows]);
  const conv = selected !== null ? model.conversations.find((c) => c.id === selected) ?? null : null;
  const counts = useMemo(() => countConnectionTransports(transportScope), [transportScope]);
  const availableTransports = useMemo(() => {
    const available = countConnectionTransports(sourceModel.conversations);
    return CONNECTION_TRANSPORTS.filter((item) => available[item] > 0 || transport === item);
  }, [sourceModel.conversations, transport]);
  const digits = Math.min(6, model.capture.timestampDigits);

  const columns: Column<Conversation>[] = [
    { key: 'transport', header: 'Type', width: '74px', value: (c) => c.transport },
    { key: 'stream', header: 'Stream', width: '72px', align: 'right', value: (c) => c.stream, title: 'Wireshark tcp.stream / udp.stream index. A reused address/port pair gets a new index.' },
    { key: 'a', header: 'Endpoint A', width: 'minmax(190px, 1.4fr)', value: (c) => endpoint(c.a, c.aPort), render: (c) => <Addr addr={c.a} port={c.aPort} /> },
    { key: 'b', header: 'Endpoint B', width: 'minmax(190px, 1.4fr)', value: (c) => endpoint(c.b, c.bPort), render: (c) => <Addr addr={c.b} port={c.bPort} /> },
    { key: 'app', header: 'Protocol', width: '96px', value: (c) => c.appProtocol, render: (c) => <span className="tag">{c.appProtocol}</span> },
    { key: 'pab', header: 'Pkts A→B', width: '84px', align: 'right', value: (c) => c.packetsAB, render: (c) => num(c.packetsAB), noSearch: true },
    { key: 'bab', header: 'Bytes A→B', width: '92px', align: 'right', value: (c) => c.bytesAB, render: (c) => bytes(c.bytesAB), noSearch: true },
    { key: 'pba', header: 'Pkts B→A', width: '84px', align: 'right', value: (c) => c.packetsBA, render: (c) => num(c.packetsBA), noSearch: true },
    { key: 'bba', header: 'Bytes B→A', width: '92px', align: 'right', value: (c) => c.bytesBA, render: (c) => bytes(c.bytesBA), noSearch: true },
    { key: 'start', header: 'Start (s)', width: '100px', align: 'right', value: (c) => c.start, render: (c) => rel(c.start, digits), noSearch: true },
    { key: 'dur', header: 'Duration', width: '96px', align: 'right', value: (c) => c.end - c.start, render: (c) => duration(c.end - c.start), noSearch: true },
    { key: 'state', header: 'TCP flags seen', width: 'minmax(140px, 1fr)', value: (c) => tcpState(c) },
  ];

  return (
    <>
      <ViewHead title="Connections"
        right={<Seg label="Transport" value={transport} onChange={setTransport}
          options={[{ value: 'all', label: `All ${num(transportScope.length)}` }, ...availableTransports.map((t) => ({ value: t, label: `${t} ${num(counts[t])}` }))]} />}>
        TCP and UDP conversations use Wireshark's stream index, so a reused address and port pair appears as separate sessions. Endpoint A is the TCP SYN sender, or otherwise the first packet's sender. Other IP traffic (such as ICMP) is grouped per address pair and protocol.
      </ViewHead>
      {hostFilter && (
        <Note>Showing conversations involving <span className="mono">{hostFilter}</span>. <button className="btn small" onClick={() => { setHostFilter(null); go('connections'); }}>Show all</button></Note>
      )}
      <Note>Transport counts use the shared capture filters and current protocol/host choices, before the transport and quality filters, so the chips partition the same conversation set. TCP indicators are full-conversation observations, not diagnoses; their counts keep that scope even when packet filters are active.</Note>
      {conv && <ConversationDetail key={conv.id} c={conv} onClose={() => setSelected(null)} />}
      <section className="panel">
        <DataTable stateId="connections.conversations" label="Conversations" exportName="conversations" rows={rows} columns={columns} rowKey={(c) => c.id} selectedKey={selected}
          onRowClick={(c) => setSelected(c.id)} initialSort={{ key: 'start', dir: 'asc' }} searchPlaceholder="Search addresses, ports, protocols"
          toolbar={
            <div className="connection-filters">
              <select className="select" value={app} onChange={(e) => setApp(e.target.value)} aria-label="Filter by protocol">
                <option value="all">All protocols</option>
                {apps.map(([a, n]) => <option key={a} value={a}>{a} ({num(n)})</option>)}
              </select>
              <div className="connection-quality-group" role="group" aria-label="Filter by connection quality observation">
                <span className="connection-quality-label">Capture observations</span>
                <div className="connection-quality-options">
                  <button className="btn small quality-filter" aria-pressed={qualityFilter === 'all'}
                    title={`${num(qualityCounts.all)} conversations`} onClick={() => setQualityFilter('all')}>
                    All ({num(qualityCounts.all)})
                  </button>
                  {connectionQualityFilters.map(({ value, label, description }) => (
                    <button key={value} className="btn small quality-filter" aria-pressed={qualityFilter === value}
                      title={`${num(qualityCounts[value])} conversations where ${description}`}
                      onClick={() => setQualityFilter(value)}>
                      {label} ({num(qualityCounts[value])})
                    </button>
                  ))}
                </div>
              </div>
            </div>
          }
          empty={unfilteredRows.length === 0 ? <><strong>No conversations.</strong>No packets could be grouped into conversations with the current filters.</> : <>
            <strong>No matching conversations.</strong>No conversations in this view show {connectionQualityFilters.find((item) => item.value === qualityFilter)?.description ?? 'this observation'}.
            <button className="btn small" style={{ marginTop: 8 }} onClick={() => setQualityFilter('all')}>Clear quality filter</button>
          </>} />
      </section>
    </>
  );
}

function ConversationDetail({ c, onClose }: { c: Conversation; onClose: () => void }) {
  const { model, engine, openDrawer } = useApp();
  const [packets, setPackets] = useState<{ rows: PacketRow[]; total: number; page: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [pageEntry, setPageEntry] = useState('1');
  const [retry, setRetry] = useState(0);
  const [follow, setFollow] = useState(false);
  const canFollow = (c.transport === 'TCP' || c.transport === 'UDP') && c.stream !== null;
  useEffect(() => {
    setPackets(null);
    setErr(null);
    setPageEntry(String(page + 1));
    let live = true;
    engine.request({ kind: 'rows', convId: c.id, skip: page * PACKET_ROW_PAGE_SIZE, limit: PACKET_ROW_PAGE_SIZE })
      .then((result) => { if (live) setPackets({ ...result, page }); })
      .catch((error: unknown) => { if (live) setErr(error instanceof Error ? error.message : String(error)); });
    return () => { live = false; };
  }, [engine, c.id, page, retry]);
  const dns = model.dns.filter((d) => d.convId === c.id);
  const http = model.http.filter((h) => h.convId === c.id);
  const tls = model.tls.filter((t) => t.convId === c.id);
  const digits = Math.min(9, model.capture.timestampDigits);
  const visiblePackets = packets?.page === page ? packets : null;
  const t = c.tcp;

  const pcols: Column<PacketRow>[] = [
    { key: 'frame', header: 'No.', width: '76px', align: 'right', value: (p) => p.frame },
    { key: 't', header: 'Time (s)', width: '120px', align: 'right', value: (p) => p.t, render: (p) => rel(p.t, digits) },
    { key: 'dir', header: 'Direction', width: '70px', value: (p) => (p.src === c.a && (p.sport ?? null) === c.aPort ? 'A→B' : 'B→A') },
    { key: 'proto', header: 'Protocol', width: '96px', value: (p) => p.protocol },
    { key: 'decryption', header: 'TLS data', width: '112px', value: (p) => p.decrypted ? 'Decrypted' : null,
      render: (p) => p.decrypted ? <span className="tag info">Decrypted</span> : null },
    { key: 'len', header: 'Length', width: '80px', align: 'right', value: (p) => p.len, render: (p) => (p.caplen < p.len ? `${p.len} (${p.caplen} captured)` : num(p.len)) },
    { key: 'flags', header: 'Notes', width: 'minmax(200px, 2fr)', value: (p) => (p.flags ? flagText(p.flags) : '') },
  ];

  return (
    <Panel title={<span className="mono" style={{ overflowWrap: 'anywhere' }}>{endpoint(c.a, c.aPort)} ↔ {endpoint(c.b, c.bPort)}</span>}
      sub={`${c.transport}${c.stream !== null ? ` stream ${c.stream}` : ''}, ${c.appProtocol}`}
      right={<>
        {canFollow && <button className="btn small" aria-pressed={follow} onClick={() => setFollow(!follow)}>{follow ? 'Hide stream' : 'Follow stream'}</button>}
        <button className="btn small ghost" onClick={onClose}>Close</button>
      </>}>
      <div style={{ display: 'grid', gap: 16, gridTemplateColumns: 'minmax(0, 1fr)' }}>
        <div className="grid-2">
          <dl className="kv">
            <dt>A → B</dt><dd>{plural(c.packetsAB, 'packet')}, {bytes(c.bytesAB)}{t ? `, ${bytes(t.payloadBytesAB)} TCP payload` : ''}</dd>
            <dt>B → A</dt><dd>{plural(c.packetsBA, 'packet')}, {bytes(c.bytesBA)}{t ? `, ${bytes(t.payloadBytesBA)} TCP payload` : ''}</dd>
            <dt>Time</dt><dd>{rel(c.start, digits)} s to {rel(c.end, digits)} s ({duration(c.end - c.start)})</dd>
            <dt>Packets</dt><dd>#{c.firstFrame} to #{c.lastFrame}</dd>
            <dt>Endpoint A chosen by</dt><dd>{c.initiator === 'SYN' ? 'TCP SYN sender' : 'first packet seen (the start may not be in the capture)'}</dd>
          </dl>
          <dl className="kv">
            <dt>Protocols</dt><dd>{c.protocols.join(', ')}</dd>
            {t && <><dt>TCP flags seen</dt><dd>{tcpState(c)}</dd>
              <dt>TCP analysis</dt><dd>{num(t.retransmissions)} retransmissions, {num(t.outOfOrder)} out of order, {num(t.lostSegments)} gaps (segments not captured)</dd></>}
            {(c.truncatedPackets > 0 || c.malformedPackets > 0) && <><dt>Data quality</dt><dd>{num(c.truncatedPackets)} truncated, {num(c.malformedPackets)} malformed packets</dd></>}
            <dt>Decoded records</dt><dd>{num(dns.length)} DNS, {num(http.length)} HTTP, {num(tls.length)} TLS</dd>
          </dl>
        </div>
        {(dns.length > 0 || http.length > 0 || tls.length > 0) && (
          <div style={{ display: 'grid', gap: 6 }}>
            <h3>Protocol records</h3>
            {dns.slice(0, 50).map((d) => (
              <button key={'d' + d.id} className="btn small" style={{ justifySelf: 'start' }}
                onClick={() => openDrawer({ title: `${d.proto} ${d.qtype ?? ''} ${d.qname ?? ''}`, frames: d.frames })}>
                {d.proto} {d.qtype} {d.qname} — {d.status}
              </button>
            ))}
            {http.slice(0, 50).map((h) => (
              <button key={'h' + h.id} className="btn small" style={{ justifySelf: 'start', maxWidth: '100%', overflow: 'hidden' }}
                onClick={() => openDrawer({ title: `HTTP ${h.method ?? ''} ${h.uri ?? ''}`, frames: h.frames })}>
                HTTP {h.method ?? '(no request)'} {h.uri} — {h.status ?? 'no response'}
              </button>
            ))}
            {tls.map((s) => (
              <button key={'t' + s.id} className="btn small" style={{ justifySelf: 'start' }}
                onClick={() => openDrawer({ title: `TLS ${s.sni ?? ''}`, frames: s.frames })}>
                TLS {s.sni ?? '(no SNI)'} — {s.negotiated?.version ?? 'no ServerHello seen'}
              </button>
            ))}
          </div>
        )}
        {canFollow && follow && (
          <div>
            <h3 style={{ marginBottom: 6 }}>Follow {c.transport} stream {c.stream}</h3>
            <FollowStream c={c} />
          </div>
        )}
        <div>
          <h3 style={{ marginBottom: 6 }}>Packets</h3>
          {err && <div className="note crit" role="alert">{err} <button className="btn small" onClick={() => setRetry((value) => value + 1)}>Retry page</button></div>}
          {!packets && !err ? <p className="muted" role="status">Loading packet page {num(page + 1)}…</p> : null}
          {visiblePackets && (
            <div className="panel" style={{ borderRadius: 6 }}>
              <p className="muted" style={{ padding: '8px 16px 0' }}>
                Showing {visiblePackets.total === 0 ? '0' : `${num(page * PACKET_ROW_PAGE_SIZE + 1)}–${num(page * PACKET_ROW_PAGE_SIZE + visiblePackets.rows.length)}`} of {num(visiblePackets.total)} packets in this conversation, including packets outside active shared filters. Search, sort and CSV export apply to this page.
              </p>
              <div className="connection-filters" role="group" aria-label="Conversation packet pages" style={{ padding: '8px 16px', alignItems: 'center' }}>
                <button className="btn small" onClick={() => setPage(0)} disabled={page === 0}>First</button>
                <button className="btn small" onClick={() => setPage((value) => Math.max(0, value - 1))} disabled={page === 0}>Previous</button>
                <span className="muted" aria-live="polite">Page {num(page + 1)} of {num(Math.max(1, Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE)))}</span>
                <label className="muted" htmlFor={`conversation-page-${c.id}`}>Go to page</label>
                <input id={`conversation-page-${c.id}`} className="input" type="number" min={1}
                  max={Math.max(1, Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE))} step={1} value={pageEntry}
                  onChange={(event) => setPageEntry(event.target.value)} style={{ width: 88 }} />
                <button className="btn small" onClick={() => {
                  const requested = Number(pageEntry);
                  const pageCount = Math.max(1, Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE));
                  if (Number.isSafeInteger(requested) && requested >= 1 && requested <= pageCount) setPage(requested - 1);
                }} disabled={!Number.isSafeInteger(Number(pageEntry)) || Number(pageEntry) < 1 || Number(pageEntry) > Math.max(1, Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE))}>Go</button>
                <button className="btn small" onClick={() => setPage((value) => Math.min(Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE) - 1, value + 1))}
                  disabled={(page + 1) * PACKET_ROW_PAGE_SIZE >= visiblePackets.total}>Next</button>
                <button className="btn small" onClick={() => setPage(Math.max(0, Math.ceil(visiblePackets.total / PACKET_ROW_PAGE_SIZE) - 1))}
                  disabled={(page + 1) * PACKET_ROW_PAGE_SIZE >= visiblePackets.total}>Last</button>
              </div>
              <DataTable stateId={`connections.packets:${c.id}`} label="Conversation packets" exportName={`conversation-${c.id}-packets-page-${page + 1}`} rows={visiblePackets.rows} columns={pcols} rowKey={(p) => p.frame}
                onRowClick={(p) => openDrawer({ title: `Packet #${p.frame}`, frames: [p.frame] })} height={360} />
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}
