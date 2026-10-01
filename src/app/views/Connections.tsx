// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useState } from 'react';
import type { Conversation, PacketRow, Transport } from '../../engine/types';
import { DataTable, type Column } from '../components/DataTable';
import { flagText } from '../components/Drawer';
import { Addr, Note, Panel, Seg, ViewHead } from '../components/bits';
import { FollowStream } from '../components/FollowStream';
import { useApp } from '../context';
import { bytes, duration, endpoint, num, plural, rel } from '../format';

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
  const { model, params, go, filter } = useApp();
  const [transport, setTransport] = useState<'all' | Transport>('all');
  const [app, setApp] = useState('all');
  const hostFilter = params.get('host');
  const [selected, setSelected] = useState<number | null>(params.get('conv') !== null ? Number(params.get('conv')) : null);
  const apps = useMemo(() => {
    const m = new Map<string, number>();
    for (const c of model.conversations) m.set(c.appProtocol, (m.get(c.appProtocol) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [model.conversations]);
  const rows = useMemo(() => model.conversations.filter((c) =>
    (transport === 'all' || c.transport === transport) && (app === 'all' || c.appProtocol === app)
    && (!hostFilter || c.a === hostFilter || c.b === hostFilter)), [model.conversations, transport, app, hostFilter]);
  const conv = selected !== null ? model.conversations.find((c) => c.id === selected) ?? null : null;
  const counts = useMemo(() => {
    const m: Record<string, number> = { TCP: 0, UDP: 0, IP: 0, 'Non-IP': 0 };
    for (const c of model.conversations) m[c.transport]++;
    return m;
  }, [model.conversations]);
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
          options={[{ value: 'all', label: `All ${num(model.conversations.length)}` }, ...(['TCP', 'UDP', 'IP', 'Non-IP'] as Transport[]).filter((t) => counts[t]).map((t) => ({ value: t, label: `${t} ${num(counts[t])}` }))]} />}>
        TCP and UDP conversations use Wireshark's stream index, so a reused address and port pair appears as separate sessions. Endpoint A is the TCP SYN sender, or otherwise the first packet's sender. Other IP traffic (such as ICMP) is grouped per address pair and protocol.
      </ViewHead>
      {hostFilter && (
        <Note>Showing conversations involving <span className="mono">{hostFilter}</span>. <button className="btn small" onClick={() => go('connections')}>Show all</button></Note>
      )}
      {(filter.start !== null || filter.host) && <Note>Conversation rows include matching packets; directional packet/byte totals and times reflect the selected traffic. TCP flags and analysis counters describe the full conversation.</Note>}
      {conv && <ConversationDetail key={conv.id} c={conv} onClose={() => setSelected(null)} />}
      <section className="panel">
        <DataTable label="Conversations" exportName="conversations" rows={rows} columns={columns} rowKey={(c) => c.id} selectedKey={selected}
          onRowClick={(c) => setSelected(c.id)} initialSort={{ key: 'start', dir: 'asc' }} searchPlaceholder="Search addresses, ports, protocols"
          toolbar={
            <select className="select" value={app} onChange={(e) => setApp(e.target.value)} aria-label="Filter by protocol">
              <option value="all">All protocols</option>
              {apps.map(([a, n]) => <option key={a} value={a}>{a} ({num(n)})</option>)}
            </select>
          }
          empty={<><strong>No conversations.</strong>No packets could be grouped into conversations.</>} />
      </section>
    </>
  );
}

function ConversationDetail({ c, onClose }: { c: Conversation; onClose: () => void }) {
  const { model, engine, openDrawer } = useApp();
  const [packets, setPackets] = useState<{ rows: PacketRow[]; total: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [follow, setFollow] = useState(false);
  const canFollow = (c.transport === 'TCP' || c.transport === 'UDP') && c.stream !== null;
  useEffect(() => {
    setPackets(null);
    engine.request({ kind: 'rows', convId: c.id, limit: 20000 }).then(setPackets).catch((e: Error) => setErr(e.message));
  }, [engine, c.id]);
  const dns = model.dns.filter((d) => d.convId === c.id);
  const http = model.http.filter((h) => h.convId === c.id);
  const tls = model.tls.filter((t) => t.convId === c.id);
  const digits = Math.min(9, model.capture.timestampDigits);
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
          {err && <div className="note crit">{err}</div>}
          {!packets ? <p className="muted">Loading packets…</p> : (
            <div className="panel" style={{ borderRadius: 6 }}>
              {packets.total > packets.rows.length && <p className="muted" style={{ padding: '8px 16px 0' }}>Showing the first {num(packets.rows.length)} of {num(packets.total)} packets.</p>}
              <DataTable label="Conversation packets" exportName={`conversation-${c.id}-packets`} rows={packets.rows} columns={pcols} rowKey={(p) => p.frame}
                onRowClick={(p) => openDrawer({ title: `Packet #${p.frame}`, frames: [p.frame] })} height={360} />
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}
