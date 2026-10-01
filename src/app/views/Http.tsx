// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo, useState } from 'react';
import type { HttpExchange } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Note, Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, duration, endpoint, num, plural } from '../format';

function statusTag(s: number | null) {
  if (s === null) return <span className="muted">none</span>;
  const cls = s >= 500 ? 'bad' : s >= 400 ? 'warn' : s >= 300 ? 'info' : '';
  return <span className={`tag ${cls}`}>{s}</span>;
}

export function Http() {
  const { model, openDrawer, go } = useApp();
  const [host, setHost] = useState('all');
  const u = model.unsupported;
  const rows = useMemo(() => (host === 'all' ? model.http : model.http.filter((h) => (h.host ?? '(no Host header)') === host)), [model.http, host]);
  const stats = useMemo(() => {
    const count = (f: (h: HttpExchange) => string | null) => {
      const m = new Map<string, number>();
      for (const h of model.http) { const k = f(h); if (k !== null) m.set(k, (m.get(k) ?? 0) + 1); }
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    return {
      methods: count((h) => h.method),
      statuses: count((h) => (h.status === null ? null : `${h.status}${h.phrase ? ' ' + h.phrase : ''}`)),
      hosts: count((h) => (h.method ? h.host ?? '(no Host header)' : null)),
      requests: model.http.filter((h) => h.method).length,
      responses: model.http.filter((h) => h.status !== null).length,
      noResponse: model.http.filter((h) => h.state === 'no response seen').length,
      orphan: model.http.filter((h) => h.state === 'response without request').length,
    };
  }, [model.http]);
  const digits = Math.min(6, model.capture.timestampDigits);

  const open = (h: HttpExchange) => openDrawer({ title: `${h.version ?? 'HTTP'} ${h.method ?? ''} ${h.uri ?? '(response only)'}`.trim(), frames: h.frames, focus: h.requestFrame ?? h.responseFrame ?? undefined, summary: <HttpSummary h={h} /> });
  const columns: Column<HttpExchange>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (h) => h.requestTime ?? h.responseTime, render: (h) => <span className="mono">{absTime(model.capture.startEpoch, h.requestTime ?? h.responseTime, digits)}</span> },
    { key: 'client', header: 'Client', width: 'minmax(140px, 1fr)', value: (h) => h.client, render: (h) => <Addr addr={h.client} /> },
    { key: 'version', header: 'Version', width: '80px', value: (h) => h.version },
    { key: 'h2stream', header: 'H2 stream', width: '84px', value: (h) => h.http2StreamId },
    { key: 'method', header: 'Method', width: '80px', value: (h) => h.method },
    { key: 'host', header: 'Host', width: 'minmax(150px, 1.2fr)', value: (h) => h.host },
    { key: 'uri', header: 'Path', width: 'minmax(220px, 2.5fr)', value: (h) => h.uri },
    { key: 'status', header: 'Status', width: '74px', value: (h) => h.status, render: (h) => statusTag(h.status) },
    { key: 'ctype', header: 'Content type', width: 'minmax(130px, 1fr)', value: (h) => h.contentType },
    { key: 'len', header: 'Length', width: '84px', align: 'right', value: (h) => h.contentLength, title: 'Content-Length header value' },
    { key: 'server', header: 'Server', width: 'minmax(150px, 1fr)', value: (h) => endpoint(h.server, h.serverPort), render: (h) => <Addr addr={h.server} port={h.serverPort} /> },
    { key: 'rt', header: 'Response time', width: '110px', align: 'right', noSearch: true, value: (h) => (h.requestTime !== null && h.responseTime !== null ? h.responseTime - h.requestTime : null),
      render: (h) => (h.requestTime !== null && h.responseTime !== null ? duration(h.responseTime - h.requestTime) : '') },
    { key: 'state', header: 'Pairing', width: '170px', value: (h) => `${h.state}${h.pairingWarning ? ` · ${h.pairingWarning}` : ''}`,
      render: (h) => h.pairingWarning ? <span className="tag warn" title={h.pairingWarning}>Check pairing</span> : h.state },
    { key: 'frames', header: 'Packets', width: '90px', value: (h) => h.frames.join(' '), render: (h) => <FramesLink frames={h.frames} onOpen={() => open(h)} /> },
  ];

  const limits = (
    <div className="notes">
      {u.encryptedConversations > 0 && <Note>{plural(u.encryptedConversations, 'conversation')} use TLS or QUIC. HTTP inside them is encrypted and is not shown here; see the TLS view for what the handshakes reveal.</Note>}
      {u.http2Packets > 0 && <Note kind="info">{plural(u.http2Packets, 'packet')} carry cleartext HTTP/2. Where Wireshark reconstructs request or response headers, they appear as HTTP/2 rows. HTTP/2 inside TLS is not visible until key-log decryption is supported; HTTP/3 request rows are not shown.</Note>}
      {u.httpPortsUndecoded.length > 0 && (
        <Note kind="warn">{plural(u.httpPortsUndecoded.length, 'TCP conversation')} on common HTTP ports carried data that Wireshark did not decode as HTTP (for example a non-HTTP protocol, missing segments, or a stream that started before the capture).{' '}
          <button className="btn small" onClick={() => go('connections', { conv: String(u.httpPortsUndecoded[0]) })}>Open the first</button></Note>
      )}
      {u.httpWithGaps.length > 0 && <Note kind="warn">{plural(u.httpWithGaps.length, 'HTTP conversation')} contain truncated packets or missing TCP segments, so some requests or responses in them may be missing or partial.</Note>}
    </div>
  );

  return (
    <>
      <ViewHead title="HTTP" right={
        <select className="select" value={host} onChange={(e) => setHost(e.target.value)} aria-label="Filter by host">
          <option value="all">All hosts</option>
          {stats.hosts.map((h) => <option key={h.key} value={h.key}>{h.key} ({num(h.value)})</option>)}
        </select>}>
        Cleartext HTTP/1.x and HTTP/2 requests and responses, reassembled by Wireshark. Wireshark’s request and response frame links are used when available; stream order is the fallback for HTTP/1.x, while HTTP/2 uses its TCP stream and HTTP/2 stream ID.
      </ViewHead>
      {limits}
      {!model.http.length ? (
        <div className="panel empty"><strong>No cleartext HTTP/1.x or HTTP/2 messages were decoded.</strong>Most web traffic is HTTPS; its contents stay encrypted.</div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Requests" value={num(stats.requests)} />
            <Fact label="Responses" value={num(stats.responses)} />
            <Fact label="Hosts requested" value={num(stats.hosts.length)} />
            <Fact label="No response seen" value={num(stats.noResponse)} />
            <Fact label="Responses without request" value={num(stats.orphan)} />
          </dl>
          <div className="grid-3">
            <Panel title="Requests by host" sub="Host header"><BarList items={stats.hosts} limit={8} onSelect={setHost} /></Panel>
            <Panel title="Methods" sub="Requests"><BarList items={stats.methods} limit={8} color="var(--s7)" /></Panel>
            <Panel title="Status codes" sub="Responses"><BarList items={stats.statuses} limit={8} color="var(--s3)" emptyText="No responses decoded." /></Panel>
          </div>
          <section className="panel">
            <DataTable label="HTTP messages" exportName="http" rows={rows} columns={columns} rowKey={(h) => h.id} onRowClick={open}
              searchPlaceholder="Search hosts, paths, user agents, status" />
          </section>
        </>
      )}
    </>
  );
}

function HttpSummary({ h }: { h: HttpExchange }) {
  return (
    <section style={{ display: 'grid', gap: 10 }}>
      <dl className="kv">
        <dt>Client</dt><dd className="mono">{endpoint(h.client, h.clientPort)}</dd>
        <dt>Server</dt><dd className="mono">{endpoint(h.server, h.serverPort)}</dd>
        <dt>Version</dt><dd>{h.version ?? 'unavailable'}</dd>
        {h.http2StreamId !== null && <><dt>HTTP/2 stream</dt><dd>{h.http2StreamId}</dd></>}
        <dt>Pairing</dt><dd>{h.state}{h.stream !== null ? ` (TCP stream ${h.stream})` : ''}</dd>
        {h.pairingWarning && <><dt>Pairing check</dt><dd>{h.pairingWarning}</dd></>}
        <dt>Request</dt><dd>{h.requestFrame === null ? 'not captured' : `packet #${h.requestFrame}`}</dd>
        <dt>Response</dt><dd>{h.responseFrame === null ? 'not captured' : `packet #${h.responseFrame}`}</dd>
        {h.location && <><dt>Location</dt><dd>{h.location}</dd></>}
      </dl>
      {h.method && (
        <div>
          <h3 style={{ marginBottom: 4 }}>Request headers</h3>
          <pre className="headers">{`${h.method} ${h.uri ?? ''} ${h.version ?? ''}\n${h.requestHeaders.join('\n')}`}</pre>
        </div>
      )}
      {h.status !== null && (
        <div>
          <h3 style={{ marginBottom: 4 }}>Response headers</h3>
          <pre className="headers">{`${h.responseVersion ?? ''} ${h.status} ${h.phrase ?? ''}\n${h.responseHeaders.join('\n')}`}</pre>
        </div>
      )}
      <p className="muted" style={{ fontSize: 12 }}>Header text is shown exactly as captured, as plain text. Bodies are not rendered.</p>
    </section>
  );
}
