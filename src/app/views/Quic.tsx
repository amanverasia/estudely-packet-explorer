// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo } from 'react';
import type { QuicConnection } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Note, Panel, SummaryCharts, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, endpoint, num } from '../format';

export function Quic() {
  const { model, openDrawer } = useApp();
  const stats = useMemo(() => {
    const count = (keys: (string | null)[]) => {
      const m = new Map<string, number>();
      for (const k of keys) if (k !== null) m.set(k, (m.get(k) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    return {
      versions: count(model.quic.flatMap((q) => q.versions)),
      sni: count(model.quic.map((q) => q.sni ?? (q.clientHelloFrame !== null ? '(no SNI sent)' : null))),
      withSni: model.quic.filter((q) => q.sni).length,
      vn: model.quic.filter((q) => q.versionNegotiation).length,
    };
  }, [model.quic]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const open = (q: QuicConnection) => openDrawer({
    title: `QUIC ${q.sni ?? endpoint(q.server, q.serverPort)}`, frames: q.frames, focus: q.clientHelloFrame ?? q.frames[0],
    summary: (
      <dl className="kv">
        <dt>Client</dt><dd className="mono">{endpoint(q.client, q.clientPort)}</dd>
        <dt>Server</dt><dd className="mono">{endpoint(q.server, q.serverPort)}</dd>
        <dt>Versions</dt><dd>{q.versions.join(', ') || 'none in long headers'}</dd>
        <dt>Version negotiation</dt><dd>{q.versionNegotiation ? `server listed ${q.versionNegotiation.join(', ')}` : 'not seen'}</dd>
        <dt>SNI</dt><dd>{q.sni ?? (q.clientHelloFrame === null ? 'unavailable (no decodable ClientHello)' : 'not sent')}</dd>
        <dt>ALPN offered</dt><dd>{q.alpn.join(', ') || (q.clientHelloFrame === null ? 'unavailable' : 'not sent')}</dd>
        <dt>QUIC packets</dt><dd>{num(q.packets)}</dd>
      </dl>
    ),
  });

  const columns: Column<QuicConnection>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (q) => q.start, render: (q) => <span className="mono">{absTime(model.capture.startEpoch, q.start, digits)}</span> },
    { key: 'client', header: 'Client', width: 'minmax(190px, 1.2fr)', value: (q) => endpoint(q.client, q.clientPort), render: (q) => <Addr addr={q.client} port={q.clientPort} /> },
    { key: 'server', header: 'Server', width: 'minmax(190px, 1.2fr)', value: (q) => endpoint(q.server, q.serverPort), render: (q) => <Addr addr={q.server} port={q.serverPort} /> },
    { key: 'sni', header: 'SNI (requested name)', width: 'minmax(170px, 1.4fr)', value: (q) => q.sni },
    { key: 'versions', header: 'Versions', width: 'minmax(150px, 1.2fr)', value: (q) => q.versions.join(', ') },
    { key: 'vn', header: 'Version negotiation', width: 'minmax(150px, 1fr)', value: (q) => (q.versionNegotiation ? `lists ${q.versionNegotiation.join(', ')}` : null) },
    { key: 'alpn', header: 'ALPN offered', width: '110px', value: (q) => q.alpn.join(', ') },
    { key: 'packets', header: 'QUIC packets', width: '110px', align: 'right', noSearch: true, value: (q) => q.packets, render: (q) => num(q.packets) },
    { key: 'frames', header: 'Packets', width: '90px', value: (q) => q.frames.join(' '), render: (q) => <FramesLink frames={q.frames} onOpen={() => open(q)} /> },
  ];

  return (
    <>
      <ViewHead title="QUIC">
        Long-header versions, plus SNI and ALPN from the client's Initial packet.
      </ViewHead>
      <Note>Initial packets are protected with keys derived from public values, so Wireshark decodes the ClientHello without any secrets. Everything after the handshake, including the certificate, is encrypted.</Note>
      {!model.quic.length ? (
        <div className="panel empty"><strong>No QUIC long-header packets were decoded.</strong>Connections that started before the capture only carry short headers, which show no version.</div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Conversations" value={num(model.quic.length)} />
            <Fact label="With SNI" value={num(stats.withSni)} />
            <Fact label="Versions seen" value={num(stats.versions.length)} small="distinct" />
            <Fact label="Version negotiation" value={num(stats.vn)} small="conversations" />
          </dl>
          <section className="panel">
            <DataTable stateId="quic.conversations" label="QUIC conversations" exportName="quic" rows={model.quic} columns={columns} rowKey={(q) => q.id} onRowClick={open}
              searchPlaceholder="Search SNI, addresses, versions" />
          </section>
          <SummaryCharts>
            <div className="grid-2">
              <Panel title="Versions" sub="Conversations per version in long headers"><BarList items={stats.versions} limit={6} /></Panel>
              <Panel title="Server names requested" sub="SNI in the Initial ClientHello"><BarList items={stats.sni} limit={8} color="var(--s7)" emptyText="No decodable ClientHello." /></Panel>
            </div>
          </SummaryCharts>
        </>
      )}
    </>
  );
}
