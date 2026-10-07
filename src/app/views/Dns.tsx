// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useRef } from 'react';
import { DNS_MATCH_WINDOW } from '../../engine/analyze';
import type { DnsProto, DnsTransaction } from '../../engine/types';
import { BarList, FlowChart } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Note, Panel, Seg, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { absTime, duration, endpoint, num, plural } from '../format';

const STATUS_TAG: Record<string, string> = {
  answered: 'good', unanswered: 'warn', retransmitted: 'info', 'response without query': 'warn', 'duplicate response': 'info',
  'multicast query': '', 'multicast response': '',
};
const DNS_STATUSES = new Set(['all', 'answered', 'unanswered', 'retransmitted', 'response without query', 'duplicate response', 'multicast query', 'multicast response']);

export function Dns() {
  const { model, openDrawer, params } = useApp();
  const counts = useMemo(() => {
    const m: Record<DnsProto, number> = { DNS: 0, mDNS: 0, LLMNR: 0, NBNS: 0 };
    for (const d of model.dns) m[d.proto]++;
    return m;
  }, [model.dns]);
  const defaultProto = counts.DNS || !model.dns.length ? 'DNS' : (Object.keys(counts) as DnsProto[]).find((k) => counts[k]) ?? 'DNS';
  const [proto, setProto] = useViewState<DnsProto>('dns.proto', defaultProto, (value): value is DnsProto => value === 'DNS' || value === 'mDNS' || value === 'LLMNR' || value === 'NBNS');
  const [status, setStatus] = useViewState<string>('dns.status', 'all', (value): value is string => typeof value === 'string' && DNS_STATUSES.has(value));
  const lastRouteProto = useRef<string | null>(null);
  useEffect(() => {
    if (!params.has('proto')) { lastRouteProto.current = null; return; }
    const requested = params.get('proto');
    if (requested !== lastRouteProto.current) {
      lastRouteProto.current = requested;
      if (requested === 'DNS' || requested === 'mDNS' || requested === 'LLMNR' || requested === 'NBNS') {
        if (requested !== proto) { setProto(requested); setStatus('all'); }
      }
    }
  }, [params, proto, setProto, setStatus]);
  const rows = useMemo(() => model.dns.filter((d) => d.proto === proto), [model.dns, proto]);
  const shown = useMemo(() => (status === 'all' ? rows : rows.filter((d) => d.status === status)), [rows, status]);
  const multicast = proto === 'mDNS';

  const stats = useMemo(() => {
    const names = new Map<string, number>();
    const types = new Map<string, number>();
    const rcodes = new Map<string, number>();
    const statuses = new Map<string, number>();
    const links = new Map<string, { left: string; right: string; value: number }>();
    const rtts: number[] = [];
    for (const d of rows) {
      statuses.set(d.status, (statuses.get(d.status) ?? 0) + 1);
      if (d.queryFrame !== null) {
        if (d.qname) names.set(d.qname, (names.get(d.qname) ?? 0) + 1);
        if (d.qtype) types.set(d.qtype, (types.get(d.qtype) ?? 0) + 1);
        const k = d.client + '\u0000' + d.server;
        const l = links.get(k) ?? { left: d.client, right: d.server, value: 0 };
        l.value++;
        links.set(k, l);
      }
      if (d.rcode) rcodes.set(d.rcode, (rcodes.get(d.rcode) ?? 0) + 1);
      if (d.rtt !== null) rtts.push(d.rtt);
    }
    rtts.sort((a, b) => a - b);
    const toItems = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    return {
      names: toItems(names), types: toItems(types), rcodes: toItems(rcodes), statuses,
      links: [...links.values()], medianRtt: rtts.length ? rtts[Math.floor(rtts.length / 2)] : null,
      queries: rows.filter((d) => d.queryFrame !== null).length,
    };
  }, [rows]);

  const open = (d: DnsTransaction) => openDrawer({
    title: `${d.proto} ${d.qtype ?? ''} ${d.qname ?? '(no question)'}`,
    frames: d.frames,
    focus: d.queryFrame ?? d.responseFrame ?? undefined,
    summary: <DnsSummary d={d} />,
  });

  const columns: Column<DnsTransaction>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', value: (d) => d.queryTime ?? d.responseTime, noSearch: true,
      render: (d) => <span className="mono">{absTime(model.capture.startEpoch, d.queryTime ?? d.responseTime, Math.min(6, model.capture.timestampDigits))}</span> },
    { key: 'client', header: multicast ? 'Sender' : 'Client', width: 'minmax(150px, 1.2fr)', value: (d) => d.client, render: (d) => <Addr addr={d.client} /> },
    { key: 'server', header: multicast ? 'Destination' : 'Server', width: 'minmax(140px, 1fr)', value: (d) => d.server, render: (d) => <Addr addr={d.server} /> },
    { key: 'name', header: 'Queried name', width: 'minmax(200px, 2fr)', value: (d) => d.qname },
    { key: 'type', header: 'Type', width: '70px', value: (d) => d.qtype },
    { key: 'rcode', header: 'Response', width: '96px', value: (d) => d.rcode, render: (d) => d.rcode ? <span className={`tag ${d.rcode === 'NoError' || d.rcode === 'OK' ? '' : 'bad'}`}>{d.rcode}</span> : <span className="muted">none</span> },
    { key: 'answers', header: 'Answers', width: 'minmax(180px, 2fr)', value: (d) => d.answers.filter((a) => a.section === 'answer').map((a) => a.value).join(', ') },
    { key: 'status', header: 'Status', width: '170px', value: (d) => d.status, render: (d) => <span className={`tag ${STATUS_TAG[d.status]}`}>{d.status}</span> },
    { key: 'rtt', header: 'Response time', width: '110px', align: 'right', value: (d) => d.rtt, noSearch: true, render: (d) => (d.rtt === null ? '' : duration(d.rtt)) },
    { key: 'transport', header: 'Transport', width: '84px', value: (d) => d.transport },
    { key: 'txid', header: 'ID', width: '72px', value: (d) => (d.txid === null ? null : '0x' + d.txid.toString(16).padStart(4, '0')) },
    { key: 'frames', header: 'Packets', width: '90px', value: (d) => d.frames.join(' '), render: (d) => <FramesLink frames={d.frames} onOpen={() => open(d)} /> },
  ];

  const unanswered = stats.statuses.get('unanswered') ?? 0;
  return (
    <>
      <ViewHead title="Name resolution"
        right={<Seg label="Protocol" value={proto} onChange={(p) => { setProto(p); setStatus('all'); }}
          options={(['DNS', 'mDNS', 'LLMNR', 'NBNS'] as DnsProto[]).map((p) => ({ value: p, label: `${p} ${num(counts[p])}` }))} />}>
        Each query packet is its own row; repeated queries are kept and linked to the original. Queries and responses are matched by transaction ID, client address and port, transport, and server; a response must arrive within {DNS_MATCH_WINDOW} s of its query, otherwise it is listed as a response without query.
      </ViewHead>
      {!model.dns.length ? (
        <div className="panel empty"><strong>No DNS, mDNS, LLMNR or NBNS messages were decoded.</strong>DNS over HTTPS (DoH) and DNS over TLS/QUIC are encrypted and appear under TLS instead.</div>
      ) : (
        <>
          {multicast && <Note>mDNS answers are usually multicast and often unsolicited, so mDNS messages are listed individually rather than matched into transactions.</Note>}
          {proto === 'NBNS' && <Note>NBNS name queries are often broadcast; a response is matched when it comes back to the querying address and port with the same transaction ID.</Note>}
          {!rows.length ? <div className="panel empty"><strong>No {proto} messages in this capture.</strong></div> : (
            <>
              <dl className="facts" style={{ margin: 0 }}>
                <Fact label={multicast ? 'Messages' : 'Transactions'} value={num(rows.length)} />
                <Fact label="Queries sent" value={num(stats.queries)} />
                <Fact label="Unique names" value={num(stats.names.length)} />
                {!multicast && <Fact label="Answered" value={num(stats.statuses.get('answered') ?? 0)} />}
                {!multicast && <Fact label="Unanswered" value={num(unanswered)} title={`Query with no matching response in the capture (within ${DNS_MATCH_WINDOW} s)`} />}
                {!multicast && <Fact label="Repeated queries" value={num(stats.statuses.get('retransmitted') ?? 0)} />}
                {!multicast && <Fact label="Responses without query" value={num(stats.statuses.get('response without query') ?? 0)} title={`Response with no matching query in the preceding ${DNS_MATCH_WINDOW} s`} />}
                {!multicast && <Fact label="Median response time" value={duration(stats.medianRtt)} />}
              </dl>
              <div className="grid-3">
                <Panel title="Most queried names" sub="Query packets per name">
                  <BarList items={stats.names} limit={8} />
                </Panel>
                <Panel title="Record types" sub="Query packets per type">
                  <BarList items={stats.types} limit={8} color="var(--s7)" />
                </Panel>
                <Panel title="Response codes" sub="Per response">
                  <BarList items={stats.rcodes} limit={8} color="var(--s3)" emptyText="No responses decoded." />
                  {!multicast && unanswered > 0 && <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>{plural(unanswered, 'query', 'queries')} received no response.</p>}
                </Panel>
              </div>
              {!multicast && (
                <Panel title={proto === 'NBNS' ? 'Clients and responders' : 'Clients and resolvers'} sub="Line width shows the number of queries sent">
                  <FlowChart links={stats.links} leftLabel="Client" rightLabel={proto === 'NBNS' ? 'Queried address' : 'Resolver'} />
                </Panel>
              )}
              <section className="panel">
                <DataTable stateId={`dns.transactions.${proto}`} key={`dns.transactions.${proto}`} label={`${proto} transactions`} exportName={`${proto.toLowerCase()}-transactions`} rows={shown} columns={columns}
                  rowKey={(d) => d.id} onRowClick={open} searchPlaceholder="Search names, addresses, answers"
                  toolbar={
                    <select className="select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
                      <option value="all">All statuses</option>
                      {[...stats.statuses.entries()].map(([s, n]) => <option key={s} value={s}>{s} ({num(n)})</option>)}
                    </select>
                  } />
              </section>
            </>
          )}
        </>
      )}
    </>
  );
}

function DnsSummary({ d }: { d: DnsTransaction }) {
  const { model } = useApp();
  const digits = Math.min(9, model.capture.timestampDigits);
  return (
    <section style={{ display: 'grid', gap: 10 }}>
      <dl className="kv">
        <dt>Status</dt><dd>{d.status}{d.relatedTo !== null && <> (related to row {d.relatedTo + 1}, query packet #{model.dns.find((related) => related.id === d.relatedTo)?.queryFrame ?? model.dns.find((related) => related.id === d.relatedTo)?.responseFrame})</>}</dd>
        <dt>Client</dt><dd className="mono">{endpoint(d.client, d.clientPort)}</dd>
        <dt>Server</dt><dd className="mono">{endpoint(d.server, d.serverPort)}</dd>
        <dt>Transport</dt><dd>{d.transport}{d.truncatedFlag ? ' — truncated (TC) flag set by server' : ''}</dd>
        <dt>Transaction ID</dt><dd className="mono">{d.txid === null ? 'unavailable' : '0x' + d.txid.toString(16).padStart(4, '0')}</dd>
        <dt>Query</dt><dd>{d.queryFrame === null ? 'not captured' : <>packet #{d.queryFrame} at {absTime(model.capture.startEpoch, d.queryTime, digits)}</>}</dd>
        <dt>Response</dt><dd>{d.responseFrame === null ? 'not captured' : <>packet #{d.responseFrame}, {d.rcode}{d.rtt !== null && <> after {duration(d.rtt)}</>}</>}</dd>
        {d.malformed && <><dt>Note</dt><dd>Wireshark marked a packet in this transaction as malformed.</dd></>}
      </dl>
      {d.answers.length > 0 && (
        <div className="headers" role="table" aria-label="Resource records">
          {d.answers.map((a, i) => <div key={i} role="row">{`${a.section.padEnd(10)} ${a.name}  ${a.type}  ${a.ttl ?? ''}  ${a.value}`}</div>)}
        </div>
      )}
    </section>
  );
}
