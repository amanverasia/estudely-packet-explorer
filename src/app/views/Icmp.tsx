// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo } from 'react';
import type { IcmpMessage } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Panel, Seg, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { absTime, endpoint, num } from '../format';

type Filter = 'all' | 'error' | 'echo' | 'other';
const filterOf = (i: IcmpMessage): Filter => (i.kind === 'error' ? 'error' : i.kind === 'other' ? 'other' : 'echo');
const typeLabel = (i: IcmpMessage) => `${i.version === 6 ? 'ICMPv6' : 'ICMP'} ${i.typeName ?? `type ${i.type}`}`;
const quotedText = (i: IcmpMessage) => (i.quoted ? `${i.quoted.protocol ?? '?'} ${endpoint(i.quoted.src, i.quoted.srcPort)} → ${endpoint(i.quoted.dst, i.quoted.dstPort)}` : null);
const echoText = (i: IcmpMessage) => (i.echo ? `id ${i.echo.ident ?? '?'} seq ${i.echo.seq ?? '?'}: ${i.echo.status}` : null);

export function Icmp() {
  const { model, openDrawer, go } = useApp();
  const [filter, setFilter] = useViewState<Filter>('icmp.kind', 'all', (value): value is Filter => value === 'all' || value === 'error' || value === 'echo' || value === 'other');
  const rows = useMemo(() => (filter === 'all' ? model.icmp : model.icmp.filter((i) => filterOf(i) === filter)), [model.icmp, filter]);
  const stats = useMemo(() => {
    const count = (keys: (string | null)[]) => {
      const m = new Map<string, number>();
      for (const k of keys) if (k !== null) m.set(k, (m.get(k) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    const errors = model.icmp.filter((i) => i.kind === 'error');
    return {
      types: count(model.icmp.map(typeLabel)),
      errorSenders: count(errors.map((i) => i.src)),
      counts: { all: model.icmp.length, error: errors.length, echo: model.icmp.filter((i) => filterOf(i) === 'echo').length, other: model.icmp.filter((i) => i.kind === 'other').length },
      linked: errors.filter((i) => i.quoted?.convId !== null && i.quoted?.convId !== undefined).length,
      noReply: model.icmp.filter((i) => i.echo?.status === 'no reply seen').length,
      v6: model.icmp.filter((i) => i.version === 6).length,
    };
  }, [model.icmp]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const open = (i: IcmpMessage) => openDrawer({ title: `${typeLabel(i)} from ${i.src}`, frames: i.frames, focus: i.frame, summary: <IcmpSummary i={i} /> });
  const openConv = (id: number) => go('connections', { conv: String(id) });

  const columns: Column<IcmpMessage>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (i) => i.t, render: (i) => <span className="mono">{absTime(model.capture.startEpoch, i.t, digits)}</span> },
    { key: 'from', header: 'From', width: 'minmax(140px, 1fr)', value: (i) => i.src, render: (i) => <Addr addr={i.src} /> },
    { key: 'to', header: 'To', width: 'minmax(140px, 1fr)', value: (i) => i.dst, render: (i) => <Addr addr={i.dst} /> },
    { key: 'type', header: 'Type', width: 'minmax(170px, 1.3fr)', value: typeLabel },
    { key: 'code', header: 'Code', width: 'minmax(150px, 1.2fr)', value: (i) => (i.kind === 'error' || i.codeName ? i.codeName ?? `code ${i.code}` : null) },
    { key: 'echo', header: 'Echo', width: 'minmax(180px, 1fr)', value: echoText },
    { key: 'quoted', header: 'Quoted packet', width: 'minmax(240px, 2fr)', value: quotedText, render: (i) => <span className="mono">{quotedText(i)}</span> },
    { key: 'conv', header: 'Quoted flow', width: '120px', noSearch: true, value: (i) => i.quoted?.convId ?? null, title: 'The captured conversation the quoted packet belongs to',
      render: (i) => (i.quoted?.convId != null ? <button className="btn small" onClick={(e) => { e.stopPropagation(); openConv(i.quoted!.convId!); }}>Conversation</button> : null) },
    { key: 'frames', header: 'Packets', width: '90px', value: (i) => i.frames.join(' '), render: (i) => <FramesLink frames={i.frames} onOpen={() => open(i)} /> },
  ];

  const labels: Record<Filter, string> = { all: 'All', error: 'Errors', echo: 'Echo', other: 'Other' };
  return (
    <>
      <ViewHead title="ICMP" right={
        <Seg label="Message kind" value={filter} onChange={setFilter}
          options={(['all', 'error', 'echo', 'other'] as Filter[]).map((f) => ({ value: f, label: `${labels[f]} ${num(stats.counts[f])}` }))} />}>
        ICMP and ICMPv6 messages. Error messages quote the start of the packet that caused them; the quoted addresses and ports are linked to that conversation when it is in the capture. Echo requests and replies are paired by addresses, identifier and sequence number.
      </ViewHead>
      {!model.icmp.length ? (
        <div className="panel empty"><strong>No ICMP or ICMPv6 messages were decoded.</strong></div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Messages" value={num(model.icmp.length)} small={stats.v6 ? `${num(stats.v6)} ICMPv6` : undefined} />
            <Fact label="Error messages" value={num(stats.counts.error)} />
            <Fact label="Linked to a conversation" value={num(stats.linked)} small="errors" />
            <Fact label="Echo requests without reply" value={num(stats.noReply)} />
          </dl>
          <div className="grid-2">
            <Panel title="Message types" sub="Per message"><BarList items={stats.types} limit={8} /></Panel>
            <Panel title="Error senders" sub="Address that sent the error"><BarList items={stats.errorSenders} limit={8} color="var(--s3)" emptyText="No error messages." /></Panel>
          </div>
          <section className="panel">
            <DataTable stateId="icmp.messages" label="ICMP messages" exportName="icmp" rows={rows} columns={columns} rowKey={(i) => i.id} onRowClick={open}
              searchPlaceholder="Search addresses, types, quoted packets" />
          </section>
        </>
      )}
    </>
  );
}

function IcmpSummary({ i }: { i: IcmpMessage }) {
  return (
    <dl className="kv">
      <dt>From</dt><dd className="mono">{i.src}</dd>
      <dt>To</dt><dd className="mono">{i.dst}</dd>
      <dt>Type</dt><dd>{i.typeName ?? 'unnamed'} ({i.type})</dd>
      <dt>Code</dt><dd>{i.codeName ? `${i.codeName} (${i.code})` : i.code ?? 'unavailable'}</dd>
      {i.echo && <><dt>Echo</dt><dd>{echoText(i)}{i.echo.pairedFrame !== null ? `, paired with #${i.echo.pairedFrame}` : ''}</dd></>}
      {i.quoted && (
        <>
          <dt>Quoted packet</dt>
          <dd><span className="mono">{quotedText(i)}</span><br />
            <span className="muted">{i.quoted.convId !== null
              ? 'The quoted conversation is in the capture; use the Conversation button in the table to open it.'
              : 'No matching TCP or UDP conversation was captured.'}</span>
          </dd>
        </>
      )}
    </dl>
  );
}
