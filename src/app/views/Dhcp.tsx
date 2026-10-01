// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo } from 'react';
import type { DhcpExchange } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, duration, num } from '../format';

const OUTCOME_TAG: Record<DhcpExchange['outcome'], string> = {
  acknowledged: '', 'refused (NAK)': 'bad', 'offered, no ACK seen': 'warn', 'no server reply seen': 'warn', released: 'info', declined: 'info',
};

const lease = (s: number | null) => (s === null ? null : `${duration(s)} (${num(s)} s)`);

export function Dhcp() {
  const { model, openDrawer } = useApp();
  const stats = useMemo(() => {
    const count = (keys: (string | null)[]) => {
      const m = new Map<string, number>();
      for (const k of keys) if (k !== null) m.set(k, (m.get(k) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    return {
      outcomes: count(model.dhcp.map((d) => d.outcome)),
      servers: count(model.dhcp.map((d) => d.server)),
      acked: model.dhcp.filter((d) => d.outcome === 'acknowledged').length,
      nak: model.dhcp.filter((d) => d.outcome === 'refused (NAK)').length,
      silent: model.dhcp.filter((d) => d.outcome === 'no server reply seen').length,
      clients: new Set(model.dhcp.map((d) => d.clientMac)).size,
    };
  }, [model.dhcp]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const open = (d: DhcpExchange) => openDrawer({ title: `DHCP ${d.clientMac}${d.hostname ? ` (${d.hostname})` : ''}`, frames: d.frames, focus: d.frames[0], summary: <DhcpSummary d={d} /> });

  const columns: Column<DhcpExchange>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (d) => d.start, render: (d) => <span className="mono">{absTime(model.capture.startEpoch, d.start, digits)}</span> },
    { key: 'mac', header: 'Client MAC', width: '170px', value: (d) => d.clientMac, render: (d) => <span className="mono">{d.clientMac}</span> },
    { key: 'host', header: 'Host name', width: 'minmax(120px, 1fr)', value: (d) => d.hostname },
    { key: 'msgs', header: 'Messages', width: 'minmax(200px, 1.6fr)', value: (d) => d.messages.map((m) => m.type).join(' → ') },
    { key: 'outcome', header: 'Outcome', width: '170px', value: (d) => d.outcome, render: (d) => <span className={`tag ${OUTCOME_TAG[d.outcome]}`}>{d.outcome}</span> },
    { key: 'ip', header: 'Assigned address', width: '140px', value: (d) => d.assignedIp, render: (d) => (d.assignedIp ? <span className="mono">{d.assignedIp}</span> : d.offeredIp ? <span className="muted">offered {d.offeredIp}</span> : null) },
    { key: 'req', header: 'Requested', width: '130px', value: (d) => d.requestedIp },
    { key: 'server', header: 'Server', width: 'minmax(130px, 1fr)', value: (d) => d.server, render: (d) => (d.server ? <Addr addr={d.server} /> : null) },
    { key: 'lease', header: 'Lease time', width: '110px', align: 'right', noSearch: true, value: (d) => d.leaseTime, render: (d) => (d.leaseTime === null ? '' : duration(d.leaseTime)) },
    { key: 'xid', header: 'Transaction ID', width: '120px', value: (d) => (d.xid === null ? null : '0x' + d.xid.toString(16).padStart(8, '0')) },
    { key: 'frames', header: 'Packets', width: '90px', value: (d) => d.frames.join(' '), render: (d) => <FramesLink frames={d.frames} onOpen={() => open(d)} /> },
  ];

  return (
    <>
      <ViewHead title="DHCP">
        DHCPv4 messages grouped by transaction ID and client MAC address. The assigned address and lease parameters are taken from the server's ACK; the host name is the one the client sent.
      </ViewHead>
      {!model.dhcp.length ? (
        <div className="panel empty"><strong>No DHCP messages were decoded.</strong>Hosts usually request an address only when they join a network, so a capture started later will not contain it.</div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Exchanges" value={num(model.dhcp.length)} />
            <Fact label="Client MACs" value={num(stats.clients)} />
            <Fact label="Addresses assigned" value={num(stats.acked)} small="ACK seen" />
            <Fact label="Refused" value={num(stats.nak)} small="NAK seen" />
            <Fact label="No server reply seen" value={num(stats.silent)} />
          </dl>
          <div className="grid-2">
            <Panel title="Outcomes" sub="Per exchange"><BarList items={stats.outcomes} limit={6} /></Panel>
            <Panel title="Servers" sub="Server Identifier option, else reply source"><BarList items={stats.servers} limit={6} color="var(--s7)" emptyText="No server replies decoded." /></Panel>
          </div>
          <section className="panel">
            <DataTable label="DHCP exchanges" exportName="dhcp" rows={model.dhcp} columns={columns} rowKey={(d) => d.id} onRowClick={open}
              searchPlaceholder="Search MACs, host names, addresses" />
          </section>
        </>
      )}
    </>
  );
}

function DhcpSummary({ d }: { d: DhcpExchange }) {
  return (
    <section style={{ display: 'grid', gap: 12 }}>
      <dl className="kv">
        <dt>Client MAC</dt><dd className="mono">{d.clientMac}</dd>
        <dt>Host name</dt><dd>{d.hostname ?? 'not sent'}</dd>
        <dt>Requested address</dt><dd>{d.requestedIp ?? 'not sent'}</dd>
        <dt>Offered address</dt><dd>{d.offeredIp ?? 'no OFFER seen'}</dd>
        <dt>Assigned address</dt><dd>{d.assignedIp ?? 'no ACK seen'}</dd>
        <dt>Server</dt><dd>{d.server ?? 'no server reply seen'}</dd>
        <dt>Lease time</dt><dd>{lease(d.leaseTime) ?? 'not stated'}</dd>
        <dt>Subnet mask</dt><dd>{d.subnetMask ?? 'not stated'}</dd>
        <dt>Routers</dt><dd>{d.routers.join(', ') || 'not stated'}</dd>
        <dt>DNS servers</dt><dd>{d.dnsServers.join(', ') || 'not stated'}</dd>
      </dl>
      <div>
        <h3 style={{ marginBottom: 6 }}>Messages</h3>
        <dl className="kv">
          {d.messages.map((m) => (
            <div key={m.frame} style={{ display: 'contents' }}>
              <dt>#{m.frame}</dt><dd>{m.type} <span className="muted">from {m.src || '?'} to {m.dst || '?'}</span></dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
