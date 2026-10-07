// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo } from 'react';
import type { SshSession } from '../../engine/types';
import { BarList } from '../components/charts';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, endpoint, num } from '../format';

export function Ssh() {
  const { model, openDrawer } = useApp();
  const stats = useMemo(() => {
    const count = (keys: (string | null)[]) => {
      const m = new Map<string, number>();
      for (const k of keys) if (k !== null) m.set(k, (m.get(k) ?? 0) + 1);
      return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([key, value]) => ({ key, value }));
    };
    return {
      clients: count(model.ssh.map((s) => s.clientVersion)),
      servers: count(model.ssh.map((s) => s.serverVersion)),
      serverHosts: new Set(model.ssh.map((s) => s.server)).size,
    };
  }, [model.ssh]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const open = (s: SshSession) => openDrawer({
    title: `SSH ${endpoint(s.server, s.serverPort)}`, frames: s.frames, focus: s.frames[0],
    summary: (
      <dl className="kv">
        <dt>Client</dt><dd className="mono">{endpoint(s.client, s.clientPort)}</dd>
        <dt>Server</dt><dd className="mono">{endpoint(s.server, s.serverPort)}</dd>
        <dt>Client version</dt><dd>{s.clientVersion ?? 'not captured'}{s.clientVersionFrame !== null ? ` (#${s.clientVersionFrame})` : ''}</dd>
        <dt>Server version</dt><dd>{s.serverVersion ?? 'not captured'}{s.serverVersionFrame !== null ? ` (#${s.serverVersionFrame})` : ''}</dd>
      </dl>
    ),
  });

  const columns: Column<SshSession>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (s) => s.start, render: (s) => <span className="mono">{absTime(model.capture.startEpoch, s.start, digits)}</span> },
    { key: 'client', header: 'Client', width: 'minmax(190px, 1.2fr)', value: (s) => endpoint(s.client, s.clientPort), render: (s) => <Addr addr={s.client} port={s.clientPort} /> },
    { key: 'server', header: 'Server', width: 'minmax(190px, 1.2fr)', value: (s) => endpoint(s.server, s.serverPort), render: (s) => <Addr addr={s.server} port={s.serverPort} /> },
    { key: 'cv', header: 'Client version string', width: 'minmax(200px, 1.6fr)', value: (s) => s.clientVersion, render: (s) => (s.clientVersion ? <span className="mono">{s.clientVersion}</span> : <span className="muted">not captured</span>) },
    { key: 'sv', header: 'Server version string', width: 'minmax(200px, 1.6fr)', value: (s) => s.serverVersion, render: (s) => (s.serverVersion ? <span className="mono">{s.serverVersion}</span> : <span className="muted">not captured</span>) },
    { key: 'frames', header: 'Packets', width: '90px', value: (s) => s.frames.join(' '), render: (s) => <FramesLink frames={s.frames} onOpen={() => open(s)} /> },
  ];

  return (
    <>
      <ViewHead title="SSH">
        The identification strings each side sends in cleartext at the start of an SSH connection, as written by the software. Everything after the key exchange is encrypted.
      </ViewHead>
      {!model.ssh.length ? (
        <div className="panel empty"><strong>No SSH version strings were decoded.</strong>Connections that started before the capture, or SSH on ports Wireshark does not associate with it, will not appear.</div>
      ) : (
        <>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="Sessions" value={num(model.ssh.length)} />
            <Fact label="Servers" value={num(stats.serverHosts)} />
            <Fact label="Client versions" value={num(stats.clients.length)} small="distinct" />
            <Fact label="Server versions" value={num(stats.servers.length)} small="distinct" />
          </dl>
          <div className="grid-2">
            <Panel title="Client version strings" sub="Per session"><BarList items={stats.clients} limit={8} emptyText="No client strings captured." /></Panel>
            <Panel title="Server version strings" sub="Per session"><BarList items={stats.servers} limit={8} color="var(--s7)" emptyText="No server strings captured." /></Panel>
          </div>
          <section className="panel">
            <DataTable stateId="ssh.sessions" label="SSH sessions" exportName="ssh" rows={model.ssh} columns={columns} rowKey={(s) => s.id} onRowClick={open}
              searchPlaceholder="Search addresses and version strings" />
          </section>
        </>
      )}
    </>
  );
}
