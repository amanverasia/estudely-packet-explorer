// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useMemo } from 'react';
import type { ArpBinding, ArpRecord } from '../../engine/types';
import { DataTable, type Column } from '../components/DataTable';
import { Addr, Fact, FramesLink, Note, Panel, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { absTime, num } from '../format';

export function Arp() {
  const { model, openDrawer } = useApp();
  const stats = useMemo(() => ({
    requests: model.arp.filter((a) => a.op === 'request').length,
    replies: model.arp.filter((a) => a.op === 'reply').length,
    gratuitous: model.arp.filter((a) => a.gratuitous).length,
    multi: model.arpBindings.filter((b) => b.macs.length > 1).length,
  }), [model.arp, model.arpBindings]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const at = (t: number) => absTime(model.capture.startEpoch, t, digits);
  const openBinding = (b: ArpBinding) => openDrawer({ title: `ARP ${b.ip}`, frames: b.frames, focus: b.frames[0], summary: <BindingSummary b={b} at={at} /> });
  const openMsg = (a: ArpRecord) => openDrawer({ title: `ARP ${a.op} from ${a.ip || a.mac}`, frames: [a.frame], focus: a.frame });

  const bindingColumns: Column<ArpBinding>[] = [
    { key: 'ip', header: 'IP address', width: 'minmax(140px, 1fr)', value: (b) => b.ip, render: (b) => <Addr addr={b.ip} /> },
    { key: 'macs', header: 'MAC addresses stated', width: 'minmax(170px, 1.4fr)', value: (b) => b.macs.join(', '), render: (b) => <span className="mono">{b.macs.join(', ')}</span> },
    { key: 'changes', header: 'Changes', width: '90px', align: 'right', value: (b) => b.changes,
      render: (b) => (b.changes ? <span className="tag info">{num(b.changes)}</span> : '0'), title: 'Times a later ARP message stated a different MAC than the one before it' },
    { key: 'periods', header: 'Sequence', width: 'minmax(240px, 2fr)', value: (b) => b.periods.map((p) => `${p.mac} (#${p.firstFrame})`).join(' → ') },
    { key: 'first', header: 'First seen (UTC)', width: '210px', noSearch: true, value: (b) => b.periods[0]?.firstSeen, render: (b) => <span className="mono">{at(b.periods[0]?.firstSeen)}</span> },
    { key: 'frames', header: 'Packets', width: '90px', value: (b) => b.frames.join(' '), render: (b) => <FramesLink frames={b.frames} onOpen={() => openBinding(b)} /> },
  ];
  const msgColumns: Column<ArpRecord>[] = [
    { key: 't', header: 'Time (UTC)', width: '210px', noSearch: true, value: (a) => a.t, render: (a) => <span className="mono">{at(a.t)}</span> },
    { key: 'op', header: 'Operation', width: '96px', value: (a) => a.op },
    { key: 'ip', header: 'Sender IP', width: 'minmax(120px, 1fr)', value: (a) => a.ip },
    { key: 'mac', header: 'Sender MAC', width: '170px', value: (a) => a.mac, render: (a) => <span className="mono">{a.mac}</span> },
    { key: 'tip', header: 'Target IP', width: 'minmax(120px, 1fr)', value: (a) => a.targetIp },
    { key: 'tmac', header: 'Target MAC', width: '170px', value: (a) => a.targetMac, render: (a) => <span className="mono">{a.targetMac}</span> },
    { key: 'grat', header: 'Gratuitous', width: '96px', value: (a) => (a.gratuitous ? 'yes' : ''), title: 'Sender and target IP are the same (an announcement)' },
    { key: 'frames', header: 'Packet', width: '90px', value: (a) => a.frame, render: (a) => <FramesLink frames={[a.frame]} onOpen={() => openMsg(a)} /> },
  ];

  return (
    <>
      <ViewHead title="ARP">
        IPv4-to-MAC mappings as stated by the senders of ARP requests and replies, in time order. A change means a later message gave a different MAC for the same address; the capture alone does not say why.
      </ViewHead>
      {!model.arp.length ? (
        <div className="panel empty"><strong>No ARP messages were decoded.</strong>ARP is only visible on the local network segment where the capture was taken.</div>
      ) : (
        <>
          <Note>Senders with address 0.0.0.0 (ARP probes) state no mapping and are listed only as messages. MAC addresses come from the ARP payload, not the Ethernet header.</Note>
          <dl className="facts" style={{ margin: 0 }}>
            <Fact label="ARP messages" value={num(model.arp.length)} />
            <Fact label="Requests" value={num(stats.requests)} />
            <Fact label="Replies" value={num(stats.replies)} />
            <Fact label="Gratuitous" value={num(stats.gratuitous)} title="Sender and target IP are the same" />
            <Fact label="Addresses mapped" value={num(model.arpBindings.length)} />
            <Fact label="With more than one MAC" value={num(stats.multi)} />
          </dl>
          <Panel title="IP-to-MAC mappings" sub="Addresses whose stated MAC changed are listed first" flush>
            <DataTable stateId="arp.mappings" label="ARP mappings" exportName="arp-mappings" rows={model.arpBindings} columns={bindingColumns} rowKey={(b) => b.ip}
              onRowClick={openBinding} searchPlaceholder="Search addresses and MACs" />
          </Panel>
          <Panel title="ARP messages" sub="Every decoded request and reply" flush>
            <DataTable stateId="arp.messages" label="ARP messages" exportName="arp" rows={model.arp} columns={msgColumns} rowKey={(a) => a.frame} onRowClick={openMsg}
              searchPlaceholder="Search addresses and MACs" />
          </Panel>
        </>
      )}
    </>
  );
}

function BindingSummary({ b, at }: { b: ArpBinding; at: (t: number) => string }) {
  return (
    <section style={{ display: 'grid', gap: 12 }}>
      <dl className="kv">
        <dt>IP address</dt><dd className="mono">{b.ip}</dd>
        <dt>MACs stated</dt><dd className="mono">{b.macs.join(', ')}</dd>
        <dt>Changes</dt><dd>{num(b.changes)}</dd>
      </dl>
      <div>
        <h3 style={{ marginBottom: 6 }}>In time order</h3>
        <dl className="kv">
          {b.periods.map((p, i) => (
            <div key={i} style={{ display: 'contents' }}>
              <dt className="mono">{p.mac}</dt>
              <dd>{num(p.messages)} message{p.messages === 1 ? '' : 's'}, packets #{p.firstFrame}{p.lastFrame !== p.firstFrame ? ` to #${p.lastFrame}` : ''}<br />
                <span className="muted">{at(p.firstSeen)}{p.lastSeen !== p.firstSeen ? ` to ${at(p.lastSeen)}` : ''}</span></dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
