// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Host } from '../../engine/types';
import { DataTable, type Column } from '../components/DataTable';
import { LocalIpDataPanel } from '../components/LocalIpData';
import { Note, Seg, ViewHead } from '../components/bits';
import { useApp, useViewState } from '../context';
import { absTime, bytes, num, plural } from '../format';
import { lookupLocalIp, type LocalIpDataKind, type LocalIpDatabase, type LocalIpMatch } from '../localIpData';

export function Hosts() {
  const { model, sourceModel, params, go, openDrawer, closeDrawer, patchRouteParams, filter, setHostFilter } = useApp();
  const [family, setFamily] = useViewState<'all' | '4' | '6'>('hosts.family', 'all', (value): value is 'all' | '4' | '6' => value === 'all' || value === '4' || value === '6');
  const [selected, setSelected] = useViewState<string | null>('hosts.selected', null, (value): value is string | null => value === null || typeof value === 'string');
  const lastRouteHost = useRef<string | null>(null);
  const openedHostFromRoute = useRef(false);
  const [hostNotice, setHostNotice] = useState<string | null>(null);
  const [databases, setDatabases] = useState<Record<LocalIpDataKind, LocalIpDatabase | null>>({ country: null, asn: null });
  const [showIpColumns, setShowIpColumns] = useViewState<boolean>('hosts.ipColumns', false, (value): value is boolean => typeof value === 'boolean');
  const rows = useMemo(() => model.hosts.filter((h) => family === 'all' || String(h.ipVersion) === family), [model.hosts, family]);
  const digits = Math.min(6, model.capture.timestampDigits);
  const openHost = (h: Host) => {
    setSelected(h.addr);
    openDrawer({
      title: h.addr,
      frames: [...new Set(h.names.map((name) => name.frame))],
      summary: <HostDetail host={h} ipData={ipMatches.get(h.addr) ?? { country: null, asn: null }} go={go} digits={digits}
        onFilter={() => setHostFilter(h.addr)} isFiltered={filter.host === h.addr}
        openFrame={(frame, title) => openDrawer({ title, frames: [frame] }, 'nest')} startEpoch={model.capture.startEpoch} />,
    });
  };
  useEffect(() => {
    if (!params.has('host')) { lastRouteHost.current = null; openedHostFromRoute.current = false; setHostNotice(null); return; }
    const requested = params.get('host') || '';
    const found = sourceModel.hosts.find((h) => h.addr === requested);
    const visible = !!found && model.hosts.some((h) => h.addr === found.addr) && (family === 'all' || String(found.ipVersion) === family);
    const notice = !found
      ? `Host ${requested || '(empty)'} (host) is not in this capture.`
      : !visible
        ? `Host ${requested} (host) is outside the current filter. Its details stay closed so the list and the drawer match.`
        : null;
    setHostNotice((current) => current === notice ? current : notice);
    if (notice) {
      if (lastRouteHost.current !== notice) {
        lastRouteHost.current = notice;
        setSelected(null);
        if (openedHostFromRoute.current) { openedHostFromRoute.current = false; closeDrawer(); }
      }
      return;
    }
    if (!found || lastRouteHost.current === requested) return;
    lastRouteHost.current = requested;
    openedHostFromRoute.current = true;
    openHost(found);
    // Route changes open the detail once; later renders keep the same host key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params, sourceModel.hosts, model.hosts, family, closeDrawer, setSelected]);
  const onDatabaseChange = useCallback((kind: LocalIpDataKind, database: LocalIpDatabase | null) => {
    setDatabases((current) => ({ ...current, [kind]: database }));
  }, []);
  const ipMatches = useMemo(() => {
    const result = new Map<string, { country: LocalIpMatch | null; asn: LocalIpMatch | null }>();
    for (const h of model.hosts) {
      result.set(h.addr, {
        country: h.globallyReachable && databases.country ? lookupLocalIp(databases.country, h.addr) : null,
        asn: h.globallyReachable && databases.asn ? lookupLocalIp(databases.asn, h.addr) : null,
      });
    }
    return result;
  }, [model.hosts, databases]);

  const columns: Column<Host>[] = [
    { key: 'addr', header: 'Address', width: 'minmax(170px, 1.4fr)', value: (h) => h.addr, render: (h) => <span className="mono">{h.addr}</span> },
    { key: 'scope', header: 'Address range', width: '120px', value: (h) => h.scope },
    { key: 'country', hidden: !databases.country && !showIpColumns, header: 'Approx. country', width: '140px', value: (h) => {
      const match = ipMatches.get(h.addr)?.country;
      return match?.kind === 'country' ? match.country : '';
    }, title: 'Approximate country from the locally installed DB-IP Lite database' },
    { key: 'asn', hidden: !databases.asn && !showIpColumns, header: 'Approx. network owner', width: 'minmax(180px, 1.4fr)', value: (h) => {
      const match = ipMatches.get(h.addr)?.asn;
      return match?.kind === 'asn' ? `AS${match.asn} ${match.organization}` : '';
    }, title: 'Approximate network owner from the locally installed DB-IP Lite database' },
    { key: 'names', header: 'Names seen in capture', width: 'minmax(180px, 1.6fr)', value: (h) => h.names.map((n) => n.name).join(', '),
      render: (h) => h.names.length ? <span>{h.names[0].name}{h.names.length > 1 && <span className="muted"> +{h.names.length - 1}</span>} <span className="muted">({h.names[0].source})</span></span> : '' },
    { key: 'mac', header: 'Source MAC', width: '170px', value: (h) => h.macs.map((m) => m.mac).join(' '),
      render: (h) => h.macs.length ? <span className="mono">{h.macs[0].mac}{h.macs.length > 1 && <span className="muted"> +{h.macs.length - 1}</span>}</span> : '' },
    { key: 'vendor', header: 'MAC vendor', width: 'minmax(140px, 1fr)', value: (h) => (h.macs[0] ? vendorText(h.macs[0]) : null),
      title: 'Registered owner of the MAC address prefix (Wireshark OUI table). Not a device identification.' },
    { key: 'txp', header: 'Sent pkts', width: '90px', align: 'right', value: (h) => h.txPackets, render: (h) => num(h.txPackets), noSearch: true },
    { key: 'txb', header: 'Sent', width: '90px', align: 'right', value: (h) => h.txBytes, render: (h) => bytes(h.txBytes), noSearch: true },
    { key: 'rxp', header: 'Recv pkts', width: '90px', align: 'right', value: (h) => h.rxPackets, render: (h) => num(h.rxPackets), noSearch: true },
    { key: 'rxb', header: 'Received', width: '90px', align: 'right', value: (h) => h.rxBytes, render: (h) => bytes(h.rxBytes), noSearch: true },
    { key: 'peers', header: 'Peers', width: '70px', align: 'right', value: (h) => h.peers, noSearch: true },
    { key: 'svc', header: 'Ports used by peers', width: 'minmax(150px, 1fr)', value: (h) => h.servicePorts.map((s) => `${s.transport}/${s.port}`).join(' '),
      title: 'Ports on this host that other hosts sent traffic to. Not proof that a port is open.' },
    { key: 'protos', header: 'Protocols', width: 'minmax(150px, 1fr)', value: (h) => h.protocols.join(', ') },
  ];

  return (
    <>
      <ViewHead title="Hosts" right={<Seg label="Address family" value={family} onChange={setFamily} options={[{ value: 'all', label: 'All' }, { value: '4', label: 'IPv4' }, { value: '6', label: 'IPv6' }]} />}>
        One row per IP address seen as a packet source or destination. Bytes are original frame lengths.
      </ViewHead>
      {hostNotice && <Note kind="warn" onDismiss={() => patchRouteParams({ host: null })}>{hostNotice}</Note>}
      <LocalIpDataPanel databases={databases} onChange={onDatabaseChange} />
      <details style={{ marginBottom: 12 }}>
        <summary>About host evidence and address ranges</summary>
        <Note>Address range labels use reviewed IANA registry snapshots (special-purpose 2025-10-09; IPv6 address space 2025-10-23; IPv4 multicast 2026-08-20). Optional country and network-owner data is matched only for globally reachable addresses; special-purpose prefixes not marked globally reachable are excluded. A subnet broadcast is labelled when the capture shows an IPv4 packet sent to the Ethernet broadcast address.</Note>
        <Note>Names are observed or inferred from capture evidence; select a host to see their source packets. MAC vendors identify registered address-prefix owners, not devices. Ports listed are observed in this capture, not proof that a port is open now. No operating-system or device identification is attempted.</Note>
      </details>
      {(filter.start !== null || filter.host) && <Note>Sent/received packet and byte totals are recalculated for the selected traffic. MAC addresses, names, ports, peers, and protocol labels remain whole-capture metadata.</Note>}
      <section className="panel">
        <DataTable stateId="hosts.list" label="Hosts" exportName="hosts" rows={rows} columns={columns} rowKey={(h) => h.addr} selectedKey={selected}
          onRowClick={openHost} initialSort={{ key: 'txb', dir: 'desc' }} searchPlaceholder="Search addresses, names, MACs, ports"
          toolbar={<label><input type="checkbox" checked={showIpColumns} onChange={(event) => setShowIpColumns(event.currentTarget.checked)} /> Show country/ASN columns</label>}
          empty={<><strong>No IP hosts.</strong>This capture has no IPv4 or IPv6 packets that Wireshark could decode.</>} />
      </section>
    </>
  );
}

function HostDetail({ host: h, ipData, go, onFilter, isFiltered, openFrame, startEpoch, digits }: {
  ipData: { country: LocalIpMatch | null; asn: LocalIpMatch | null };
  host: Host; go: (v: string, p?: Record<string, string>) => void;
  onFilter: () => void; isFiltered: boolean;
  openFrame: (f: number, title: string) => void; startEpoch: string | null; digits: number;
}) {
  return (
    <section aria-label="Summary">
      <p className="muted">IPv{h.ipVersion}, {h.scope} address range</p>
      <div className="actions" style={{ margin: '8px 0 12px' }}>
        <button className="btn small" onClick={() => go('connections', { host: h.addr })}>Connections ({num(h.conversations)})</button>
        <button className="btn small" onClick={() => go('network', { host: h.addr })}>Show in graph</button>
        <button className="btn small" onClick={onFilter} aria-pressed={isFiltered}>{isFiltered ? 'Filtered across views' : 'Filter all views to host'}</button>
      </div>
      <div className="grid-2">
        <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
          <dl className="kv">
            <dt>Sent</dt><dd>{plural(h.txPackets, 'packet')}, {bytes(h.txBytes)}</dd>
            <dt>Received</dt><dd>{plural(h.rxPackets, 'packet')}, {bytes(h.rxBytes)}</dd>
            <dt>Peers</dt><dd>{num(h.peers)} addresses in {plural(h.conversations, 'conversation')}</dd>
            <dt>First seen</dt><dd className="mono">{absTime(startEpoch, h.firstSeen, digits)}</dd>
            <dt>Last seen</dt><dd className="mono">{absTime(startEpoch, h.lastSeen, digits)}</dd>
            {ipData.country?.kind === 'country' && <><dt>Country (approx.)</dt><dd>{ipData.country.country} · <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a></dd></>}
            {ipData.asn?.kind === 'asn' && <><dt>Network owner (approx.)</dt><dd>AS{ipData.asn.asn}{ipData.asn.organization ? ` · ${ipData.asn.organization}` : ''} · <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a></dd></>}
            <dt>Client ports</dt><dd>{h.clientPortCount ? `${num(h.clientPortCount)} distinct source ports used when starting conversations` : 'none observed'}</dd>
            <dt>Protocols</dt><dd>{h.protocols.join(', ') || '—'}</dd>
          </dl>
          <div>
            <h3 style={{ marginBottom: 6 }}>MAC addresses</h3>
            {h.macs.length ? (
              <dl className="kv">
                {h.macs.map((m) => (
                  <div key={m.mac} style={{ display: 'contents' }}>
                    <dt className="mono">{m.mac}</dt>
                    <dd>{vendorText(m)}; source of {plural(m.packets, 'packet')} from this address</dd>
                  </div>
                ))}
              </dl>
            ) : <p className="muted">No Ethernet source address observed (for example raw-IP or tunnelled captures).</p>}
            {h.arpMacs.length > 0 && <p style={{ marginTop: 6 }}>ARP announced this address at <span className="mono">{h.arpMacs.join(', ')}</span>.</p>}
            {h.macs.length > 0 && h.globallyReachable && (
              <p className="muted" style={{ marginTop: 6, fontSize: 12 }}>For addresses outside the local network the source MAC is usually a router, not this host.</p>
            )}
            {h.macs.length > 0 && (
              <p className="muted" style={{ marginTop: 6, fontSize: 12 }}>Vendors are the registered owners of each address prefix, from Wireshark's built-in table. They describe the network interface's maker, not the device, and can be spoofed.</p>
            )}
          </div>
        </div>
        <div style={{ display: 'grid', gap: 14, alignContent: 'start' }}>
          <div>
            <h3 style={{ marginBottom: 6 }}>Names learned from the capture</h3>
            {h.names.length ? (
              <dl className="kv">
                {h.names.map((n) => (
                  <div key={n.name + n.source} style={{ display: 'contents' }}>
                    <dt>{n.name}</dt>
                    <dd>
                      {n.source}, <span className={`tag ${n.kind === 'observed' ? 'good' : 'info'}`} title={n.kind === 'observed' ? 'The capture states this name-to-address mapping' : 'A client used this name when talking to this address; the mapping is not stated directly'}>{n.kind}</span>{' '}
                      <button className="btn small ghost" onClick={() => openFrame(n.frame, `${n.name} (${n.source})`)}>packet #{n.frame}</button>
                    </dd>
                  </div>
                ))}
              </dl>
            ) : <p className="muted">No names for this address appear in DNS, mDNS, NBNS, DHCP, TLS SNI or HTTP Host headers.</p>}
          </div>
          <div>
            <h3 style={{ marginBottom: 6 }}>Ports peers sent traffic to</h3>
            {h.servicePorts.length ? (
              <dl className="kv">
                {h.servicePorts.map((s) => (
                  <div key={s.transport + s.port} style={{ display: 'contents' }}>
                    <dt className="mono">{s.transport}/{s.port}</dt>
                    <dd>{s.evidence}; {plural(s.conversations, 'conversation')} from {plural(s.peers, 'peer')}</dd>
                  </div>
                ))}
              </dl>
            ) : <p className="muted">No conversations were directed at this address.</p>}
          </div>
        </div>
      </div>
    </section>
  );
}

function vendorText(m: Host['macs'][number]): string {
  if (m.locallyAdministered) return 'locally administered (no vendor; often a randomised address)';
  return m.vendor ?? 'vendor not in Wireshark\'s table';
}
