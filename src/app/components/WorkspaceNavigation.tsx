// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import { num } from '../format';
import { BuildTag } from './BuildTag';
import './WorkspaceNavigation.css';

export interface WorkspaceNavigationItem {
  id: string;
  label: string;
  count?: number;
  /** Whole-capture count: filtered zeroes must remain in the main group. */
  total?: number;
}

const investigationIds = ['overview', 'hosts', 'connections', 'network', 'packets'];
const protocolIds = ['dns', 'http', 'files', 'tls', 'quic', 'ssh', 'dhcp', 'arp', 'icmp'];

function countText(item: WorkspaceNavigationItem) {
  if (item.count === undefined) return '';
  return num(item.count) + (item.total !== undefined && item.total !== item.count ? `/${num(item.total)}` : '');
}

export function WorkspaceNavigation({ items, current, onNavigate, wireshark, localNotice }: {
  items: WorkspaceNavigationItem[];
  current: string;
  onNavigate: (id: string) => void;
  wireshark: string;
  localNotice: string;
}) {
  const uid = useId();
  const ordered = (ids: string[]) => ids.flatMap((id) => items.filter((item) => item.id === id));
  const investigation = ordered(investigationIds);
  const protocols = ordered(protocolIds);
  const present = protocols.filter((item) => item.total !== 0);
  const absent = protocols.filter((item) => item.total === 0);
  const activeAbsent = absent.some((item) => item.id === current);
  const currentGroup = investigationIds.includes(current) ? 'Investigation' : 'Protocols';
  const link = (item: WorkspaceNavigationItem) => (
    <a key={item.id} href={`#/${item.id}`} onClick={(event) => { event.preventDefault(); onNavigate(item.id); }} aria-current={current === item.id ? 'page' : undefined}>
      <span className="nav-mark" aria-hidden="true" />
      <span>{item.label}</span>
      {item.count !== undefined && <span className="nav-count" aria-label={item.total !== undefined && item.total !== item.count ? `${num(item.count)} of ${num(item.total)} in capture` : `${num(item.count)} in capture`}>{countText(item)}</span>}
    </a>
  );
  return (
    <aside className="sidebar workspace-sidebar" aria-label="Views">
      <div className="brand workspace-desktop">
        <div className="brand-name">Estudely Packet Explorer</div>
        <div className="brand-sub">Local capture analysis</div>
      </div>
      <nav className="workspace-desktop workspace-groups" aria-label="Capture views">
        <section aria-labelledby={`${uid}-investigation`}>
          <h2 id={`${uid}-investigation`} className="workspace-group-title">Investigation</h2>
          <div className="nav">{investigation.map(link)}</div>
        </section>
        <section aria-labelledby={`${uid}-protocols`}>
          <h2 id={`${uid}-protocols`} className="workspace-group-title">Protocols</h2>
          <div className="nav">{present.map(link)}</div>
          {absent.length > 0 && <details className="workspace-absent" open={activeAbsent || undefined}>
            <summary>Absent protocols <span className="mono">({absent.length})</span></summary>
            <p>No records in this capture.</p>
            <div className="nav">{absent.map(link)}</div>
          </details>}
        </section>
      </nav>
      <nav className="workspace-mobile" aria-label="Capture views">
        <div className="workspace-selector-label"><label htmlFor={`${uid}-select`}>Current view</label><span>{currentGroup}</span></div>
        <select id={`${uid}-select`} value={current} onChange={(event) => onNavigate(event.target.value)}>
          <optgroup label="Investigation">{investigation.map((item) => <option key={item.id} value={item.id}>{item.label}{item.count !== undefined ? ` · ${countText(item)}` : ''}</option>)}</optgroup>
          <optgroup label="Protocols">{protocols.map((item) => <option key={item.id} value={item.id}>{item.label}{item.count !== undefined ? ` · ${countText(item)}` : ''}{item.total === 0 ? ' · absent' : ''}</option>)}</optgroup>
        </select>
      </nav>
      <div className="sidebar-foot workspace-desktop">
        {localNotice && <p className="local-note">{localNotice}</p>}
        <p>Decoded with Wireshark {wireshark} via Wiregasm. <a href="./ABOUT.html" target="_blank" rel="noopener">Licences and limitations</a></p>
        <BuildTag />
      </div>
    </aside>
  );
}
