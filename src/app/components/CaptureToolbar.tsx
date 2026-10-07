// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useRef, type ReactNode } from 'react';
import { ThemeButton, type Theme } from './ThemeButton';
import './CaptureToolbar.css';

export function CaptureToolbar({ fileName, facts, exports, keys, timeline, filters, onOpen, onClose, onCompare, theme, setTheme }: {
  fileName: string; facts: ReactNode; exports: ReactNode; keys: ReactNode; timeline: ReactNode; filters: ReactNode;
  onOpen: (file: File) => void; onClose: () => void; onCompare: () => void; theme: Theme; setTheme: (theme: Theme) => void;
}) {
  const file = useRef<HTMLInputElement>(null);
  const actions = useRef<HTMLDetailsElement>(null);
  const help = useRef<HTMLDetailsElement>(null);
  const action = (callback: () => void) => { if (actions.current) actions.current.open = false; callback(); };
  return <header className="topbar capture-toolbar" aria-label="Capture toolbar">
    <div className="capture-toolbar-row">
      <div className="cap-title">
        <h1 title={fileName}>{fileName}</h1>
        <div className="cap-facts">{facts}</div>
      </div>
      <div className="capture-toolbar-actions">
        {exports}
        <details className="capture-action-menu" ref={actions} onKeyDown={(event) => {
          if (event.key === 'Escape') { actions.current!.open = false; actions.current?.querySelector('summary')?.focus(); }
        }}>
          <summary className="btn">Capture actions</summary>
          <div className="capture-action-panel">
            <button className="btn" onClick={() => { actions.current!.open = false; actions.current?.querySelector('summary')?.focus(); }}>Close capture actions</button>
            <button className="btn" onClick={() => action(() => file.current?.click())}>Open another</button>
            <button className="btn" onClick={() => action(onCompare)}>Compare captures</button>
            <button className="btn" onClick={() => action(onClose)}>Close</button>
            <p className="muted">Opening another capture clears this investigation and its TLS keys.</p>
          </div>
        </details>
        <ThemeButton theme={theme} setTheme={setTheme} />
        <details ref={help} className="capture-action-menu capture-help" onKeyDown={(event) => {
          if (event.key === 'Escape') { help.current!.open = false; help.current?.querySelector('summary')?.focus(); }
        }}>
          <summary className="btn">Help</summary>
          <div className="capture-action-panel">
            <h2>Capture information</h2>
            <button className="btn" onClick={() => { help.current!.open = false; help.current?.querySelector('summary')?.focus(); }}>Close help</button>
            <p className="mono">{fileName}</p>
            <p>Your capture is processed locally in your browser. Capture and key-log files are not uploaded or saved by the app.</p>
            <p>Use the traffic strip or Overview time bounds to select a time range. Shared filters follow you between views.</p>
            <a href="./ABOUT.html" target="_blank" rel="noopener">Licences and limitations</a>
          </div>
        </details>
      </div>
    </div>
    <input type="file" ref={file} hidden aria-label="Open another capture" accept=".pcap,.pcapng,.cap,.pcap.gz,.pcapng.gz,.ntar,.dmp,.erf,.snoop,application/vnd.tcpdump.pcap"
      onChange={(event) => { const selected = event.currentTarget.files?.[0]; event.currentTarget.value = ''; if (selected) onOpen(selected); }} />
    <div className="capture-toolbar-filter-row">
      <div className="capture-timeline"><span className="muted">Traffic / time filter</span>{timeline}</div>
      <div className="capture-toolbar-context">{keys}{filters}</div>
    </div>
  </header>;
}
