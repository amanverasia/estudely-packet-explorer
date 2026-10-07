// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useRef, useState } from 'react';
import type { AnalysisModel } from '../../engine/types';
import { downloadBlob, summaryJson } from '../download';

interface CaptureExportProps {
  model: AnalysisModel;
  selectionAvailable: boolean;
  selectionDescription?: string;
  onWholeHtml: () => void;
  onSelectionHtml: () => void;
}

export function JsonExport({ model, selectionAvailable, selectionDescription, onWholeHtml, onSelectionHtml }: CaptureExportProps) {
  const [redactSensitive, setRedactSensitive] = useState(true);
  const menu = useRef<HTMLDetailsElement>(null);
  const trigger = useRef<HTMLElement>(null);

  const close = (returnFocus: boolean) => {
    if (menu.current) menu.current.open = false;
    if (returnFocus) trigger.current?.focus();
  };

  useEffect(() => {
    const dismissOutside = (event: PointerEvent) => {
      if (menu.current?.open && event.target instanceof Node && !menu.current.contains(event.target)) close(false);
    };
    const dismissEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && menu.current?.open) {
        event.preventDefault();
        close(true);
      }
    };
    document.addEventListener('pointerdown', dismissOutside);
    document.addEventListener('keydown', dismissEscape);
    return () => {
      document.removeEventListener('pointerdown', dismissOutside);
      document.removeEventListener('keydown', dismissEscape);
    };
  }, []);

  const exportHtml = (download: () => void) => {
    download();
    close(true);
  };

  const exportJson = (mode: 'aggregate' | 'detailed') => {
    const suffix = mode === 'aggregate' ? 'summary' : 'details';
    const json = summaryJson(model, { mode, redactSensitive });
    downloadBlob(`capture-${suffix}.json`, new Blob([json], { type: 'application/json;charset=utf-8' }));
    close(true);
  };

  return (
    <details ref={menu} className="json-export-menu">
      <summary ref={trigger} className="btn">Export</summary>
      <div className="json-export-panel">
        <h2>Choose export scope and format</h2>
        <button className="btn" onClick={() => close(true)}>Close export menu</button>
        <p className="json-export-exclusions">Whole capture: {model.capture.packetCount.toLocaleString()} analyzed packets. Shared time and host filters do not change whole-capture downloads.</p>
        <section className="json-export-choice" aria-labelledby="html-export-heading">
          <h3 id="html-export-heading">HTML report</h3>
          <p>Self-contained aggregate report for offline viewing. Includes observed names and network addresses; review before sharing.</p>
          <button className="btn" onClick={() => exportHtml(onWholeHtml)}>Download whole capture HTML</button>
          <p>Current selection: {selectionAvailable ? selectionDescription || 'Active shared time and host filters.' : 'Apply a shared time or host filter to enable this report.'} Selection reports retain labelled whole-capture metadata and correlated record details.</p>
          <button className="btn" disabled={!selectionAvailable} onClick={() => exportHtml(onSelectionHtml)}>Download current selection HTML</button>
        </section>
        <section className="json-export-choice" aria-labelledby="aggregate-export-heading">
          <h3 id="aggregate-export-heading">Whole capture JSON · aggregate summary</h3>
          <p>Recommended for sharing. Includes protocol totals, capture quality counts, and record totals. It omits file names, addresses, names, ports, packet references, request details, and certificate identities.</p>
          <button className="btn" onClick={() => exportJson('aggregate')}>Download whole capture aggregate JSON</button>
        </section>
        <section className="json-export-choice" aria-labelledby="detailed-export-heading">
          <h3 id="detailed-export-heading">Whole capture JSON · detailed analysis</h3>
          <p>Includes host and address data, DNS names and answers, HTTP paths and headers, TLS server and certificate details, DHCP identifiers, and packet references. It stays in this browser until downloaded.</p>
          <label className="json-export-redaction">
            <input type="checkbox" checked={redactSensitive} onChange={(e) => setRedactSensitive(e.target.checked)} />
            Redact known identifying and content-like values
          </label>
          <button className="btn" onClick={() => exportJson('detailed')}>Download whole capture detailed JSON</button>
          <p className="muted">Redaction replaces values in known sensitive fields. Relative timings, frame numbers, ports, traffic sizes, protocol labels, and counts remain, so the result is not anonymous. Review it before sharing.</p>
        </section>
        <p className="json-export-exclusions">JSON downloads always cover the whole capture. Both JSON choices exclude packet bytes, packet field trees, stream payloads, TLS key logs and secrets, exported-file inventory, and file contents. Downloads are created locally; no capture data is sent.</p>
        <p className="json-export-exclusions">CSV exports are available in each table and use that table’s current search and sort. Conversation packet CSV exports cover the current page.</p>
      </div>
    </details>
  );
}
