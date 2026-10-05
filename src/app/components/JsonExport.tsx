// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useRef, useState } from 'react';
import type { AnalysisModel } from '../../engine/types';
import { downloadBlob, summaryJson } from '../download';

export function JsonExport({ model }: { model: AnalysisModel }) {
  const [redactSensitive, setRedactSensitive] = useState(true);
  const menu = useRef<HTMLDetailsElement>(null);

  const exportJson = (mode: 'aggregate' | 'detailed') => {
    const suffix = mode === 'aggregate' ? 'summary' : 'details';
    const json = summaryJson(model, { mode, redactSensitive });
    downloadBlob(`capture-${suffix}.json`, new Blob([json], { type: 'application/json;charset=utf-8' }));
    if (menu.current) menu.current.open = false;
  };

  return (
    <details ref={menu} className="json-export-menu">
      <summary className="btn" aria-label="JSON export options">Export JSON</summary>
      <div className="json-export-panel">
        <h2>Choose JSON export detail</h2>
        <section className="json-export-choice" aria-labelledby="aggregate-export-heading">
          <h3 id="aggregate-export-heading">Aggregate summary</h3>
          <p>Recommended for sharing. Includes protocol totals, capture quality counts, and record totals. It omits file names, addresses, names, ports, packet references, request details, and certificate identities.</p>
          <button className="btn" onClick={() => exportJson('aggregate')}>Download aggregate JSON</button>
        </section>
        <section className="json-export-choice" aria-labelledby="detailed-export-heading">
          <h3 id="detailed-export-heading">Detailed analysis</h3>
          <p>Includes host and address data, DNS names and answers, HTTP paths and headers, TLS server and certificate details, DHCP identifiers, and packet references. It stays in this browser until downloaded.</p>
          <label className="json-export-redaction">
            <input type="checkbox" checked={redactSensitive} onChange={(e) => setRedactSensitive(e.target.checked)} />
            Redact known identifying and content-like values
          </label>
          <button className="btn" onClick={() => exportJson('detailed')}>Download detailed JSON</button>
          <p className="muted">Redaction replaces values in known sensitive fields. Relative timings, frame numbers, ports, traffic sizes, protocol labels, and counts remain, so the result is not anonymous. Review it before sharing.</p>
        </section>
        <p className="json-export-exclusions">Both choices exclude packet bytes, packet field trees, stream payloads, TLS key logs and secrets, exported-file inventory, and file contents. Downloads are created locally; no capture data is sent.</p>
      </div>
    </details>
  );
}
