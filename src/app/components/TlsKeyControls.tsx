// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useRef, useState } from 'react';
import type { AnalysisModel } from '../../engine/types';

/** Staging a file never changes results. Applying creates a fresh local worker. */
export function TlsKeyControls({ activeKeyLog, model, onApplyKeys, onRemoveKeys }: {
  activeKeyLog: File | null; model: AnalysisModel; onApplyKeys: (file: File) => void; onRemoveKeys: () => void;
}) {
  const [staged, setStaged] = useState<File | null>(null);
  const ref = useRef<HTMLInputElement>(null);
  const disclosure = useRef<HTMLDetailsElement>(null);
  const close = () => { if (disclosure.current) { disclosure.current.open = false; disclosure.current.querySelector('summary')?.focus(); } };
  useEffect(() => {
    const dismiss = (event: PointerEvent) => {
      if (!(disclosure.current?.open && event.target instanceof Node && !disclosure.current.contains(event.target))) return;
      const summary = disclosure.current.querySelector('summary');
      disclosure.current.open = false;
      requestAnimationFrame(() => { if (summary instanceof HTMLElement) summary.focus(); });
    };
    document.addEventListener('pointerdown', dismiss);
    return () => document.removeEventListener('pointerdown', dismiss);
  }, []);
  const decrypted = model.tls.filter((session) => session.decryptionStatus === 'decrypted').length;
  const summary = staged ? `Staged: ${staged.name}` : activeKeyLog ? `${activeKeyLog.name} · ${decrypted} decrypted` : 'None';
  return <details ref={disclosure} className="capture-action-menu tls-key-menu" onKeyDown={(event) => {
    if (event.key === 'Escape' && disclosure.current?.open) {
      event.preventDefault(); close();
    }
  }}>
    <summary className="btn" title={`TLS keys · ${summary}`}><span>TLS keys</span><span className="capture-action-value">{summary}</span></summary>
    <div className="capture-action-panel">
      <button type="button" className="menu-row" onClick={() => ref.current?.click()}>Choose TLS key log (optional)</button>
      <input ref={ref} type="file" hidden accept=".keys,.txt,text/plain" aria-label="Choose current capture TLS key log" onChange={(event) => { setStaged(event.target.files?.[0] ?? null); event.target.value = ''; if (disclosure.current) disclosure.current.open = true; }} />
      {staged && <div role="status">Staged: {staged.name} · results unchanged <button className="btn small" onClick={() => onApplyKeys(staged)}>Apply keys to current capture</button><button className="btn small ghost" onClick={() => setStaged(null)}>Discard staged keys</button></div>}
      {activeKeyLog ? <div role="status">Active key log: {activeKeyLog.name} · {decrypted} sessions decrypted{decrypted === 0 ? ' · no matching decrypted sessions' : ''} <button className="btn small" onClick={onRemoveKeys}>Remove active keys</button></div> : <span className="muted">No active key log</span>}
      <p className="muted" style={{ fontSize: 12 }}>Session secrets stay in tab memory for this capture, including comparison return. Opening another capture clears them.</p>
    </div>
  </details>;
}
