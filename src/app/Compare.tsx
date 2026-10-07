// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useRef, useState } from 'react';
import type { AnalysisModel } from '../engine/types';
import { compareCaptures, comparisonSource, countChanges, type CaptureComparison, type ChangeStatus, type ComparisonSource } from '../engine/compare';
import { EngineClient, type EngineState } from './engine';
import { bytes, duration, num } from './format';
import { DataTable, type Column } from './components/DataTable';
import { CAPTURE_ACCEPT, FileChoice } from './components/FileChoice';
import { ThemeButton, type Theme } from './components/ThemeButton';

export function ComparePage({ seed, onClearSeed, onClose, theme, setTheme }: {
  seed: AnalysisModel | null;
  onClearSeed: () => void;
  onClose: () => void;
  theme: Theme;
  setTheme: (theme: Theme) => void;
}) {
  const [fileA, setFileA] = useState<File | null>(null);
  const [fileB, setFileB] = useState<File | null>(null);
  const [seeded, setSeeded] = useState(!!seed);
  const [modelA, setModelA] = useState<ComparisonSource | null>(() => seed ? comparisonSource(seed) : null);
  const [comparison, setComparison] = useState<CaptureComparison | null>(null);
  const [phase, setPhase] = useState<'idle' | 'first' | 'second' | 'done' | 'error'>('idle');
  const [progress, setProgress] = useState<Extract<EngineState, { kind: 'working' }>['progress'] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const clientRef = useRef<EngineClient | null>(null);
  const stageRef = useRef<'first' | 'second'>('first');
  const firstModelRef = useRef<ComparisonSource | null>(modelA);

  useEffect(() => () => clientRef.current?.close(), []);
  useEffect(() => { if (seed) onClearSeed(); }, [seed, onClearSeed]);

  const running = phase === 'first' || phase === 'second';
  const canStart = !!fileB && (!!modelA || !!fileA) && !running;

  const selectA = (file: File | null) => {
    setFileA(file);
    setSeeded(false);
    setModelA(null);
    firstModelRef.current = null;
    setComparison(null);
    setPhase('idle');
    setError(null);
  };
  const selectB = (file: File | null) => {
    setFileB(file);
    setComparison(null);
    setPhase('idle');
    setError(null);
  };

  const run = () => {
    if (!fileB || (!modelA && !fileA) || running) return;
    setComparison(null);
    setError(null);
    setProgress(null);
    const left = modelA;
    const rightFile = fileB;
    const firstFile = fileA;
    stageRef.current = left ? 'second' : 'first';
    firstModelRef.current = left;
    const client = new EngineClient((state) => {
      if (state.kind === 'working') {
        setPhase(stageRef.current);
        setProgress(state.progress);
      } else if (state.kind === 'error') {
        client.close();
        setPhase('error');
        setProgress(null);
        setError(`${state.fileName ? `${state.fileName}: ` : ''}${state.message}`);
      } else if (state.kind === 'ready') {
        if (stageRef.current === 'first') {
          const summary = comparisonSource(state.model);
          firstModelRef.current = summary;
          setModelA(summary);
          stageRef.current = 'second';
          setPhase('second');
          setProgress(null);
          client.open(rightFile);
        } else {
          const leftModel = firstModelRef.current;
          if (!leftModel) {
            setPhase('error');
            setError('The first capture summary was unavailable. Start the comparison again.');
            client.close();
            return;
          }
          setComparison(compareCaptures(leftModel, comparisonSource(state.model)));
          setPhase('done');
          setProgress(null);
          client.close();
        }
      }
    });
    clientRef.current = client;
    if (left) {
      client.open(rightFile);
    } else if (firstFile) {
      client.open(firstFile);
    }
  };

  const cancel = () => {
    clientRef.current?.cancel();
    clientRef.current = null;
    firstModelRef.current = modelA;
    setPhase('idle');
    setProgress(null);
  };

  const names = useMemo(() => ({
    a: comparison?.before.fileName ?? modelA?.capture.fileName ?? fileA?.name ?? 'Capture A',
    b: comparison?.after.fileName ?? fileB?.name ?? 'Capture B',
  }), [comparison, modelA, fileA, fileB]);

  return (
    <main className="landing compare-page">
      <div className="landing-card">
        <header className="compare-head">
          <div>
            <div className="brand-name" style={{ fontSize: 18 }}>Estudely Packet Explorer</div>
            <h1>Compare two captures</h1>
            <p className="muted">Capture A is the baseline. New means only in B; missing means only in A; changed means present in both with different details.</p>
          </div>
          <ThemeButton theme={theme} setTheme={setTheme} />
        </header>

        <div className="compare-pickers">
          <section className="panel compare-picker">
            <h2>Capture A · baseline</h2>
            {seeded ? <div className="compare-baseline">
              <p className="mono">{modelA?.capture.fileName ?? seed?.capture.fileName ?? 'Already analyzed'}</p>
              <button className="btn small" disabled={running} onClick={() => { setSeeded(false); setModelA(null); firstModelRef.current = null; setFileA(null); setComparison(null); }}>Choose different capture A</button>
            </div> : <FileChoice label="Choose capture A" file={fileA} accept={CAPTURE_ACCEPT} disabled={running} onChange={selectA} />}
            {fileA && <p className="muted">{bytes(fileA.size)}</p>}
            {modelA && modelA.capture.partial && <p className="note warn">Capture A is a partial analysis of the first {bytes(modelA.capture.analyzedBytes)}.</p>}
          </section>
          <section className="panel compare-picker">
            <h2>Capture B</h2>
            <FileChoice label="Choose capture B" file={fileB} accept={CAPTURE_ACCEPT} disabled={running} onChange={selectB} />
            {fileB && <p className="muted">{bytes(fileB.size)}</p>}
            {comparison?.after.partial && <p className="note warn">Capture B is a partial analysis of the first {bytes(comparison.after.analyzedBytes)}.</p>}
          </section>
        </div>

        <div className="actions">
          {!running ? <button className="btn primary" disabled={!canStart} onClick={run}>{phase === 'done' ? 'Compare again' : 'Compare captures'}</button>
            : <button className="btn" onClick={cancel}>Cancel</button>}
          <button className="btn" onClick={() => { clientRef.current?.close(); clientRef.current = null; onClose(); }}>Back</button>
        </div>

        {running && <section className="compare-progress" aria-live="polite">
          <h2>Analyzing capture {phase === 'first' ? 'A' : 'B'} of 2</h2>
          <p>{progress?.message ?? 'Starting…'}</p>
          <div className={`progress${progress?.fraction === null || !progress ? ' indeterminate' : ''}`} role="progressbar" aria-label={`Capture ${phase === 'first' ? 'A' : 'B'} analysis progress`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress?.fraction === null || !progress ? undefined : Math.round(progress.fraction * 100)}>
            <div style={{ width: progress?.fraction === null || !progress ? undefined : `${Math.round(progress.fraction * 100)}%` }} />
          </div>
          <p className="muted">Only one Wiregasm engine session runs at a time. The captures remain on this device.</p>
        </section>}
        {error && <div className="note crit" role="alert">{error}</div>}

        {comparison && <>
          <section className="panel compare-overview">
            <div className="panel-head"><h2>Capture comparison</h2><span className="sub">A · {names.a} &nbsp;→&nbsp; B · {names.b}</span></div>
            <div className="panel-body">
              <p>{num(comparison.before.packetCount)} packets over {duration(comparison.before.duration)} in A; {num(comparison.after.packetCount)} packets over {duration(comparison.after.duration)} in B.</p>
              <p className="muted">Conversations match by protocol and the unordered pair of endpoint addresses and ports. Reused tuples are paired in first-seen order.</p>
              {(comparison.before.partial || comparison.after.partial) && <p className="note warn" role="status">At least one capture is partial. Changes may reflect packets beyond its analyzed prefix being absent.</p>}
            </div>
          </section>
          <DiffTable label="Host and name changes" rows={comparison.hosts} exportName="capture-host-changes" columns={[
            { key: 'status', header: 'Status', width: '150px', value: (r) => r.status, render: (r) => statusLabel(r.status) },
            { key: 'address', header: 'Host', width: 'minmax(150px, 1fr)', value: (r) => r.address },
            { key: 'names-a', header: 'Names in A', width: 'minmax(140px, 1fr)', value: (r) => joinOrDash(r.beforeNames) },
            { key: 'names-b', header: 'Names in B', width: 'minmax(140px, 1fr)', value: (r) => joinOrDash(r.afterNames) },
            { key: 'protocols-a', header: 'Protocols in A', width: 'minmax(120px, 1fr)', value: (r) => joinOrDash(r.beforeProtocols) },
            { key: 'protocols-b', header: 'Protocols in B', width: 'minmax(120px, 1fr)', value: (r) => joinOrDash(r.afterProtocols) },
          ]} />
          <DiffTable label="Protocol changes" rows={comparison.protocols} exportName="capture-protocol-changes" columns={[
            { key: 'status', header: 'Status', width: '150px', value: (r) => r.status, render: (r) => statusLabel(r.status) },
            { key: 'protocol', header: 'Protocol', width: 'minmax(150px, 1fr)', value: (r) => r.protocol },
            { key: 'packets-a', header: 'Packets in A', width: '120px', value: (r) => r.before?.packets ?? 0 },
            { key: 'packets-b', header: 'Packets in B', width: '120px', value: (r) => r.after?.packets ?? 0 },
            { key: 'bytes-a', header: 'Bytes in A', width: '120px', value: (r) => r.before?.bytes ?? 0 },
            { key: 'bytes-b', header: 'Bytes in B', width: '120px', value: (r) => r.after?.bytes ?? 0 },
          ]} />
          <DiffTable label="Conversation changes" rows={comparison.conversations} exportName="capture-conversation-changes" columns={[
            { key: 'status', header: 'Status', width: '150px', value: (r) => r.status, render: (r) => statusLabel(r.status) },
            { key: 'transport', header: 'Transport', width: '110px', value: (r) => r.transport },
            { key: 'endpoints', header: 'Endpoints', width: 'minmax(240px, 2fr)', value: (r) => `${r.endpointA} ↔ ${r.endpointB}` },
            { key: 'app-a', header: 'Application in A', width: 'minmax(130px, 1fr)', value: (r) => r.before?.appProtocol ?? '—' },
            { key: 'app-b', header: 'Application in B', width: 'minmax(130px, 1fr)', value: (r) => r.after?.appProtocol ?? '—' },
            { key: 'packets-a', header: 'Packets in A', width: '110px', value: (r) => r.before?.packets ?? 0 },
            { key: 'packets-b', header: 'Packets in B', width: '110px', value: (r) => r.after?.packets ?? 0 },
            { key: 'bytes-a', header: 'Bytes in A', width: '110px', value: (r) => r.before?.bytes ?? 0 },
            { key: 'bytes-b', header: 'Bytes in B', width: '110px', value: (r) => r.after?.bytes ?? 0 },
          ]} />
        </>}
      </div>
    </main>
  );
}

function DiffTable<T extends { key: string; status: ChangeStatus }>({ label, rows, columns, exportName }: {
  label: string;
  rows: T[];
  columns: Column<T>[];
  exportName: string;
}) {
  const changes = rows.filter((row) => row.status !== 'same');
  const counts = countChanges(rows);
  return (
    <section className="panel compare-table-panel">
      <div className="panel-head"><h2>{label}</h2><span className="sub">{counts.new} new · {counts.missing} missing · {counts.changed} changed · {counts.same} unchanged</span></div>
      <div className="panel-body">
        {changes.length ? <DataTable rows={changes} columns={columns} rowKey={(row) => row.key} label={label} exportName={exportName} searchPlaceholder={`Search ${label.toLowerCase()}`} />
          : <p className="muted">No changes found.</p>}
      </div>
    </section>
  );
}

function joinOrDash(values: string[]): string {
  return values.length ? values.join(', ') : '—';
}

function statusLabel(status: ChangeStatus): string {
  if (status === 'new') return 'New in B';
  if (status === 'missing') return 'Missing from B';
  return status === 'changed' ? 'Changed' : 'Unchanged';
}
