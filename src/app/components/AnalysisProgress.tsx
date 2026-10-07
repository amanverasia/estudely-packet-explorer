// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useState } from 'react';
import type { EngineState } from '../engine';
import { bytes, duration } from '../format';

const PHASES = [
  { phase: 'engine', label: 'Download engine files (first time only)' },
  { phase: 'init', label: 'Initialize the Wireshark engine' },
  { phase: 'read', label: 'Read the file from your device' },
  { phase: 'load', label: 'Index packets' },
  { phase: 'extract', label: 'Decode every packet' },
  { phase: 'parse', label: 'Read decoded fields' },
  { phase: 'analyze', label: 'Build summaries' },
];

/** Mount with the run's startedAt as key: idle and previous-run clocks cannot leak in. */
export function AnalysisProgress({ working }: { working: Extract<EngineState, { kind: 'working' }> }) {
  const [now, setNow] = useState(() => performance.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(performance.now()), 500);
    return () => clearInterval(timer);
  }, []);
  const phaseIdx = PHASES.findIndex((phase) => phase.phase === working.progress.phase);
  const label = PHASES[phaseIdx]?.label ?? 'Analyze capture';
  const percent = working.progress.fraction === null ? null : Math.round(working.progress.fraction * 100);
  const percentScope = working.progress.phase === 'engine' ? 'current download' : 'this phase';
  return <>
    <p className="muted" data-testid="analysis-elapsed">{bytes(working.fileSize)}, {duration(Math.max(0, now - working.startedAt) / 1000)} elapsed</p>
    <p><strong>{label}</strong>{percent !== null && ` · ${percent}% of ${percentScope}`}</p>
    <div className={`progress${percent === null ? ' indeterminate' : ''}`} role="progressbar"
      aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent ?? undefined} aria-label={`${label} progress`}
      aria-valuetext={percent === null ? `${label}: in progress` : `${percent}% of ${percentScope}; capture analysis is still running`}>
      <div style={{ width: percent === null ? undefined : `${percent}%` }} />
    </div>
    <p>{working.progress.message}</p>
    <div className="steps"><ol>
      {PHASES.map((phase, index) => <li key={phase.phase} data-state={index < phaseIdx ? 'done' : index === phaseIdx ? 'active' : 'todo'}>
        <span aria-hidden="true" style={{ width: 14 }}>{index < phaseIdx ? '✓' : index === phaseIdx ? '›' : ''}</span>{phase.label}
      </li>)}
    </ol></div>
  </>;
}
