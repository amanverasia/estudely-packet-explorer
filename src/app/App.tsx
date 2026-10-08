// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { AnalysisModel } from '../engine/types';
import { AnalysisProgress } from './components/AnalysisProgress';
import { BuildTag } from './components/BuildTag';
import { Strip } from './components/charts';
import { Drawer } from './components/Drawer';
import { CAPTURE_ACCEPT, FileChoice } from './components/FileChoice';
import sampleCaptureUrl from '../../fixtures/dns.pcap?url';
import { OfflineStatus, UpdateBanner } from './components/Offline';
import { ThemeButton, type Theme } from './components/ThemeButton';
import { ComparePage } from './Compare';
import { TlsKeyControls } from './components/TlsKeyControls';
import { Ctx, ViewStateCtx, type AppCtx, type DrawerSpec, type ViewStateStore } from './context';
import { applySharedFilter, type SharedFilter } from './filtering';
import { downloadBlob, safeBase } from './download';
import { CaptureToolbar } from './components/CaptureToolbar';
import { WorkspaceNavigation } from './components/WorkspaceNavigation';
import { JsonExport } from './components/JsonExport';
import { htmlReport } from './report';
import { EngineClient, HARD_LIMIT_BYTES, SOFT_LIMIT_BYTES, type EngineState } from './engine';
import { landingDragLeaveAction, probeFromDragLeave } from './dropHighlight';
import { bytes, duration, num } from './format';
import { Overview } from './views/Overview';
import { Dns } from './views/Dns';

const Http = lazy(() => import('./views/Http').then((m) => ({ default: m.Http })));
const Tls = lazy(() => import('./views/Tls').then((m) => ({ default: m.Tls })));
const Hosts = lazy(() => import('./views/Hosts').then((m) => ({ default: m.Hosts })));
const Connections = lazy(() => import('./views/Connections').then((m) => ({ default: m.Connections })));
const Network = lazy(() => import('./views/Network').then((m) => ({ default: m.Network })));
const Packets = lazy(() => import('./views/Packets').then((m) => ({ default: m.Packets })));
const Dhcp = lazy(() => import('./views/Dhcp').then((m) => ({ default: m.Dhcp })));
const Arp = lazy(() => import('./views/Arp').then((m) => ({ default: m.Arp })));
const Icmp = lazy(() => import('./views/Icmp').then((m) => ({ default: m.Icmp })));
const Ssh = lazy(() => import('./views/Ssh').then((m) => ({ default: m.Ssh })));
const Quic = lazy(() => import('./views/Quic').then((m) => ({ default: m.Quic })));
const Files = lazy(() => import('./views/Files').then((m) => ({ default: m.Files })));

export const LOCAL_NOTICE = 'Your capture is processed locally in your browser.';

const VIEWS = ['overview', 'dns', 'http', 'files', 'tls', 'hosts', 'connections', 'network', 'packets', 'dhcp', 'arp', 'icmp', 'ssh', 'quic'] as const;
type View = (typeof VIEWS)[number];

function parseHash(): { view: View; params: URLSearchParams } {
  const h = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = h.split('?');
  const view = (VIEWS as readonly string[]).includes(path) ? (path as View) : 'overview';
  return { view, params: new URLSearchParams(query) };
}

function loadTheme(): Theme {
  try { return (localStorage.getItem('epx-theme') as Theme) || 'system'; } catch { return 'system'; }
}

export function App() {
  const [state, setState] = useState<EngineState>({ kind: 'idle' });
  const engineRef = useRef<EngineClient | null>(null);
  if (!engineRef.current) engineRef.current = new EngineClient(setState);
  const engine = engineRef.current;
  const [route, setRoute] = useState(parseHash);
  const [drawers, setDrawers] = useState<DrawerSpec[]>([]);
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const currentFileRef = useRef<File | null>(null);
  const [activeKeyLog, setActiveKeyLog] = useState<File | null>(null);
  const pendingKeysRef = useRef<File | null>(null);
  const [returnOperation, setReturnOperation] = useState<'restore' | 'keys' | null>(null);
  const snapshotRef = useRef<{ hash: string; drawers: DrawerSpec[]; scroll: number; workspaceScroll: number; tables: { label: string | null; top: number }[] } | null>(null);
  const [compareMode, setCompareMode] = useState(false);
  const [compareSeed, setCompareSeed] = useState<AnalysisModel | null>(null);
  const [captureSession, setCaptureSession] = useState(0);
  const captureSessionRef = useRef(0);
  const captureAttempted = useRef(false);
  const lastRouteEventKey = useRef('');
  const viewStateRef = useRef(new Map<string, unknown>());
  const viewState = useMemo<ViewStateStore>(() => ({
    get: (key) => viewStateRef.current.get(key),
    set: (key, value) => { viewStateRef.current.set(key, value); },
    session: () => captureSessionRef.current,
  }), []);
  const setHistoryCaptureSession = useCallback((session: number, hash?: string) => {
    const oldState = history.state;
    const stateObject = oldState && typeof oldState === 'object' ? oldState as Record<string, unknown> : {};
    const nextState = { ...stateObject, __epxCaptureSession: session };
    const url = hash === undefined ? location.href : `${location.pathname}${location.search}${hash}`;
    history.replaceState(nextState, '', url);
    lastRouteEventKey.current = `${location.href}\u0000${session}`;
  }, []);
  const replaceRoute = useCallback((hash: string, session: number) => {
    setHistoryCaptureSession(session, hash);
    setRoute(parseHash());
  }, [setHistoryCaptureSession]);
  const resetViewState = useCallback(() => {
    viewStateRef.current.clear();
    const next = captureSessionRef.current + 1;
    captureSessionRef.current = next;
    setCaptureSession(next);
    return next;
  }, []);

  useEffect(() => {
    const on = () => {
      const state = history.state;
      const taggedSession = state && typeof state === 'object' ? (state as Record<string, unknown>).__epxCaptureSession : undefined;
      const eventKey = `${location.href}\u0000${String(taggedSession)}`;
      if (eventKey === lastRouteEventKey.current) return;
      lastRouteEventKey.current = eventKey;
      if (captureAttempted.current && typeof taggedSession === 'number' && taggedSession !== captureSessionRef.current) {
        // Back/Forward can reach an entry from the previous capture. Replace its
        // stale capture-specific route before that state is applied to this one.
        replaceRoute('#/overview', captureSessionRef.current);
        return;
      }
      if (captureAttempted.current && taggedSession !== captureSessionRef.current) setHistoryCaptureSession(captureSessionRef.current);
      setRoute(parseHash());
    };
    window.addEventListener('hashchange', on);
    window.addEventListener('popstate', on);
    return () => {
      window.removeEventListener('hashchange', on);
      window.removeEventListener('popstate', on);
    };
  }, [replaceRoute, setHistoryCaptureSession]);
  useEffect(() => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('epx-theme', theme); } catch { /* storage unavailable */ }
  }, [theme]);
  useEffect(() => () => engine.close(), [engine]);

  const openFile = useCallback((file: File, keyLog?: File | null) => {
    currentFileRef.current = file;
    pendingKeysRef.current = keyLog ?? null;
    setActiveKeyLog(null);
    setReturnOperation(null);
    snapshotRef.current = null;
    captureAttempted.current = true;
    const session = resetViewState();
    // A first open has no investigation yet. Leaving the previous hash in place
    // would apply someone else's view, conversation, and filters to this file.
    replaceRoute('#/overview', session);
    setDrawers([]);
    engine.open(file, keyLog);
  }, [engine, replaceRoute, resetViewState]);
  const retryFailedOpen = useCallback(() => {
    const file = currentFileRef.current;
    if (!file) return;
    openFile(file, pendingKeysRef.current);
  }, [openFile]);

  const saveSnapshot = useCallback(() => {
    snapshotRef.current = { hash: location.hash, drawers, scroll: window.scrollY, workspaceScroll: document.querySelector('.content')?.scrollTop ?? 0, tables: Array.from(document.querySelectorAll('.dt-scroll')).map((element) => ({ label: element.getAttribute('aria-label'), top: element.scrollTop })) };
  }, [drawers]);
  const enterCompare = useCallback((seed: AnalysisModel | null) => {
    if (seed) saveSnapshot();
    else { currentFileRef.current = null; pendingKeysRef.current = null; setActiveKeyLog(null); snapshotRef.current = null; }
    engine.close();
    setState({ kind: 'idle' });
    setDrawers([]);
    setCompareSeed(seed);
    setCompareMode(true);
  }, [engine, saveSnapshot]);
  const reanalyze = useCallback((keys: File | null, operation: 'restore' | 'keys') => {
    const file = currentFileRef.current;
    if (!file) return;
    pendingKeysRef.current = keys;
    setReturnOperation(operation);
    setDrawers([]);
    engine.open(file, keys);
  }, [engine]);
  const leaveCompare = useCallback(() => {
    setCompareMode(false);
    setCompareSeed(null);
    if (currentFileRef.current) reanalyze(activeKeyLog, 'restore');
  }, [activeKeyLog, reanalyze]);
  const clearCompareSeed = useCallback(() => setCompareSeed(null), []);
  const openDrawer = useCallback((spec: DrawerSpec, mode: 'replace' | 'nest' = 'replace') => {
    setDrawers((stack) => (mode === 'nest' ? [...stack, spec] : [spec]));
  }, []);
  const closeDrawer = useCallback(() => setDrawers((stack) => stack.slice(0, -1)), []);
  const closeAllDrawers = useCallback(() => setDrawers([]), []);
  const closeCapture = useCallback(() => {
    currentFileRef.current = null;
    pendingKeysRef.current = null;
    setActiveKeyLog(null);
    setReturnOperation(null);
    snapshotRef.current = null;
    captureAttempted.current = true;
    const session = resetViewState();
    replaceRoute('#/overview', session);
    engine.cancel();
    setDrawers([]);
  }, [engine, replaceRoute, resetViewState]);
  useEffect(() => {
    if (state.kind !== 'ready') return;
    setActiveKeyLog(pendingKeysRef.current);
    if (!returnOperation) return;
    const snapshot = snapshotRef.current;
    if (snapshot) {
      replaceRoute(snapshot.hash, captureSessionRef.current);
      setDrawers(snapshot.drawers);
      const restorePageScroll = () => {
        window.scrollTo(0, snapshot.scroll);
        const main = document.querySelector('.content');
        if (main) main.scrollTop = snapshot.workspaceScroll;
      };
      // Packet counts and virtual height arrive after the ready model. Consume
      // this once in Packets when its content can accept the saved page offset.
      if (/^#\/?packets(?:\?|$)/.test(snapshot.hash)) viewState.set('workspace.pendingPageScroll', { hash: snapshot.hash, restore: restorePageScroll });
      requestAnimationFrame(() => {
        restorePageScroll();
        for (const table of document.querySelectorAll('.dt-scroll')) {
          // The packet list restores its own offset once its virtual rows are
          // laid out; writing here would clamp against its empty body and the
          // clamping scroll event would overwrite the saved offset.
          if (table.getAttribute('aria-label') === 'Packets') continue;
          const saved = snapshot.tables.find((entry) => entry.label === table.getAttribute('aria-label'));
          if (saved) table.scrollTop = saved.top;
        }
      });
    }
    setReturnOperation(null);
  }, [state, returnOperation, replaceRoute, viewState]);

  const patchRouteParams = useCallback((updates: Record<string, string | null>) => {
    const current = parseHash();
    for (const [key, value] of Object.entries(updates)) {
      if (value === null) current.params.delete(key);
      else current.params.set(key, value);
    }
    const q = current.params.toString();
    location.hash = `#/${current.view}${q ? `?${q}` : ''}`;
  }, []);

  const go = useCallback((view: string, params?: Record<string, string>) => {
    const current = parseHash().params;
    const next = new URLSearchParams();
    for (const key of ['t0', 't1', 'hf']) {
      const value = current.get(key);
      if (value !== null) next.set(key, value);
    }
    for (const [key, value] of Object.entries(params ?? {})) next.set(key, value);
    if (view === 'packets' && !Object.prototype.hasOwnProperty.call(params ?? {}, 'filter')) {
      const savedFilter = viewStateRef.current.get('packets.filter.applied');
      if (typeof savedFilter === 'string') {
        next.set('filter', savedFilter);
        viewStateRef.current.set('packets.filter.routeRestore', savedFilter);
      }
    }
    const q = next.toString();
    location.hash = `#/${view}${q ? `?${q}` : ''}`;
  }, []);

  const model = state.kind === 'ready' ? state.model : null;
  return (
    <>
      {compareMode ? (
        <ComparePage seed={compareSeed} onClearSeed={clearCompareSeed} onClose={leaveCompare} theme={theme} setTheme={setTheme} />
      ) : model ? (
        <Workspace key={captureSession} model={model} engine={engine} view={route.view} params={route.params} go={go} openDrawer={openDrawer} closeTopDrawer={closeDrawer} closeAllDrawers={closeAllDrawers}
          patchRouteParams={patchRouteParams}
          onOpen={openFile} onClose={closeCapture} onCompare={() => enterCompare(model)} theme={theme} setTheme={setTheme} drawers={drawers}
          viewState={viewState} captureSession={captureSession} activeKeyLog={activeKeyLog}
          onApplyKeys={(keys) => { saveSnapshot(); reanalyze(keys, 'keys'); }} onRemoveKeys={() => { saveSnapshot(); reanalyze(null, 'keys'); }} />
      ) : returnOperation ? (
        <main className="landing"><section className="landing-card" aria-live="polite">
          <h1>{returnOperation === 'restore' ? 'Restoring your investigation' : 'Updating TLS decryption'}</h1>
          {state.kind === 'working' && <AnalysisProgress key={state.startedAt} working={state} />}
          {state.kind === 'error' && <><p className="note crit" role="alert">{state.message}</p><button className="btn primary" onClick={() => reanalyze(pendingKeysRef.current, returnOperation)}>Retry</button></>}
          <button className="btn" onClick={() => reanalyze(activeKeyLog, 'restore')}>Return to previous analysis</button>
          <button className="btn" onClick={closeCapture}>Return to start</button>
        </section></main>
      ) : (
        <Landing state={state} onOpen={openFile} onCancel={closeCapture} onCompare={() => enterCompare(null)} onRetry={state.kind === 'error' && currentFileRef.current ? retryFailedOpen : undefined} theme={theme} setTheme={setTheme} />
      )}
      <UpdateBanner captureOpen={state.kind !== 'idle' && state.kind !== 'error'} />
    </>
  );
}

// Small fixtures are inlined as data URLs. Fetching those is blocked by
// connect-src 'self', so decode them in the page. A same-origin file URL is
// fetched only when the bundler emits a separate asset.
async function bundledSample(url: string): Promise<Blob> {
  if (!url.startsWith('data:')) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`The sample capture could not be loaded (${response.status}).`);
    return response.blob();
  }
  const comma = url.indexOf(',');
  if (comma < 0) throw new Error('The sample capture is not bundled with this page.');
  const meta = url.slice(5, comma);
  const payload = url.slice(comma + 1);
  const bytes = meta.includes('base64')
    ? Uint8Array.from(atob(payload), (char) => char.charCodeAt(0))
    : new TextEncoder().encode(decodeURIComponent(payload));
  return new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
}

function ShieldIcon() {
  return <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1 2.5 3v4.3c0 3.4 2.3 6.4 5.5 7.7 3.2-1.3 5.5-4.3 5.5-7.7V3L8 1Zm-1 9.7L4.6 8.3l1.1-1.1L7 8.5l3.3-3.3 1.1 1.1L7 10.7Z" /></svg>;
}

function Landing({ state, onOpen, onCancel, onCompare, onRetry, theme, setTheme }: { state: EngineState; onOpen: (f: File, keyLog?: File | null) => void; onCancel: () => void; onCompare: () => void; onRetry?: () => void; theme: Theme; setTheme: (t: Theme) => void }) {
  const [over, setOver] = useState(false);
  const [keyLog, setKeyLog] = useState<File | null>(null);
  const [dropError, setDropError] = useState<string | null>(null);
  const [sampleError, setSampleError] = useState<string | null>(null);
  const [sampleBusy, setSampleBusy] = useState(false);
  const dragLeaveTimer = useRef<number | null>(null);
  const working = state.kind === 'working' ? state : null;
  const clearDragLeaveTimer = () => {
    if (dragLeaveTimer.current !== null) {
      window.clearTimeout(dragLeaveTimer.current);
      dragLeaveTimer.current = null;
    }
  };
  const showDropHighlight = () => {
    clearDragLeaveTimer();
    setOver(true);
  };
  const hideDropHighlight = () => {
    clearDragLeaveTimer();
    setOver(false);
  };
  useEffect(() => {
    const endDrag = () => hideDropHighlight();
    window.addEventListener('dragend', endDrag);
    return () => {
      window.removeEventListener('dragend', endDrag);
      clearDragLeaveTimer();
    };
  }, []);
  const openSample = async () => {
    setSampleError(null);
    setSampleBusy(true);
    try {
      const blob = await bundledSample(sampleCaptureUrl);
      onOpen(new File([blob], 'synthetic-sample.pcap', { type: 'application/vnd.tcpdump.pcap' }), null);
    } catch (error) {
      setSampleError(error instanceof Error ? error.message : String(error));
    } finally {
      setSampleBusy(false);
    }
  };
  return (
    <main className="landing"
      onDragOver={(e) => { e.preventDefault(); showDropHighlight(); }}
      onDragLeave={(e) => {
        const action = landingDragLeaveAction(probeFromDragLeave(e.currentTarget, e));
        if (action === 'keep') return;
        if (action === 'clear') { hideDropHighlight(); return; }
        clearDragLeaveTimer();
        dragLeaveTimer.current = window.setTimeout(() => {
          dragLeaveTimer.current = null;
          setOver(false);
        }, 0);
      }}
      onDrop={(e) => {
        e.preventDefault();
        hideDropHighlight();
        if (working) return;
        const file = e.dataTransfer.files?.[0];
        if (!file) { setDropError('Drop a capture file to open it.'); return; }
        setDropError(null);
        onOpen(file, keyLog);
        setKeyLog(null);
      }}>
      <div className="landing-card">
        <header className="landing-header">
          <div className="landing-brand">
            <span className="landing-brand-mark" aria-hidden="true">EP</span>
            <div>
              <div className="brand-name">Estudely Packet Explorer</div>
              <div className="muted">Protocol dashboards for packet captures</div>
            </div>
          </div>
          <ThemeButton theme={theme} setTheme={setTheme} />
        </header>
        <div className="landing-hero">
          <div className="landing-copy">
            <p className="landing-kicker"><span aria-hidden="true" />BROWSER-BASED PACKET ANALYSIS</p>
            <h1>Make sense of every packet.</h1>
            <p className="landing-lede">Explore protocols, hosts, conversations and timelines in clear dashboards, powered by Wireshark and running right here in your browser.</p>
          </div>
          <div className="landing-action-column">
            {working ? (
              <section className="drop landing-drop landing-processing" aria-live="polite">
                <p className="landing-kicker">ANALYZING CAPTURE</p>
                <h2 style={{ overflowWrap: 'anywhere' }}>{working.fileName}</h2>
                <AnalysisProgress key={working.startedAt} working={working} />
                <button className="btn" onClick={onCancel}>Cancel</button>
              </section>
            ) : (
              <section className={`drop landing-drop${over ? ' over' : ''}`}>
                <div className="landing-file-icon" aria-hidden="true">
                  <svg viewBox="0 0 32 32" fill="none">
                    <path d="M8 3.75h10l7 7V26a2.25 2.25 0 0 1-2.25 2.25h-14A2.25 2.25 0 0 1 6.5 26V6A2.25 2.25 0 0 1 8.75 3.75Z" />
                    <path d="M18 4v7h7M16 23v-7m-3 3 3-3 3 3" />
                  </svg>
                </div>
                <div>
                  <h2>Open a packet capture</h2>
                  <p className="ink2">Choose a .pcap or .pcapng file, or drop it here.</p>
                </div>
                <FileChoice label="Choose capture file" file={null} primary showStatus={false} accept={CAPTURE_ACCEPT} onChange={(file) => { if (file) { onOpen(file, keyLog); setKeyLog(null); } }} />
                <p className="local-note landing-local-note"><ShieldIcon />{LOCAL_NOTICE}</p>
                <details className="landing-advanced">
                  <summary>Advanced: TLS key log</summary>
                  <FileChoice label="Choose TLS key log (optional)" file={keyLog} accept=".txt,text/plain" onChange={setKeyLog} />
                  <p className="muted">Key logs contain session secrets. They are read locally and held only while this capture is open.</p>
                </details>
                <div className="landing-secondary">
                  <button className="btn" onClick={onCompare}>Compare two captures</button>
                  <button className="btn" onClick={() => void openSample()} disabled={sampleBusy}>{sampleBusy ? 'Loading sample…' : 'Try a sample capture'}</button>
                </div>
                <p className="muted landing-sample-note">The sample is synthetic DNS traffic bundled with this page. It is practice data, not a capture from a real network, and it is not a security finding.</p>
                {dropError && <p className="note crit" role="alert">{dropError}</p>}
                {sampleError && <p className="note crit" role="alert">{sampleError}</p>}
              </section>
            )}
            {state.kind === 'error' && (
              <>
                <div className="note crit" role="alert">
                  <div><b>{state.fileName ? `Could not analyse ${state.fileName}.` : 'Something went wrong.'}</b> {state.message}</div>
                </div>
                {onRetry && <button className="btn primary" type="button" onClick={onRetry}>Retry</button>}
              </>
            )}
            {working && working.fileSize > SOFT_LIMIT_BYTES && (
              <div className="note warn">{working.fileSize > HARD_LIMIT_BYTES
                ? <>Large capture: analysis is capped at the first {bytes(HARD_LIMIT_BYTES)} of capture data. If the cap is reached, results are marked partial.</>
                : <>Large capture: analysis takes roughly a minute per 400,000 packets and needs several times the file size in memory. You can cancel at any time.</>}</div>
            )}
          </div>
        </div>
        <section className="landing-details" aria-label="Capture support">
          <article className="landing-detail">
            <span className="landing-detail-label">FORMATS</span>
            <h3>Bring your capture</h3>
            <p>pcap and pcapng, including multiple interfaces, plus Wireshark 4.4 formats such as gzip-compressed pcap, snoop and ERF.</p>
          </article>
          <article className="landing-detail">
            <span className="landing-detail-label">CAPACITY</span>
            <h3>Large captures still open</h3>
            <p>The first {bytes(HARD_LIMIT_BYTES)} of capture data is analyzed; if there is more, results are marked partial. Tested up to 350 MB (decimal) and 400,000 packets; expect slower analysis above {bytes(SOFT_LIMIT_BYTES)}.</p>
          </article>
          <article className="landing-detail landing-detail-offline">
            <span className="landing-detail-label">AVAILABILITY</span>
            <OfflineStatus />
          </article>
        </section>
        <footer className="landing-footer">
          <BuildTag className="corner" />
        </footer>
      </div>
    </main>
  );
}

function Workspace(props: {
  model: AnalysisModel; engine: EngineClient; view: View; params: URLSearchParams; go: AppCtx['go']; patchRouteParams: (p: Record<string, string | null>) => void; openDrawer: AppCtx['openDrawer']; closeTopDrawer: () => void; closeAllDrawers: () => void;
  onOpen: (f: File, keyLog?: File | null) => void; onClose: () => void; onCompare: () => void; theme: Theme; setTheme: (t: Theme) => void; drawers: DrawerSpec[];
  viewState: ViewStateStore; captureSession: number;
  activeKeyLog: File | null; onApplyKeys: (keys: File) => void; onRemoveKeys: () => void;
}) {
  const { model: sourceModel, view } = props;
  const c = sourceModel.capture;
  const filter: SharedFilter = useMemo(() => {
    const origin = sourceModel.timeline.origin;
    const limit = origin + c.duration;
    const rawStart = props.params.get('t0'), rawEnd = props.params.get('t1');
    let start: number | null = null, end: number | null = null;
    if (rawStart !== null && rawEnd !== null && Number.isFinite(Number(rawStart)) && Number.isFinite(Number(rawEnd))) {
      const a = Math.max(origin, Math.min(limit, Number(rawStart)));
      const b = Math.max(origin, Math.min(limit, Number(rawEnd)));
      if (a < b && (a > origin || b < limit)) { start = a; end = b; }
    }
    const host = props.params.get('hf');
    return { start, end, host: host && sourceModel.hosts.some((h) => h.addr === host) ? host : null };
  }, [props.params, sourceModel, c.duration]);
  const { model, stats } = useMemo(() => applySharedFilter(sourceModel, filter), [sourceModel, filter]);
  const setHostFilter = useCallback((host: string | null) => props.patchRouteParams({ hf: host }), [props.patchRouteParams]);
  const setTimeRange = useCallback((start: number, end: number) => {
    const min = sourceModel.timeline.origin, max = min + c.duration;
    const a = Math.max(min, Math.min(max, start)), b = Math.max(min, Math.min(max, end));
    if (a >= b || (a <= min && b >= max)) props.patchRouteParams({ t0: null, t1: null });
    else props.patchRouteParams({ t0: String(a), t1: String(b) });
  }, [sourceModel.timeline.origin, c.duration, props.patchRouteParams]);
  const clearTimeRange = useCallback(() => props.patchRouteParams({ t0: null, t1: null }), [props.patchRouteParams]);
  const clearFilters = useCallback(() => props.patchRouteParams({ t0: null, t1: null, hf: null }), [props.patchRouteParams]);
  const names = useMemo(() => {
    const m = new Map<string, string>();
    for (const h of sourceModel.hosts) {
      const best = h.names.find((n) => n.kind === 'observed') ?? h.names[0];
      if (best) m.set(h.addr, best.name);
    }
    return m;
  }, [sourceModel.hosts]);
  const ctx: AppCtx = useMemo(() => ({
    model, sourceModel, engine: props.engine, openDrawer: props.openDrawer, closeDrawer: props.closeTopDrawer, go: props.go, patchRouteParams: props.patchRouteParams, params: props.params, nameOf: (a: string) => names.get(a) ?? null,
    filter, stats, setHostFilter, setTimeRange, clearTimeRange, clearFilters,
  }), [model, sourceModel, props.engine, props.openDrawer, props.closeTopDrawer, props.go, props.patchRouteParams, props.params, names, filter, stats, setHostFilter, setTimeRange, clearTimeRange, clearFilters]);

  useEffect(() => { document.title = `${c.fileName} — Estudely Packet Explorer`; return () => { document.title = 'Estudely Packet Explorer'; }; }, [c.fileName]);
  const seenView = useRef(view);
  useEffect(() => {
    if (seenView.current === view) return;
    seenView.current = view;
    props.closeAllDrawers();
  }, [view, props.closeAllDrawers]);
  useEffect(() => { document.querySelector('.main')?.scrollTo?.(0, 0); window.scrollTo(0, 0); }, [view]);

  const nav: { id: View; label: string; count?: number; total?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'dns', label: 'DNS', count: model.dns.length, total: sourceModel.dns.length },
    { id: 'http', label: 'HTTP', count: model.http.length, total: sourceModel.http.length },
    { id: 'files', label: 'Files' },
    { id: 'tls', label: 'TLS', count: model.tls.length, total: sourceModel.tls.length },
    { id: 'quic', label: 'QUIC', count: model.quic.length, total: sourceModel.quic.length },
    { id: 'ssh', label: 'SSH', count: model.ssh.length, total: sourceModel.ssh.length },
    { id: 'dhcp', label: 'DHCP', count: model.dhcp.length, total: sourceModel.dhcp.length },
    { id: 'arp', label: 'ARP', count: model.arp.length, total: sourceModel.arp.length },
    { id: 'icmp', label: 'ICMP', count: model.icmp.length, total: sourceModel.icmp.length },
    { id: 'hosts', label: 'Hosts', count: model.hosts.length, total: sourceModel.hosts.length },
    { id: 'connections', label: 'Connections', count: model.conversations.length, total: sourceModel.conversations.length },
    { id: 'network', label: 'Network' },
  ];
  let body: ReactNode;
  switch (view) {
    case 'dns': body = <Dns />; break;
    case 'http': body = <Http />; break;
    case 'files': body = <Files />; break;
    case 'tls': body = <Tls />; break;
    case 'hosts': body = <Hosts />; break;
    case 'connections': body = <Connections />; break;
    case 'network': body = <Network />; break;
    case 'packets': body = <Packets captureSession={props.captureSession} />; break;
    case 'dhcp': body = <Dhcp />; break;
    case 'arp': body = <Arp />; break;
    case 'icmp': body = <Icmp />; break;
    case 'ssh': body = <Ssh />; break;
    case 'quic': body = <Quic />; break;
    default: body = <Overview />;
  }
  return (
    <ViewStateCtx.Provider value={props.viewState}>
    <Ctx.Provider value={ctx}>
      <div className="shell">
        <WorkspaceNavigation items={[...nav, { id: 'packets', label: 'Packet list', count: stats.packets, total: c.packetCount }]}
          current={view} onNavigate={props.go} wireshark={c.engine.wireshark} localNotice={LOCAL_NOTICE} />
        <div className="main workspace-main">
          <CaptureToolbar fileName={c.fileName} theme={props.theme} setTheme={props.setTheme}
            onOpen={(file) => props.onOpen(file, null)} onClose={props.onClose} onCompare={props.onCompare}
            facts={<>
                  <span><b>{num(stats.packets)}</b>{stats.packets !== c.packetCount ? ` / ${num(c.packetCount)}` : ''} packets</span>
                  <span><b>{duration(filter.start !== null && filter.end !== null ? filter.end - filter.start : stats.end !== null && stats.start !== null ? Math.max(0, stats.end - stats.start) : c.duration)}</b>{filter.start !== null || filter.host ? ' selected' : ''}</span>
                  <span><b>{bytes(stats.wireBytes)}</b> on wire{stats.wireBytes !== c.wireBytes ? ` / ${bytes(c.wireBytes)}` : ''}</span>
                  <span><b>{num(model.hosts.length)}</b>{stats.allHosts !== model.hosts.length ? ` / ${num(stats.allHosts)}` : ''} hosts</span>
                  {c.partial && <span className="tag warn">partial analysis</span>}
                  {c.incomplete && <span className="tag bad">incomplete file</span>}
            </>}
            exports={<JsonExport model={sourceModel} selectionAvailable={filter.start !== null || !!filter.host}
              selectionDescription={`${num(stats.packets)} of ${num(c.packetCount)} packets${filter.start !== null && filter.end !== null ? ` · time ${rangeLabel(filter.start, filter.end)}` : ''}${filter.host ? ` · host ${filter.host}` : ''}`}
              onWholeHtml={() => downloadBlob(`${safeBase(c.fileName)}-report.html`, new Blob([htmlReport(sourceModel)], { type: 'text/html;charset=utf-8' }))}
              onSelectionHtml={() => downloadBlob(`${safeBase(c.fileName)}-filtered-report.html`, new Blob([htmlReport(model, { filter, stats })], { type: 'text/html;charset=utf-8' }))} />}
            keys={<TlsKeyControls activeKeyLog={props.activeKeyLog} model={sourceModel} onApplyKeys={props.onApplyKeys} onRemoveKeys={props.onRemoveKeys} />}
            timeline={<Strip timeline={sourceModel.timeline} timestampDigits={c.timestampDigits} selection={filter.start !== null && filter.end !== null ? { start: filter.start, end: filter.end } : null} onRangeChange={setTimeRange} />}
            filters={(filter.start !== null || filter.host) && <div className="filter-chips" aria-label="Shared filters">
              {filter.start !== null && filter.end !== null && <button className="filter-chip" onClick={clearTimeRange} aria-label="Remove time range filter">Time {rangeLabel(filter.start, filter.end)} <span aria-hidden="true">×</span></button>}
              {filter.host && <button className="filter-chip" onClick={() => setHostFilter(null)} aria-label={`Remove host filter for ${filter.host}`}>Host {filter.host} <span aria-hidden="true">×</span></button>}
              <button className="btn ghost small" onClick={clearFilters}>Clear filters</button>
            </div>} />
          <main className="content" id="content">
            {(view === 'overview' || view === 'http' || view === 'tls') && model.tls.length > 0 && <TlsStatusBanner sessions={model.tls} />}
            {c.partial && <div className="note warn" role="status" style={{ marginBottom: 14 }}>
              <b>Partial analysis.</b> Only the first {bytes(c.analyzedBytes)} of capture data was analyzed. Packets after this prefix are omitted from every view and export.
            </div>}
            {(filter.start !== null || filter.host) && <div className="note info" role="status">
              Shared filter: {num(stats.packets)} of {num(c.packetCount)} packets, {num(model.dns.length)} of {num(sourceModel.dns.length)} DNS records, {num(model.http.length)} of {num(sourceModel.http.length)} HTTP records, {num(model.tls.length)} of {num(sourceModel.tls.length)} TLS sessions, {num(model.hosts.length)} of {num(sourceModel.hosts.length)} hosts, and {num(model.conversations.length)} of {num(sourceModel.conversations.length)} conversations. A correlated exchange appears when any source packet meets the filter; its details can include packets outside the time window.
            </div>}
            <Suspense fallback={<div className="muted">Loading view…</div>}>{body}</Suspense>
            <BuildTag className="mobile-only" />
          </main>
        </div>
      </div>
      {props.drawers.map((spec, index) => (
        <Drawer key={index} spec={spec} active={index === props.drawers.length - 1} onClose={props.closeTopDrawer} />
      ))}
    </Ctx.Provider>
    </ViewStateCtx.Provider>
  );
}

function rangeLabel(start: number, end: number): string {
  const fmt = (v: number) => `${+v.toFixed(3)} s`;
  return `${fmt(start)}–${fmt(end)}`;
}

function TlsStatusBanner({ sessions }: { sessions: AnalysisModel['tls'] }) {
  const decrypted = sessions.filter((s) => s.decryptionStatus === 'decrypted').length;
  const encrypted = sessions.filter((s) => s.decryptionStatus === 'encrypted').length;
  const noData = sessions.length - decrypted - encrypted;
  const parts = [`${num(decrypted)} of ${num(sessions.length)} sessions decrypted`];
  if (encrypted > 0) parts.push(`${num(encrypted)} with application data remain encrypted`);
  if (noData > 0) parts.push(`${num(noData)} had no application data to assess`);
  return (
    <div className="note info" role="status" style={{ marginBottom: 14 }}>
      <b>TLS decryption:</b> {parts.join('; ')}.
    </div>
  );
}
