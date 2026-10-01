// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { AnalysisModel } from '../engine/types';
import { BuildTag } from './components/BuildTag';
import { Strip } from './components/charts';
import { Drawer } from './components/Drawer';
import { Ctx, type AppCtx, type DrawerSpec } from './context';
import { downloadBlob, safeBase, summaryJson } from './download';
import { EngineClient, HARD_LIMIT_BYTES, SOFT_LIMIT_BYTES, type EngineState } from './engine';
import { bytes, duration, num } from './format';
import { Overview } from './views/Overview';
import { Dns } from './views/Dns';

const Http = lazy(() => import('./views/Http').then((m) => ({ default: m.Http })));
const Tls = lazy(() => import('./views/Tls').then((m) => ({ default: m.Tls })));
const Hosts = lazy(() => import('./views/Hosts').then((m) => ({ default: m.Hosts })));
const Connections = lazy(() => import('./views/Connections').then((m) => ({ default: m.Connections })));
const Network = lazy(() => import('./views/Network').then((m) => ({ default: m.Network })));
const Packets = lazy(() => import('./views/Packets').then((m) => ({ default: m.Packets })));

export const LOCAL_NOTICE = 'Your capture is processed locally in your browser.';

const VIEWS = ['overview', 'dns', 'http', 'tls', 'hosts', 'connections', 'network', 'packets'] as const;
type View = (typeof VIEWS)[number];

function parseHash(): { view: View; params: URLSearchParams } {
  const h = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = h.split('?');
  const view = (VIEWS as readonly string[]).includes(path) ? (path as View) : 'overview';
  return { view, params: new URLSearchParams(query) };
}

type Theme = 'system' | 'light' | 'dark';
function loadTheme(): Theme {
  try { return (localStorage.getItem('epx-theme') as Theme) || 'system'; } catch { return 'system'; }
}

export function App() {
  const [state, setState] = useState<EngineState>({ kind: 'idle' });
  const engineRef = useRef<EngineClient | null>(null);
  if (!engineRef.current) engineRef.current = new EngineClient(setState);
  const engine = engineRef.current;
  const [route, setRoute] = useState(parseHash);
  const [drawer, setDrawer] = useState<DrawerSpec | null>(null);
  const [theme, setTheme] = useState<Theme>(loadTheme);

  useEffect(() => {
    const on = () => setRoute(parseHash());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  useEffect(() => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('epx-theme', theme); } catch { /* storage unavailable */ }
  }, [theme]);
  useEffect(() => () => engine.close(), [engine]);

  const openFile = useCallback((file: File) => {
    if (file.size > HARD_LIMIT_BYTES) {
      setState({ kind: 'error', fileName: file.name, message: `This file is ${bytes(file.size)}. The limit is ${bytes(HARD_LIMIT_BYTES)}: the WebAssembly engine has a 2 GiB memory ceiling and needs room for decoding state. Split the capture (for example with editcap -c) and open the parts.` });
      return;
    }
    setDrawer(null);
    engine.open(file);
  }, [engine]);

  const go = useCallback((view: string, params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : '';
    location.hash = `#/${view}${q}`;
  }, []);

  const model = state.kind === 'ready' ? state.model : null;
  return (
    <>
      {model ? (
        <Workspace model={model} engine={engine} view={route.view} params={route.params} go={go} openDrawer={setDrawer}
          onOpen={openFile} onClose={() => { engine.cancel(); setDrawer(null); }} theme={theme} setTheme={setTheme} drawer={drawer} closeDrawer={() => setDrawer(null)} />
      ) : (
        <Landing state={state} onOpen={openFile} onCancel={() => engine.cancel()} theme={theme} setTheme={setTheme} />
      )}
    </>
  );
}

function ThemeButton({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  const next: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };
  return (
    <button className="btn" onClick={() => setTheme(next[theme])} title="Switch colour theme" aria-label={`Colour theme: ${theme}. Switch to ${next[theme]}`}>
      Theme: {theme}
    </button>
  );
}

function OpenButton({ onOpen, primary, label = 'Open capture' }: { onOpen: (f: File) => void; primary?: boolean; label?: string }) {
  const ref = useRef<HTMLInputElement>(null);
  return (
    <>
      <button className={`btn${primary ? ' primary' : ''}`} onClick={() => ref.current?.click()}>{label}</button>
      <input ref={ref} type="file" hidden accept=".pcap,.pcapng,.cap,.pcap.gz,.pcapng.gz,.ntar,.dmp,.erf,.snoop,application/vnd.tcpdump.pcap"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onOpen(f); e.target.value = ''; }} />
    </>
  );
}

function ShieldIcon() {
  return <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1 2.5 3v4.3c0 3.4 2.3 6.4 5.5 7.7 3.2-1.3 5.5-4.3 5.5-7.7V3L8 1Zm-1 9.7L4.6 8.3l1.1-1.1L7 8.5l3.3-3.3 1.1 1.1L7 10.7Z" /></svg>;
}

const PHASES: { phase: string; label: string }[] = [
  { phase: 'engine', label: 'Load the Wireshark engine (first time only)' },
  { phase: 'read', label: 'Read the file from your device' },
  { phase: 'load', label: 'Index packets' },
  { phase: 'extract', label: 'Decode every packet' },
  { phase: 'parse', label: 'Read decoded fields' },
  { phase: 'analyze', label: 'Build summaries' },
];

function Landing({ state, onOpen, onCancel, theme, setTheme }: { state: EngineState; onOpen: (f: File) => void; onCancel: () => void; theme: Theme; setTheme: (t: Theme) => void }) {
  const [over, setOver] = useState(false);
  const [now, setNow] = useState(performance.now());
  useEffect(() => {
    if (state.kind !== 'working') return;
    const t = setInterval(() => setNow(performance.now()), 500);
    return () => clearInterval(t);
  }, [state.kind]);
  const working = state.kind === 'working' ? state : null;
  const phaseIdx = working ? PHASES.findIndex((p) => p.phase === working.progress.phase) : -1;
  return (
    <main className="landing"
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files?.[0]; if (f && !working) onOpen(f); }}>
      <div className="landing-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div className="brand-name" style={{ fontSize: 18 }}>Estudely Packet Explorer</div>
            <div className="muted">Protocol dashboards for packet captures</div>
          </div>
          <ThemeButton theme={theme} setTheme={setTheme} />
        </div>
        {working ? (
          <section className="drop" aria-live="polite">
            <h2 style={{ overflowWrap: 'anywhere' }}>{working.fileName}</h2>
            <p className="muted">{bytes(working.fileSize)}, {duration((now - working.startedAt) / 1000)} elapsed</p>
            <div className={`progress${working.progress.fraction === null ? ' indeterminate' : ''}`} role="progressbar"
              aria-valuemin={0} aria-valuemax={100} aria-valuenow={working.progress.fraction === null ? undefined : Math.round(working.progress.fraction * 100)} aria-label="Analysis progress">
              <div style={{ width: working.progress.fraction === null ? undefined : `${Math.round(working.progress.fraction * 100)}%` }} />
            </div>
            <p>{working.progress.message}</p>
            <div className="steps"><ol>
              {PHASES.map((p, i) => (
                <li key={p.phase} data-state={i < phaseIdx ? 'done' : i === phaseIdx ? 'active' : 'todo'}>
                  <span aria-hidden="true" style={{ width: 14 }}>{i < phaseIdx ? '✓' : i === phaseIdx ? '›' : ''}</span>{p.label}
                </li>
              ))}
            </ol></div>
            <button className="btn" onClick={onCancel}>Cancel</button>
          </section>
        ) : (
          <section className={`drop${over ? ' over' : ''}`}>
            <h2>Open a packet capture</h2>
            <p className="ink2" style={{ maxWidth: '52ch' }}>Choose a .pcap or .pcapng file, or drop it here. Wireshark's dissectors run inside this page, so the file is opened, not uploaded.</p>
            <OpenButton onOpen={onOpen} primary label="Choose capture file" />
            <p className="local-note" style={{ fontSize: 13 }}><ShieldIcon />{LOCAL_NOTICE}</p>
          </section>
        )}
        {state.kind === 'error' && (
          <div className="note crit" role="alert">
            <div><b>{state.fileName ? `Could not analyse ${state.fileName}.` : 'Something went wrong.'}</b> {state.message}</div>
          </div>
        )}
        {working && working.fileSize > SOFT_LIMIT_BYTES && (
          <div className="note warn">Large capture: analysis takes roughly a minute per 400,000 packets and needs several times the file size in memory. You can cancel at any time.</div>
        )}
        <div className="landing-list">
          <div><h3>Formats</h3>pcap and pcapng (including multiple interfaces), plus other formats Wireshark 4.4's file reader supports, such as gzip-compressed pcap, snoop and ERF.</div>
          <div><h3>Size</h3>Tested up to 350 MB and 400,000 packets. Files over {bytes(HARD_LIMIT_BYTES)} are refused; over {bytes(SOFT_LIMIT_BYTES)} expect slow analysis.</div>
          <div><h3>Privacy</h3>No uploads, analytics or lookups. The capture stays in this tab's memory until you close it or the tab.</div>
        </div>
      </div>
      <BuildTag className="corner" />
    </main>
  );
}

function Workspace(props: {
  model: AnalysisModel; engine: EngineClient; view: View; params: URLSearchParams; go: AppCtx['go']; openDrawer: (d: DrawerSpec) => void;
  onOpen: (f: File) => void; onClose: () => void; theme: Theme; setTheme: (t: Theme) => void; drawer: DrawerSpec | null; closeDrawer: () => void;
}) {
  const { model, view } = props;
  const c = model.capture;
  const names = useMemo(() => {
    const m = new Map<string, string>();
    for (const h of model.hosts) {
      const best = h.names.find((n) => n.kind === 'observed') ?? h.names[0];
      if (best) m.set(h.addr, best.name);
    }
    return m;
  }, [model.hosts]);
  const ctx: AppCtx = useMemo(() => ({
    model, engine: props.engine, openDrawer: props.openDrawer, go: props.go, params: props.params, nameOf: (a: string) => names.get(a) ?? null,
  }), [model, props.engine, props.openDrawer, props.go, props.params, names]);

  useEffect(() => { document.title = `${c.fileName} — Estudely Packet Explorer`; return () => { document.title = 'Estudely Packet Explorer'; }; }, [c.fileName]);
  useEffect(() => { document.querySelector('.main')?.scrollTo?.(0, 0); window.scrollTo(0, 0); }, [view]);

  const nav: { id: View; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'dns', label: 'DNS', count: model.dns.length },
    { id: 'http', label: 'HTTP', count: model.http.length },
    { id: 'tls', label: 'TLS', count: model.tls.length },
    { id: 'hosts', label: 'Hosts', count: model.hosts.length },
    { id: 'connections', label: 'Connections', count: model.conversations.length },
    { id: 'network', label: 'Network' },
  ];
  let body: ReactNode;
  switch (view) {
    case 'dns': body = <Dns key={props.params.toString()} />; break;
    case 'http': body = <Http />; break;
    case 'tls': body = <Tls />; break;
    case 'hosts': body = <Hosts key={props.params.toString()} />; break;
    case 'connections': body = <Connections key={props.params.toString()} />; break;
    case 'network': body = <Network />; break;
    case 'packets': body = <Packets key={props.params.toString()} />; break;
    default: body = <Overview />;
  }
  return (
    <Ctx.Provider value={ctx}>
      <div className="shell">
        <aside className="sidebar" aria-label="Views">
          <div className="brand">
            <div className="brand-name">Estudely Packet Explorer</div>
            <div className="brand-sub">Local capture analysis</div>
          </div>
          <nav className="nav">
            {nav.map((n) => (
              <a key={n.id} href={`#/${n.id}`} aria-current={view === n.id ? 'page' : undefined}>
                <span className="nav-mark" aria-hidden="true" />{n.label}
                {n.count !== undefined && <span className="nav-count">{num(n.count)}</span>}
              </a>
            ))}
            <div className="nav-sep" />
            <a href="#/packets" aria-current={view === 'packets' ? 'page' : undefined}><span className="nav-mark" aria-hidden="true" />Packet list<span className="nav-count">{num(c.packetCount)}</span></a>
          </nav>
          <div className="sidebar-foot">
            <p className="local-note"><ShieldIcon />{LOCAL_NOTICE}</p>
            <p>Decoded with Wireshark {c.engine.wireshark} via Wiregasm. <a href="./ABOUT.html" target="_blank" rel="noopener">Licences and limitations</a></p>
            <BuildTag />
          </div>
        </aside>
        <div className="main">
          <header className="topbar">
            <div className="topbar-row">
              <div className="cap-title">
                <h1>{c.fileName}</h1>
                <div className="cap-facts">
                  <span><b>{num(c.packetCount)}</b> packets</span>
                  <span><b>{duration(c.duration)}</b></span>
                  <span><b>{bytes(c.wireBytes)}</b> on wire</span>
                  <span><b>{num(model.hosts.length)}</b> hosts</span>
                  {c.incomplete && <span className="tag bad">incomplete file</span>}
                </div>
              </div>
              <div className="actions">
                <button className="btn" onClick={() => downloadBlob(`${safeBase(c.fileName)}-summary.json`, new Blob([summaryJson(model)], { type: 'application/json' }))}>Export JSON summary</button>
                <OpenButton onOpen={props.onOpen} label="Open another" />
                <button className="btn" onClick={props.onClose} title="Close this capture and free its memory">Close</button>
                <ThemeButton theme={props.theme} setTheme={props.setTheme} />
              </div>
            </div>
            <Strip timeline={model.timeline} />
            <p className="mobile-local local-note" style={{ fontSize: 12, padding: '4px 0 8px' }}><ShieldIcon />{LOCAL_NOTICE}</p>
          </header>
          <main className="content" id="content">
            <Suspense fallback={<div className="muted">Loading view…</div>}>{body}</Suspense>
            <BuildTag className="mobile-only" />
          </main>
        </div>
      </div>
      {props.drawer && <Drawer spec={props.drawer} onClose={props.closeDrawer} />}
    </Ctx.Provider>
  );
}
