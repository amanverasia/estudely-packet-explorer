import type { ReactNode } from 'react';
import { useApp } from '../context';

export function Panel({ title, sub, right, children, flush }: { title: ReactNode; sub?: ReactNode; right?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h3>{title}</h3>
        {sub && <span className="sub">{sub}</span>}
        {right && <div className="right">{right}</div>}
      </div>
      {flush ? <div style={{ marginTop: 12 }}>{children}</div> : <div className="panel-body">{children}</div>}
    </section>
  );
}

export function Fact({ label, value, small, title }: { label: string; value: ReactNode; small?: ReactNode; title?: string }) {
  return (
    <div className="fact" title={title}>
      <dt>{label}</dt>
      <dd>{value}{small && <small>{small}</small>}</dd>
    </div>
  );
}

const ICONS = {
  info: <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13Zm0 3a.9.9 0 1 1 0 1.8.9.9 0 0 1 0-1.8ZM7.2 7.5h1.6v4.2H7.2z" />,
  warn: <path d="M8 1.2 15.2 14H.8L8 1.2Zm-.8 4.6v4h1.6v-4H7.2Zm0 5.2v1.6h1.6V11H7.2Z" />,
  crit: <path d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM5.2 4.1 8 6.9l2.8-2.8 1.1 1.1L9.1 8l2.8 2.8-1.1 1.1L8 9.1l-2.8 2.8-1.1-1.1L6.9 8 4.1 5.2l1.1-1.1Z" />,
};

export function Note({ kind = 'info', children }: { kind?: 'info' | 'warn' | 'crit'; children: ReactNode }) {
  return (
    <div className={`note ${kind}`} role={kind === 'crit' ? 'alert' : 'note'}>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">{ICONS[kind]}</svg>
      <div>{children}</div>
    </div>
  );
}

/** Address with its best learned name as secondary text. */
export function Addr({ addr, port }: { addr: string; port?: number | null }) {
  const { nameOf } = useApp();
  const n = nameOf(addr);
  const shown = port === null || port === undefined ? addr : addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
  return (
    <span title={n ? `${addr} (${n}, learned from the capture)` : addr}>
      <span className="mono">{shown}</span>
      {n && <span className="muted" style={{ marginLeft: 6 }}>{n}</span>}
    </span>
  );
}

export function Unavailable({ why }: { why?: string }) {
  return <span className="muted" title={why}>unavailable</span>;
}

export function ViewHead({ title, children, right }: { title: string; children?: ReactNode; right?: ReactNode }) {
  return (
    <div className="view-head">
      <div style={{ flex: '1 1 380px' }}>
        <h2>{title}</h2>
        {children && <p>{children}</p>}
      </div>
      {right && <div className="actions">{right}</div>}
    </div>
  );
}

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} aria-pressed={o.value === value} onClick={() => onChange(o.value)}>{o.label}</button>
      ))}
    </div>
  );
}

export function FramesLink({ frames, onOpen }: { frames: number[]; onOpen: () => void }) {
  if (!frames.length) return null;
  return (
    <button className="btn small" onClick={(e) => { e.stopPropagation(); onOpen(); }} title={`Packets ${frames.slice(0, 12).join(', ')}${frames.length > 12 ? '…' : ''}`}>
      #{frames[0]}{frames.length > 1 ? ` +${frames.length - 1}` : ''}
    </button>
  );
}
