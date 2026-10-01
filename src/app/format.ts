// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Formatting helpers. Every function returns plain text; captured strings are
// always rendered by React as text nodes, never as HTML.

export const nf = new Intl.NumberFormat('en');

export function num(n: number | null | undefined): string {
  return n === null || n === undefined ? '—' : nf.format(n);
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0)} ${units[i]}`;
}

export function duration(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s)) return '—';
  const a = Math.abs(s);
  if (a === 0) return '0 s';
  if (a < 1e-6) return `${(s * 1e9).toFixed(0)} ns`;
  if (a < 1e-3) return `${(s * 1e6).toFixed(a < 1e-5 ? 2 : 0)} µs`;
  if (a < 1) return `${(s * 1e3).toFixed(a < 0.01 ? 2 : 1)} ms`;
  if (a < 60) return `${s.toFixed(a < 10 ? 3 : 1)} s`;
  if (a < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  if (a < 86400) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  return `${Math.floor(s / 86400)} d ${Math.round((s % 86400) / 3600)} h`;
}

/** Relative seconds with a fixed number of decimals (capture precision, max 9). */
export function rel(t: number | null | undefined, digits = 6): string {
  if (t === null || t === undefined) return '—';
  return t.toFixed(Math.min(9, Math.max(0, digits)));
}

export function pct(part: number, whole: number): string {
  if (!whole) return '0%';
  const p = (part / whole) * 100;
  return p < 0.1 && p > 0 ? '<0.1%' : `${p < 10 ? p.toFixed(1) : p.toFixed(0)}%`;
}

/**
 * Absolute UTC time for a relative offset, computed from the exact epoch
 * string of the first packet so sub-microsecond digits are not invented.
 */
export function absTime(startEpoch: string | null, t: number | null | undefined, digits: number): string {
  if (!startEpoch || t === null || t === undefined) return '—';
  const [secStr, fracStr = ''] = startEpoch.split('.');
  const base = Number(secStr);
  const startFrac = fracStr ? Number('0.' + fracStr) : 0;
  const sum = startFrac + t;
  const whole = Math.floor(sum);
  const d = Math.min(9, Math.max(0, digits));
  const fixed = (sum - whole).toFixed(d); // "0.123", or "1.000" after rounding up
  const carry = fixed.startsWith('1') ? 1 : 0;
  const fracText = d ? (carry ? '0'.repeat(d) : fixed.slice(2)) : '';
  const date = new Date((base + whole + carry) * 1000);
  const iso = date.toISOString().replace('T', ' ').slice(0, 19);
  return d ? `${iso}.${fracText}` : iso;
}

/** Epoch string ("1700000000.123456789") to UTC text with its own digits. */
export function epochText(epoch: string | null): string {
  if (!epoch) return '—';
  const [s, f = ''] = epoch.split('.');
  const iso = new Date(Number(s) * 1000).toISOString().replace('T', ' ').slice(0, 19);
  return f ? `${iso}.${f} UTC` : `${iso} UTC`;
}

export function endpoint(addr: string, port: number | null | undefined): string {
  if (port === null || port === undefined) return addr;
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

export function plural(n: number, one: string, many = one + 's'): string {
  return `${num(n)} ${n === 1 ? one : many}`;
}
