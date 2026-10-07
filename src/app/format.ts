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
  if (a < 1e-6) {
    const ns = compact(s * 1e9);
    return Math.abs(Number(ns)) >= 1000 ? `${compact(s * 1e6)} µs` : `${ns} ns`;
  }
  if (a < 1e-3) {
    const us = compact(s * 1e6);
    return Math.abs(Number(us)) >= 1000 ? `${compact(s * 1e3)} ms` : `${us} µs`;
  }
  if (a < 1) {
    const ms = compact(s * 1e3);
    return Math.abs(Number(ms)) >= 1000 ? `${compact(s)} s` : `${ms} ms`;
  }
  if (a < 60) {
    const seconds = compact(s);
    if (Math.abs(Number(seconds)) >= 60) return `${s < 0 ? '-' : ''}1 min 0 s`;
    return `${seconds} s`;
  }
  const totalSeconds = Math.round(a);
  const sign = s < 0 ? '-' : '';
  if (totalSeconds < 3600) return `${sign}${Math.floor(totalSeconds / 60)} min ${totalSeconds % 60} s`;
  if (totalSeconds < 86400) return `${sign}${Math.floor(totalSeconds / 3600)} h ${Math.floor((totalSeconds % 3600) / 60)} min`;
  return `${sign}${Math.floor(totalSeconds / 86400)} d ${Math.floor((totalSeconds % 86400) / 3600)} h`;
}

function compact(value: number): string {
  return Number(value.toPrecision(4)).toString();
}

/** Stable decimal seconds for editable bounds, without exponent notation or float tails. */
export function editableSeconds(value: number, digits: number): string {
  if (!Number.isFinite(value)) return '';
  const precision = Math.min(9, Math.max(0, Math.trunc(digits)));
  const fixed = value.toFixed(precision);
  if (Number(fixed) === 0) return '0';
  return fixed.includes('.') ? fixed.replace(/0+$/, '').replace(/\.$/, '') : fixed;
}

/** Keep a displayed default's original boundary exactly when it is submitted unchanged. */
export function parseEditableSeconds(input: string, displayedDefault: string, exactDefault: number): number {
  if (!input.trim()) return Number.NaN;
  const value = Number(input);
  if (Number.isFinite(value) && value === Number(displayedDefault)) return exactDefault;
  return value;
}

/** Expand JavaScript's shortest round-trippable number into a plain decimal literal. */
export function decimalLiteral(value: number): string {
  const literal = String(value);
  const match = /^(-?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$/.exec(literal);
  if (!match) return literal;
  const [, sign, whole, fraction = '', exponentText] = match;
  const digits = whole + fraction;
  const point = whole.length + Number(exponentText);
  if (point <= 0) return `${sign}0.${'0'.repeat(-point)}${digits}`;
  if (point >= digits.length) return `${sign}${digits}${'0'.repeat(point - digits.length)}`;
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
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
