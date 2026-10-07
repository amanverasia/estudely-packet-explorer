// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Follow stream: turns the follower's segments into display runs, plain text
// and hex dumps. Everything here produces strings for text nodes; captured
// payload is never interpreted as markup.
import type { FollowStream } from '../engine/types';

/** Bytes shown in the view, and the larger cap for "Save raw". */
export const FOLLOW_VIEW_BYTES = 512 * 1024;
export const FOLLOW_VIEW_SEGMENTS = 5000;
export const FOLLOW_SAVE_BYTES = 64 * 1024 * 1024;

export type FollowDirection = 'both' | 'client' | 'server';

/** Consecutive segments sent in one direction, merged. */
export interface FollowRun {
  fromServer: boolean;
  frames: number[];
  bytes: Uint8Array;
  /** Offset of this run within its direction's byte stream (as Wireshark numbers hex dumps). */
  dirOffset: number;
  /** Byte ranges from the follower's segments, relative to this run. */
  provenance: FollowProvenance[];
}

export interface FollowProvenance {
  runByteStart: number;
  length: number;
  frame: number;
}

export function followRuns(f: FollowStream, dir: FollowDirection): FollowRun[] {
  const runs: { fromServer: boolean; frames: number[]; parts: [number, number, number][]; dirOffset: number }[] = [];
  const seen = [0, 0];
  for (const g of f.segments) {
    const side = g.fromServer ? 1 : 0;
    const dirOffset = seen[side];
    seen[side] += g.length;
    if (dir === 'client' && g.fromServer) continue;
    if (dir === 'server' && !g.fromServer) continue;
    const last = runs[runs.length - 1];
    if (last && last.fromServer === g.fromServer) {
      if (last.frames[last.frames.length - 1] !== g.frame) last.frames.push(g.frame);
      last.parts.push([g.offset, g.length, g.frame]);
    } else {
      runs.push({ fromServer: g.fromServer, frames: [g.frame], parts: [[g.offset, g.length, g.frame]], dirOffset });
    }
  }
  return runs.map((r) => {
    const size = r.parts.reduce((n, [, len]) => n + len, 0);
    const bytes = new Uint8Array(size);
    const provenance: FollowProvenance[] = [];
    let off = 0;
    for (const [o, len, frame] of r.parts) {
      bytes.set(f.data.subarray(o, o + len), off);
      if (len > 0) provenance.push({ runByteStart: off, length: len, frame });
      off += len;
    }
    return { fromServer: r.fromServer, frames: r.frames, bytes, dirOffset: r.dirOffset, provenance };
  });
}

/** Payload bytes in the selected directions over the whole stream, before any cap. */
export function directionBytes(f: FollowStream, dir: FollowDirection): number {
  return (dir === 'server' ? 0 : f.clientBytes) + (dir === 'client' ? 0 : f.serverBytes);
}

/** The selected directions' payload as one buffer, in capture order (for saving). */
export function joinRuns(runs: FollowRun[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(runs.reduce((n, r) => n + r.bytes.length, 0));
  let off = 0;
  for (const r of runs) { out.set(r.bytes, off); off += r.bytes.length; }
  return out;
}

// C0/C1 controls (except tab and newline) and bidirectional overrides, which
// could make captured text display as something it is not.
const UNSAFE_CHAR = /^[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]$/u;
const UNSAFE_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/** Maps rendered UTF-16 code units back to the bytes that produced them. */
export interface MappedPayloadText {
  text: string;
  byteStarts: Uint32Array;
  byteEnds: Uint32Array;
}

interface DecodedScalar {
  value: number;
  end: number;
}

/** Decode one Unicode scalar using TextDecoder's UTF-8 replacement boundaries. */
function decodeScalar(bytes: Uint8Array, start: number): DecodedScalar {
  const lead = bytes[start];
  if (lead <= 0x7f) return { value: lead, end: start + 1 };

  let needed: number;
  let value: number;
  let min: number;
  if (lead >= 0xc2 && lead <= 0xdf) { needed = 2; value = lead & 0x1f; min = 0x80; }
  else if (lead >= 0xe0 && lead <= 0xef) { needed = 3; value = lead & 0x0f; min = 0x800; }
  else if (lead >= 0xf0 && lead <= 0xf4) { needed = 4; value = lead & 0x07; min = 0x10000; }
  else return { value: 0xfffd, end: start + 1 };

  let end = start + 1;
  while (end < bytes.length && end < start + needed) {
    const next = bytes[end];
    if (next < 0x80 || next > 0xbf) {
      // The decoder reports the incomplete prefix, then retries this byte.
      return { value: 0xfffd, end };
    }
    if (end === start + 1 && ((lead === 0xe0 && next < 0xa0)
      || (lead === 0xed && next > 0x9f)
      || (lead === 0xf0 && next < 0x90)
      || (lead === 0xf4 && next > 0x8f))) {
      // A constrained second byte is retried as a new lead byte.
      return { value: 0xfffd, end: start + 1 };
    }
    value = (value << 6) | (next & 0x3f);
    end++;
  }
  if (end < start + needed) return { value: 0xfffd, end };
  if (value < min || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
    return { value: 0xfffd, end };
  }
  return { value, end };
}

/** UTF-8 text matching TextDecoder, with a compact mapping to original byte spans. */
export function mappedPayloadText(bytes: Uint8Array): MappedPayloadText {
  const byteStarts = new Uint32Array(bytes.length);
  const byteEnds = new Uint32Array(bytes.length);
  const parts: string[] = [];
  let chars = 0;
  let offset = 0;

  while (offset < bytes.length) {
    const start = offset;
    const scalar = decodeScalar(bytes, offset);
    offset = scalar.end;
    let value = scalar.value;
    let end = offset;
    // Match payloadText's CRLF normalization while preserving both source bytes.
    if (value === 0x0d && offset < bytes.length) {
      const next = decodeScalar(bytes, offset);
      if (next.value === 0x0a) {
        value = 0x0a;
        end = next.end;
        offset = next.end;
      }
    }
    let piece = String.fromCodePoint(value);
    if (UNSAFE_CHAR.test(piece)) piece = '.';
    parts.push(piece);
    for (let unit = 0; unit < piece.length; unit++) {
      byteStarts[chars] = start;
      byteEnds[chars] = end;
      chars++;
    }
  }

  return { text: parts.join(''), byteStarts: byteStarts.subarray(0, chars), byteEnds: byteEnds.subarray(0, chars) };
}

/** UTF-8 text with invalid sequences as U+FFFD and unsafe characters as '.'. */
export function payloadText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes).replace(/\r\n/g, '\n').replace(UNSAFE_CHARS, '.');
}

export interface FollowSearchMatch {
  runIndex: number;
  fromServer: boolean;
  byteStart: number;
  byteEnd: number;
  textStart: number;
  textEnd: number;
  frames: number[];
}

export interface FollowSearchResult {
  matches: FollowSearchMatch[];
  capped: boolean;
}

export const FOLLOW_SEARCH_MATCH_LIMIT = 10_000;

/** Parse pairs of hex digits, with or without ASCII whitespace between pairs. */
export function parseHexQuery(query: string): Uint8Array {
  const trimmed = query.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
  if (trimmed.length === 0) return new Uint8Array();
  const pairs = trimmed.split(/[\t\n\f\r ]+/);
  if (pairs.some((part) => !/^[0-9a-fA-F]+$/.test(part))) throw new Error('Use only hexadecimal digits and ASCII whitespace.');
  if (pairs.some((part) => part.length % 2 !== 0)) throw new Error('Enter complete pairs of hexadecimal digits.');
  const compact = pairs.join('');
  const out = new Uint8Array(compact.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(compact.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function framesForRange(run: FollowRun, start: number, end: number): number[] {
  const frames: number[] = [];
  for (const p of run.provenance) {
    if (p.runByteStart < end && p.runByteStart + p.length > start && !frames.includes(p.frame)) frames.push(p.frame);
  }
  return frames;
}

function textRangeForBytes(text: MappedPayloadText, byteStart: number, byteEnd: number): [number, number] {
  let lo = 0;
  let hi = text.byteEnds.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (text.byteEnds[mid] <= byteStart) lo = mid + 1;
    else hi = mid;
  }
  const start = lo;
  lo = start;
  hi = text.byteStarts.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (text.byteStarts[mid] < byteEnd) lo = mid + 1;
    else hi = mid;
  }
  return [start, lo];
}

/** Search literal, case-sensitive text independently within each displayed run. */
export function findFollowTextMatches(
  runs: FollowRun[], texts: MappedPayloadText[], query: string, limit = FOLLOW_SEARCH_MATCH_LIMIT,
): FollowSearchResult {
  const matches: FollowSearchMatch[] = [];
  if (!query) return { matches, capped: false };
  for (let runIndex = 0; runIndex < runs.length; runIndex++) {
    const run = runs[runIndex];
    const text = texts[runIndex];
    let from = 0;
    while (from <= text.text.length - query.length) {
      const textStart = text.text.indexOf(query, from);
      if (textStart < 0) break;
      if (matches.length === limit) return { matches, capped: true };
      const textEnd = textStart + query.length;
      const byteStart = text.byteStarts[textStart];
      const byteEnd = text.byteEnds[textEnd - 1];
      matches.push({ runIndex, fromServer: run.fromServer, byteStart, byteEnd, textStart, textEnd, frames: framesForRange(run, byteStart, byteEnd) });
      from = textStart + 1;
    }
  }
  return { matches, capped: false };
}

/** Search actual bytes independently within each displayed run using KMP. */
export function findFollowByteMatches(
  runs: FollowRun[], texts: MappedPayloadText[], query: Uint8Array, limit = FOLLOW_SEARCH_MATCH_LIMIT,
): FollowSearchResult {
  const matches: FollowSearchMatch[] = [];
  if (!query.length) return { matches, capped: false };
  const prefix = new Uint32Array(query.length);
  for (let i = 1, j = 0; i < query.length; i++) {
    while (j > 0 && query[i] !== query[j]) j = prefix[j - 1];
    if (query[i] === query[j]) j++;
    prefix[i] = j;
  }
  for (let runIndex = 0; runIndex < runs.length; runIndex++) {
    const run = runs[runIndex];
    let matched = 0;
    for (let i = 0; i < run.bytes.length; i++) {
      while (matched > 0 && run.bytes[i] !== query[matched]) matched = prefix[matched - 1];
      if (run.bytes[i] === query[matched]) matched++;
      if (matched === query.length) {
        if (matches.length === limit) return { matches, capped: true };
        const byteStart = i + 1 - query.length;
        const byteEnd = i + 1;
        const [textStart, textEnd] = textRangeForBytes(texts[runIndex], byteStart, byteEnd);
        matches.push({ runIndex, fromServer: run.fromServer, byteStart, byteEnd, textStart, textEnd, frames: framesForRange(run, byteStart, byteEnd) });
        matched = prefix[matched - 1];
      }
    }
  }
  return { matches, capped: false };
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

/** Classic 16-bytes-per-line dump: offset, two groups of 8, printable ASCII. */
export function hexDump(bytes: Uint8Array, startOffset = 0): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    const hex: string[] = [];
    let ascii = '';
    for (let j = 0; j < row.length; j++) {
      hex.push(HEX[row[j]]);
      ascii += row[j] >= 0x20 && row[j] < 0x7f ? String.fromCharCode(row[j]) : '.';
    }
    const left = hex.slice(0, 8).join(' ').padEnd(23);
    const right = hex.slice(8).join(' ').padEnd(23);
    lines.push(`${(startOffset + i).toString(16).padStart(8, '0')}  ${left}  ${right}  ${ascii}`);
  }
  return lines.join('\n');
}
