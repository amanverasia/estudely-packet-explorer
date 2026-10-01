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
}

export function followRuns(f: FollowStream, dir: FollowDirection): FollowRun[] {
  const runs: { fromServer: boolean; frames: number[]; parts: [number, number][]; dirOffset: number }[] = [];
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
      last.parts.push([g.offset, g.length]);
    } else {
      runs.push({ fromServer: g.fromServer, frames: [g.frame], parts: [[g.offset, g.length]], dirOffset });
    }
  }
  return runs.map((r) => {
    const size = r.parts.reduce((n, [, len]) => n + len, 0);
    const bytes = new Uint8Array(size);
    let off = 0;
    for (const [o, len] of r.parts) { bytes.set(f.data.subarray(o, o + len), off); off += len; }
    return { fromServer: r.fromServer, frames: r.frames, bytes, dirOffset: r.dirOffset };
  });
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
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;

/** UTF-8 text with invalid sequences as U+FFFD and unsafe characters as '.'. */
export function payloadText(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes).replace(/\r\n/g, '\n').replace(UNSAFE, '.');
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
