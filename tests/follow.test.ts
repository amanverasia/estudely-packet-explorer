// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { followRuns, hexDump, joinRuns, payloadText } from '../src/app/follow';
import type { FollowStream } from '../src/engine/types';

const enc = (s: string) => new TextEncoder().encode(s);

function stream(parts: [number, boolean, string][]): FollowStream {
  const bytes = parts.map(([, , s]) => enc(s));
  const data = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let off = 0;
  const segments = parts.map(([frame, fromServer], i) => {
    data.set(bytes[i], off);
    const g = { frame, fromServer, offset: off, length: bytes[i].length };
    off += bytes[i].length;
    return g;
  });
  return { transport: 'TCP', stream: 0, client: null, server: null, clientBytes: 0, serverBytes: 0, totalSegments: parts.length, data, segments, truncated: false };
}

describe('follow stream helpers', () => {
  const f = stream([[4, false, 'GET / HT'], [5, false, 'TP/1.1\r\n\r\n'], [6, true, 'HTTP/1.1 200 OK\r\n\r\n<b>hi</b>'], [7, false, 'bye']]);

  it('merges consecutive segments in one direction into a run', () => {
    const runs = followRuns(f, 'both');
    expect(runs.map((r) => [r.fromServer, r.frames, new TextDecoder().decode(r.bytes)])).toEqual([
      [false, [4, 5], 'GET / HTTP/1.1\r\n\r\n'],
      [true, [6], 'HTTP/1.1 200 OK\r\n\r\n<b>hi</b>'],
      [false, [7], 'bye'],
    ]);
    expect(runs.map((r) => r.dirOffset)).toEqual([0, 0, 18]);
  });

  it('filters by direction', () => {
    expect(followRuns(f, 'client').map((r) => r.frames)).toEqual([[4, 5, 7]]);
    expect(followRuns(f, 'server').map((r) => r.frames)).toEqual([[6]]);
    expect(new TextDecoder().decode(joinRuns(followRuns(f, 'client')))).toBe('GET / HTTP/1.1\r\n\r\nbye');
  });

  it('renders text with control and bidi characters neutralised', () => {
    expect(payloadText(enc('a\r\nb\tc\x00d\x1be‮f\r'))).toBe('a\nb\tc.d.e.f.');
    expect(payloadText(enc('naïve'))).toBe('naïve');
  });

  it('formats a hex dump with offsets and printable ASCII', () => {
    expect(hexDump(enc('GET /index.html HTTP/1.1\r\n'), 16)).toBe(
      '00000010  47 45 54 20 2f 69 6e 64  65 78 2e 68 74 6d 6c 20  GET /index.html \n'
      + '00000020  48 54 54 50 2f 31 2e 31  0d 0a                    HTTP/1.1..',
    );
  });
});
