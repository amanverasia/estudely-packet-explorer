// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import {
  directionBytes, findFollowByteMatches, findFollowTextMatches, followRuns, followSaveData, hexDump, joinRuns,
  mappedPayloadText, parseHexQuery, payloadText,
} from '../src/app/follow';
import type { FollowStream } from '../src/engine/types';

const enc = (s: string) => new TextEncoder().encode(s);

function stream(parts: [number, boolean, string][]): FollowStream {
  return streamRaw(parts.map(([frame, fromServer, text]) => [frame, fromServer, enc(text)]));
}

function streamRaw(parts: [number, boolean, Uint8Array][]): FollowStream {
  const bytes = parts.map(([, , b]) => b);
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

  it('totals only the selected directions (what a save should hold)', () => {
    const g = { ...f, clientBytes: 100, serverBytes: 40 };
    expect(directionBytes(g, 'client')).toBe(100);
    expect(directionBytes(g, 'server')).toBe(40);
    expect(directionBytes(g, 'both')).toBe(140);
  });

  it('saves both directions without copying and each single direction with one output buffer', () => {
    expect(followSaveData(f, 'both')).toBe(f.data);
    for (const direction of ['client', 'server'] as const) {
      expect(followSaveData(f, direction)).toEqual(joinRuns(followRuns(f, direction)));
    }
  });

  it('saves only retained selected-direction bytes when the shared cap excludes later segments', () => {
    const capped = stream([[1, false, 'request'], [2, true, 'res']]);
    capped.clientBytes = 7;
    capped.serverBytes = 100;
    capped.truncated = true;
    expect(Buffer.from(followSaveData(capped, 'server')).toString()).toBe('res');
    expect(followSaveData(capped, 'server').length).toBeLessThan(directionBytes(capped, 'server'));
    const excluded = stream([[1, false, 'request']]);
    excluded.serverBytes = 100;
    excluded.truncated = true;
    expect(followSaveData(excluded, 'server')).toEqual(new Uint8Array());
  });

  it('renders text with control and bidi characters neutralised', () => {
    expect(payloadText(enc('a\r\nb\tc\x00d\x1be\u202ef\u2066g\u061ch\r'))).toBe('a\nb\tc.d.e.f.g.h.');
    expect(payloadText(enc('naïve'))).toBe('naïve');
  });

  it('formats a hex dump with offsets and printable ASCII', () => {
    expect(hexDump(enc('GET /index.html HTTP/1.1\r\n'), 16)).toBe(
      '00000010  47 45 54 20 2f 69 6e 64  65 78 2e 68 74 6d 6c 20  GET /index.html \n'
      + '00000020  48 54 54 50 2f 31 2e 31  0d 0a                    HTTP/1.1..',
    );
  });

  it('maps UTF-8, CRLF, replacements, and neutralized controls to original byte spans', () => {
    const raw = new Uint8Array([0x41, 0xc3, 0xa9, 0x0d, 0x0a, 0xe2, 0x82, 0xac, 0x00, 0xff]);
    const mapped = mappedPayloadText(raw);
    expect(mapped.text).toBe('Aé\n€.�');
    expect(Array.from(mapped.byteStarts)).toEqual([0, 1, 3, 5, 8, 9]);
    expect(Array.from(mapped.byteEnds)).toEqual([1, 3, 5, 8, 9, 10]);
    expect(payloadText(raw)).toBe(mapped.text);
  });

  it('matches TextDecoder replacement behavior for invalid and truncated UTF-8', () => {
    const samples = [
      [0xe2, 0x82], [0xe2, 0x28, 0xa1], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80],
      [0xf0, 0x90, 0x80, 0x41], [0xf4, 0x90, 0x80, 0x80], [0xc0, 0xaf], [0x80, 0x80],
    ];
    for (const sample of samples) {
      const raw = new Uint8Array(sample);
      const expected = new TextDecoder('utf-8').decode(raw).replace(/\r\n/g, '\n')
        .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '.');
      expect(mappedPayloadText(raw).text).toBe(expected);
    }
  });

  it('finds overlapping literal text matches across adjacent segments and maps byte offsets', () => {
    const f = stream([[20, false, 'ban'], [21, false, 'ana']]);
    const runs = followRuns(f, 'both');
    const texts = runs.map((r) => mappedPayloadText(r.bytes));
    const found = findFollowTextMatches(runs, texts, 'ana');
    expect(found.matches.map((m) => [m.textStart, m.byteStart, m.byteEnd, m.frames])).toEqual([
      [1, 1, 4, [20, 21]],
      [3, 3, 6, [21]],
    ]);
    expect(found.capped).toBe(false);
  });

  it('does not match across opposite-direction runs, but merges when one direction is selected', () => {
    const f = stream([[30, false, 'a'], [31, true, 'noise'], [32, false, 'b']]);
    const both = followRuns(f, 'both');
    expect(findFollowTextMatches(both, both.map((r) => mappedPayloadText(r.bytes)), 'ab').matches).toEqual([]);
    const client = followRuns(f, 'client');
    const found = findFollowTextMatches(client, client.map((r) => mappedPayloadText(r.bytes)), 'ab');
    expect(found.matches.map((m) => [m.byteStart, m.byteEnd, m.frames])).toEqual([[0, 2, [30, 32]]]);
  });

  it('parses compact or whitespace-separated hex pairs and rejects malformed queries', () => {
    expect(Array.from(parseHexQuery('00 ff'))).toEqual([0, 255]);
    expect(Array.from(parseHexQuery('00FF'))).toEqual([0, 255]);
    expect(Array.from(parseHexQuery('  00\tFF\n'))).toEqual([0, 255]);
    expect(parseHexQuery('  ').length).toBe(0);
    expect(() => parseHexQuery('0')).toThrow(/complete pairs/);
    expect(() => parseHexQuery('0 0')).toThrow(/complete pairs/);
    expect(() => parseHexQuery('gg')).toThrow(/hexadecimal/);
    expect(() => parseHexQuery('00\u00a0ff')).toThrow(/hexadecimal/);
  });

  it('finds byte matches across adjacent segments, with direction offsets and follower frame provenance', () => {
    const f = streamRaw([[40, false, new Uint8Array([0x10])], [41, false, new Uint8Array([0x00])],
      [42, true, new Uint8Array([0xaa])], [43, false, new Uint8Array([0xff])]]);
    const both = followRuns(f, 'both');
    const bothTexts = both.map((r) => mappedPayloadText(r.bytes));
    expect(findFollowByteMatches(both, bothTexts, parseHexQuery('00ff')).matches).toEqual([]);
    const client = followRuns(f, 'client');
    const found = findFollowByteMatches(client, client.map((r) => mappedPayloadText(r.bytes)), parseHexQuery('00 ff'));
    expect(found.matches.map((m) => [m.byteStart, m.byteEnd, m.frames, client[m.runIndex].dirOffset])).toEqual([[1, 3, [41, 43], 0]]);
  });

  it('caps repetitive search results and reports whether more matches exist', () => {
    const run = followRuns(stream([[50, false, 'aaaaa']]), 'both');
    const text = run.map((r) => mappedPayloadText(r.bytes));
    expect(findFollowTextMatches(run, text, 'a', 3)).toMatchObject({ matches: expect.any(Array), capped: true });
    expect(findFollowTextMatches(run, text, 'z', 3)).toMatchObject({ matches: [], capped: false });
    expect(findFollowTextMatches(run, text, '', 3)).toMatchObject({ matches: [], capped: false });
  });
});
