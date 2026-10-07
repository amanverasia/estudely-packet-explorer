// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { afterEach, describe, expect, it, vi } from 'vitest';
import { collectFollowPayloads, FOLLOW_DECODE_CHARS, type FollowPayload } from '../src/engine/follow-payloads';
import { CaptureSession, type WiregasmModule } from '../src/engine/session';

function vector(parts: [number, boolean, string][]) {
  return {
    size: vi.fn(() => parts.length),
    get: vi.fn((i: number): FollowPayload => ({ number: parts[i][0], server: Number(parts[i][1]), data: parts[i][2] })),
    delete: vi.fn(),
  };
}
const encoded = (text: string) => Buffer.from(text).toString('base64');
const content = (result: ReturnType<typeof collectFollowPayloads>) => Buffer.from(result.data).toString();
afterEach(() => vi.restoreAllMocks());

describe('bounded decoded Follow Stream prefix', () => {
  it('scans totals without a full-payload array, then fetches only retained prefix records', () => {
    const payloads = vector([[10, false, encoded('abc')], [11, true, encoded('defgh')], [12, true, encoded('rest')]]);
    const result = collectFollowPayloads(payloads, 5, 5000);
    expect(content(result)).toBe('abcde');
    expect(result).toMatchObject({ clientBytes: 3, serverBytes: 9, totalSegments: 3, truncated: true });
    expect(result.segments).toEqual([
      { frame: 10, fromServer: false, offset: 0, length: 3 },
      { frame: 11, fromServer: true, offset: 3, length: 2 },
    ]);
    expect(payloads.get.mock.calls.map(([i]) => i)).toEqual([0, 1, 2, 0, 1]);
    expect(payloads.delete).toHaveBeenCalledOnce();
  });

  it.each([0, 1, 2, 3, 4, 7, 49151, 49152, 49153])('decodes exactly %i bytes of one oversized record', (cap) => {
    const raw = Buffer.alloc(2 * 1024 * 1024, 0xff);
    const payloads = vector([[1, false, raw.toString('base64')]]);
    const decode = vi.spyOn(globalThis, 'atob');
    const result = collectFollowPayloads(payloads, cap, 5000);
    expect(Buffer.from(result.data)).toEqual(raw.subarray(0, cap));
    expect(result.clientBytes).toBe(raw.length);
    expect(result.truncated).toBe(true);
    const lengths = decode.mock.calls.map(([s]) => s.length);
    expect(lengths.reduce((n, length) => n + length, 0)).toBe(Math.ceil(cap / 3) * 4);
    expect(lengths.every((length) => length <= FOLLOW_DECODE_CHARS && length % 4 === 0)).toBe(true);
    expect(payloads.delete).toHaveBeenCalledOnce();
  });

  it.each([1, 2, 3, 4, 5, 6])('preserves base64 padding at exact %i byte boundaries', (length) => {
    const payloads = vector([[1, false, encoded('x'.repeat(length))]]);
    const result = collectFollowPayloads(payloads, length, 1);
    expect(content(result)).toBe('x'.repeat(length));
    expect(result.truncated).toBe(false);
  });

  it('does not decode any bytes for a zero segment cap, but retains accurate direction totals', () => {
    const payloads = vector([[1, false, encoded('abc')], [2, true, encoded('hello')]]);
    const decode = vi.spyOn(globalThis, 'atob');
    expect(collectFollowPayloads(payloads, Infinity, 0)).toMatchObject({
      data: new Uint8Array(), segments: [], clientBytes: 3, serverBytes: 5, totalSegments: 2, truncated: true,
    });
    expect(decode).not.toHaveBeenCalled();
  });

  it('caps empty and many tiny records by segments without decoding empty records', () => {
    const parts: [number, boolean, string][] = Array.from({ length: 10000 }, (_, i) => [i + 1, false, i % 2 ? encoded('x') : '']);
    const payloads = vector(parts);
    const result = collectFollowPayloads(payloads, 10000, 5);
    expect(result.segments.map((s) => s.length)).toEqual([0, 1, 0, 1, 0]);
    expect(content(result)).toBe('xx');
    expect(result).toMatchObject({ clientBytes: 5000, totalSegments: 10000, truncated: true });
    expect(payloads.get).toHaveBeenCalledTimes(10002);
  });

  it('keeps missing streams empty with no truncation, including zero caps', () => {
    expect(collectFollowPayloads(vector([]), 0, 0)).toMatchObject({ totalSegments: 0, truncated: false, data: new Uint8Array() });
  });

  it.each(['!!!!', 'bad'])('releases the vector after malformed base64 %s', (data) => {
    const payloads = vector([[1, false, data]]);
    expect(() => collectFollowPayloads(payloads, 10, 10)).toThrow();
    expect(payloads.delete).toHaveBeenCalledOnce();
  });

  it('releases the vector on a getter failure or decoder failure', () => {
    const getFailure = vector([[1, false, encoded('x')]]);
    getFailure.get.mockImplementation(() => { throw new Error('getter failure'); });
    expect(() => collectFollowPayloads(getFailure, 10, 10)).toThrow('getter failure');
    expect(getFailure.delete).toHaveBeenCalledOnce();
    const decodeFailure = vector([[1, false, encoded('x')]]);
    vi.spyOn(globalThis, 'atob').mockImplementation(() => { throw new Error('decoder failure'); });
    expect(() => collectFollowPayloads(decodeFailure, 10, 10)).toThrow('decoder failure');
    expect(decodeFailure.delete).toHaveBeenCalledOnce();
  });

  it.each([-1, 0.5, NaN, -Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid cap %s before the follower runs', (cap) => {
    const session = new CaptureSession({ getUploadDirectory: () => '/uploads' } as WiregasmModule, 'test');
    // No capture is open: validation must throw before trying to call its follower.
    expect(() => session.follow('TCP', 0, { maxBytes: cap })).toThrow(/maxBytes must/);
    expect(() => session.follow('TCP', 0, { maxSegments: cap })).toThrow(/maxSegments must/);
  });

  it('repeated preview and save calls independently release each vector', () => {
    for (let i = 0; i < 20; i++) {
      const payloads = vector([[1, false, encoded('hello')], [2, true, encoded('world!')]]);
      const result = collectFollowPayloads(payloads, i % 2 ? 64 * 1024 * 1024 : 4, Infinity);
      expect(content(result)).toBe(i % 2 ? 'helloworld!' : 'hell');
      expect(payloads.delete).toHaveBeenCalledOnce();
    }
  });
});
