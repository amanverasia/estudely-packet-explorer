// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { FollowStream } from './types';
import type { WgVector } from './session';

export interface FollowPayload { number: number; server: number; data: string }

/** Infinity is an explicit opt-out; reject malformed caps before calling WASM. */
export function validateFollowCap(name: string, value: number): void {
  if (value !== Infinity && (!Number.isSafeInteger(value) || value < 0)) {
    throw new Error(`${name} must be a nonnegative safe integer or Infinity.`);
  }
}

function decodedLength(data: string): number {
  // Wiregasm emits canonical, padded base64, including an empty string for
  // empty records. Shape validation also prevents fractional allocation sizes.
  if (data.length % 4 !== 0) throw new Error('Invalid base64 payload length.');
  return data.length / 4 * 3 - (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
}

/** At most 48 KiB of binary-string scratch, even for a much larger save. */
export const FOLLOW_DECODE_CHARS = 64 * 1024;

function decodePrefixInto(encoded: string, out: Uint8Array, offset: number, length: number): void {
  const end = Math.ceil(length / 3) * 4;
  let written = 0;
  for (let start = 0; start < end; start += FOLLOW_DECODE_CHARS) {
    const binary = atob(encoded.slice(start, Math.min(end, start + FOLLOW_DECODE_CHARS)));
    const count = Math.min(binary.length, length - written);
    for (let i = 0; i < count; i++) out[offset + written + i] = binary.charCodeAt(i);
    written += count;
  }
  if (written !== length) throw new Error('Invalid base64 payload length.');
}

/**
 * Retain only numeric prefix metadata and one exact decoded output buffer.
 * Wiregasm 1.9.1 still collects the whole stream in WASM, and each get() copies
 * one complete base64 record into JS. This bounds decoded copies, not that
 * upstream collection or the size of one Embind string. Totals require a full
 * scan because upstream direction byte totals disagree with payload flags.
 */
export function collectFollowPayloads(payloads: WgVector<FollowPayload>, maxBytes: number, maxSegments: number):
  Pick<FollowStream, 'clientBytes' | 'serverBytes' | 'totalSegments' | 'data' | 'segments' | 'truncated'> {
  try {
    validateFollowCap('maxBytes', maxBytes);
    validateFollowCap('maxSegments', maxSegments);
    const totalSegments = payloads.size();
    let clientBytes = 0;
    let serverBytes = 0;
    let size = 0;
    let truncated = false;
    const segments: FollowStream['segments'] = [];
    for (let i = 0; i < totalSegments; i++) {
      const payload = payloads.get(i);
      const length = decodedLength(payload.data);
      if (payload.server) serverBytes += length;
      else clientBytes += length;
      if (truncated || segments.length >= maxSegments || size >= maxBytes) {
        truncated = true;
        continue;
      }
      const retained = Math.min(length, maxBytes - size);
      segments.push({ frame: payload.number, fromServer: !!payload.server, offset: size, length: retained });
      size += retained;
      if (retained < length) truncated = true;
    }
    const data = new Uint8Array(size);
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      if (segment.length > 0) decodePrefixInto(payloads.get(i).data, data, segment.offset, segment.length);
    }
    return { clientBytes, serverBytes, totalSegments, data, segments, truncated };
  } finally {
    payloads.delete?.();
  }
}
