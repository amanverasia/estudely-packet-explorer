// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import {
  overviewAverageRateBytesPerSecond,
  rankConversationsByBytes,
  rankProtocols,
  resolveSelectedDuration,
  sliceTopHosts,
} from '../src/app/views/overviewTotals';
import type { Conversation, Host, ProtoStat } from '../src/engine/types';

function conv(id: number, bytes: number): Conversation {
  return { id, bytesAB: bytes, bytesBA: 0 } as Conversation;
}

describe('overview shared-filter totals', () => {
  it('prefers the filter window, then the stats window, then the capture duration', () => {
    expect(resolveSelectedDuration({ start: 2, end: 7 }, { start: 0, end: 100 }, 100)).toBe(5);
    expect(resolveSelectedDuration({ start: null, end: null }, { start: 3, end: 9 }, 100)).toBe(6);
    expect(resolveSelectedDuration({ start: null, end: null }, { start: null, end: null }, 42)).toBe(42);
  });

  it('clamps a reversed stats window at zero and ignores a half-open filter', () => {
    expect(resolveSelectedDuration({ start: null, end: null }, { start: 9, end: 3 }, 42)).toBe(0);
    expect(resolveSelectedDuration({ start: 4, end: null }, { start: 0, end: 10 }, 42)).toBe(10);
  });

  it('ranks conversations by bytes on wire without mutating the input', () => {
    const input = [conv(1, 10), conv(2, 300), conv(3, 200)];
    const ranked = rankConversationsByBytes(input);
    expect(ranked.map((c) => c.id)).toEqual([2, 3, 1]);
    expect(input.map((c) => c.id)).toEqual([1, 2, 3]);
    expect(rankConversationsByBytes(input, 2).map((c) => c.id)).toEqual([2, 3]);
  });

  it('ranks protocols by the selected metric without mutating the input', () => {
    const input = [
      { proto: 'DNS', packets: 100, bytes: 10 },
      { proto: 'TLS', packets: 5, bytes: 9000 },
    ] as ProtoStat[];
    expect(rankProtocols(input, 'packets').map((p) => p.proto)).toEqual(['DNS', 'TLS']);
    expect(rankProtocols(input, 'bytes').map((p) => p.proto)).toEqual(['TLS', 'DNS']);
    expect(input.map((p) => p.proto)).toEqual(['DNS', 'TLS']);
  });

  it('keeps only the first fifty hosts and conversations by default', () => {
    const hosts = Array.from({ length: 60 }, (_, i) => ({ addr: `10.0.0.${i}` }) as Host);
    expect(sliceTopHosts(hosts)).toHaveLength(50);
    expect(sliceTopHosts(hosts)[0].addr).toBe('10.0.0.0');
    const convs = Array.from({ length: 60 }, (_, i) => conv(i, i));
    expect(rankConversationsByBytes(convs)).toHaveLength(50);
    expect(rankConversationsByBytes(convs)[0].id).toBe(59);
  });

  it('computes the average rate or null when duration is not positive', () => {
    expect(overviewAverageRateBytesPerSecond(1000, 4)).toBe(250);
    expect(overviewAverageRateBytesPerSecond(1000, 6)).toBe(167);
    expect(overviewAverageRateBytesPerSecond(1000, 0)).toBeNull();
    expect(overviewAverageRateBytesPerSecond(1000, -2)).toBeNull();
  });
});
