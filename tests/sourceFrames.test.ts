// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { SOURCE_PACKET_PAGE_SIZE, sourceFramePage } from '../src/app/sourceFrames';

describe('source packet pages', () => {
  it('deduplicates and sorts frames and exposes every page with bounded rows', () => {
    const sourceFrames = [...Array.from({ length: 602 }, (_, index) => 602 - index), 201, 1, 602];
    const first = sourceFramePage(sourceFrames, '', 0);
    const middle = sourceFramePage(sourceFrames, '', 4);
    const last = sourceFramePage(sourceFrames, '', 999);

    expect(first.frames).toEqual(Array.from({ length: SOURCE_PACKET_PAGE_SIZE }, (_, index) => index + 1));
    expect(middle).toMatchObject({ page: 4, pageCount: 13, total: 602, firstShown: 201, lastShown: 250 });
    expect(last).toMatchObject({ page: 12, pageCount: 13, total: 602, firstShown: 601, lastShown: 602 });
    expect(last.frames).toEqual([601, 602]);
    expect(last.frames.length).toBeLessThanOrEqual(SOURCE_PACKET_PAGE_SIZE);
  });

  it('searches frame numbers and handles empty and out-of-range pages', () => {
    expect(sourceFramePage([105, 15, 115, 5], '15', 0)).toMatchObject({ frames: [15, 115], total: 2, pageCount: 1 });
    expect(sourceFramePage([], '', 0)).toMatchObject({ frames: [], total: 0, pageCount: 0, firstShown: 0, lastShown: 0 });
    expect(sourceFramePage([1, 2, 3], 'missing', 3)).toMatchObject({ frames: [], page: 0, total: 0, pageCount: 0 });
  });
});
