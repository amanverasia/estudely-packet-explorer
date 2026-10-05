// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

export const SOURCE_PACKET_PAGE_SIZE = 50;

export interface SourceFramePage {
  frames: number[];
  page: number;
  pageCount: number;
  total: number;
  firstShown: number;
  lastShown: number;
}

/** Build a bounded, searchable page from a record's source packet numbers. */
export function sourceFramePage(sourceFrames: number[], search: string, requestedPage: number): SourceFramePage {
  const frames = [...new Set(sourceFrames)].sort((a, b) => a - b);
  const query = search.trim();
  const matching = query ? frames.filter((frame) => String(frame).includes(query)) : frames;
  const pageCount = Math.ceil(matching.length / SOURCE_PACKET_PAGE_SIZE);
  const pageRequest = Number.isFinite(requestedPage) ? Math.floor(requestedPage) : 0;
  const page = Math.min(Math.max(0, pageRequest), Math.max(0, pageCount - 1));
  const start = page * SOURCE_PACKET_PAGE_SIZE;
  const visible = matching.slice(start, start + SOURCE_PACKET_PAGE_SIZE);
  return {
    frames: visible,
    page,
    pageCount,
    total: matching.length,
    firstShown: matching.length ? start + 1 : 0,
    lastShown: Math.min(start + visible.length, matching.length),
  };
}
