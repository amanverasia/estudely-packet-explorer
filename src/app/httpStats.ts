// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { HttpExchange } from '../engine/types';

/** Response charts group by numeric status; optional reason phrases stay on each record. */
export function countHttpStatuses(exchanges: readonly Pick<HttpExchange, 'status'>[]): { key: string; value: number }[] {
  const counts = new Map<number, number>();
  for (const exchange of exchanges) {
    if (exchange.status !== null) counts.set(exchange.status, (counts.get(exchange.status) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([aCode, aCount], [bCode, bCount]) => bCount - aCount || aCode - bCode)
    .map(([code, value]) => ({ key: String(code), value }));
}
