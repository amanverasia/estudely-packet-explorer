// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Pure helpers for the Overview shared-filter totals. Extracted from
// Overview.tsx so the duration, ranking and rate maths are unit-testable
// without rendering. Overview.tsx remains the only caller.
import type { FilterStats, SharedFilter } from '../filtering';
import type { Conversation, Host, ProtoStat } from '../../engine/types';

export type OverviewProtoMetric = 'packets' | 'bytes';

export function resolveSelectedDuration(
  filter: Pick<SharedFilter, 'start' | 'end'>,
  stats: Pick<FilterStats, 'start' | 'end'>,
  captureDuration: number,
): number {
  if (filter.start !== null && filter.end !== null) return filter.end - filter.start;
  if (stats.start !== null && stats.end !== null) return Math.max(0, stats.end - stats.start);
  return captureDuration;
}

export function rankConversationsByBytes<T extends Pick<Conversation, 'bytesAB' | 'bytesBA'>>(
  conversations: readonly T[],
  limit = 50,
): T[] {
  return [...conversations]
    .sort((a, b) => b.bytesAB + b.bytesBA - (a.bytesAB + a.bytesBA))
    .slice(0, limit);
}

export function rankProtocols<T extends Pick<ProtoStat, 'packets' | 'bytes'>>(
  protocols: readonly T[],
  metric: OverviewProtoMetric,
): T[] {
  return [...protocols].sort((a, b) => b[metric] - a[metric]);
}

export function sliceTopHosts<T extends Pick<Host, 'addr'>>(hosts: readonly T[], limit = 50): T[] {
  return hosts.slice(0, limit);
}

export function overviewAverageRateBytesPerSecond(wireBytes: number, selectedDuration: number): number | null {
  if (!(selectedDuration > 0)) return null;
  return Math.round(wireBytes / selectedDuration);
}
