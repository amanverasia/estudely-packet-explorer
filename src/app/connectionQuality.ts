// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { Conversation } from '../engine/types';

export const connectionQualityFilters = [
  { value: 'retransmissions', label: 'Retransmissions', description: 'Wireshark marked TCP retransmissions' },
  { value: 'outOfOrder', label: 'Out of order', description: 'Wireshark marked out-of-order TCP segments' },
  { value: 'gaps', label: 'Sequence gaps', description: 'Wireshark observed gaps in TCP sequence numbers' },
  { value: 'rstSeen', label: 'RST seen', description: 'a TCP reset flag was present' },
  { value: 'truncated', label: 'Truncated', description: 'one or more captured packets were shorter than their original frame length' },
  { value: 'malformed', label: 'Malformed', description: 'Wireshark marked one or more packets malformed' },
] as const;

export type ConnectionQualityFilter = 'all' | typeof connectionQualityFilters[number]['value'];

export function hasConnectionQualityIndicator(c: Conversation, filter: ConnectionQualityFilter): boolean {
  switch (filter) {
    case 'all': return true;
    case 'retransmissions': return (c.tcp?.retransmissions ?? 0) > 0;
    case 'outOfOrder': return (c.tcp?.outOfOrder ?? 0) > 0;
    case 'gaps': return (c.tcp?.lostSegments ?? 0) > 0;
    case 'rstSeen': return c.tcp?.rstSeen ?? false;
    case 'truncated': return c.truncatedPackets > 0;
    case 'malformed': return c.malformedPackets > 0;
  }
}

/** Counts distinct conversations with at least one observation for each filter. */
export function countConnectionQuality(conversations: Conversation[]): Record<ConnectionQualityFilter, number> {
  const counts: Record<ConnectionQualityFilter, number> = {
    all: conversations.length,
    retransmissions: 0,
    outOfOrder: 0,
    gaps: 0,
    rstSeen: 0,
    truncated: 0,
    malformed: 0,
  };
  for (const c of conversations) {
    for (const { value } of connectionQualityFilters) {
      if (hasConnectionQualityIndicator(c, value)) counts[value]++;
    }
  }
  return counts;
}

export function filterConnectionsByQuality(conversations: Conversation[], filter: ConnectionQualityFilter): Conversation[] {
  return filter === 'all' ? conversations : conversations.filter((c) => hasConnectionQualityIndicator(c, filter));
}
