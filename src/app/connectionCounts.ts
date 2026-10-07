// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { Conversation, Transport } from '../engine/types';

export const CONNECTION_TRANSPORTS: readonly Transport[] = ['TCP', 'UDP', 'IP', 'Non-IP'];

export function countConnectionTransports(conversations: readonly Pick<Conversation, 'transport'>[]): Record<Transport, number> {
  const counts: Record<Transport, number> = { TCP: 0, UDP: 0, IP: 0, 'Non-IP': 0 };
  for (const conversation of conversations) counts[conversation.transport]++;
  return counts;
}
