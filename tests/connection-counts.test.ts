// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { countConnectionTransports } from '../src/app/connectionCounts';
import type { Conversation } from '../src/engine/types';

describe('connection transport counts', () => {
  it('partitions one scoped conversation list and retains zero categories', () => {
    const counts = countConnectionTransports([
      { transport: 'TCP' }, { transport: 'TCP' }, { transport: 'UDP' }, { transport: 'IP' },
    ] as Pick<Conversation, 'transport'>[]);

    expect(counts).toEqual({ TCP: 2, UDP: 1, IP: 1, 'Non-IP': 0 });
    expect(Object.values(counts).reduce((sum, count) => sum + count, 0)).toBe(4);
  });
});
