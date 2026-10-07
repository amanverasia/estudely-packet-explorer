// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { countHttpStatuses } from '../src/app/httpStats';
import type { HttpExchange } from '../src/engine/types';

describe('HTTP response status counts', () => {
  it('groups equal numeric codes regardless of optional reason phrases', () => {
    const exchanges: { status: number | null; phrase: string | null }[] = [
      { status: 200, phrase: 'OK' }, { status: 200, phrase: null },
      { status: 404, phrase: 'Not Found' }, { status: 404, phrase: 'Resource missing' },
      { status: 401, phrase: 'Unauthorized' }, { status: 304, phrase: null },
      { status: 599, phrase: 'Custom status' }, { status: null, phrase: null },
    ];

    expect(countHttpStatuses(exchanges)).toEqual([
      { key: '200', value: 2 }, { key: '404', value: 2 }, { key: '304', value: 1 },
      { key: '401', value: 1 }, { key: '599', value: 1 },
    ]);
  });
});
