// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { columnVisible, isColumnChoice } from '../src/app/columns';

describe('column visibility', () => {
  it('keeps primary columns and hides optional ones until chosen', () => {
    expect(columnVisible({ key: 'method' }, {})).toBe(true);
    expect(columnVisible({ key: 'version', choosable: true, defaultHidden: true }, {})).toBe(false);
    expect(columnVisible({ key: 'version', choosable: true, defaultHidden: true }, { version: true })).toBe(true);
    expect(columnVisible({ key: 'version', choosable: true }, { version: false })).toBe(false);
    expect(columnVisible({ key: 'country', hidden: true, choosable: true }, { country: true })).toBe(false);
  });

  it('rejects malformed saved choices', () => {
    expect(isColumnChoice({ version: true })).toBe(true);
    expect(isColumnChoice({ version: 'yes' })).toBe(false);
    expect(isColumnChoice(['version'])).toBe(false);
    expect(isColumnChoice(null)).toBe(false);
  });
});
