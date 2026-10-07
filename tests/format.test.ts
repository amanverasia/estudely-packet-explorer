// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { decimalLiteral, duration, editableSeconds, parseEditableSeconds } from '../src/app/format';

describe('editable time and duration formatting', () => {
  it('formats millisecond and nanosecond bounds without float tails or exponent notation', () => {
    const cutEnd = 0.019999999999999997;
    const tinyEnd = 7.890000000010389e-7;

    expect(editableSeconds(cutEnd, 2)).toBe('0.02');
    expect(editableSeconds(tinyEnd, 9)).toBe('0.000000789');
    expect(parseEditableSeconds('0.02', '0.02', cutEnd)).toBe(cutEnd);
    expect(parseEditableSeconds('0.000000700', '0.000000789', tinyEnd)).toBe(0.0000007);
    expect(decimalLiteral(tinyEnd)).toBe('0.0000007890000000010389');
    expect(Number(decimalLiteral(tinyEnd))).toBe(tinyEnd);
  });

  it('uses consistent precision near unit thresholds and preserves negative values', () => {
    expect(duration(0.01)).toBe('10 ms');
    expect(duration(0.009999999999999998)).toBe('10 ms');
    expect(duration(0.999999999)).toBe('1 s');
    expect(duration(59.9999999)).toBe('1 min 0 s');
    expect(duration(3599.9999)).toBe('1 h 0 min');
    expect(duration(86399.9999)).toBe('1 d 0 h');
    expect(duration(-0.000001234)).toBe('-1.234 µs');
  });
});
