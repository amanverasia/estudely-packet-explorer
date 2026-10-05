// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { addressScope, isGloballyReachable, parseIpAddress } from '../src/engine/address-scope';

describe('IANA-based address classification', () => {
  it('uses the most-specific IPv4 registration and gates special-purpose lookups', () => {
    expect(addressScope('192.0.0.9')).toBe('Port Control Protocol anycast');
    expect(isGloballyReachable('192.0.0.9')).toBe(true);
    expect(isGloballyReachable('192.0.0.10')).toBe(true);
    expect(isGloballyReachable('192.0.0.8')).toBe(false);
    expect(isGloballyReachable('192.0.0.170')).toBe(false);
    expect(isGloballyReachable('192.0.0.20')).toBe(false);
    expect(addressScope('198.18.0.1')).toBe('benchmarking');
    expect(isGloballyReachable('198.18.0.1')).toBe(false);
    expect(addressScope('100.64.0.1')).toBe('shared (CGNAT)');
    expect(isGloballyReachable('1.1.1.1')).toBe(true);
    expect(isGloballyReachable('224.0.0.1')).toBe(false);
  });

  it('matches expanded IPv6 and honors nested globally-reachable exceptions', () => {
    const expandedDocumentation = '2001:0db8:0000:0000:0000:0000:0000:0001';
    expect(addressScope(expandedDocumentation)).toBe('documentation');
    expect(isGloballyReachable(expandedDocumentation)).toBe(false);
    expect(addressScope('2001:0000:0000:0000:0000:0000:0000:0001')).toBe('Teredo');
    expect(isGloballyReachable('2001:0000:0000:0000:0000:0000:0000:0001')).toBe(false);
    expect(isGloballyReachable('2001:100::1')).toBe(false); // IANA 2001::/23, except specific true entries.
    expect(isGloballyReachable('2001:1::1')).toBe(true);
    expect(isGloballyReachable('2001:2::1')).toBe(false);
    expect(isGloballyReachable('2001:3::1')).toBe(true);
    expect(isGloballyReachable('64:ff9b::1')).toBe(true);
    expect(isGloballyReachable('64:ff9b:1::1')).toBe(false);
    expect(isGloballyReachable('2001:4860:4860::8888')).toBe(true);
    expect(addressScope('2001:1000::1')).toBe('global');
    expect(isGloballyReachable('2001:1000::1')).toBe(true);
    expect(isGloballyReachable('2002::1')).toBe(false); // IANA special-purpose Globally Reachable is N/A for 6to4.
    expect(addressScope('fc00::1')).toBe('unique local');
    expect(addressScope('ff02::1')).toBe('multicast');
    expect(isGloballyReachable('4000::1')).toBe(false);
  });

  it('rejects malformed literals and keeps invalid addresses ineligible', () => {
    for (const address of ['300.1.1.1', '192.0.2', '2001:::1', '2001:db8::1%eth0', 'not-an-address']) {
      expect(parseIpAddress(address)).toBeNull();
      expect(addressScope(address)).toBe('unknown');
      expect(isGloballyReachable(address)).toBe(false);
    }
    expect(parseIpAddress('0.0.0.0')).toEqual({ version: 4, words: [0] });
    expect(parseIpAddress('2001:db8:0:0:0:0:0:1')?.version).toBe(6);
    expect(parseIpAddress('::ffff:192.0.2.1')?.version).toBe(6);
  });
});
