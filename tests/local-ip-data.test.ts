// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { lookupLocalIp, parseLocalIpCsv } from '../src/app/localIpData';

describe('local DB-IP Lite CSV indexes', () => {
  it('looks up IPv4 and IPv6 country ranges and returns no result outside them', () => {
    const db = parseLocalIpCsv('country', [
      'ip_start,ip_end,country',
      '1.1.1.0,1.1.1.255,AU',
      '8.8.8.0,8.8.8.255,US',
      '2001:4860::,2001:4860::ffff,US',
    ].join('\n'), 'dbip-country-lite-2026-10.csv');

    expect(lookupLocalIp(db, '1.1.1.1')).toEqual({ kind: 'country', country: 'AU' });
    expect(lookupLocalIp(db, '8.8.8.255')).toEqual({ kind: 'country', country: 'US' });
    expect(lookupLocalIp(db, '2001:4860::1')).toEqual({ kind: 'country', country: 'US' });
    expect(lookupLocalIp(db, '9.9.9.9')).toBeNull();
    expect(lookupLocalIp(db, '192.168.1.1')).toBeNull();
    expect(db.release).toBe('2026-10');
  });

  it('parses quoted organization names and AS numbers', () => {
    const db = parseLocalIpCsv('asn', [
      'ip_start,ip_end,as_number,organization_name',
      '8.8.8.0,8.8.8.255,15169,"Google, LLC"',
      '2001:4860::,2001:4860::ffff,15169,"Google, LLC"',
    ].join('\n'), 'asn.csv');

    expect(lookupLocalIp(db, '8.8.8.8')).toEqual({ kind: 'asn', asn: 15169, organization: 'Google, LLC' });
    expect(lookupLocalIp(db, '2001:4860::10')).toEqual({ kind: 'asn', asn: 15169, organization: 'Google, LLC' });
  });

  it('treats rows without an assigned AS as unavailable', () => {
    const db = parseLocalIpCsv('asn', '1.1.1.0,1.1.1.255,,', 'asn.csv');
    expect(lookupLocalIp(db, '1.1.1.1')).toBeNull();
  });

  it('rejects malformed, reversed, and overlapping ranges, and sorts valid ranges', () => {
    expect(() => parseLocalIpCsv('country', 'not-an-ip,8.8.8.255,US', 'x.csv')).toThrow('invalid IP range');
    expect(() => parseLocalIpCsv('country', '8.8.8.8,8.8.8.1,US', 'x.csv')).toThrow('reversed IP range');
    expect(() => parseLocalIpCsv('country', '8.8.8.0,8.8.8.255,US\n8.8.8.128,8.8.9.0,CA', 'x.csv')).toThrow('overlapping IP ranges');
    const unordered = parseLocalIpCsv('country', '8.8.8.0,8.8.8.255,US\n1.1.1.0,1.1.1.255,AU', 'x.csv');
    expect(lookupLocalIp(unordered, '1.1.1.1')).toEqual({ kind: 'country', country: 'AU' });
  });
});
