// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { createLocalIpCsvParser, lookupLocalIp, parseLocalIpCsv } from '../src/app/localIpData';

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


describe('incremental local IP CSV parser', () => {
  const csv = '\uFEFFIP_START,IP_END,ASN,AS_NAME\r\n\r\n2001:db8::2,2001:db8::3,4294967295,"Café, ""quoted""\nnetwork"\r\n1.1.1.2,1.1.1.3,,\r\n1.1.1.0,1.1.1.1,AS42,"Café, ""quoted""\nnetwork"';
  it('keeps tokenizer state across every possible split, including one-character chunks', () => {
    const expected = parseLocalIpCsv('asn', csv, 'asn-2026_10.csv');
    for (let split = 0; split <= csv.length; split++) {
      const parser = createLocalIpCsvParser('asn', 'asn-2026_10.csv');
      parser.write(csv.slice(0, split));
      parser.write(csv.slice(split));
      expect({ ...parser.finish(), importedAt: '' }).toEqual({ ...expected, importedAt: '' });
    }
    const parser = createLocalIpCsvParser('asn', 'asn-2026_10.csv');
    for (const character of csv) parser.write(character);
    const result = parser.finish();
    expect(lookupLocalIp(result, '2001:db8::2')).toEqual({ kind: 'asn', asn: 4294967295, organization: 'Café, "quoted"\nnetwork' });
    expect(lookupLocalIp(result, '1.1.1.0')).toEqual({ kind: 'asn', asn: 42, organization: 'Café, "quoted"\nnetwork' });
    expect(lookupLocalIp(result, '1.1.1.2')).toBeNull();
  });
  it('supports escaped quotes, CRLF, final quoted fields, and headerless country data', () => {
    for (const input of ['1.1.1.0,1.1.1.1,us', '\uFEFF1.1.1.0,1.1.1.1,"us"\r\n']) {
      const parser = createLocalIpCsvParser('country', 'country.csv');
      for (const character of input) parser.write(character);
      expect(lookupLocalIp(parser.finish(), '1.1.1.1')).toEqual({ kind: 'country', country: 'US' });
    }
    const parser = createLocalIpCsvParser('asn', 'asn.csv');
    for (const character of '1.1.1.0,1.1.1.1,1,"a""b"') parser.write(character);
    expect(lookupLocalIp(parser.finish(), '1.1.1.0')).toEqual({ kind: 'asn', asn: 1, organization: 'a"b' });
  });
  it.each([
    ['', 'no IP ranges'], ['\r\n', 'no IP ranges'],
    ['1.1.1.0,1.1.1.1,1,"unclosed', 'unclosed quoted field'],
    ['1.1.1.0,1.1.1.1,4294967296,x', 'invalid AS number'],
    ['1.1.1.0,1.1.1.1,-1,x', 'invalid AS number'],
    ['1.1.1.0,1.1.1.1,1,x,extra', 'CSV format'],
    ['ip_start,ip_end,asn,wrong\n1.1.1.0,1.1.1.1,1,x', 'not a DB-IP Lite ASN'],
    ['2001:db8::2,2001:db8::1,1,x', 'reversed IP range'],
    ['2001:db8::2,2001:db8::3,1,x\n2001:db8::1,2001:db8::2,2,y', 'overlapping IP ranges'],
  ])('preserves streamed validation for %s', (input, message) => {
    const parser = createLocalIpCsvParser('asn', 'asn.csv');
    expect(() => { for (const char of input) parser.write(char); parser.finish(); }).toThrow(message);
  });
  it('packs multiple typed blocks and preserves row metadata when sorting', () => {
    const parser = createLocalIpCsvParser('asn', 'asn.csv');
    for (let i = 16_385; i >= 0; i--) {
      const ip = `1.${Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}`;
      parser.write(`${ip},${ip},${i + 1},org-${i % 3}\n`);
    }
    const result = parser.finish();
    expect(result.ipv4Start.length).toBe(16_386);
    expect(lookupLocalIp(result, '1.0.64.1')).toEqual({ kind: 'asn', asn: 16_386, organization: 'org-2' });
    expect(lookupLocalIp(result, '1.0.0.0')).toEqual({ kind: 'asn', asn: 1, organization: 'org-0' });
  });
});


it.each(['organization_name', 'as_organization', 'as_name'])('accepts case-insensitive ASN header alias %s', (alias) => {
  const parser = createLocalIpCsvParser('asn', 'asn.csv');
  parser.write(`IP_START,IP_END,AS_NUMBER,${alias.toUpperCase()}\n1.1.1.0,1.1.1.1,4294967295,ISP`);
  expect(lookupLocalIp(parser.finish(), '1.1.1.1')).toEqual({ kind: 'asn', asn: 4294967295, organization: 'ISP' });
});

it('rejects malformed country columns and codes in streaming mode', () => {
  for (const csv of ['1.1.1.0,1.1.1.1,USA', '1.1.1.0,1.1.1.1,1,ISP']) {
    const parser = createLocalIpCsvParser('country', 'country.csv');
    expect(() => { parser.write(csv); parser.finish(); }).toThrow();
  }
});
