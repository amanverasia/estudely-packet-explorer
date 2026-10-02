// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

export type LocalIpDataKind = 'country' | 'asn';

/** Compact range indexes for a DB-IP Lite CSV, stored only in this browser. */
export interface LocalIpDatabase {
  schema: 1;
  kind: LocalIpDataKind;
  release: string | null;
  importedAt: string;
  recordCount: number;
  values: string[];
  ipv4Start: Uint32Array;
  ipv4End: Uint32Array;
  ipv4Value: Uint32Array;
  ipv4Asn: Uint32Array;
  // Each IPv6 address has four unsigned 32-bit words, most significant first.
  ipv6Start: Uint32Array;
  ipv6End: Uint32Array;
  ipv6Value: Uint32Array;
  ipv6Asn: Uint32Array;
}

export type LocalIpMatch =
  | { kind: 'country'; country: string }
  | { kind: 'asn'; asn: number; organization: string };

type RangeArrays = {
  start: number[];
  end: number[];
  value: number[];
  asn: number[];
};

/** Parse a DB-IP Lite Country or ASN CSV entirely in local memory. */
export function parseLocalIpCsv(kind: LocalIpDataKind, csv: string, fileName: string): LocalIpDatabase {
  const v4: RangeArrays = { start: [], end: [], value: [], asn: [] };
  const v6: RangeArrays = { start: [], end: [], value: [], asn: [] };
  const valueIds = new Map<string, number>();
  const values: string[] = [];
  let count = 0;
  let columns: Map<string, number> | null = null;

  for (const fields of csvRows(csv)) {
    if (fields.length === 1 && !fields[0].trim()) continue;
    if (!columns && fields[0]?.trim().toLowerCase() === 'ip_start') {
      columns = new Map(fields.map((field, i) => [field.trim().toLowerCase(), i]));
      continue;
    }
    const col = (name: string, fallback: number) => columns?.get(name) ?? fallback;
    const start = parseIp(fields[col('ip_start', 0)]?.trim() ?? '');
    const end = parseIp(fields[col('ip_end', 1)]?.trim() ?? '');
    if (!start || !end || start.version !== end.version) {
      throw new Error(`Row ${count + 1} has an invalid IP range.`);
    }
    const target = start.version === 4 ? v4 : v6;
    const expectedFields = kind === 'country' ? 3 : 4;
    if (fields.length !== expectedFields) throw new Error(`Row ${count + 1} does not match the DB-IP Lite ${kind} CSV format.`);
    if (compareWords(start.words, end.words) > 0) throw new Error(`Row ${count + 1} has a reversed IP range.`);

    let label: string;
    let asn = 0;
    if (kind === 'country') {
      label = (fields[col('country', 2)] ?? '').trim().toUpperCase();
      if (!/^[A-Z]{2}$/.test(label)) throw new Error(`Row ${count + 1} has an invalid country code.`);
    } else {
      const asnColumn = columns?.get('as_number') ?? columns?.get('asn') ?? 2;
      const organizationColumn = columns?.get('organization_name') ?? columns?.get('as_organization') ?? columns?.get('as_name') ?? 3;
      const asnText = (fields[asnColumn] ?? '').trim().replace(/^AS/i, '');
      asn = asnText ? Number(asnText) : 0;
      label = (fields[organizationColumn] ?? '').trim();
      if ((asnText !== '' && !/^\d{1,10}$/.test(asnText)) || !Number.isSafeInteger(asn) || asn < 0 || asn > 0xffff_ffff) {
        throw new Error(`Row ${count + 1} has an invalid AS number.`);
      }
      const headerColumns = columns;
      if (headerColumns && !['organization_name', 'as_organization', 'as_name'].some((name) => headerColumns.has(name))) {
        throw new Error('This is not a DB-IP Lite ASN CSV file.');
      }
    }

    let valueId = valueIds.get(label);
    if (valueId === undefined) {
      valueId = values.length;
      values.push(label);
      valueIds.set(label, valueId);
    }
    target.start.push(...start.words);
    target.end.push(...end.words);
    target.value.push(valueId);
    target.asn.push(asn);
    count++;
  }
  if (count === 0) throw new Error('The selected CSV contains no IP ranges.');

  const pack = (input: RangeArrays, width: number) => {
    const length = input.value.length;
    if (input.start.length !== length * width || input.end.length !== length * width) throw new Error('The CSV contains an incomplete IP range.');
    const order = Array.from({ length }, (_, i) => i);
    order.sort((a, b) => compareFlat(input.start, a * width, input.start, b * width, width));
    const starts = new Uint32Array(length * width), ends = new Uint32Array(length * width);
    const value = new Uint32Array(length), asn = new Uint32Array(length);
    for (let sorted = 0; sorted < length; sorted++) {
      const source = order[sorted];
      const sourceOffset = source * width, targetOffset = sorted * width;
      if (sorted && compareFlat(ends, targetOffset - width, input.start, sourceOffset, width) >= 0) {
        throw new Error('The CSV contains overlapping IP ranges and cannot be imported safely.');
      }
      for (let i = 0; i < width; i++) {
        starts[targetOffset + i] = input.start[sourceOffset + i];
        ends[targetOffset + i] = input.end[sourceOffset + i];
      }
      value[sorted] = input.value[source];
      asn[sorted] = input.asn[source];
    }
    return {
      start: starts,
      end: ends,
      value,
      asn,
    };
  };
  const a4 = pack(v4, 1), a6 = pack(v6, 4);
  const releaseMatch = /(?:^|[^\d])(20\d{2})[-_](0[1-9]|1[0-2])(?:[^\d]|$)/.exec(fileName);
  return {
    schema: 1,
    kind,
    release: releaseMatch ? `${releaseMatch[1]}-${releaseMatch[2]}` : null,
    importedAt: new Date().toISOString(),
    recordCount: count,
    values,
    ipv4Start: a4.start,
    ipv4End: a4.end,
    ipv4Value: a4.value,
    ipv4Asn: a4.asn,
    ipv6Start: a6.start,
    ipv6End: a6.end,
    ipv6Value: a6.value,
    ipv6Asn: a6.asn,
  };
}

export function lookupLocalIp(db: LocalIpDatabase, address: string): LocalIpMatch | null {
  const parsed = parseIp(address);
  if (!parsed) return null;
  const isV4 = parsed.version === 4;
  const starts = isV4 ? db.ipv4Start : db.ipv6Start;
  const ends = isV4 ? db.ipv4End : db.ipv6End;
  const ids = isV4 ? db.ipv4Value : db.ipv6Value;
  const asns = isV4 ? db.ipv4Asn : db.ipv6Asn;
  const width = isV4 ? 1 : 4;
  let lo = 0, hi = ids.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (compareAt(starts, mid * width, parsed.words) <= 0) lo = mid + 1;
    else hi = mid;
  }
  const index = lo - 1;
  if (index < 0 || compareAt(ends, index * width, parsed.words) < 0) return null;
  if (db.kind === 'country') return { kind: 'country', country: db.values[ids[index]] };
  if (asns[index] === 0) return null;
  return { kind: 'asn', asn: asns[index], organization: db.values[ids[index]] };
}

type ParsedIp = { version: 4 | 6; words: number[] };

function parseIp(address: string): ParsedIp | null {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (v4) {
    const bytes = v4.slice(1).map(Number);
    if (bytes.some((n) => n > 255)) return null;
    return { version: 4, words: [bytes[0] * 0x1_00_00_00 + bytes[1] * 0x1_00_00 + bytes[2] * 0x100 + bytes[3]] };
  }
  if (!address.includes(':') || address.includes('%')) return null;
  let input = address.toLowerCase();
  const mapped = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(input);
  if (mapped) {
    const parsedV4 = parseIp(mapped[2]);
    if (!parsedV4) return null;
    const n = parsedV4.words[0];
    input = `${mapped[1]}${((n / 0x1_0000) >>> 0).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const hextets = [...left, ...Array(missing).fill('0'), ...right];
  if (hextets.length !== 8 || hextets.some((part) => !/^[\da-f]{1,4}$/.test(part))) return null;
  const words = [];
  for (let i = 0; i < hextets.length; i += 2) words.push((parseInt(hextets[i], 16) * 0x1_0000 + parseInt(hextets[i + 1], 16)) >>> 0);
  return { version: 6, words };
}

function compareWords(a: number[], b: number[]): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

function compareAt(data: Uint32Array, offset: number, words: number[]): number {
  for (let i = 0; i < words.length; i++) {
    if (data[offset + i] !== words[i]) return data[offset + i] < words[i] ? -1 : 1;
  }
  return 0;
}

function compareFlat(a: number[] | Uint32Array, offsetA: number, b: number[] | Uint32Array, offsetB: number, width: number): number {
  for (let i = 0; i < width; i++) {
    if (a[offsetA + i] !== b[offsetB + i]) return a[offsetA + i] < b[offsetB + i] ? -1 : 1;
  }
  return 0;
}

function* csvRows(text: string): Generator<string[]> {
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field.length === 0) quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[i + 1] === '\n') i++;
      row.push(field.replace(/^\uFEFF/, ''));
      yield row;
      row = [];
      field = '';
    } else field += char;
  }
  if (quoted) throw new Error('The CSV has an unclosed quoted field.');
  if (field || row.length) { row.push(field); yield row; }
}
