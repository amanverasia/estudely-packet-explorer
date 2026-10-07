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

// Fixed blocks avoid ordinary number arrays and geometric growth copies.
const RANGE_BLOCK_ROWS = 16_384;
type RangeBlock = { start: Uint32Array; end: Uint32Array; value: Uint32Array; asn: Uint32Array };

class RangeBuilder {
  private blocks: RangeBlock[] = [];
  private length = 0;
  private sorted = true;
  constructor(private width: number) {}

  add(start: number[], end: number[], value: number, asn: number) {
    const position = this.length % RANGE_BLOCK_ROWS;
    if (position === 0) this.blocks.push({
      start: new Uint32Array(RANGE_BLOCK_ROWS * this.width), end: new Uint32Array(RANGE_BLOCK_ROWS * this.width),
      value: new Uint32Array(RANGE_BLOCK_ROWS), asn: new Uint32Array(RANGE_BLOCK_ROWS),
    });
    if (this.length) {
      const previous = this.length - 1;
      const previousBlock = this.blocks[Math.floor(previous / RANGE_BLOCK_ROWS)];
      if (compareAt(previousBlock.start, previous % RANGE_BLOCK_ROWS * this.width, start) > 0) this.sorted = false;
    }
    const block = this.blocks[this.blocks.length - 1];
    block.start.set(start, position * this.width);
    block.end.set(end, position * this.width);
    block.value[position] = value;
    block.asn[position] = asn;
    this.length++;
  }

  finish(): RangeBlock {
    const { length, width } = this;
    const output = {
      start: new Uint32Array(length * width), end: new Uint32Array(length * width),
      value: new Uint32Array(length), asn: new Uint32Array(length),
    };
    let order: Uint32Array | undefined;
    if (!this.sorted) {
      order = new Uint32Array(length);
      for (let i = 0; i < length; i++) order[i] = i;
      sortRangeOrder(order, (a, b) => {
        const blockA = this.blocks[Math.floor(a / RANGE_BLOCK_ROWS)];
        const blockB = this.blocks[Math.floor(b / RANGE_BLOCK_ROWS)];
        return compareFlat(blockA.start, a % RANGE_BLOCK_ROWS * width, blockB.start, b % RANGE_BLOCK_ROWS * width, width);
      });
    }
    for (let sorted = 0; sorted < length; sorted++) {
      const source = order ? order[sorted] : sorted;
      const block = this.blocks[Math.floor(source / RANGE_BLOCK_ROWS)];
      const sourceOffset = (source % RANGE_BLOCK_ROWS) * width, targetOffset = sorted * width;
      if (sorted && compareFlat(output.end, targetOffset - width, block.start, sourceOffset, width) >= 0) {
        throw new Error('The CSV contains overlapping IP ranges and cannot be imported safely.');
      }
      output.start.set(block.start.subarray(sourceOffset, sourceOffset + width), targetOffset);
      output.end.set(block.end.subarray(sourceOffset, sourceOffset + width), targetOffset);
      output.value[sorted] = block.value[source % RANGE_BLOCK_ROWS];
      output.asn[sorted] = block.asn[source % RANGE_BLOCK_ROWS];
    }
    this.blocks = [];
    return output;
  }
}

/** In-place heapsort keeps fallback scratch constant (native comparator sorts may allocate).
 * Only the typed permutation moves; all four range columns remain associated. */
function sortRangeOrder(order: Uint32Array, compare: (a: number, b: number) => number) {
  const sift = (root: number, length: number) => {
    for (;;) {
      let child = root * 2 + 1;
      if (child >= length) return;
      if (child + 1 < length && compare(order[child], order[child + 1]) < 0) child++;
      if (compare(order[root], order[child]) >= 0) return;
      const value = order[root]; order[root] = order[child]; order[child] = value;
      root = child;
    }
  };
  for (let root = Math.floor(order.length / 2) - 1; root >= 0; root--) sift(root, order.length);
  for (let end = order.length - 1; end > 0; end--) {
    const value = order[0]; order[0] = order[end]; order[end] = value;
    sift(0, end);
  }
}

/** Consume decoded CSV chunks without retaining the whole input. */
export function createLocalIpCsvParser(kind: LocalIpDataKind, fileName: string) {
  const v4 = new RangeBuilder(1), v6 = new RangeBuilder(4);
  const valueIds = new Map<string, number>();
  const values: string[] = [];
  let count = 0;
  let columns: Map<string, number> | null = null;
  let finished = false;
  const tokenizer = new CsvTokenizer((fields) => {
    if (fields.length === 1 && !fields[0].trim()) return;
    if (!columns && fields[0]?.trim().toLowerCase() === 'ip_start') {
      columns = new Map(fields.map((field, i) => [field.trim().toLowerCase(), i]));
      return;
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
    target.add(start.words, end.words, valueId, asn);
    count++;
  });
  return {
    get recordCount() { return count; },
    write(text: string) {
      if (finished) throw new Error('The CSV parser has already finished.');
      tokenizer.write(text);
    },
    finish(): LocalIpDatabase {
      if (finished) throw new Error('The CSV parser has already finished.');
      finished = true;
      tokenizer.finish();
      if (count === 0) throw new Error('The selected CSV contains no IP ranges.');
      const a4 = v4.finish(), a6 = v6.finish();
      valueIds.clear();
      const releaseMatch = /(?:^|[^\d])(20\d{2})[-_](0[1-9]|1[0-2])(?:[^\d]|$)/.exec(fileName);
      return {
        schema: 1, kind, release: releaseMatch ? `${releaseMatch[1]}-${releaseMatch[2]}` : null,
        importedAt: new Date().toISOString(), recordCount: count, values,
        ipv4Start: a4.start, ipv4End: a4.end, ipv4Value: a4.value, ipv4Asn: a4.asn,
        ipv6Start: a6.start, ipv6End: a6.end, ipv6Value: a6.value, ipv6Asn: a6.asn,
      };
    },
  };
}

/** Compatibility wrapper; file imports use the incremental parser directly. */
export function parseLocalIpCsv(kind: LocalIpDataKind, csv: string, fileName: string): LocalIpDatabase {
  const parser = createLocalIpCsvParser(kind, fileName);
  parser.write(csv);
  return parser.finish();
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

/** RFC 4180 state survives quoted newlines, escaped quotes, CRLF and chunk boundaries. */
class CsvTokenizer {
  private row: string[] = [];
  private field = '';
  private quoted = false;
  private quotePending = false;
  private skipLf = false;
  private first = true;
  constructor(private accept: (fields: string[]) => void) {}

  write(text: string) {
    const delimiters = /[,"\r\n]/g;
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      if (this.first) {
        this.first = false;
        if (char === '\uFEFF') continue;
      }
      if (this.skipLf) {
        this.skipLf = false;
        if (char === '\n') continue;
      }
      if (this.quotePending) {
        this.quotePending = false;
        if (char === '"') { this.field += '"'; continue; }
        this.quoted = false;
      }
      if (this.quoted) {
        if (char === '"') this.quotePending = true;
        else {
          const quote = text.indexOf('"', i);
          const end = quote < 0 ? text.length : quote;
          this.field += text.slice(i, end);
          i = end - 1;
        }
      } else if (char === '"' && this.field.length === 0) this.quoted = true;
      else if (char === ',') { this.row.push(this.field); this.field = ''; }
      else if (char === '\n' || char === '\r') {
        this.row.push(this.field);
        this.accept(this.row);
        this.row = [];
        this.field = '';
        this.skipLf = char === '\r';
      } else {
        delimiters.lastIndex = i + 1;
        const end = delimiters.exec(text)?.index ?? text.length;
        this.field += text.slice(i, end);
        i = end - 1;
      }
    }
  }

  finish() {
    if (this.quoted && !this.quotePending) throw new Error('The CSV has an unclosed quoted field.');
    if (this.field || this.row.length) { this.row.push(this.field); this.accept(this.row); }
    this.row = [];
    this.field = '';
  }
}
