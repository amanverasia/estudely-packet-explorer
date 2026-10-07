// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { File } from 'node:buffer';
import { gzipSync } from 'node:zlib';
import { describe, expect, it, vi } from 'vitest';
import { lookupLocalIp } from '../src/app/localIpData';
import { importLocalIpFile, importLocalIpStream, MAX_LOCAL_IP_CSV_BYTES } from '../src/app/localIpImport';

const csv = '\uFEFF1.1.1.0,1.1.1.255,1,"Café, ""ISP""\r\nnetwork"';
const file = (bytes: Uint8Array, name: string) => new File([new Uint8Array(bytes)], name) as unknown as globalThis.File;

describe('local IP import decoding', () => {
  it('decodes UTF-8 split inside multibyte characters and reports accepted rows', async () => {
    const bytes = new TextEncoder().encode(csv);
    let position = 0;
    const progress = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ pull(controller) {
      if (position === bytes.length) controller.close();
      else controller.enqueue(bytes.slice(position, ++position));
    } });
    const db = await importLocalIpStream(stream, 'asn', 'asn.csv', progress);
    expect(lookupLocalIp(db, '1.1.1.1')).toEqual({ kind: 'asn', asn: 1, organization: 'Café, "ISP"\r\nnetwork' });
    expect(progress).toHaveBeenLastCalledWith(bytes.length, 1);
    expect(stream.locked).toBe(false);
  });
  it('detects gzip by magic bytes and matches plain CSV', async () => {
    const plain = new TextEncoder().encode(csv);
    const a = await importLocalIpFile(file(plain, 'asn.csv'), 'asn');
    const b = await importLocalIpFile(file(gzipSync(plain), 'asn.csv.gz'), 'asn');
    expect({ ...a, importedAt: '' }).toEqual({ ...b, importedAt: '' });
  });
  it('rejects truncated gzip and invalid UTF-8', async () => {
    const compressed = gzipSync(csv);
    await expect(importLocalIpFile(file(compressed.subarray(0, compressed.length - 6), 'bad.gz'), 'asn')).rejects.toThrow();
    await expect(importLocalIpFile(file(new Uint8Array([0xff]), 'bad.csv'), 'asn')).rejects.toThrow();
  });
  it('cancels and unlocks malformed streams without masking the original error', async () => {
    const cancel = vi.fn(() => { throw new Error('cancel failed'); });
    const stream = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(new TextEncoder().encode('bad,range,US\n'));
    }, cancel });
    await expect(importLocalIpStream(stream, 'country', 'bad.csv')).rejects.toThrow('invalid IP range');
    expect(cancel).toHaveBeenCalledOnce();
    expect(stream.locked).toBe(false);
  });
  it('preserves the decompressed 150 MiB bound', async () => {
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(new Uint8Array(MAX_LOCAL_IP_CSV_BYTES + 1));
    }, cancel });
    await expect(importLocalIpStream(stream, 'country', 'large.csv')).rejects.toThrow('larger than 150 MB');
    expect(cancel).toHaveBeenCalledOnce();
    expect(stream.locked).toBe(false);
  });
  it('explains browsers without gzip decoding support', async () => {
    vi.stubGlobal('DecompressionStream', undefined);
    try {
      await expect(importLocalIpFile(file(gzipSync(csv), 'asn.gz'), 'asn')).rejects.toThrow('Download the plain CSV');
    } finally { vi.unstubAllGlobals(); }
  });
});
