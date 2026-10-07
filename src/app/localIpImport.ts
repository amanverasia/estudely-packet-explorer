// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { createLocalIpCsvParser, type LocalIpDataKind } from './localIpData';

export const MAX_LOCAL_IP_CSV_BYTES = 150 * 1024 * 1024;

/** Decode and validate locally; cancel failed streams and always release their reader. */
export async function importLocalIpStream(
  stream: ReadableStream<Uint8Array>, kind: LocalIpDataKind, fileName: string,
  progress?: (bytes: number, rows: number) => void,
) {
  const reader = stream.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const parser = createLocalIpCsvParser(kind, fileName);
  let bytes = 0, lastProgress = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_LOCAL_IP_CSV_BYTES) {
        throw new Error('The unpacked CSV is larger than 150 MB. Choose a DB-IP Lite Country or ASN CSV file.');
      }
      parser.write(decoder.decode(value, { stream: true }));
      if (performance.now() - lastProgress >= 250) {
        progress?.(bytes, parser.recordCount);
        lastProgress = performance.now();
      }
    }
    parser.write(decoder.decode());
    const database = parser.finish();
    progress?.(bytes, database.recordCount);
    return database;
  } catch (error) {
    // Cancellation errors must not hide the actionable decode/CSV error.
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

export async function importLocalIpFile(
  file: File, kind: LocalIpDataKind, progress?: (bytes: number, rows: number) => void,
) {
  const magic = new Uint8Array(await file.slice(0, 2).arrayBuffer());
  let stream: ReadableStream<Uint8Array> = file.stream();
  if (magic[0] === 0x1f && magic[1] === 0x8b) {
    if (typeof DecompressionStream === 'undefined') throw new Error('This browser cannot unpack a gzip CSV. Download the plain CSV file instead.');
    stream = stream.pipeThrough(new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>);
  }
  return importLocalIpStream(stream, kind, file.name, progress);
}
