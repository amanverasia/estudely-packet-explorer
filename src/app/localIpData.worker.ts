/// <reference lib="webworker" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { parseLocalIpCsv, type LocalIpDataKind } from './localIpData';

declare const self: DedicatedWorkerGlobalScope;

type RequestMessage = { file: File; kind: LocalIpDataKind };

self.onmessage = async (event: MessageEvent<RequestMessage>) => {
  try {
    const { file, kind } = event.data;
    const magic = new Uint8Array(await file.slice(0, 2).arrayBuffer());
    const compressed = magic[0] === 0x1f && magic[1] === 0x8b;
    let stream: ReadableStream<Uint8Array> = file.stream();
    if (compressed) {
      if (typeof DecompressionStream === 'undefined') throw new Error('This browser cannot unpack a gzip CSV. Download the plain CSV file instead.');
      const decompressor = new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>;
      stream = stream.pipeThrough(decompressor);
    }
    self.postMessage({ type: 'progress', message: compressed ? 'Unpacking the selected database…' : 'Reading the selected database…' });
    const reader = stream.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const chunks: string[] = [];
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 150 * 1024 * 1024) {
        await reader.cancel();
        throw new Error('The unpacked CSV is larger than 150 MB. Choose a DB-IP Lite Country or ASN CSV file.');
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    self.postMessage({ type: 'progress', message: 'Checking IP ranges and building the local index…' });
    const database = parseLocalIpCsv(kind, chunks.join(''), file.name);
    const transfer = [
      database.ipv4Start.buffer, database.ipv4End.buffer, database.ipv4Value.buffer, database.ipv4Asn.buffer,
      database.ipv6Start.buffer, database.ipv6End.buffer, database.ipv6Value.buffer, database.ipv6Asn.buffer,
    ];
    self.postMessage({ type: 'complete', database }, transfer);
  } catch (error) {
    self.postMessage({ type: 'error', message: error instanceof Error ? error.message : String(error) });
  }
};
