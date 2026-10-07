// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Reproducible local synthetic TCP test. Reports sampled JS usage and reserved
// WASM linear-memory capacity separately; samples are not a proven peak bound.
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const [mode, sizeText, capText] = process.argv.slice(2);
if (!mode) {
  for (const size of [1, 8, 32]) for (const cap of [512 * 1024, 64 * 1024 * 1024]) for (const method of ['baseline', 'improved']) {
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--expose-gc', fileURLToPath(import.meta.url), method, String(size), String(cap)], {
        cwd: root, stdio: 'inherit',
      });
      child.on('error', reject);
      child.on('exit', (code) => code === 0 ? resolve() : reject(new Error(`Measurement exited ${code}`)));
    });
  }
  process.exit();
}

function capture(size) {
  const records = [];
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6);
  global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20);
  let frame = 0;
  function packet(server, seq, ack, flags, length = 0) {
    const data = Buffer.alloc(54 + length, 0x78);
    data.fill(0, 0, 54);
    data.writeUInt16BE(0x0800, 12);
    data[14] = 0x45; data.writeUInt16BE(40 + length, 16); data[22] = 64; data[23] = 6;
    data.set(server ? [10, 0, 0, 80] : [10, 0, 0, 5], 26);
    data.set(server ? [10, 0, 0, 5] : [10, 0, 0, 80], 30);
    data.writeUInt16BE(server ? 9000 : 41000, 34); data.writeUInt16BE(server ? 41000 : 9000, 36);
    data.writeUInt32BE(seq, 38); data.writeUInt32BE(ack, 42); data[46] = 0x50; data[47] = flags;
    data.writeUInt16BE(65535, 48);
    // Correct IPv4 header checksum; TCP validation is disabled by default.
    let sum = 0;
    for (let i = 14; i < 34; i += 2) sum += data.readUInt16BE(i);
    while (sum >>> 16) sum = (sum & 65535) + (sum >>> 16);
    data.writeUInt16BE((~sum) & 65535, 24);
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1700000000 + Math.floor(frame / 1000), 0);
    record.writeUInt32LE((frame++ % 1000) * 1000, 4);
    record.writeUInt32LE(data.length, 8); record.writeUInt32LE(data.length, 12);
    records.push(record, data);
  }
  packet(false, 1000, 0, 2); packet(true, 2000, 1001, 18); packet(false, 1001, 2001, 16);
  for (let offset = 0; offset < size; offset += 1400) {
    const length = Math.min(1400, size - offset);
    packet(true, 2001 + offset, 1001, 24, length);
    packet(false, 1001, 2001 + offset + length, 16);
  }
  return Buffer.concat([global, ...records]);
}

const require = createRequire(import.meta.url);
const dist = join(dirname(require.resolve('@goodtools/wiregasm/package.json')), 'dist');
const loadWiregasm = require(join(dist, 'wiregasm.js'));
const lib = await loadWiregasm({ locateFile: (name) => join(dist, name), print: () => {}, printErr: () => {} });
if (!lib.init()) throw new Error('Wiregasm initialization failed');
const path = lib.getUploadDirectory() + '/follow-memory.pcap';
const size = Number(sizeText) * 1024 * 1024;
const cap = Number(capText);
lib.FS.writeFile(path, capture(size));
const session = new lib.DissectSession(path);
if (session.load().code !== 0) throw new Error('Synthetic capture did not load');
const vite = await createServer({
  root, configFile: false, server: { middlewareMode: true, hmr: false, ws: false }, appType: 'custom',
  optimizeDeps: { noDiscovery: true, include: [] },
});
const { collectFollowPayloads } = await vite.ssrLoadModule('/src/engine/follow-payloads.ts');
globalThis.gc?.();
await new Promise((resolve) => setImmediate(resolve));
globalThis.gc?.();
const start = process.memoryUsage();
const wasmStart = lib.HEAPU8.byteLength;
let heapPeak = start.heapUsed;
let arrayPeak = start.arrayBuffers;
function sample() {
  const current = process.memoryUsage();
  heapPeak = Math.max(heapPeak, current.heapUsed);
  arrayPeak = Math.max(arrayPeak, current.arrayBuffers);
}
const nativeAtob = globalThis.atob;
globalThis.atob = (encoded) => { const result = nativeAtob(encoded); sample(); return result; };
let decoded;
try {
  const followed = session.follow('TCP', 'tcp.stream eq 0');
  sample();
  const payloads = {
    size: () => followed.payloads.size(),
    get: (index) => { const result = followed.payloads.get(index); sample(); return result; },
    delete: () => followed.payloads.delete(),
  };
  if (mode === 'improved') {
    decoded = collectFollowPayloads(payloads, cap, cap === 512 * 1024 ? 5000 : 100000);
  } else {
    // The pre-change implementation: materialize all base64 records, decode
    // whole accepted records, then retain parts and concatenate a second copy.
    const all = Array.from({ length: payloads.size() }, (_, i) => payloads.get(i));
    payloads.delete();
    const parts = [];
    let length = 0;
    for (const payload of all) {
      if (length >= cap || parts.length >= (cap === 512 * 1024 ? 5000 : 100000)) break;
      const binary = atob(payload.data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const retained = bytes.subarray(0, Math.min(bytes.length, cap - length));
      parts.push(retained); length += retained.length; sample();
    }
    const data = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) { data.set(part, offset); offset += part.length; }
    sample();
    decoded = { data, totalSegments: all.length };
  }
  sample();
  if (decoded.data.length !== Math.min(size, cap)) throw new Error(`Wrong output: ${decoded.data.length}`);
  console.log(JSON.stringify({
    method: mode, streamMiB: Number(sizeText), capBytes: cap, outputBytes: decoded.data.length,
    segments: decoded.totalSegments, sampledJsHeapGrowthBytes: heapPeak - start.heapUsed,
    sampledJsArrayBufferGrowthBytes: arrayPeak - start.arrayBuffers,
    wasmCapacityBeforeBytes: wasmStart, wasmCapacityAfterBytes: lib.HEAPU8.byteLength,
  }));
} finally {
  globalThis.atob = nativeAtob;
  session.delete();
  await vite.close();
}
