/// <reference lib="webworker" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Analysis worker: hosts Wiregasm (Wireshark WASM) and one capture session.
// The capture never leaves this worker except as aggregated results posted
// back to the page. A new worker is created for every capture and terminated
// on close/cancel, which releases all WASM memory.
import extractorSource from '../engine/extractor.lua?raw';
import { CaptureSession, installExtractor, type WiregasmModule } from '../engine/session';
import type { FromWorker, ToWorker, WorkerRequest } from './protocol';
import { postWithModule } from './compat';

declare const self: DedicatedWorkerGlobalScope;

let lib: (WiregasmModule & { wiresharkVersion(): string }) | null = null;
let session: CaptureSession | null = null;
let engineReady: Promise<void> | null = null;
let wiregasmVersion = 'unknown';

const post = (m: FromWorker, transfer: Transferable[] = []) => self.postMessage(m, transfer);

async function fetchBytes(url: string, label: string): Promise<ArrayBuffer> {
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error(`Could not load ${label} (${res.status} ${res.statusText}) from ${url}`);
  const total = Number(res.headers.get('content-length')) || 0;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    got += value.length;
    post({ type: 'progress', progress: { phase: 'engine', fraction: total ? Math.min(1, got / total) : null, message: `Downloading ${label}… ${(got / 1e6).toFixed(1)} MB` } });
  }
  const buf = new Uint8Array(got);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  // Shipped gzip-compressed. Some servers already decode .gz transparently,
  // so only decompress when the gzip magic bytes are still present.
  if (buf[0] === 0x1f && buf[1] === 0x8b) {
    // The page checks for this before starting a worker; this guards the worker on its own.
    if (typeof DecompressionStream === 'undefined') throw new Error('This browser does not support DecompressionStream, which is needed to unpack the Wireshark engine.');
    const stream = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
    return await new Response(stream).arrayBuffer();
  }
  return buf.buffer;
}

async function initEngine(base: string, cachedModule: WebAssembly.Module | null, cachedData: ArrayBuffer | null): Promise<void> {
  try {
    wiregasmVersion = (await (await fetch(base + 'manifest.json')).json()).version ?? 'unknown';
  } catch { /* optional */ }
  const { default: loadWiregasm } = await import(/* @vite-ignore */ base + 'wiregasm.mjs');
  let wasmModule = cachedModule;
  if (!wasmModule) {
    const bytes = await fetchBytes(base + 'wiregasm.wasm.gz', 'Wireshark engine');
    post({ type: 'progress', progress: { phase: 'engine', fraction: null, message: 'Compiling Wireshark engine…' } });
    wasmModule = await WebAssembly.compile(bytes);
  }
  const data = cachedData ?? (await fetchBytes(base + 'wiregasm.data.gz', 'engine data'));
  post({ type: 'progress', progress: { phase: 'engine', fraction: null, message: 'Starting Wireshark engine…' } });
  const module = wasmModule;
  lib = await loadWiregasm({
    locateFile: (p: string) => base + p,
    instantiateWasm(imports: WebAssembly.Imports, done: (inst: WebAssembly.Instance, mod: WebAssembly.Module) => void) {
      WebAssembly.instantiate(module, imports).then((inst) => done(inst, module));
      return {};
    },
    getPreloadedPackage: () => data.slice(0),
    print: (line: string) => session?.handlePrint(line),
    printErr: () => {},
    handleStatus: () => {},
  });
  installExtractor(lib!, extractorSource);
  if (!lib!.init()) throw new Error('The Wireshark engine failed to initialise.');
  const ready: Extract<FromWorker, { type: 'engine-ready' }> = { type: 'engine-ready', wasmModule: module, data, versions: { wireshark: lib!.wiresharkVersion(), wiregasm: wiregasmVersion } };
  // Without the module the page still works; the next worker compiles its own.
  postWithModule((m) => post(m), ready);
}

function handle(req: WorkerRequest): unknown {
  if (!session) throw new Error('No capture is open.');
  switch (req.kind) {
    case 'frame': return session.frame(req.number);
    case 'packetList': return session.packetList(req.filter, req.skip, req.limit);
    case 'checkFilter': return session.checkFilter(req.filter);
    case 'rows': return session.rows(req);
    case 'follow': return session.follow(req.transport, req.stream, req);
    case 'exportObjects': return session.exportObjects();
    case 'downloadObject': return session.downloadExportObject(req.token);
  }
}

self.onmessage = async (ev: MessageEvent<ToWorker>) => {
  const msg = ev.data;
  if (msg.type === 'init') {
    engineReady = initEngine(msg.base, msg.wasmModule, msg.data).catch((e) => {
      post({ type: 'error', stage: 'engine', message: e instanceof Error ? e.message : String(e) });
      throw e;
    });
    return;
  }
  if (msg.type === 'open') {
    try {
      await engineReady;
    } catch {
      return;
    }
    try {
      post({ type: 'progress', progress: { phase: 'read', fraction: null, message: 'Reading file from your device…' } });
      const bytes = new Uint8Array(await msg.file.arrayBuffer());
      const keyLog = msg.keyLog ? new Uint8Array(await msg.keyLog.arrayBuffer()) : null;
      session = new CaptureSession(lib!, wiregasmVersion);
      const model = await session.open(msg.file.name, bytes, (progress) => post({ type: 'progress', progress }), keyLog);
      post({ type: 'ready', model });
    } catch (e) {
      session?.close();
      session = null;
      post({ type: 'error', stage: 'open', message: e instanceof Error ? e.message : String(e) });
    }
    return;
  }
  if (msg.type === 'request') {
    try {
      const data = handle(msg.req);
      const transfer: Transferable[] = [];
      if (msg.req.kind === 'frame') for (const s of (data as { sources: { bytes: Uint8Array }[] }).sources) transfer.push(s.bytes.buffer);
      if (msg.req.kind === 'follow') transfer.push((data as { data: Uint8Array }).data.buffer);
      if (msg.req.kind === 'downloadObject') transfer.push((data as { bytes: Uint8Array }).bytes.buffer);
      post({ type: 'response', id: msg.id, ok: true, data }, transfer);
    } catch (e) {
      post({ type: 'response', id: msg.id, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  }
};
