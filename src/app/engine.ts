// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// UI-side controller for the analysis worker. One worker per capture:
// cancelling or replacing a capture terminates the worker, which frees the
// whole WASM heap. The compiled engine module is kept and handed to the next
// worker so the 19 MB download and compile happen once per page load.
import type { AnalysisModel } from '../engine/types';
import type { ExportObjectFile, ExportObjectRow } from '../engine/session';
import type { Progress } from '../engine/session';
import type { FromWorker, ToWorker, WorkerRequest, WorkerResponses } from '../worker/protocol';
import { postWithModule } from '../worker/compat';
import { missingFeatures, SUPPORTED_BROWSERS } from './support';
import { LARGE_CAPTURE_WARNING_BYTES, MAX_ANALYSIS_BYTES } from '../engine/limits';

export const SOFT_LIMIT_BYTES = LARGE_CAPTURE_WARNING_BYTES;
export const HARD_LIMIT_BYTES = MAX_ANALYSIS_BYTES;

export type EngineState =
  | { kind: 'idle' }
  | { kind: 'working'; fileName: string; fileSize: number; progress: Progress; startedAt: number }
  | { kind: 'ready'; model: AnalysisModel }
  | { kind: 'error'; message: string; fileName?: string };

type Listener = (s: EngineState) => void;

export class EngineClient {
  private worker: Worker | null = null;
  private wasmModule: WebAssembly.Module | null = null;
  private data: ArrayBuffer | null = null;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private exportObjectRows: ExportObjectRow[] | null = null;
  private exportObjectsRequest: Promise<ExportObjectRow[]> | null = null;
  private listener: Listener;
  versions: { wireshark: string; wiregasm: string } | null = null;

  constructor(listener: Listener) {
    this.listener = listener;
  }

  private base(): string {
    return new URL('wiregasm/', document.baseURI).href;
  }

  private spawn(): Worker {
    const w = new Worker(new URL('../worker/analysis.worker.ts', import.meta.url), { type: 'module', name: 'estudely-analysis' });
    w.onmessage = (ev: MessageEvent<FromWorker>) => this.onMessage(w, ev.data);
    w.onerror = (ev) => {
      if (w !== this.worker) return;
      this.listener({ kind: 'error', message: `The analysis worker stopped unexpectedly${ev.message ? `: ${ev.message}` : ''}. Very large captures can exceed the browser's memory.` });
    };
    const init: Extract<ToWorker, { type: 'init' }> = { type: 'init', base: this.base(), wasmModule: this.wasmModule, data: this.data ? this.data.slice(0) : null };
    // If this browser cannot post the module, stop offering it: each worker compiles its own.
    try {
      if (!postWithModule((m) => w.postMessage(m), init)) this.wasmModule = null;
    } catch (e) {
      w.terminate();
      throw e;
    }
    return w;
  }

  private onMessage(w: Worker, m: FromWorker): void {
    if (w !== this.worker) return; // stale worker
    switch (m.type) {
      case 'engine-ready':
        this.wasmModule = m.wasmModule;
        this.data = m.data;
        this.versions = m.versions;
        break;
      case 'progress':
        this.listenerProgress(m.progress);
        break;
      case 'ready':
        this.listener({ kind: 'ready', model: m.model });
        break;
      case 'error':
        this.listener({ kind: 'error', message: m.message, fileName: this.currentFile?.name });
        if (m.stage === 'engine') this.close();
        break;
      case 'response': {
        const p = this.pending.get(m.id);
        if (!p) return;
        this.pending.delete(m.id);
        if (m.ok) p.resolve(m.data);
        else p.reject(new Error(m.error));
        break;
      }
    }
  }

  private currentFile: File | null = null;
  private startedAt = 0;

  private listenerProgress(progress: Progress): void {
    if (!this.currentFile) return;
    this.listener({ kind: 'working', fileName: this.currentFile.name, fileSize: this.currentFile.size, progress, startedAt: this.startedAt });
  }

  /** Opens a capture locally. Any previous capture and its worker are discarded. */
  open(file: File, keyLog?: File | null): void {
    this.close();
    const missing = missingFeatures();
    if (missing.length) {
      this.listener({ kind: 'error', fileName: file.name, message: `This browser does not support ${missing.join(', ')}, which the analysis engine needs. Use ${SUPPORTED_BROWSERS}.` });
      return;
    }
    try {
      this.worker = this.spawn();
    } catch (e) {
      // Older browsers throw here for module workers.
      this.listener({ kind: 'error', fileName: file.name, message: `This browser could not start the analysis worker (${e instanceof Error ? e.message : String(e)}). Use ${SUPPORTED_BROWSERS}.` });
      return;
    }
    this.currentFile = file;
    this.startedAt = performance.now();
    this.listenerProgress({ phase: this.wasmModule ? 'read' : 'engine', fraction: null, message: this.wasmModule ? 'Starting…' : 'Loading the Wireshark engine…' });
    const msg: ToWorker = { type: 'open', file, keyLog };
    this.worker.postMessage(msg);
  }

  /** Cancels work in progress (or closes the open capture) and frees memory. */
  close(): void {
    if (this.worker) this.worker.terminate();
    this.worker = null;
    this.currentFile = null;
    this.exportObjectRows = null;
    this.exportObjectsRequest = null;
    for (const p of this.pending.values()) p.reject(new Error('Capture closed'));
    this.pending.clear();
  }

  cancel(): void {
    this.close();
    this.listener({ kind: 'idle' });
  }

  request<K extends WorkerRequest['kind']>(req: Extract<WorkerRequest, { kind: K }>): Promise<WorkerResponses[K]> {
    const w = this.worker;
    if (!w) return Promise.reject(new Error('No capture is open.'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      const msg: ToWorker = { type: 'request', id, req };
      w.postMessage(msg);
    });
  }

  exportObjects(): Promise<ExportObjectRow[]> {
    if (this.exportObjectRows) return Promise.resolve(this.exportObjectRows);
    if (!this.exportObjectsRequest) {
      const request = this.request({ kind: 'exportObjects' });
      this.exportObjectsRequest = request;
      void request.then((rows) => { this.exportObjectRows = rows; }, () => {}).finally(() => {
        if (this.exportObjectsRequest === request) this.exportObjectsRequest = null;
      });
    }
    return this.exportObjectsRequest;
  }

  downloadExportObject(token: string): Promise<ExportObjectFile> {
    return this.request({ kind: 'downloadObject', token });
  }
}
