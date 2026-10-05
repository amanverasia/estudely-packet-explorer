// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Drives Wiregasm for one capture: load -> armed extraction pass -> parse ->
// aggregate. Also serves packet details and the packet list on demand.
// Used by the Web Worker in the browser and directly by Node tests.
import { analyze, type PacketIndex } from './analyze';
import { parseRecords } from './records';
import type { AnalysisModel, FollowStream, FrameDetails, PacketListPage, PacketRow, ProtoTreeNode } from './types';
import { protoName, topProtocol } from './analyze';

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface WgVector<T> { size(): number; get(i: number): T; delete?(): void }
export interface WgMapInput { set(key: string, value: string): void; delete?(): void }
export interface WiregasmModule {
  FS: any;
  DissectSession: new (path: string) => any;
  MapInput: new () => WgMapInput;
  init(): boolean;
  getPluginsDirectory(): string;
  getUploadDirectory(): string;
  wiresharkVersion(): string;
  getColumns(): WgVector<string>;
  checkFilter(filter: string): { ok: boolean; error: string };
  setPref(module: string, key: string, value: string): { code: number; error: string };
  applyPreferences(): void;
}

export interface ExportObjectRow {
  token: string;
  protocol: string;
  host: string | null;
  hostAddresses: string[];
  name: string | null;
  contentType: string | null;
  size: number;
  packet: number;
  relativeTime: number | null;
}

export interface ExportObjectFile {
  fileName: string;
  bytes: Uint8Array<ArrayBuffer>;
}

export type ProgressPhase = 'engine' | 'read' | 'load' | 'extract' | 'parse' | 'analyze';
export interface Progress {
  phase: ProgressPhase;
  /** 0..1 when known */
  fraction: number | null;
  message: string;
}

export interface CaptureInputOptions {
  /** Size of the user's original file, before any prefix limit or decompression. */
  fileSize?: number;
  /** Maximum uncompressed capture bytes to keep in the in-memory filesystem. */
  maxBytes?: number;
  /** The caller already knows that the supplied stream is only a prefix. */
  partial?: boolean;
}

const ESTX_DIR = '/estx';
const OUT_PATH = '/estx/out.tsv';
const ARM_PATH = '/estx/arm';
const DONE_PATH = '/estx/done';
const TLS_KEYLOG_PATH = '/estx/tls-keys.log';
const EXPORT_OBJECT_TAPS = [
  { tap: 'eo:dicom', label: 'DICOM' },
  { tap: 'eo:http', label: 'HTTP' },
  { tap: 'eo:imf', label: 'IMF' },
  { tap: 'eo:smb', label: 'SMB' },
  { tap: 'eo:tftp', label: 'TFTP' },
] as const;

/** Install the Lua extractor. Must run before lib.init(). */
export function installExtractor(lib: WiregasmModule, luaSource: string): void {
  try { lib.FS.mkdirTree(ESTX_DIR); } catch { /* exists */ }
  lib.FS.writeFile(lib.getPluginsDirectory() + '/estudely_extract.lua', luaSource);
}

// libwiretap error codes (wiretap/wtap.h, Wireshark 4.4)
const WTAP_ERRORS: Record<number, string> = {
  [-3]: 'The file is not in a capture format this engine recognises.',
  [-4]: 'The capture uses a format or link-layer type this engine does not support.',
  [-12]: 'The capture file ends in the middle of a packet (it was cut short).',
  [-13]: 'The capture file appears to be damaged or corrupt.',
  [-15]: 'Decompression failed: the compressed data is damaged.',
  [-17]: 'This compression format is not supported.',
  [-20]: 'Decompression failed: the compressed data is damaged.',
  [-22]: 'A packet in the file is larger than the engine supports.',
  [-26]: 'This compression format is not supported.',
};

export function describeLoadError(code: number, error: string): string {
  if (code > 0) return 'This file could not be opened as a packet capture. Supported formats include pcap and pcapng.' + (error && error !== 'Unable to open the file' ? ` (${error})` : '');
  return WTAP_ERRORS[code] ?? `The capture could not be read completely (libwiretap error ${code}${error ? ': ' + error : ''}).`;
}

function vec<T>(v: WgVector<T>): T[] {
  const out: T[] = [];
  const n = v.size();
  for (let i = 0; i < n; i++) out.push(v.get(i));
  return out;
}

function free(v: unknown): void {
  try { (v as { delete?: () => void })?.delete?.(); } catch { /* already freed */ }
}

/** Decoded length of a base64 string, without decoding it. */
function b64Length(b64: string): number {
  const pad = b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0;
  return (b64.length / 4) * 3 - pad;
}

/** Follow-stream caps: enough to read a conversation, small enough to render. */
export const FOLLOW_MAX_BYTES = 512 * 1024;
export const FOLLOW_MAX_SEGMENTS = 5000;

function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export class CaptureSession {
  private sess: any = null;
  private path: string;
  private index: PacketIndex | null = null;
  private progress: ((p: Progress) => void) | null = null;
  private loadedPackets = 0;

  constructor(private lib: WiregasmModule, private wiregasmVersion: string) {
    this.path = lib.getUploadDirectory() + '/capture';
  }

  /** Route the module's stdout here; the extractor reports progress through it. */
  handlePrint(line: string): void {
    if (!line.startsWith('@@ESTX ')) return;
    const [, phase, n] = line.split(' ');
    const count = Number(n);
    if (phase === 'load') {
      this.progress?.({ phase: 'load', fraction: null, message: `Indexing packets… ${count.toLocaleString()} read` });
    } else if (phase === 'extract' && this.loadedPackets) {
      this.progress?.({ phase: 'extract', fraction: count / this.loadedPackets, message: `Decoding packets… ${count.toLocaleString()} of ${this.loadedPackets.toLocaleString()}` });
    }
  }

  async open(
    fileName: string,
    input: Uint8Array | ReadableStream<Uint8Array>,
    onProgress: (p: Progress) => void,
    keyLog?: Uint8Array | null,
    inputOptions: CaptureInputOptions = {},
  ): Promise<AnalysisModel> {
    this.progress = onProgress;
    const FS = this.lib.FS;
    // Keep the optional key log only in Wiregasm's in-memory filesystem while
    // this worker analyzes the capture. Wireshark may revisit packets during
    // dissection, so the file is removed when this session closes; terminating
    // the per-capture worker then releases the imported secrets as well.
    try { FS.unlink(TLS_KEYLOG_PATH); } catch { /* no previous key log */ }
    if (keyLog?.length) FS.writeFile(TLS_KEYLOG_PATH, keyLog);
    try {
      const pref = this.lib.setPref('tls', 'keylog_file', keyLog?.length ? TLS_KEYLOG_PATH : '');
      if (pref.code !== 0) throw new Error(pref.error || 'Wireshark could not set the TLS key log preference.');
      this.lib.applyPreferences();
    } catch (error) {
      try { FS.unlink(TLS_KEYLOG_PATH); } catch { /* no key log file */ }
      throw error;
    }
    // Stream capture bytes directly into Wiregasm's in-memory filesystem. The
    // browser worker bounds this to a prefix, so a huge File is never first
    // materialized as one large ArrayBuffer in JavaScript memory.
    const stream = FS.open(this.path, 'w+');
    const maxBytes = inputOptions.maxBytes ?? Number.POSITIVE_INFINITY;
    let analyzedBytes = 0;
    let partial = inputOptions.partial ?? false;
    try {
      if (input instanceof Uint8Array) {
        const length = Math.min(input.byteLength, maxBytes);
        if (length > 0) FS.write(stream, input, 0, length, 0, length === input.byteLength);
        analyzedBytes = length;
        if (length < input.byteLength) partial = true;
      } else {
        const reader = input.getReader();
        let reachedEnd = false;
        try {
          while (analyzedBytes < maxBytes) {
            const { done, value } = await reader.read();
            if (done) { reachedEnd = true; break; }
            const length = Math.min(value.byteLength, maxBytes - analyzedBytes);
            if (length > 0) FS.write(stream, value, 0, length, analyzedBytes, false);
            analyzedBytes += length;
            if (length < value.byteLength) { partial = true; break; }
          }
          if (!reachedEnd && analyzedBytes >= maxBytes) {
            // Read only enough to tell whether the cap excluded more data.
            try { partial ||= !(await reader.read()).done; }
            catch { partial = true; }
          }
        } finally {
          if (!reachedEnd) await reader.cancel().catch(() => {});
          reader.releaseLock();
        }
      }
    } finally {
      FS.close(stream);
    }

    onProgress({ phase: 'load', fraction: null, message: 'Indexing packets…' });
    this.sess = new this.lib.DissectSession(this.path);
    const res = this.sess.load();
    const summary = res.summary;
    let incomplete: string | null = null;
    if (res.code !== 0) {
      const expectedPrefixEnd = partial && res.code === -12 && !!summary && summary.packet_count > 0;
      if (!expectedPrefixEnd) {
        const msg = describeLoadError(res.code, res.error);
        if (res.code > 0 || !summary || summary.packet_count === 0) throw new Error(msg);
        incomplete = `${msg} Packets read before the problem (${summary.packet_count.toLocaleString()}) were analysed.`;
      }
    }
    const count: number = summary.packet_count;
    this.loadedPackets = count;
    const warnings: string[] = [];

    let out: Uint8Array = new Uint8Array(0);
    if (count > 0) {
      onProgress({ phase: 'extract', fraction: 0, message: 'Decoding packets…' });
      try { FS.unlink(DONE_PATH); } catch { /* none */ }
      FS.writeFile(ARM_PATH, `${OUT_PATH} ${count}`);
      // A filtered scan forces a full protocol-tree dissection of every frame,
      // which is when the armed extractor writes its records.
      const fr = this.sess.getFrames('frame', 0, 1);
      free(fr.frames);
      let done = false;
      try { done = FS.readFile(DONE_PATH, { encoding: 'utf8' }) === 'ok'; } catch { /* missing */ }
      try { FS.unlink(ARM_PATH); } catch { /* consumed */ }
      if (!done) warnings.push('The extraction pass did not reach the last packet; results may be partial.');
      out = FS.readFile(OUT_PATH);
      FS.unlink(OUT_PATH);
    }

    onProgress({ phase: 'parse', fraction: 0, message: 'Reading decoded fields…' });
    const raw = parseRecords(out, (f) => onProgress({ phase: 'parse', fraction: f, message: 'Reading decoded fields…' }));
    out = new Uint8Array(0);
    onProgress({ phase: 'analyze', fraction: null, message: 'Aggregating…' });
    const { model, index } = await analyze(raw, {
      fileName,
      fileSize: inputOptions.fileSize ?? (input instanceof Uint8Array ? input.byteLength : analyzedBytes),
      analyzedBytes,
      partial,
      fileType: summary.file_type, linkType: summary.file_encap_type, incomplete,
      engine: { wireshark: this.lib.wiresharkVersion(), wiregasm: this.wiregasmVersion }, warnings,
    }, (m) => onProgress({ phase: 'analyze', fraction: null, message: m }));
    this.index = index;
    this.progress = null;
    return model;
  }

  frame(number: number, maxNodes = 20000): FrameDetails {
    const f = this.sess.getFrame(number);
    let budget = maxNodes;
    let epoch: string | null = null;
    const conv = (v: WgVector<any>): ProtoTreeNode[] => {
      const out: ProtoTreeNode[] = [];
      const n = v.size();
      for (let i = 0; i < n && budget > 0; i++) {
        const t = v.get(i);
        budget--;
        if (epoch === null && typeof t.filter === 'string' && t.filter.startsWith('frame.time_epoch == ')) epoch = t.filter.slice(20);
        out.push({ label: t.label, filter: t.filter, start: t.start, length: t.length, source: t.data_source_idx, children: conv(t.tree) });
      }
      return out;
    };
    const tree = conv(f.tree);
    const sources = vec<{ name: string; data: string }>(f.data_sources).map((s) => ({ name: s.name, bytes: b64ToBytes(s.data) }));
    const comments = vec<string>(f.comments);
    free(f.tree); free(f.data_sources); free(f.comments); free(f.follow);
    return { number, epoch, tree, sources, comments, truncatedTree: budget <= 0 };
  }

  checkFilter(filter: string): { ok: boolean; error: string } {
    return this.lib.checkFilter(filter);
  }

  packetList(filter: string, skip: number, limit: number): PacketListPage {
    const res = this.sess.getFrames(filter, skip, limit);
    const columns = vec(this.lib.getColumns());
    const rows = vec<any>(res.frames).map((f) => {
      const cols = vec<string>(f.columns);
      free(f.columns);
      return { number: f.number, columns: cols };
    });
    free(res.frames);
    return { columns, rows, matched: res.matched };
  }

  /**
   * Reassembled payload of one TCP or UDP stream through Wiregasm's follower.
   * The follower names are sharkd's ('TCP', 'UDP'); it reports a stream it
   * found nothing for with the host 'NONE'.
   */
  follow(transport: 'TCP' | 'UDP', stream: number, caps: { maxBytes?: number; maxSegments?: number } = {}): FollowStream {
    if (!Number.isInteger(stream) || stream < 0) throw new Error(`Invalid stream index ${stream}`);
    const maxBytes = caps.maxBytes ?? FOLLOW_MAX_BYTES;
    const maxSegments = caps.maxSegments ?? FOLLOW_MAX_SEGMENTS;
    const res = this.sess.follow(transport, `${transport.toLowerCase()}.stream eq ${stream}`);
    const payloads = vec<{ number: number; server: number; data: string }>(res.payloads);
    free(res.payloads);
    const known = res.chost && res.chost !== 'NONE';
    const port = (p: string) => (p && Number.isFinite(Number(p)) ? Number(p) : null);
    // Byte totals are summed here: sharkd's sbytes/cbytes do not reliably
    // match the direction flags on the payloads.
    let clientBytes = 0;
    let serverBytes = 0;
    for (const p of payloads) {
      if (p.server) serverBytes += b64Length(p.data);
      else clientBytes += b64Length(p.data);
    }
    const segments: FollowStream['segments'] = [];
    const parts: Uint8Array[] = [];
    let size = 0;
    let truncated = false;
    for (const p of payloads) {
      if (segments.length >= maxSegments || size >= maxBytes) { truncated = true; break; }
      let bytes = b64ToBytes(p.data);
      if (size + bytes.length > maxBytes) { bytes = bytes.subarray(0, maxBytes - size); truncated = true; }
      segments.push({ frame: p.number, fromServer: !!p.server, offset: size, length: bytes.length });
      parts.push(bytes);
      size += bytes.length;
    }
    const data = new Uint8Array(size);
    for (let i = 0; i < parts.length; i++) data.set(parts[i], segments[i].offset);
    return {
      transport, stream,
      client: known ? { addr: res.chost, port: port(res.cport) } : null,
      server: known ? { addr: res.shost, port: port(res.sport) } : null,
      clientBytes, serverBytes, totalSegments: payloads.length, data, segments, truncated,
    };
  }

  /** Metadata for Wireshark's export-object taps. Payloads stay inside WASM until a file is selected. */
  exportObjects(): ExportObjectRow[] {
    if (!this.sess || !this.index) throw new Error('No capture is open.');
    const input = new this.lib.MapInput();
    for (let i = 0; i < EXPORT_OBJECT_TAPS.length; i++) input.set(`tap${i}`, EXPORT_OBJECT_TAPS[i].tap);

    const raw: { token: string; protocol: string; host: string | null; name: string | null; contentType: string | null; size: number; packet: number }[] = [];
    let response: any;
    try {
      response = this.sess.tap(input);
    } finally {
      free(input);
    }
    if (response.error) {
      free(response.taps);
      throw new Error(`Wireshark could not scan exported files: ${response.error}`);
    }
    const taps = vec<any>(response.taps);
    free(response.taps);
    for (const tap of taps) {
      try {
        const objects = vec<any>(tap.objects);
        free(tap.objects);
        for (const object of objects) {
          const token = String(object._download ?? '');
          const packet = Number(object.pkt);
          if (!/^eo:[a-z0-9_-]+_\d+$/i.test(token) || !Number.isInteger(packet) || packet < 1) continue;
          raw.push({
            token,
            protocol: String(tap.proto || EXPORT_OBJECT_TAPS.find((item) => item.tap === tap.tap)?.label || 'Unknown').toUpperCase(),
            host: typeof object.hostname === 'string' && object.hostname ? object.hostname : null,
            name: typeof object.filename === 'string' && object.filename ? object.filename : null,
            contentType: typeof object.type === 'string' && object.type ? object.type : null,
            size: Math.max(0, Number(object.len) || 0),
            packet,
          });
        }
      } finally {
        free(tap);
      }
    }

    const needed = new Set(raw.map((object) => object.packet));
    const packetInfo = new Map<number, { time: number; hosts: string[] }>();
    for (const packet of this.index.packets) {
      if (!needed.has(packet.frame)) continue;
      const hosts = [...new Set([packet.src || packet.ethSrc, packet.dst || packet.ethDst].filter(Boolean))];
      packetInfo.set(packet.frame, { time: packet.t, hosts });
    }
    return raw.map((object) => {
      const info = packetInfo.get(object.packet);
      const endpointLabel = info?.hosts.join(' → ') || null;
      return {
        ...object,
        host: object.host || endpointLabel,
        hostAddresses: info?.hosts ?? [],
        relativeTime: info?.time ?? null,
      };
    });
  }

  /** Decode only the selected object's bytes for a download initiated by the user. */
  downloadExportObject(token: string): ExportObjectFile {
    if (!this.sess) throw new Error('No capture is open.');
    if (!/^eo:[a-z0-9_-]+_\d+$/i.test(token)) throw new Error('Invalid exported-file token.');
    const response = this.sess.download(token);
    if (response.error) throw new Error(`Wireshark could not retrieve this file: ${response.error}`);
    if (!response.download || typeof response.download.data !== 'string') throw new Error('Wireshark did not return this file.');
    return {
      fileName: typeof response.download.file === 'string' ? response.download.file : '',
      bytes: b64ToBytes(response.download.data),
    };
  }

  /** Lightweight rows from the extraction pass, for drill-downs. */
  rows(opts: { convId?: number; frames?: number[]; limit?: number }): { rows: PacketRow[]; total: number } {
    const idx = this.index;
    if (!idx) return { rows: [], total: 0 };
    const limit = opts.limit ?? 50000;
    const out: PacketRow[] = [];
    let total = 0;
    const push = (i: number) => {
      total++;
      if (out.length >= limit) return;
      const p = idx.packets[i];
      out.push({
        frame: p.frame, t: p.t, len: p.len, caplen: p.caplen, src: p.src || p.ethSrc, dst: p.dst || p.ethDst,
        sport: p.sport, dport: p.dport, protocol: protoName(topProtocol(p.protos)), flags: p.flags, iface: p.iface,
        decrypted: p.decrypted,
      });
    };
    if (opts.convId !== undefined) {
      for (let i = 0; i < idx.packets.length; i++) if (idx.convOf[i] === opts.convId) push(i);
    } else if (opts.frames) {
      const want = new Set(opts.frames);
      for (let i = 0; i < idx.packets.length; i++) if (want.has(idx.packets[i].frame)) push(i);
    }
    return { rows: out, total };
  }

  close(): void {
    if (this.sess) {
      try { this.sess.delete(); } catch { /* ignore */ }
      this.sess = null;
    }
    try { this.lib.FS.unlink(this.path); } catch { /* ignore */ }
    try { this.lib.FS.unlink(TLS_KEYLOG_PATH); } catch { /* ignore */ }
    this.index = null;
  }
}
