// Messages exchanged between the UI thread and the analysis worker.
import type { AnalysisModel, FrameDetails, PacketListPage, PacketRow } from '../engine/types';
import type { Progress } from '../engine/session';

export type ToWorker =
  | { type: 'init'; base: string; wasmModule: WebAssembly.Module | null; data: ArrayBuffer | null }
  | { type: 'open'; file: File }
  | { type: 'request'; id: number; req: WorkerRequest };

export type WorkerRequest =
  | { kind: 'frame'; number: number }
  | { kind: 'packetList'; filter: string; skip: number; limit: number }
  | { kind: 'checkFilter'; filter: string }
  | { kind: 'rows'; convId?: number; frames?: number[]; limit?: number };

export interface WorkerResponses {
  frame: FrameDetails;
  packetList: PacketListPage;
  checkFilter: { ok: boolean; error: string };
  rows: { rows: PacketRow[]; total: number };
}

export type FromWorker =
  | { type: 'progress'; progress: Progress }
  | { type: 'engine-ready'; wasmModule: WebAssembly.Module; data: ArrayBuffer; versions: { wireshark: string; wiregasm: string } }
  | { type: 'ready'; model: AnalysisModel }
  | { type: 'error'; message: string; stage: 'engine' | 'open' }
  | { type: 'response'; id: number; ok: true; data: unknown }
  | { type: 'response'; id: number; ok: false; error: string };
