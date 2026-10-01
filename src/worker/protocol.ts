// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Messages exchanged between the UI thread and the analysis worker.
import type { AnalysisModel, FollowStream, FrameDetails, PacketListPage, PacketRow } from '../engine/types';
import type { Progress } from '../engine/session';

export type ToWorker =
  | { type: 'init'; base: string; wasmModule: WebAssembly.Module | null; data: ArrayBuffer | null }
  | { type: 'open'; file: File; keyLog?: File | null }
  | { type: 'request'; id: number; req: WorkerRequest };

export type WorkerRequest =
  | { kind: 'frame'; number: number }
  | { kind: 'packetList'; filter: string; skip: number; limit: number }
  | { kind: 'checkFilter'; filter: string }
  | { kind: 'rows'; convId?: number; frames?: number[]; limit?: number }
  | { kind: 'follow'; transport: 'TCP' | 'UDP'; stream: number; maxBytes?: number; maxSegments?: number };

export interface WorkerResponses {
  frame: FrameDetails;
  packetList: PacketListPage;
  checkFilter: { ok: boolean; error: string };
  rows: { rows: PacketRow[]; total: number };
  follow: FollowStream;
}

export type FromWorker =
  | { type: 'progress'; progress: Progress }
  | { type: 'engine-ready'; wasmModule: WebAssembly.Module | null; data: ArrayBuffer; versions: { wireshark: string; wiregasm: string } }
  | { type: 'ready'; model: AnalysisModel }
  | { type: 'error'; message: string; stage: 'engine' | 'open' }
  | { type: 'response'; id: number; ok: true; data: unknown }
  | { type: 'response'; id: number; ok: false; error: string };
