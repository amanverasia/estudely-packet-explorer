/// <reference lib="webworker" />
// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { LocalIpDataKind } from './localIpData';
import { importLocalIpFile } from './localIpImport';

declare const self: DedicatedWorkerGlobalScope;

type RequestMessage = { file: File; kind: LocalIpDataKind };

self.onmessage = async (event: MessageEvent<RequestMessage>) => {
  try {
    const { file, kind } = event.data;
    const database = await importLocalIpFile(file, kind, (bytes, rows) => {
      self.postMessage({ type: 'progress', bytes, rows, message: `Reading database… ${(bytes / 1024 / 1024).toFixed(1)} MB · ${rows.toLocaleString()} ranges` });
    });
    const transfer = [
      database.ipv4Start.buffer, database.ipv4End.buffer, database.ipv4Value.buffer, database.ipv4Asn.buffer,
      database.ipv6Start.buffer, database.ipv6End.buffer, database.ipv6Value.buffer, database.ipv6Asn.buffer,
    ];
    self.postMessage({ type: 'complete', database }, transfer);
  } catch (error) {
    self.postMessage({ type: 'error', message: error instanceof Error ? error.message : String(error) });
  }
};
