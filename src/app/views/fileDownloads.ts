// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

/** Per-row Files download controls. One object's busy state must not disable the others. */
export interface FileDownloadState {
  busy: ReadonlySet<string>;
  errors: ReadonlyMap<string, string>;
}

export function idleFileDownloads(): FileDownloadState {
  return { busy: new Set(), errors: new Map() };
}

/** Marks one object as saving and clears only that object's previous error. */
export function beginFileDownload(state: FileDownloadState, token: string): FileDownloadState {
  if (state.busy.has(token)) return state;
  const busy = new Set(state.busy);
  busy.add(token);
  const errors = new Map(state.errors);
  errors.delete(token);
  return { busy, errors };
}

/** Clears one object's busy flag. A failure is recorded on that object alone. */
export function endFileDownload(state: FileDownloadState, token: string, error: string | null): FileDownloadState {
  const busy = new Set(state.busy);
  busy.delete(token);
  const errors = new Map(state.errors);
  if (error) errors.set(token, error);
  else errors.delete(token);
  return { busy, errors };
}

export function fileDownloadDisabled(state: FileDownloadState, token: string): boolean {
  return state.busy.has(token);
}

export function fileDownloadLabel(state: FileDownloadState, token: string): 'Saving…' | 'Download' {
  return state.busy.has(token) ? 'Saving…' : 'Download';
}
