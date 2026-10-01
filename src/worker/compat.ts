// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Cross-browser fallback for handing the compiled engine between threads.
// Chromium, Firefox and Safari can all post a WebAssembly.Module to a worker
// of the same page, but the spec lets a browser refuse (DataCloneError), for
// example across agent clusters. The module is only a cache, so on refusal
// the message goes without it and the receiver compiles its own copy.

/**
 * Posts `msg`; if the browser cannot clone its `wasmModule`, posts it again
 * with `wasmModule: null`. Returns whether the module went along.
 */
export function postWithModule<T extends { wasmModule: WebAssembly.Module | null }>(
  post: (m: T) => void,
  msg: T,
): boolean {
  try {
    post(msg);
    return true;
  } catch (e) {
    if (!msg.wasmModule || !(e instanceof DOMException) || e.name !== 'DataCloneError') throw e;
    post({ ...msg, wasmModule: null });
    return false;
  }
}
