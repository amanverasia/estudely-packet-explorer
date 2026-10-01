// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Browser feature check run before a capture is opened, so an old browser gets
// a plain explanation instead of a failure deep inside the worker. Minimum
// versions: Chrome/Edge 94 (ES2022 build), Firefox 114 (module workers),
// Safari 16.4 (DecompressionStream). See docs/BROWSERS.md.

export const SUPPORTED_BROWSERS = 'a current version of Chrome, Edge, Firefox or Safari (16.4 or later)';

/** Names the features this app needs that `g` (normally globalThis) lacks. */
export function missingFeatures(g: object = globalThis): string[] {
  const has = (name: string) => (g as Record<string, unknown>)[name] !== undefined;
  const missing: string[] = [];
  if (!has('WebAssembly')) missing.push('WebAssembly');
  if (!has('Worker')) missing.push('Web Workers');
  if (!has('DecompressionStream')) missing.push('DecompressionStream');
  return missing;
}
