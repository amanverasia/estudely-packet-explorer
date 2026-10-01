// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { missingFeatures } from '../src/app/support';
import { postWithModule } from '../src/worker/compat';

const dataCloneError = () => new DOMException('WebAssembly.Module could not be cloned.', 'DataCloneError');

describe('posting the compiled engine module', () => {
  it('posts the message unchanged when the browser can clone the module', () => {
    const sent: unknown[] = [];
    const msg = { type: 'init', wasmModule: {} as WebAssembly.Module };
    expect(postWithModule((m) => sent.push(m), msg)).toBe(true);
    expect(sent).toEqual([msg]);
  });

  it('drops the module and posts again when cloning it fails', () => {
    const sent: { wasmModule: unknown }[] = [];
    const msg = { type: 'init', base: 'x/', wasmModule: {} as WebAssembly.Module };
    const post = (m: typeof msg | { wasmModule: null }) => {
      if (m.wasmModule) throw dataCloneError();
      sent.push(m);
    };
    expect(postWithModule(post, msg)).toBe(false);
    expect(sent).toEqual([{ type: 'init', base: 'x/', wasmModule: null }]);
  });

  it('does not hide other errors', () => {
    expect(() => postWithModule(() => { throw new TypeError('boom'); }, { wasmModule: null })).toThrow('boom');
  });
});

describe('browser feature check', () => {
  const full = { WebAssembly: {}, Worker: function Worker() {}, DecompressionStream: function DecompressionStream() {} };

  it('finds nothing missing in a current browser', () => {
    expect(missingFeatures(full)).toEqual([]);
  });

  it('names each missing feature', () => {
    expect(missingFeatures({ ...full, DecompressionStream: undefined })).toEqual(['DecompressionStream']);
    expect(missingFeatures({})).toEqual(['WebAssembly', 'Web Workers', 'DecompressionStream']);
  });
});
