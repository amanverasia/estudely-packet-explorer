// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

function metaPolicy(): string[] {
  const block = /const CSP = \[([\s\S]*?)\]\.join/.exec(read('vite.config.ts'));
  if (!block) throw new Error('CSP array not found in vite.config.ts');
  return [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

function headerPolicy(): string[] {
  const line = /^\s*\/\*\n\s*Content-Security-Policy: (.+)$/m.exec(read('public/_headers'));
  if (!line) throw new Error('Content-Security-Policy not found for /* in public/_headers');
  return line[1].split(';').map((d) => d.trim()).filter(Boolean);
}

describe('content security policy', () => {
  it('keeps the meta tag policy and the HTTP header policy equivalent', () => {
    // frame-ancestors is ignored in a meta tag, so only the header sets it.
    const header = headerPolicy().filter((d) => !d.startsWith('frame-ancestors'));
    expect([...header].sort()).toEqual([...metaPolicy()].sort());
  });

  it('never lets the page connect anywhere but itself', () => {
    expect(metaPolicy()).toContain("connect-src 'self'");
    expect(headerPolicy()).toContain("connect-src 'self'");
  });
});
