// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { MAX_ANALYSIS_BYTES, LARGE_CAPTURE_WARNING_BYTES } from '../src/engine/limits';

const page = readFileSync(new URL('../public/ABOUT.html', import.meta.url), 'utf8');

describe('public/ABOUT.html', () => {
  it('keeps the legal text that shipped before the About section was added', () => {
    for (const phrase of [
      'GNU General Public License',
      'version 2 or (at your option) any later version',
      'It comes with no warranty',
      'Wireshark</a> 4.4.5',
      'Wiregasm</a> 1.9.1',
      './wiregasm/LICENSE-GPL-2.0.txt',
      'https://github.com/amanverasia/estudely-packet-explorer/releases/tag/engine-source-1.9.1',
      'https://github.com/good-tools/wiregasm/tree/v1.9.1',
      'https://www.wireshark.org/download/src/all-versions/',
      'https://github.com/amanverasia/estudely-packet-explorer',
      'SIL Open Font License 1.1',
      '<h2>Packet decoding engine</h2>',
      '<h2>This application</h2>',
      '<h2>Other components</h2>',
      '<h2>Known limitations</h2>',
      'HTTP/3 is not turned into request rows',
      'DoH and DoT are not shown as DNS queries or request rows',
      'The first 1.00 GiB of capture data is analyzed',
    ]) expect(page, phrase).toContain(phrase);
  });

  it('has the About sections and exactly one h1', () => {
    expect(page.match(/<h1[ >]/g)).toHaveLength(1);
    expect(page).toContain('<title>About and licences</title>');
    expect(page).toContain('<h1>About Estudely Packet Explorer</h1>');
    for (const h of ['What is this?', 'How it works', 'What leaves your device', 'What stays on your device', 'Limits', 'Who made this', 'Licences and limitations']) {
      expect(page).toMatch(new RegExp(`<h2[^>]*>${h.replace('?', '\\?')}</h2>`));
    }
    expect(page).toContain('<nav class="estudely-links" aria-label="Estudely">');
    expect(page).toContain('<a href="https://estudely.com/tools/" target="_blank" rel="noopener noreferrer">All tools</a>');
  });

  it('loads nothing external and only follows allowed links', () => {
    expect(page).not.toMatch(/<script/i);
    expect(page).not.toMatch(/\bsrc=/i);
    expect(page).not.toMatch(/<link\b/i);
    expect(page).not.toMatch(/@import|url\(/i);
    const hrefs = [...page.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
    const external = hrefs.filter((h) => /^https?:/.test(h));
    const allowed = /^https:\/\/(www\.wireshark\.org|github\.com\/(good-tools|amanverasia)|estudely\.com|amanverasia\.com)(\/|$)/;
    for (const h of external) expect(h, h).toMatch(allowed);
  });

  it('quotes the same limits the app uses', () => {
    expect(MAX_ANALYSIS_BYTES).toBe(1024 ** 3);
    expect(LARGE_CAPTURE_WARNING_BYTES).toBe(250 * 1024 ** 2);
    expect(page).toContain('first 1 GiB of capture data');
    expect(page).toContain('above 250 MiB');
  });

  it('names the storage the app really uses', () => {
    const app = readFileSync(new URL('../src/app/App.tsx', import.meta.url), 'utf8');
    const idb = readFileSync(new URL('../src/app/localIpStorage.ts', import.meta.url), 'utf8');
    expect(app).toContain("'epx-theme'");
    expect(page).toContain('epx-theme');
    expect(idb).toContain("'estudely-local-ip-data'");
    expect(page).toContain('estudely-local-ip-data');
  });
});
