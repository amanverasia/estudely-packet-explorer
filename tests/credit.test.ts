// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { Credit } from '../src/app/components/Credit';
import { BuildTag } from '../src/app/components/BuildTag';
import { WorkspaceNavigation } from '../src/app/components/WorkspaceNavigation';

beforeAll(() => {
  vi.stubGlobal('__APP_COMMIT__', 'abc1234');
  vi.stubGlobal('__APP_VERSION__', '0.0.0');
  vi.stubGlobal('__BUILD_DATE__', '2026-01-01');
});

const text = (html: string) => html.replace(/<[^>]+>/g, '').replace(/&#x27;/g, "'");
const CREDIT_TEXT = 'made by Aman Verasia · estudely.com · github.com/amanverasia';
const LINKS = [
  '<a href="https://estudely.com" target="_blank" rel="noopener noreferrer">estudely.com</a>',
  '<a href="https://github.com/amanverasia" target="_blank" rel="noopener noreferrer">github.com/amanverasia</a>',
];

describe('credit line', () => {
  it('renders the shared text with both links opening safely in a new tab', () => {
    const html = renderToStaticMarkup(createElement(Credit));
    expect(text(html)).toBe(CREDIT_TEXT);
    for (const link of LINKS) expect(html).toContain(link);
  });

  it('appears in the build tag', () => {
    const html = renderToStaticMarkup(createElement(BuildTag, { className: 'corner' }));
    expect(text(html)).toContain(CREDIT_TEXT);
    for (const link of LINKS) expect(html).toContain(link);
  });

  it('appears once in the workspace sidebar, below the licence link', () => {
    const html = renderToStaticMarkup(createElement(WorkspaceNavigation, {
      items: [{ id: 'overview', label: 'Overview' }], current: 'overview', onNavigate: () => {}, wireshark: '4.4.5', localNotice: '',
    }));
    expect(html.split(CREDIT_TEXT.slice(0, 7) + ' Aman').length - 1).toBe(1);
    for (const link of LINKS) expect(html).toContain(link);
    expect(html.indexOf('About and licences')).toBeGreaterThan(-1);
    expect(html.indexOf('About and licences')).toBeLessThan(html.indexOf('made by'));
    expect(html).not.toContain('Licences and limitations');
  });
});
