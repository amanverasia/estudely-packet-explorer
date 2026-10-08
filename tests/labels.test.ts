// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { placeLabels } from '../src/app/labels';

describe('graph label placement', () => {
  it('puts a label on the right when nothing is in the way', () => {
    const p = placeLabels([{ id: 'a', x: 0, y: 0, r: 5, label: '10.0.0.1' }], []);
    expect(p.get('a')).toMatchObject({ side: 'right' });
  });

  it('moves a label off the side an edge leaves from', () => {
    const p = placeLabels(
      [{ id: 'a', x: 0, y: 0, r: 5, label: '10.0.0.1' }, { id: 'b', x: 200, y: 0, r: 5, label: '10.0.0.2' }],
      [{ x1: 0, y1: 0, x2: 200, y2: 0 }],
    );
    expect(p.get('a')!.side).not.toBe('right');
    expect(p.get('b')!.side).not.toBe('left');
  });

  it('avoids edges and nodes on all sides where it can', () => {
    // Edges leave to the right and left; above and below are free.
    const p = placeLabels(
      [{ id: 'a', x: 0, y: 0, r: 5, label: 'host' }, { id: 'b', x: 150, y: 0, r: 5, label: 'b' }, { id: 'c', x: -150, y: 0, r: 5, label: 'c' }],
      [{ x1: 0, y1: 0, x2: 150, y2: 0 }, { x1: 0, y1: 0, x2: -150, y2: 0 }],
    );
    expect(['above', 'below']).toContain(p.get('a')!.side);
  });

  it('keeps a broadcast label clear of its own ring', () => {
    const node = { id: 'bcast', x: 40, y: 40, r: 8, label: '255.255.255.255' };
    const at = placeLabels([node], []).get('bcast')!;
    const gap = at.side === 'left' || at.side === 'right' ? Math.abs(at.x) - node.r : Math.abs(at.y) - node.r;
    expect(gap).toBeGreaterThanOrEqual(10);
  });

  it('does not stack two labels on top of each other', () => {
    // Two nodes close together vertically: their right-hand labels would overlap.
    const p = placeLabels([{ id: 'a', x: 0, y: 0, r: 5, label: 'first.example' }, { id: 'b', x: 0, y: 8, r: 2, label: 'second.example' }], []);
    expect(p.get('a')!.side === 'right' && p.get('b')!.side === 'right').toBe(false);
  });
});
