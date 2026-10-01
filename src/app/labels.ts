// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Places node labels in the host graph on the side that crosses the fewest
// edges, nodes and already placed labels. Greedy, largest nodes first.

export interface LabelNode { id: string; x: number; y: number; r: number; label: string }
export interface Segment { x1: number; y1: number; x2: number; y2: number }
export type LabelSide = 'right' | 'left' | 'above' | 'below';
export interface LabelPlacement { side: LabelSide; x: number; y: number; anchor: 'start' | 'end' | 'middle' }

interface Box { x0: number; y0: number; x1: number; y1: number }

// Graph labels are 11px; this is a conservative average glyph width.
const CHAR_W = 6.4;
const LINE_H = 13;
const GAP = 4;
// Tried in this order, so ties keep the familiar right-hand label.
const SIDES: LabelSide[] = ['right', 'left', 'below', 'above'];

function boxFor(n: LabelNode, side: LabelSide, w: number): { box: Box; at: LabelPlacement } {
  const h = LINE_H;
  switch (side) {
    case 'right': return { box: { x0: n.x + n.r + GAP, y0: n.y - h / 2, x1: n.x + n.r + GAP + w, y1: n.y + h / 2 }, at: { side, x: n.r + GAP, y: 0, anchor: 'start' } };
    case 'left': return { box: { x0: n.x - n.r - GAP - w, y0: n.y - h / 2, x1: n.x - n.r - GAP, y1: n.y + h / 2 }, at: { side, x: -(n.r + GAP), y: 0, anchor: 'end' } };
    case 'below': return { box: { x0: n.x - w / 2, y0: n.y + n.r + 2, x1: n.x + w / 2, y1: n.y + n.r + 2 + h }, at: { side, x: 0, y: n.r + 2 + h / 2, anchor: 'middle' } };
    case 'above': return { box: { x0: n.x - w / 2, y0: n.y - n.r - 2 - h, x1: n.x + w / 2, y1: n.y - n.r - 2 }, at: { side, x: 0, y: -(n.r + 2 + h / 2), anchor: 'middle' } };
  }
}

/** Liang–Barsky: does the segment pass through the box? */
function segmentHitsBox(s: Segment, b: Box): boolean {
  const dx = s.x2 - s.x1, dy = s.y2 - s.y1;
  let t0 = 0, t1 = 1;
  for (const [p, q] of [[-dx, s.x1 - b.x0], [dx, b.x1 - s.x1], [-dy, s.y1 - b.y0], [dy, b.y1 - s.y1]]) {
    if (p === 0) { if (q < 0) return false; continue; }
    const t = q / p;
    if (p < 0) { if (t > t1) return false; if (t > t0) t0 = t; } else { if (t < t0) return false; if (t < t1) t1 = t; }
  }
  return true;
}

function circleHitsBox(n: LabelNode, b: Box): boolean {
  const cx = Math.max(b.x0, Math.min(n.x, b.x1)), cy = Math.max(b.y0, Math.min(n.y, b.y1));
  return (n.x - cx) ** 2 + (n.y - cy) ** 2 < n.r * n.r;
}

function boxesOverlap(a: Box, b: Box): boolean {
  return a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;
}

export function placeLabels(nodes: LabelNode[], edges: Segment[]): Map<string, LabelPlacement> {
  const out = new Map<string, LabelPlacement>();
  const placed: Box[] = [];
  for (const n of [...nodes].sort((a, b) => b.r - a.r)) {
    const w = n.label.length * CHAR_W;
    let best: { box: Box; at: LabelPlacement } | null = null;
    let bestScore = Infinity;
    for (const side of SIDES) {
      const c = boxFor(n, side, w);
      let score = 0;
      for (const e of edges) if (segmentHitsBox(e, c.box)) score += 1;
      for (const o of nodes) if (o !== n && circleHitsBox(o, c.box)) score += 2;
      for (const p of placed) if (boxesOverlap(p, c.box)) score += 3;
      if (score < bestScore) { bestScore = score; best = c; }
      if (score === 0) break;
    }
    placed.push(best!.box);
    out.set(n.id, best!.at);
  }
  return out;
}
