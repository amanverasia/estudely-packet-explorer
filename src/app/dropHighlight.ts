// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

export type LandingDragLeave = 'keep' | 'clear' | 'clear-unless-drag-continues';

export interface LandingDragLeaveProbe {
  relatedInside: boolean;
  clientX: number;
  clientY: number;
  viewportWidth: number;
  viewportHeight: number;
  surfaceLeft: number;
  surfaceTop: number;
  surfaceRight: number;
  surfaceBottom: number;
}

/**
 * A dragleave whose related target is still inside the landing surface is only
 * a child boundary. External file drags often report no related target; if the
 * pointer is still inside, a following dragover means the drag continued, and
 * silence means it was cancelled. Coordinates on the viewport edge are a real
 * leave: a full-page surface still contains the origin geometrically.
 */
export function landingDragLeaveAction(probe: LandingDragLeaveProbe): LandingDragLeave {
  if (probe.relatedInside) return 'keep';
  const { clientX: x, clientY: y } = probe;
  if (x <= 0 || y <= 0 || x >= probe.viewportWidth || y >= probe.viewportHeight) return 'clear';
  const inside = x >= probe.surfaceLeft && x < probe.surfaceRight && y >= probe.surfaceTop && y < probe.surfaceBottom;
  return inside ? 'clear-unless-drag-continues' : 'clear';
}

export function probeFromDragLeave(surface: HTMLElement, event: { relatedTarget: EventTarget | null; clientX: number; clientY: number }): LandingDragLeaveProbe {
  const related = event.relatedTarget;
  const rect = surface.getBoundingClientRect();
  return {
    relatedInside: related instanceof Node && surface.contains(related),
    clientX: event.clientX,
    clientY: event.clientY,
    viewportWidth: window.innerWidth,
    viewportHeight: window.innerHeight,
    surfaceLeft: rect.left,
    surfaceTop: rect.top,
    surfaceRight: rect.right,
    surfaceBottom: rect.bottom,
  };
}
