// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { landingDragLeaveAction, type LandingDragLeaveProbe } from '../src/app/dropHighlight';

const page: LandingDragLeaveProbe = {
  relatedInside: false,
  clientX: 240,
  clientY: 180,
  viewportWidth: 1280,
  viewportHeight: 800,
  surfaceLeft: 0,
  surfaceTop: 0,
  surfaceRight: 1280,
  surfaceBottom: 800,
};

describe('landing drop highlight', () => {
  it('keeps the highlight when the pointer moves onto a child', () => {
    expect(landingDragLeaveAction({ ...page, relatedInside: true })).toBe('keep');
    expect(landingDragLeaveAction(page)).toBe('clear-unless-drag-continues');
  });

  it('clears when the pointer leaves the landing surface but stays in the window', () => {
    expect(landingDragLeaveAction({
      ...page,
      clientX: 20,
      clientY: 20,
      surfaceLeft: 80,
      surfaceTop: 60,
      surfaceRight: 400,
      surfaceBottom: 500,
    })).toBe('clear');
  });

  it('clears at the viewport edge even when that point is still inside the surface', () => {
    expect(landingDragLeaveAction({ ...page, clientX: 0, clientY: 180 })).toBe('clear');
    expect(landingDragLeaveAction({ ...page, clientX: 40, clientY: 0 })).toBe('clear');
    expect(landingDragLeaveAction({ ...page, clientX: page.viewportWidth, clientY: 180 })).toBe('clear');
    expect(landingDragLeaveAction({ ...page, clientY: page.viewportHeight })).toBe('clear');
    expect(landingDragLeaveAction({ ...page, clientX: -1, clientY: -4 })).toBe('clear');
  });
});
