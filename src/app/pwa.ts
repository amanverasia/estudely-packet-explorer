// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Registers the service worker (src/pwa/sw.js, built to dist/sw.js) that
// keeps the app and engine cached for offline use, and tracks its state for
// the UI: whether the offline copy is ready, how much storage it uses, and
// whether a newly deployed version is waiting to take over.
import { useSyncExternalStore } from 'react';

export type OfflineState =
  | { kind: 'unsupported' } // no service workers (or a development build)
  | { kind: 'installing' }
  | { kind: 'ready'; usage: number | null }
  | { kind: 'error'; message: string };

export interface PwaState {
  offline: OfflineState;
  /** A new version is installed and waiting; applyUpdate() switches to it. */
  updateWaiting: boolean;
  /** Another tab applied an update; this tab still runs the old version. */
  updatedElsewhere: boolean;
}

let state: PwaState = { offline: { kind: 'unsupported' }, updateWaiting: false, updatedElsewhere: false };
const listeners = new Set<() => void>();
function set(patch: Partial<PwaState>) {
  state = { ...state, ...patch };
  for (const l of listeners) l();
}

let registration: ServiceWorkerRegistration | null = null;
let reloadOnTakeover = false;

async function storageUsage(): Promise<number | null> {
  try {
    return (await navigator.storage?.estimate?.())?.usage ?? null;
  } catch {
    return null;
  }
}

function markReady() {
  // Service worker activation confirms the precache is installed. Report that
  // immediately; estimating a large cache can be slow in some browsers.
  set({ offline: { kind: 'ready', usage: null } });
  void storageUsage().then((usage) => {
    if (state.offline.kind === 'ready') set({ offline: { kind: 'ready', usage } });
  });
}

function watchInstalling(sw: ServiceWorker) {
  sw.addEventListener('statechange', () => {
    // With a controller, an installed worker is an update waiting its turn;
    // without one it is the first install, which activates on its own.
    if (sw.state === 'installed' && navigator.serviceWorker.controller) set({ updateWaiting: true });
    if (sw.state === 'activated' && !state.updateWaiting) void markReady();
    if (sw.state === 'redundant' && !registration?.active) set({ offline: { kind: 'error', message: 'Saving the app for offline use failed.' } });
  });
}

export function registerServiceWorker(): void {
  if (!import.meta.env.PROD || !('serviceWorker' in navigator)) return;
  set({ offline: { kind: 'installing' } });
  // Relative to the page, so the app works at a domain root or in a subdirectory.
  const script = new URL('sw.js', document.baseURI);
  navigator.serviceWorker.register(script, { scope: './' }).then((reg) => {
    registration = reg;
    if (reg.waiting && navigator.serviceWorker.controller) set({ updateWaiting: true });
    // An active worker means the offline copy is ready, even while an update
    // installs alongside it.
    if (reg.active) void markReady();
    if (reg.installing) watchInstalling(reg.installing);
    reg.addEventListener('updatefound', () => { if (reg.installing) watchInstalling(reg.installing); });
    // Look for a new deploy whenever the tab comes back into view.
    document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') reg.update().catch(() => {}); });
  }, (e: unknown) => {
    set({ offline: { kind: 'error', message: e instanceof Error ? e.message : String(e) } });
  });
  let hadController = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloadOnTakeover) { location.reload(); return; }
    // The first install taking control is not an update.
    if (hadController) set({ updatedElsewhere: true, updateWaiting: false });
    hadController = true;
  });
}

/** Switches to the waiting version and reloads this tab. */
export function applyUpdate(): void {
  const waiting = registration?.waiting;
  if (!waiting) { location.reload(); return; }
  reloadOnTakeover = true;
  waiting.postMessage({ type: 'skip-waiting' });
}

export function usePwa(): PwaState {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, () => state);
}
