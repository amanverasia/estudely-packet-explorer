// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { createContext, useCallback, useContext, useEffect, useState, type Dispatch, type ReactNode, type SetStateAction } from 'react';
import type { AnalysisModel } from '../engine/types';
import type { EngineClient } from './engine';
import type { FilterStats, SharedFilter } from './filtering';

export interface DrawerSpec {
  title: string;
  frames: number[];
  focus?: number;
  /** Record-level summary shown above the packet details. */
  summary?: ReactNode;
}

export interface AppCtx {
  model: AnalysisModel;
  /** Unfiltered capture model, used to validate saved selections hidden by a shared filter. */
  sourceModel: AnalysisModel;
  filter: SharedFilter;
  stats: FilterStats;
  engine: EngineClient;
  openDrawer: (spec: DrawerSpec) => void;
  go: (view: string, params?: Record<string, string>) => void;
  patchRouteParams: (params: Record<string, string | null>) => void;
  setHostFilter: (host: string | null) => void;
  setTimeRange: (start: number, end: number) => void;
  clearTimeRange: () => void;
  clearFilters: () => void;
  params: URLSearchParams;
  /** Best learned name for an address, for secondary labels. */
  nameOf: (addr: string) => string | null;
}

export interface ViewStateStore {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
}

export const Ctx = createContext<AppCtx | null>(null);
export const ViewStateCtx = createContext<ViewStateStore | null>(null);

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('App context missing');
  return c;
}

/** Keeps small view controls in tab memory while inactive views are unmounted. */
export function useViewState<T>(key: string, initial: T, valid: (value: unknown) => value is T): [T, Dispatch<SetStateAction<T>>] {
  const store = useContext(ViewStateCtx);
  const [value, setValue] = useState<T>(() => {
    const saved = store?.get(key);
    return valid(saved) ? saved : initial;
  });
  const setStoredValue = useCallback<Dispatch<SetStateAction<T>>>((action) => {
    setValue((previous) => {
      const next = typeof action === 'function' ? (action as (value: T) => T)(previous) : action;
      store?.set(key, next);
      return next;
    });
  }, [key, store]);
  useEffect(() => { store?.set(key, value); }, [key, store, value]);
  return [value, setStoredValue];
}
