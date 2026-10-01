// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { createContext, useContext, type ReactNode } from 'react';
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
  filter: SharedFilter;
  stats: FilterStats;
  engine: EngineClient;
  openDrawer: (spec: DrawerSpec) => void;
  go: (view: string, params?: Record<string, string>) => void;
  setHostFilter: (host: string | null) => void;
  setTimeRange: (start: number, end: number) => void;
  clearTimeRange: () => void;
  clearFilters: () => void;
  params: URLSearchParams;
  /** Best learned name for an address, for secondary labels. */
  nameOf: (addr: string) => string | null;
}

export const Ctx = createContext<AppCtx | null>(null);

export function useApp(): AppCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('App context missing');
  return c;
}
