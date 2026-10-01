// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { createContext, useContext, type ReactNode } from 'react';
import type { AnalysisModel } from '../engine/types';
import type { EngineClient } from './engine';

export interface DrawerSpec {
  title: string;
  frames: number[];
  focus?: number;
  /** Record-level summary shown above the packet details. */
  summary?: ReactNode;
}

export interface AppCtx {
  model: AnalysisModel;
  engine: EngineClient;
  openDrawer: (spec: DrawerSpec) => void;
  go: (view: string, params?: Record<string, string>) => void;
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
