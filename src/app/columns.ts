// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

export interface ColumnChoice {
  key: string;
  hidden?: boolean;
  /** User can show or hide this column. */
  choosable?: boolean;
  /** Choosable columns start hidden until the user enables them. */
  defaultHidden?: boolean;
}

export function columnVisible(column: ColumnChoice, choice: Record<string, boolean>): boolean {
  if (column.hidden) return false;
  if (!column.choosable && !column.defaultHidden) return true;
  const selected = choice[column.key];
  if (typeof selected === 'boolean') return selected;
  return !column.defaultHidden;
}

export function isColumnChoice(value: unknown): value is Record<string, boolean> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.values(value).every((item) => typeof item === 'boolean');
}
