// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later

export type Theme = 'system' | 'light' | 'dark';

export function ThemeButton({ theme, setTheme }: { theme: Theme; setTheme: (theme: Theme) => void }) {
  const next: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };
  return (
    <button className="btn" onClick={() => setTheme(next[theme])} title="Switch colour theme" aria-label={`Colour theme: ${theme}. Switch to ${next[theme]}`}>
      Theme: {theme}
    </button>
  );
}
