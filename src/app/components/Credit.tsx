// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// The one credit line shared by every esdy.cc tool. Keep the strings here only.

export const CREDIT = {
  name: 'Aman Verasia',
  site: { href: 'https://estudely.com', text: 'estudely.com' },
  github: { href: 'https://github.com/amanverasia', text: 'github.com/amanverasia' },
};

function CreditLink({ href, text }: { href: string; text: string }) {
  return <a href={href} target="_blank" rel="noopener noreferrer">{text}</a>;
}

export function Credit({ className }: { className?: string }) {
  return (
    <span className={`credit${className ? ' ' + className : ''}`}>
      made by {CREDIT.name} · <CreditLink {...CREDIT.site} /> · <CreditLink {...CREDIT.github} />
    </span>
  );
}
