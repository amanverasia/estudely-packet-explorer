// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Creator credit and Estudely navigation, shared by the landing and workspace.

export const CREDIT = {
  name: 'Aman Verasia',
  creator: { href: 'https://amanverasia.com/', text: 'Aman Verasia' },
  site: { href: 'https://estudely.com', text: 'An Estudely tool' },
  tools: { href: 'https://estudely.com/tools/', text: 'All tools' },
  about: { href: 'https://estudely.com/about/', text: 'About Estudely' },
  github: { href: 'https://github.com/amanverasia', text: 'GitHub' },
};

function CreditLink({ href, text }: { href: string; text: string }) {
  return <a href={href} target="_blank" rel="noopener noreferrer">{text}</a>;
}

export function Credit({ className }: { className?: string }) {
  return (
    <div className={`credit${className ? ' ' + className : ''}`}>
      <span>made by <CreditLink {...CREDIT.creator} /> · <CreditLink {...CREDIT.github} /></span>
      <nav className="estudely-links" aria-label="Estudely">
        <CreditLink {...CREDIT.site} />
        <CreditLink {...CREDIT.tools} />
        <CreditLink {...CREDIT.about} />
      </nav>
    </div>
  );
}
