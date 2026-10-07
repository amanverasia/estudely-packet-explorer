# Issue #58: grouped capture navigation

The workspace groups Overview, Hosts, Connections, Network and Packet list under **Investigation**. DNS, HTTP, Files, TLS, QUIC, SSH, DHCP, ARP and ICMP appear under **Protocols**.

On desktop, protocols whose whole-capture total is zero live in a native **Absent protocols** disclosure. Its summary gives the number of absent destinations and its contents explain that the capture contains no records. A direct route to an absent protocol opens the disclosure. Protocols with records in the original capture stay in the main list even when shared filters reduce their visible count to zero. Counts show visible/whole-capture totals when they differ.

At widths of 860 pixels or below, a labelled native **Current view** selector exposes every route, including absent protocols, in two option groups. The active group appears beside the label. The desktop brand and sidebar footer are hidden in this compact navigation. The selector avoids horizontal tab scrolling and retains native keyboard and screen-reader behavior.

The component delegates route changes to the existing application navigation callback, preserving shared filter parameters and the existing capture replacement lifecycle. Links retain their route URLs and selected destinations have `aria-current="page"` on desktop. A native selected option exposes the current destination on narrow screens. Focus outlines cover links, the disclosure and selector.

## Evidence

`e2e/navigation.spec.ts` exercises all fourteen routes at 390×844, 820×900 and 1440×900, grouped accessible names, current destination, native keyboard selection, keyboard disclosure, absent routes reached directly, and sidebar width. A separate test checks shared host/time filter retention, filtered-zero protocol visibility and replacement capture reset.

Executed against the integrated production build on 7 October 2026:

- `PORT=4180 npx playwright test e2e/navigation.spec.ts --project=chromium --project=firefox --workers=2 --output=/tmp/esdy-navigation-58-results`: **8 tests passed** (40.5 seconds).
- Chromium full-page screenshots were visually inspected and retained at [390px](screenshots/issue-58/navigation-390.png), [820px](screenshots/issue-58/navigation-820.png) and [1440px](screenshots/issue-58/navigation-1440.png). All use the six synthetic fixtures specified by the audit recipe. The compact selector fills the available width without a repeated brand. Desktop groups, counts and the selected destination are visible without clipping.
- The initial sandboxed run could not start a local server (`listen EPERM`); the same test command passed with sandbox escalation. This was an environment restriction, not a test failure.

This evidence covers semantic naming and keyboard behavior in browser automation; it does not claim a manual assistive-technology session or replace the broader screen-reader and contrast audit in issue #22.
