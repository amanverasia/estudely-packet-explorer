# Issue #60: graph framing, controls and host focus

Synthetic captures stay local throughout these checks. The mixed fixture uses
`dns.pcap`, `http.pcap`, `tls.pcap`, `protocols.pcap`, `http2.pcap` and `ip-data.pcap`
(30 hosts / 25 links), as in the audit recipe. The final evidence and browser tests
normalize each capture's timestamps into consecutive 10-second windows. Baseline
screenshots used the same packet records without timestamp normalization; network
nodes, link totals and protocol aggregation are identical.

## Changes and acceptance evidence

- Initial framing packs disconnected components without changing each component's
  settled shape, includes placed labels in the fit bounds, and refits on container
  resize. Automatic fit remains capped at **1.2**, including tiny captures.
- **Fit graph**, **Reset viewport**, **Zoom in graph** and **Zoom out graph** are
  native keyboard-accessible buttons. Reset explicitly restores the fitted viewport
  while retaining graph protocol/focus and shared filters.
- Address/name search narrows the labelled host-focus selector. **Clear host focus**
  clears only graph focus/search/selection, retaining the protocol and shared filters.
- Selected host identity is shown in a 14px screen-space badge independent of zoom,
  alongside the existing detail panel. Narrow detail panels scroll within 42% of the
  graph height to leave room to inspect the graph.
- The accessible host/link tables still use the same graph data and remain available
  below the graph. No packet selection, provenance or shared-filter logic changed.

## Validation

`npm run typecheck` passed. The four targeted Playwright tests passed in Chromium and Firefox (8/8):

```sh
npx playwright test e2e/network-controls.spec.ts --project=chromium --project=firefox --workers=1
```

The tests synchronize with stable rendered SVG dimensions and transforms across
animation frames before saving viewport baselines, allowing ResizeObserver and
React to complete the initial fit. They verify 30-host mixed framing, keyboard zoom and reset, recovery after mouse pan,
protocol plus host focus preservation, the filtered accessible link-list counts,
clear-focus scope, and mixed/DNS/HTTP framing and the 1.2 cap through **1440**, **960**
and **390** pixel resizes. The cap assertions tolerate SVG matrix float rounding
(`1.2000000476837158`). Project-wide engine, production build and browser validation
are recorded with the combined three-issue change.

## Visual evidence

Baseline screenshots reproduce the missing controls and the narrow viewport's
clipped disconnected graph. Final screenshots show packed graph framing at the
same widths and a readable selected host with focus active.

| Width | Baseline | Final |
| --- | --- | --- |
| 1440px | [Before](screenshots/issues-60/before-1440.png) | [After](screenshots/issues-60/after-1440.png) |
| 960px | [Before](screenshots/issues-60/before-960.png) | [After](screenshots/issues-60/after-960.png) |
| 390px | [Before](screenshots/issues-60/before-390.png) | [After](screenshots/issues-60/after-390.png) |

Selected host: [desktop](screenshots/issues-60/after-focused-1440.png),
[narrow](screenshots/issues-60/after-focused-390.png).
