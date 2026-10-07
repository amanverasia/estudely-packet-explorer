# Issue #54: compact capture toolbar

The baseline and final screenshots use synthetic `http.pcap`, Chromium, identical
viewports and the production build served from `/tools/packet-explorer/`.

| Viewport | Baseline header height | Final header height | Evidence |
| --- | --- | --- | --- |
| 1440×900 | 219.9px | 107.6px | [Before](screenshots/issue-54/before-1440.png), [After](screenshots/issue-54/after-1440.png) |
| 960×900 | 259.9px | 107.6px | [Before](screenshots/issue-54/before-960.png), [After](screenshots/issue-54/after-960.png) |
| 390×844 | 384.7px | 139.6px | [Before](screenshots/issue-54/before-390.png), [After](screenshots/issue-54/after-390.png) |

Measurements are also retained as before/after-heights.json beside the screenshots.
The new toolbar has two compact rows on desktop, wraps actions on mobile, and scrolls
with the page rather than obscuring focused content. The filename is truncated visually
but has its full accessible text/title and is repeated in Help. Capture actions retains
Open another, Compare and Close; Export, Theme, Help and contextual TLS keys remain
visible. Shared filters have compact removal chips; traffic/time filtering remains available.

`e2e/capture-toolbar.spec.ts` verifies long filenames, compact heights, keyboard and
touch-friendly Help/capture actions, colour theme, active time/host chips and clear,
no page overflow, and the incomplete-file indicator using `cut.pcap` at all three
widths. Decrypted-key states, replacement and comparison are exercised by
`e2e/workspace-lifecycle.spec.ts`. Partial-analysis facts and limitations remain on the
same shared model and retain the existing engine and browser quality coverage.

Run `npm run build`, then `npx playwright test e2e/capture-toolbar.spec.ts`.

All six focused Chromium/Firefox toolbar checks passed. The parent change records
the full browser suite, engine tests, build and GitHub CI results.
