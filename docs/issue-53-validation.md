# Issue 53: export scope evidence

The top bar has one **Export** disclosure. It names scope and format before
download: whole-capture HTML, current-selection HTML, whole-capture aggregate
JSON, and whole-capture detailed JSON. Current-selection HTML is disabled until
a shared time or host filter is active. The disclosure shows the selected packet
count and filter description, and states that JSON always covers the whole
capture. Table CSV exports retain their current search and sort; conversation
packet CSV exports retain their current-page scope.

Aggregate JSON still uses the explicit allowlist in `src/app/download.ts`.
Detailed JSON keeps identifying/content-value redaction enabled by default and
explains its limits. Both JSON choices retain the packet bytes, stream payload,
TLS secret, exported-file inventory, and file-content exclusions. HTML keeps
its existing offline aggregate report and labels retained whole-capture metadata
in selected reports.

## Reproducible fixture and browser checks

`e2e/export-scope.spec.ts` combines the existing `dns`, `http`, `tls`,
`protocols`, `http2`, and `ip-data` PCAP fixtures into `mixed.pcap`. Each
fixture starts in a successive ten-second window. The combined capture has
129 packets; the HTTP window at 10–16 seconds contains 31 packets.

The browser test applies that range and checks:

- Before download: 31 of 129 selected packets, explicit whole-capture JSON
  scope, and redaction enabled.
- Current-selection HTML: 31 matching packets and the 10–16-second report
  scope. Whole-capture HTML and both JSON variants: 129 packets.
- All four choices activate with the keyboard and return focus to Export.
- Escape closes the disclosure and returns focus; outside clicks close it.
  A visible Close export menu button also closes it and returns focus.
- The panel fits a 390-pixel viewport.
- Capture processing and downloads introduce no outbound HTTP requests.

Run after the production build:

```sh
npx playwright test e2e/export-scope.spec.ts
```

On 7 October 2026, all four targeted checks passed against the integrated
production build in Chromium and Firefox:

```sh
PORT=4176 npx playwright test e2e/export-scope.spec.ts --project=chromium --project=firefox --output=/tmp/esdy-issue53-tests
```

Result: **4 passed (7.8 seconds)**. These include the concrete 31/129 download
contents, keyboard activation of all choices, safe redaction defaults, local-only
requests, Escape/outside/visible-button dismissal, focus return, and narrow-panel
bounds. WebKit execution remains part of CI; it was not run locally for this
targeted validation.
