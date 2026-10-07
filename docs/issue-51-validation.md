# Issue #51: analysis timing and phase evidence

The original landing timer was initialized on the idle page and reused when a newer
`startedAt` arrived. `AnalysisProgress` is now mounted per run with `startedAt` as its
React key, samples the clock on mount, and releases its interval on cancellation,
error or completion. A nonnegative elapsed fallback also handles equal/stale samples.

Engine downloads precede a separate initialization phase. Progress bars name their
phase and describe percentages as current-download or phase progress; 100% download leaves analysis and
Cancel active. Only the worker's ready message displays the investigation workspace.

Reproduction and acceptance evidence lives in `e2e/loading.spec.ts`:

- A controlled `performance.now()` advances five minutes while landing is idle,
  then verifies the first analysis render is 0 seconds and its next tick is 12 seconds.
- Download at 100% remains working; initialization changes the progressbar name and
  removes its percentage for indeterminate work.
- Cancel terminates the worker; a later run starts at 0 seconds. Stale progress from
  the cancelled worker is ignored, and an actionable error allows a fresh retry.
- Real `dns.pcap` cold analysis and `http.pcap` warm replacement reach ready results.

Run `npm run build` then `npx playwright test e2e/loading.spec.ts` against the
production build served from `/tools/packet-explorer/`. Chromium and Firefox passed
locally; the local WebKit runtime lacks `libavif.so.16`, so its result is verified
in GitHub CI, which installs browser OS dependencies.
