# Completion report

## What works and was verified

- **Browser-only engine**: Wiregasm 1.9.1 (Wireshark 4.4.5) runs in a module Web Worker. A Lua postdissector extracts compact records in one armed full-dissection pass (see ARCHITECTURE.md). Verified in Node and in Chromium.
- **Engine tests**: `tests/engine.test.ts` has 18 tests, all passing, run against real Wiregasm on synthetic fixtures. They cover:
  - DNS answered / NXDOMAIN / SERVFAIL / unanswered
  - a repeated query kept as its own row and linked to the original
  - a reused transaction ID treated as a new transaction
  - IPv6 AAAA, CNAME chains, DNS over TCP split across segments (provenance 20, 21, 22)
  - mDNS and NBNS kept separate
  - HTTP pairing, including a request split across segments, IPv6 and a missing response
  - distinct TCP sessions on a reused 4-tuple
  - TLS offered vs negotiated parameters (1.2 via the version field, 1.3 via `supported_versions`), certificate decoding, SNI learned as an inferred name
  - malformed, fragmented and truncated packets
  - a cut-short file (partial analysis, marked incomplete) and a non-capture file (refused)
  - pcapng with Ethernet and raw-IP interfaces at µs and ns resolution
  - packet details and filtered packet lists
- **Browser end-to-end** (Chromium via Playwright, production build served from a subdirectory `/tools/packet-explorer/` by a plain static server, with the CSP active): opened `dns.pcap` through the file input; the Overview, the DNS view and the packet drawer showed the expected numbers. The analysis took under 1 s. **Every network request was a same-origin GET for app or engine files; none had a body.**
- **Performance**: measured at 100k packets / 88 MB (≈15 s) and 400k / 351 MB (≈52 s, 334 MB WASM heap). Limits are set from these numbers.

## Browser test suite (`npm run e2e`)

10 Playwright tests, all passing. They run against the production build, served from `/tools/packet-explorer/` by a plain static server (`scripts/serve-subdir.mjs`):

- local-processing notice shown before a file is chosen
- DNS: counts, statuses, mDNS/NBNS tabs, packet drawer showing reassembly provenance (#20–#22) and Wireshark's decode
- HTTP: 5 exchanges, request headers, captured `<script>` never rendered, distinct sessions on a reused port pair, conversation drill-down, host evidence, network graph, packet list with display filter and invalid-filter error
- TLS: offered vs negotiated parameters, cleartext certificate, encrypted TLS 1.3 certificate, empty DNS and HTTP states with the encrypted-traffic explanation
- edge cases: truncated/malformed notes, cut-short file marked incomplete, non-capture file refused, multi-interface pcapng with nanosecond timestamps
- **cancellation**: cancel mid-analysis, confirm no late result arrives, then open another capture
- **replacement**: opening a second capture replaces every count and the packet session; Close returns to the start
- exports: JSON summary and CSV arrive as downloads with the right contents
- tablet (820 px) and phone (390 px): no horizontal page scroll on any view
- every test that loads a capture also asserts that no request leaves the origin, uses a method other than GET, or has a body

Two bugs found and fixed by the suite: the Network view's filter controls overflowed on phones, and the test server's directory index (test infrastructure only).

## Deployment

Live at https://trace.esdy.cc (Cloudflare, static assets only; `npm run deploy`). A real analysis on the live site works: `tls.pcap` took 3.4 s including the first engine download.

First deploy found a bug the local suite had missed. Production CSP headers blocked the worker, because the engine glue needs `eval`. Fixed with a worker-specific policy in `public/_headers`. The test server now applies `_headers` too, and the suite was confirmed to fail with the old headers.

## Not done / incomplete

- **Accessibility**: keyboard navigation, ARIA roles on tables, trees and the drawer, focus handling, `prefers-reduced-motion` and forced colours are in place. No screen-reader audit or contrast tooling has been run.
- **Browsers**: the suite runs in Chromium only. Firefox and Safari have not been tested (WebKit's `DecompressionStream` and passing a compiled WebAssembly module to a worker are worth checking first).
- **Cloudflare zone settings**: Web Analytics auto-injection and Bot Fight Mode / JavaScript detections are on for the zone and inject scripts. The CSP blocks them, but they must be switched off in the dashboard (see DEPLOYMENT.md).
- **Not supported**: HTTP/2 and HTTP/3 requests, decryption (key logs), DHCPv6 and LLDP names.
- **Decision for the owner**: the licence of the app's own code (see LICENSES.md), and hosting a mirror of the GPL corresponding source.
