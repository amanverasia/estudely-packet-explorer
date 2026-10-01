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

## Views checked in the browser

All views typecheck and build. They were also checked in Chromium against the production build served from a subdirectory: HTTP, Hosts, Connections, Network and the packet list with `http.pcap`, TLS with `tls.pcap`, and Network with `dns.pcap`. Each view showed the expected fixture data, with no console errors and no request other than same-origin GETs. The check was a screenshot script outside the repo; it is not yet a committed test.

## Not done / incomplete

- **Cancellation and capture replacement**: implemented by terminating the worker and ignoring stale messages, but no automated test covers them yet. Neither does the empty-state rendering of each view.
- **Playwright e2e test in the repo**: the browser check above was an ad-hoc script outside the repo. The next step is a committed `e2e/` test that opens each fixture, checks the views and asserts the no-upload property.
- **Accessibility**: keyboard navigation, ARIA roles on tables, trees and the drawer, focus handling, `prefers-reduced-motion` and forced colours are in place. No screen-reader audit or contrast tooling has been run.
- **Mobile**: there are responsive styles. Only the desktop layout has been visually checked.
- **Not supported**: HTTP/2 and HTTP/3 requests, decryption (key logs), DHCPv6 and LLDP names.
- **Decision for the owner**: the licence of the app's own code (see LICENSES.md), and hosting a mirror of the GPL corresponding source.
