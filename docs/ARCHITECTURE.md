# Architecture and parser integration

## Overview

```
 UI thread (React)                         Analysis worker (one per capture)
 ─────────────────                         ─────────────────────────────────
 File picker / drop  ── capture + key log ──▶ bounded File stream  (local read)
 EngineClient        ◀── progress ───      Wiregasm (Wireshark 4.4.5 WASM)
   │                                         1. load()        index packets
   │                                         2. armed pass    Lua extractor writes TSV
   │                                         3. parseRecords  TSV → typed raw records
   │                                         4. analyze       raw → AnalysisModel
 Views  ◀────────── AnalysisModel ────────   keeps packet index + session
 Drawer / packet list / conversation detail ──▶ getFrame(n) / getFrames(filter, skip, limit) / rows(convId, skip, limit)
```

Record drawers stack: a packet opened from a host, conversation or stream match stays above that record, and Escape returns to it. One source packet skips the page controls. Protocol charts sit in a collapsed Summary so the records are first.

All views read one shared `AnalysisModel` (`src/engine/types.ts`). The file is decoded once; tabs never re-parse it. The model carries a compact, columnar packet filter index (times, lengths, endpoint/stream IDs and top protocol IDs), not packet payloads. The UI uses it to recalculate time/host-filtered packet, host and conversation totals. Protocol hierarchy and non-traffic host metadata remain capture-wide.

Compare mode analyzes the baseline capture, copies only host names/protocols, top-protocol totals, conversation summaries and capture metadata, then terminates that worker before analyzing the second capture. Conversation IDs use protocol and the order-independent endpoint address/port pair; repeated uses of one tuple are paired by first-seen order. The comparison keeps no packet index or payloads and never holds two Wiregasm sessions concurrently.

An optional TLS key log follows the capture directly to the worker. The worker places it in the virtual filesystem and applies Wireshark's `tls.keylog_file` preference. Wireshark can read the file again during later dissections, so the temporary copy stays in the in-memory filesystem until the worker is terminated with the capture.

## Why Wiregasm

Wiregasm compiles Wireshark's `epan` dissectors and `libwiretap` file readers to WebAssembly. Checked before committing to it:

| Question | Finding |
|---|---|
| API | A small sharkd-like subset: `DissectSession.load()`, `getFrames(filter, skip, limit)`, `getFrame(n)` (protocol tree as labels + filter strings), `follow`, `tap` (conv/endpoint/export-object), `iograph`, `checkFilter`. No API returns typed field values for all packets. |
| Formats | Everything libwiretap 4.4.5 reads: pcap, pcapng (multi-interface, per-interface link types and timestamp resolutions), gzip-compressed captures and other Wireshark formats. Verified: pcap, pcapng with Ethernet + raw-IP interfaces, cut-short files, non-capture files. |
| Browser | Emscripten build without pthreads, so no COOP/COEP headers are needed. Memory growth enabled; the wasm32 ceiling is 2 GiB. Works in a module worker in Chromium, Firefox and WebKit (see BROWSERS.md). |
| Size | `wiregasm.wasm` is 69 MB (19 MB gzipped) plus a 2.7 MB data package (0.45 MB gzipped). |
| Licence | GPL-2.0 (Wireshark derivative). See LICENSES.md. |
| Extensibility | Lua plugins can be written into the virtual FS before `init()`. This is what makes efficient extraction possible. |

Alternatives considered: a hand-written TypeScript parser (small, fast, but would need its own TCP reassembly, IP defragmentation, DNS-over-TCP framing, HTTP reassembly, TLS record/handshake reassembly, QUIC Initial decryption and dozens of link types — exactly the things the brief says not to approximate); and per-packet `getFrame()` tree walking (correct but ~100× slower and memory-heavy). Wiregasm with a Lua extractor keeps Wireshark's correctness while producing compact output.

## Exported files

The Files view uses Wiregasm's export-object taps for DICOM, HTTP, IMF, SMB and TFTP. A tap returns object metadata and an opaque download token; file payloads stay in Wiregasm's worker memory. When the user chooses Download, the worker asks `DissectSession.download(token)` for only that object's bytes and transfers those bytes to the page as a one-time download. The page uses an `application/octet-stream` Blob and a download link; it does not put captured content into the DOM, preview it, or execute it. The capture remains local to the browser.

## The extraction pass (the key integration detail)

`load()` dissects every packet once **without** building protocol trees (`lib.cpp`, `load_cap_file`: a tree is built only if a postdissector registered wanted hfids, which Lua postdissectors do not do). Lua `Field` extractors therefore return nothing during `load()`.

So the engine does this (`src/engine/session.ts`):

1. `load()` — Wireshark reads and indexes all packets, performs TCP/IP reassembly bookkeeping.
2. Writes `/estx/arm` (output path + packet count) into the in-memory FS.
3. Calls `getFrames('frame', 0, 1)`. A non-empty display filter makes Wiregasm re-dissect **every** frame with a protocol tree, in order. The extractor (`src/engine/extractor.lua`, registered as a postdissector) sees the arm file at frame 1, reads the fields it needs and appends tab-separated records to `/estx/out.tsv`, then writes `/estx/done` at the last frame.
4. The worker reads the output file, deletes it, and parses it in 4 MB chunks.

Because this is Wireshark's second pass, reassembled PDUs (DNS over TCP, HTTP headers split across segments, fragmented IP datagrams, TLS handshakes) are decoded where they complete, and `tcp.segment` / `ip.fragment` give the contributing packet numbers — these become each record's provenance.

Outside the armed pass (packet details, filtered packet lists) the extractor returns immediately. Progress is printed to stdout (`@@ESTX load|extract N`), which the worker forwards to the UI.

Notable details handled in the extractor:
- Multiple DNS/HTTP messages in one packet are separated by the byte range of each protocol item; TLS handshake messages by the offset of each `tls.handshake.type`. Offsets are compared only when both fields have the same `FieldInfo.source`, or when neither exposes a source. If only one source is available, the extractor leaves the field unassigned instead of guessing across reassembly buffers.
- HTTP/2 frame IDs live in the packet Tvb, while HPACK-decoded fields live in generated header Tvbs. Those fields are grouped by source and collected across HEADERS/CONTINUATION fragments through END_HEADERS; their offsets are never compared with packet offsets.
- Wireshark flags some real fields as *generated* (e.g. `dns.id` on unanswered queries); only zero-length generated items are skipped.
- ICMP error payloads quote other packets; protocol records are not taken from quoted headers.
- Missing field names are reported once as a warning instead of failing the script.

## Aggregation (`src/engine/analyze.ts` and focused modules)

Pure TypeScript, unit-testable in Node. `analyze.ts` builds the packet lookups, calls each focused builder in dependency order, updates conversation record counts, and assembles the shared model. The builders accept explicit inputs and return model data; `analyze.ts` remains the worker-facing entry point:

- **Conversations** (`conversations.ts`): TCP/UDP by Wireshark `tcp.stream` / `udp.stream` (so a reused 4-tuple after FIN is a separate session); other IP by protocol + address pair; non-IP by protocol + MAC pair. Endpoint A is the SYN sender when a SYN is seen, else the first packet's sender (labelled as such).
- **DNS/LLMNR/NBNS correlation** (`dns.ts`): key = protocol + transport + client address + client port + transaction ID; the response must name the same query and type and come from the queried server (or any server if the query went to a broadcast/multicast address) within 60 s. A repeated query (same key, name, type, server, still unanswered) becomes its own row with status `retransmitted` linked to the original. A reused ID after an answer starts a new transaction. Unmatched responses are `response without query` or `duplicate response`. mDNS messages are listed individually.
- **HTTP** (`http.ts`): Wireshark's `http.request_in` / `http.response_in` frame references take precedence when available; stream FIFO is the fallback. Disagreements with stream order are shown in the HTTP view. 1xx interim responses (except 101) do not consume a request. HTTP/2 header blocks pair by TCP stream and HTTP/2 stream ID, including blocks completed by CONTINUATION frames.
- **TLS** (`tls.ts`): one session per ClientHello; ServerHello/Certificate attach to the latest session in that conversation. Negotiated version comes from the ServerHello `supported_versions` extension when present, else the version field. A session is decrypted when a protocol other than bare data is dissected above TLS, or a protocol other than the Initial TLS handshake and bare data is dissected above QUIC. QUIC stream data alone leaves the session encrypted. Decrypted application packets and HTTP rows are marked. Certificates are parsed from DER in `src/engine/x509.ts` (display fields only, no trust validation) and fingerprinted with WebCrypto.
- **Hosts** (`hosts.ts`): per IP address; IANA special-purpose range label; a separate globally-reachable flag for local metadata eligibility; source MACs; ARP-announced MACs; ports peers sent traffic to with evidence (`handshake completed`, `SYN-ACK sent`, `SYN received, no SYN-ACK seen`, `mid-stream traffic`, `UDP traffic received`); names with source and observed/inferred kind. Range classification uses the static IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry) Special-Purpose Address Registry snapshot last updated 2025-10-09, the [IPv6 Address Space](https://www.iana.org/assignments/ipv6-address-space) snapshot last updated 2025-10-23, and the [IPv4 Multicast Address Space](https://www.iana.org/assignments/multicast-addresses) snapshot last updated 2026-08-20. Prefixes use longest-match semantics; a separate flag gates metadata lookups. An IANA special-purpose row is eligible only when `Globally Reachable` is true; false, N/A, and expired entries are excluded. Ordinary IPv4 addresses outside special-purpose rows use the unicast default; ordinary IPv6 unicast uses the IANA `2000::/3` Global Unicast allocation, with special-purpose rows overriding that default. These labels describe registered allocation and reachability policy, not observed routing.
- **Timeline and filter index** (`traffic.ts`): timeline bins and the compact packet filter index, including per-frame times, host endpoints, protocol IDs, conversation IDs, and direction. Unsupported protocol summaries are also finalized there.
- **Shared aggregation helpers** (`analysis-utils.ts`, `address-scope.ts`): protocol labels, payload-protocol exclusions, address scope and special-purpose classifications used by the builders.
- Optional Hosts metadata is separate from the capture model. A user-selected DB-IP Lite Country or ASN CSV is decoded incrementally in a short-lived worker. A stateful CSV tokenizer handles quoted newlines and chunk boundaries, and range rows accumulate in fixed typed-array blocks. Finalization checks inclusive overlaps and sorts unordered input using a typed permutation before transferring the compact IPv4/IPv6 index to the page for IndexedDB storage. Imports retain the 100 MiB input-file and 150 MiB decompressed limits; progress reports bytes and accepted rows. Numeric storage scales with range count, and interned labels and the largest incomplete CSV record still consume memory. [IP_IMPORT_MEMORY.md](IP_IMPORT_MEMORY.md) documents the storage budget and whole-import measurements. Only hosts whose separate globally-reachable flag is true are matched against that index locally. Country and network-owner results are explicitly approximate. The worker receives only the chosen database file, never the capture.
- **DHCP, ARP, ICMP, SSH, QUIC** (`src/engine/protocols.ts`): DHCP messages group by transaction ID + client MAC, the outcome taken from the last deciding message (a DECLINE after an ACK reads as declined); ARP mappings come from sender addresses in frame order, a change being a different MAC than the previous message for that IP; ICMP echo replies pair with the oldest unanswered request of the same addresses, identifier and sequence number; the quoted packet of an error is the IP and TCP/UDP header after the ICMP header in the same data source (so tunnel headers before it, and fields from another reassembly buffer, are skipped), and error messages link to the latest captured TCP/UDP conversation with the quoted 5-tuple that started before the error; SSH and QUIC records group per conversation, with the QUIC client taken from the Initial ClientHello.
- Timeline bins are about 150 at a "nice" width from the earliest timestamp (timestamps need not be monotonic), stacked by highest decoded protocol (top 6 + Other).

Times are stored relative to the first packet so that nanosecond precision survives (`startEpoch` keeps the exact epoch string). Absolute times are reconstructed from that string, never from a rounded float.

## Worker lifecycle, cancellation and memory

The workspace keeps small view controls and table search/sort values in a capture-scoped in-memory store so they survive view unmounts. The accepted Packet display filter is also written to the URL hash for Back/Forward navigation; draft text stays only in memory. Route history entries carry a capture-session marker. Replacing or closing a capture and entering Compare advance the session and clear the store, so Back/Forward cannot apply an earlier capture's filters to the current capture. No packet data is stored in this UI state.

- `EngineClient` (`src/app/engine.ts`) creates a **new worker per capture**. Cancel, Close and Open-another call `worker.terminate()`, which discards the whole WASM heap and the capture bytes. Stale messages from an old worker are ignored.
- The compiled `WebAssembly.Module` and the data package are posted back to the UI thread and handed to the next worker, so the 19 MB download and compile happen once per page load.
- The capture is written into the Emscripten FS with `canOwn` so it is not copied again. Per-packet data kept in the worker is ~17 fields per packet (interned strings), never full trees. Packet trees are produced only on demand for the drawer (capped at 20,000 nodes); packet lists request 500-row pages, and conversation packet requests enforce a 500-row page cap. Conversation details keep one compact matching packet-index list in the worker for the active conversation and reset it when a session opens or closes; packet rows themselves remain page-local in the UI. The drawer asks for metadata only for the selected frame.
- Tables are virtualised (`@tanstack/react-virtual`).

Follow Stream iterates Wiregasm's payload vector without retaining an array of all base64 records. It collects numeric metadata for the capped prefix, allocates one output buffer, and decodes that prefix with bounded scratch space; the vector is deleted on success and failure. Full direction totals still require visiting every payload. Wiregasm 1.9.1 performs full follower collection and serialization before this code runs, so its WASM allocation and a single base64 getter remain proportional to stream size. [FOLLOW-MEMORY.md](FOLLOW-MEMORY.md) records the measured improvement and unresolved hard bound.

## Security and privacy

- Captured strings are rendered only as React text nodes. Nothing is rendered as HTML; bodies are never rendered; CSV exports neutralise spreadsheet formulas.
- JSON exports are serialized in the page and downloaded as local Blobs. The aggregate serializer selects fields through an explicit allowlist; detailed export omits the internal packet filter index and offers a known-field redaction pass over a fresh object tree. Neither mode serializes packet bytes, stream payloads, TLS key logs, or exported file objects. Redaction replaces known sensitive fields, including MAC vendor and ALPN strings, and leaves frame numbers, relative timings, ports, sizes, and counts, so it does not guarantee anonymity. Download names use the capture basename.
- The production page ships a Content-Security-Policy with `connect-src 'self'`; app code makes only same-origin GETs for app and engine files. The Hosts view has explicit links that open DB-IP's download pages in a new tab; the user downloads and imports CSV data manually. No capture address is included in those requests.
- Theme preference is written to `localStorage`. Optional DB-IP range indexes are stored in IndexedDB until removed; captures and key logs are never persisted.
- A selected key log is read with the File API and passed to the analysis worker. Its temporary virtual file and imported secrets stay in the worker's memory until that capture is closed; the user's original key-log file is never modified.
- The service worker (`src/pwa/sw.js`, built to `dist/sw.js`) caches only the files listed in its precache list, which the build generates from `dist/`. It never stores runtime responses; captures and key files are read with the File API and never pass through it. A browser test checks the Cache Storage contents after opening a capture.

## Offline app (PWA)

- `vite.config.ts` (`pwaPlugin`) writes `dist/sw.js` with two precache groups: the app shell and `wiregasm/*`, each named after a hash of its files (`epx-shell-…`, `epx-engine-…`). A deploy changes `sw.js`, so browsers install the new worker; an unchanged engine keeps its cache name and is not downloaded again. Old caches are deleted when the new worker activates.
- The worker and its scope are registered relative to the page (`./sw.js`, scope `./`), so it works at a domain root and in a subdirectory. `manifest.webmanifest` uses relative `start_url` and `scope` for the same reason.
- A new version waits until the user clicks "Reload to update" (a reload closes the open capture, so it is never forced). The start screen shows offline status and storage use from `navigator.storage.estimate()`.
- `npm run dev` does not register the service worker.

## Measured performance (Node 26, same WASM, one core)

| Capture | Load | Extraction pass | WASM heap | Process RSS |
|---|---|---|---|---|
| 100k packets, 88 MB | 3.4 s | 11.4 s | 161 MB | — |
| 400k packets, 351 MB | 12.6 s | 39.5 s | 334 MB | 930 MB |

Hence the limits in `src/engine/limits.ts`: a warning above 250 MB and a 1 GiB cap on bytes streamed into the in-memory capture. Larger inputs are read as a bounded prefix, never materialized as one large JavaScript `ArrayBuffer`, and are marked partial throughout the UI and exported summaries. Gzip data is bounded after decompression. Browser times are similar to Node; expect a few seconds of engine start-up on first use.

### Capture restoration and TLS reanalysis

The App retains the original File and applied key-log File in refs/state only for the
current tab. Comparison keeps a compact seed summary, closes the investigation worker,
and snapshots capture-local route, selection and table state. Its Back action closes
its own EngineClient synchronously before App starts restoration. Reanalysis preserves
the capture-session identity, whereas replacement and Close reset state and keys.
Worker identity checks reject stale messages. Key updates stage a file explicitly,
reanalyze the retained original File, and commit active-key status only on ready results;
failure/cancellation can reanalyze using the prior applied keys.
