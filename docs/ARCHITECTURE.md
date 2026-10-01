# Architecture and parser integration

## Overview

```
 UI thread (React)                         Analysis worker (one per capture)
 ─────────────────                         ─────────────────────────────────
 File picker / drop  ── File object ──▶    file.arrayBuffer()  (local read)
 EngineClient        ◀── progress ───      Wiregasm (Wireshark 4.4.5 WASM)
   │                                         1. load()        index packets
   │                                         2. armed pass    Lua extractor writes TSV
   │                                         3. parseRecords  TSV → typed raw records
   │                                         4. analyze       raw → AnalysisModel
 Views  ◀────────── AnalysisModel ────────   keeps packet index + session
 Drawer / packet list ── requests ──▶      getFrame(n) / getFrames(filter, skip, limit)
```

All views read one shared `AnalysisModel` (`src/engine/types.ts`). The file is decoded once; tabs never re-parse it.

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
- Multiple DNS/HTTP messages in one packet are separated by the byte range of each protocol item; TLS handshake messages by the offset of each `tls.handshake.type`.
- Wireshark flags some real fields as *generated* (e.g. `dns.id` on unanswered queries); only zero-length generated items are skipped.
- ICMP error payloads quote other packets; protocol records are not taken from quoted headers.
- Missing field names are reported once as a warning instead of failing the script.

## Aggregation (`src/engine/analyze.ts`)

Pure TypeScript, unit-testable in Node:

- **Conversations**: TCP/UDP by Wireshark `tcp.stream` / `udp.stream` (so a reused 4-tuple after FIN is a separate session); other IP by protocol + address pair; non-IP by protocol + MAC pair. Endpoint A is the SYN sender when a SYN is seen, else the first packet's sender (labelled as such).
- **DNS/LLMNR/NBNS correlation**: key = protocol + transport + client address + client port + transaction ID; the response must come from the queried server (or any server if the query went to a broadcast/multicast address) within 60 s. A repeated query (same key, name, type, server, still unanswered) becomes its own row with status `retransmitted` linked to the original. A reused ID after an answer starts a new transaction. Unmatched responses are `response without query` or `duplicate response`. mDNS messages are listed individually.
- **HTTP**: per TCP stream FIFO pairing (HTTP/1.1 is in-order); 1xx interim responses (except 101) do not consume a request.
- **TLS**: one session per ClientHello; ServerHello/Certificate attach to the latest session in that conversation. Negotiated version comes from the ServerHello `supported_versions` extension when present, else the version field. Certificates are parsed from DER in `src/engine/x509.ts` (display fields only, no trust validation) and fingerprinted with WebCrypto.
- **Hosts**: per IP address; source MACs; ARP-announced MACs; ports peers sent traffic to with evidence (`handshake completed`, `SYN-ACK sent`, `SYN received, no SYN-ACK seen`, `mid-stream traffic`, `UDP traffic received`); names with source and observed/inferred kind.
- **DHCP, ARP, ICMP, SSH, QUIC** (`src/engine/protocols.ts`): DHCP messages group by transaction ID + client MAC, the outcome taken from the last deciding message (a DECLINE after an ACK reads as declined); ARP mappings come from sender addresses in frame order, a change being a different MAC than the previous message for that IP; ICMP echo replies pair with the oldest unanswered request of the same addresses, identifier and sequence number; the quoted packet of an error is the IP and TCP/UDP header after the ICMP header (so tunnel headers before it are skipped), and error messages link to the latest captured TCP/UDP conversation with the quoted 5-tuple that started before the error; SSH and QUIC records group per conversation, with the QUIC client taken from the Initial ClientHello.
- **Timeline**: ~150 bins at a "nice" width from the earliest timestamp (timestamps need not be monotonic), stacked by highest decoded protocol (top 6 + Other).

Times are stored relative to the first packet so that nanosecond precision survives (`startEpoch` keeps the exact epoch string). Absolute times are reconstructed from that string, never from a rounded float.

## Worker lifecycle, cancellation and memory

- `EngineClient` (`src/app/engine.ts`) creates a **new worker per capture**. Cancel, Close and Open-another call `worker.terminate()`, which discards the whole WASM heap and the capture bytes. Stale messages from an old worker are ignored.
- The compiled `WebAssembly.Module` and the data package are posted back to the UI thread and handed to the next worker, so the 19 MB download and compile happen once per page load.
- The capture is written into the Emscripten FS with `canOwn` so it is not copied again. Per-packet data kept in the worker is ~17 fields per packet (interned strings), never full trees. Packet trees are produced only on demand for the drawer (capped at 20,000 nodes); packet lists are paged 500 rows at a time.
- Tables are virtualised (`@tanstack/react-virtual`).

## Security and privacy

- Captured strings are rendered only as React text nodes. Nothing is rendered as HTML; bodies are never rendered; CSV exports neutralise spreadsheet formulas.
- The production page ships a Content-Security-Policy with `connect-src 'self'`; the only network requests are same-origin GETs for the app and engine files (verified in Chromium, Firefox and WebKit with request logging — no request has a body).
- Theme preference is the only thing written to `localStorage`. Captures are never persisted.
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

Hence the limits in `src/app/engine.ts`: a warning above 250 MB and a hard refusal above 1 GiB. Browser times are similar to Node; expect a few seconds of engine start-up on first use.
