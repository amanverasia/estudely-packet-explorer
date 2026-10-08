# Features and known limitations

## Views

| View | What it shows | Source of truth |
|---|---|---|
| Overview | Packets, duration, bytes on wire vs captured, file size, hosts, conversations, time range (UTC, file precision), interfaces, traffic over time (bytes or packets, stacked by top protocol), protocol distribution, top talkers, largest conversations, protocol hierarchy, data-quality notes; shared time-window and host filters | Every packet |
| DNS | DNS / mDNS / LLMNR / NBNS tabs. The table starts with queried name, client, resolver, answers, response code, response time and status; time, type, transport, transaction ID and packets are optional columns. Counts, charts and the client→resolver diagram are in Summary charts | `dns.*`, `nbns.*` fields |
| HTTP | HTTP/1.x and HTTP/2 requests. The table starts with relative time, method, host, path, status, response time and packets; version, stream, headers metadata and pairing are optional columns. Decrypted messages are marked on the status. The lead text says cleartext, decrypted, or both. Counts by host, method and numeric status code (reason phrases do not split categories) are in Summary charts | `http.*` and decoded `http2.*` header fields |
| Files | Reassembled DICOM, HTTP, IMF, SMB and TFTP objects; protocol, server host, filename, content type, size and packet; explicit download action | Wiregasm export-object taps |
| TLS | ClientHello SNI, offered versions, ALPN and cipher suites; ServerHello negotiated version (and where it came from), cipher, ALPN; cleartext certificates; per-session status for decrypted, still-encrypted, or absent application data | `tls.handshake.*`, `tls.app_data`, and the packet protocol stack |
| QUIC | Per UDP conversation: versions in long headers, versions listed by Version Negotiation, SNI and offered ALPN from the Initial ClientHello, packet count; matching TLS key logs can expose decrypted QUIC stream packets | `quic.version`, `quic.supported_version`, `quic.stream_data`, `tls.handshake.*` |
| SSH | Client and server identification strings per TCP session | `ssh.protocol`, `ssh.direction` |
| DHCP | DHCPv4 exchanges by transaction ID + client MAC: message sequence, outcome (ACK, NAK, offer only, no server reply), client host name, requested/offered/assigned address, server, lease time, subnet mask, routers, DNS servers | `dhcp.*` fields |
| ARP | Every request/reply (sender and target, gratuitous flag); per IPv4 address the MACs ARP senders stated, in time order, with the number of changes. Probes (sender 0.0.0.0) state no mapping | `arp.*` fields |
| ICMP | ICMP and ICMPv6 messages with type and code names; echo requests paired with replies; error messages with the quoted packet's addresses and ports, linked to that captured TCP/UDP conversation | `icmp.*`, `icmpv6.*`, inner `ip`/`ipv6`/`tcp`/`udp` fields |
| Hosts | IPv4/IPv6 addresses and IANA special-purpose range labels, source MACs (with the registered vendor of the address prefix from Wireshark's built-in table, or "locally administered") and ARP MACs, sent/received packets and bytes, peers, ports peers used (with evidence), names learned with source and observed/inferred label; optional approximate country and ASN owner from user-imported DB-IP Lite data for globally reachable addresses only. Selecting a host opens the same record drawer as other views | Packets, conversations, DNS/mDNS/NBNS/DHCP/SNI/Host; optional local DB-IP Lite CSV |
| Connections | TCP/UDP sessions by stream index, other IP and non-IP groups; directional packets/bytes; start and duration; TCP flags seen and analysis counts, including a separate spurious-retransmission count; one-click filters for ordinary retransmissions (not spurious), spurious retransmissions, out-of-order segments, sequence gaps, RST, truncated packets, and malformed packets. The selected conversation opens in the record drawer with summary, related DNS/HTTP/TLS records, Follow Stream, and the full packet list, paged in 500-row blocks with direct page navigation | Packets |
| Follow Stream | Reassembled TCP/UDP payload in text or hex, direction selection, local raw-byte download, and literal text or hex-byte search over the displayed runs; previous/next navigation, highlighted matches, direction and byte offset, and packet links when the follower reports segment provenance | Wiregasm follower |
| Network | Force-directed host graph, edge width = log bytes, edge colour = main protocol; protocol filter, host focus, node limit with "Other hosts" aggregation; node and edge details; keyboard-accessible host-link table with traffic totals and conversation actions | Conversations |
| Compare captures | Sequentially analyze two local captures and list new, missing and changed hosts/names, protocol totals and conversations; CSV export for each changes table | Per-capture `AnalysisModel` summaries |
| Packet list | Wireshark's columns for every packet, Wireshark display filters, paged with explicit retry for failed pages while the capture remains open; accepted filters participate in URL history | Wiregasm `getFrames` |
| Packet drawer | One source packet offers a direct decode action. Several source packets keep searchable paging (50 per page), first/last decode, and the chosen packet's exact timestamp, Wireshark's keyboard-navigable field tree and a hex dump with field highlighting. A nested packet leaves the record underneath it. Selected fields can copy the displayed label or exact Wireshark display filter, or open matching packets. The bundled tree API does not expose a separate typed field value. | Wiregasm `getFrame` |

Follow Stream search is case-sensitive for text and accepts contiguous hexadecimal pairs or pairs separated by ASCII whitespace. It searches each currently displayed run independently, so it cannot create a match across client/server directions. Search is capped at 10,000 reported matches. When the loaded stream preview is truncated, the view says that unshown bytes are not searched. Packet links use frames reported by Wireshark's follower; those frames may not identify the exact on-wire byte origin.

Follow Stream retains only the capped decoded prefix and its segment metadata in JavaScript, with bounded decoding scratch space. The preview holds up to 512 KiB and 5,000 segments; Save raw holds up to 64 MiB and 100,000 segments across both directions, reports truncation, and then selects the requested direction from that prefix. These limits do not bound Wiregasm's internal follower: the pinned engine still collects and serializes the full stream before returning it. See [the memory measurements and remaining upstream requirement](FOLLOW-MEMORY.md).

## In-tab view state

During navigation within one open capture, the app remembers view filters and selections for DNS protocol/status, HTTP host, Hosts family/selection, Connections transport/protocol/quality and selected conversation, Network protocol/focus/limit/selection, ICMP message kind, and Overview chart metrics/time-input drafts. Packet display-filter drafts remain separate from the accepted filter. Table searches, sorts and optional-column choices are retained independently per table, including separate DNS protocol tables and conversation packet tables. Changing views closes record drawers. An explicit `proto`, `host`, `conv`, or `filter` route parameter takes precedence for that navigation; an absent packet `filter` can restore the last accepted in-tab filter, while explicit `filter=` represents a cleared filter.

The accepted Packet filter is stored in the URL hash, so Back and Forward restore the expression and its rows. Invalid draft filters leave the accepted filter/results in place. View state and packet filters reset when a capture closes or is replaced, or when Compare mode starts. Browser-history entries from an earlier capture are ignored after the capture changes. These values remain in tab memory or the URL; capture contents and packet data are not persisted.

Exports: CSV from every table (rows as currently searched/sorted, including columns hidden on screen; conversation packet CSV names and contains the current page), an aggregate JSON summary using an explicit allowlist, detailed JSON with an option to redact known identifiers and content-like strings, and self-contained HTML reports for either the whole capture or the active shared time/host filters. A filtered HTML report labels its packet scope and distinguishes whole-capture metadata; correlated records and retained names or protocol metadata can include observations from outside the selected packet set. Detailed JSON can include addresses, names, HTTP paths and headers, certificate identities, and packet references. JSON downloads are named from the capture basename, so office.pcapng becomes office-summary.json and office-details.json. Redaction is on by default and replaces known sensitive fields, including MAC vendor strings and TLS/QUIC ALPN values. Frame numbers, relative timings, ports, traffic sizes, protocol labels, and counts remain; review the result before sharing. Both JSON choices exclude packet bytes, stream payloads, TLS key logs and secrets, exported-file inventory, and file contents. HTML reports open offline and make no external requests; they include observed names and addresses, so share them carefully. Exports are browser downloads created locally.

Conversation matching in Compare uses protocol and the unordered pair of endpoint addresses and ports. When one capture reuses the same tuple for multiple sessions, occurrences are paired in first-seen order. Capture A is the baseline; new rows appear only in B, missing rows only in A, and changed rows appear in both with differing summary fields. Only the compact comparison data is retained for A while B is analyzed; Wiregasm sessions never run at the same time.

Local IP database imports parse plain or gzip CSV incrementally and report read bytes and accepted ranges. They retain the 100 MiB selected-file and 150 MiB unpacked limits, reject malformed or overlapping ranges, and keep the installed database if a replacement fails. See [the import memory budget and measurements](IP_IMPORT_MEMORY.md).

## Accessibility checks

The browser suite runs axe WCAG 2.1 A/AA checks on the start screen, every view, the packet drawer, and the expanded network link list in light and dark themes. It checks text palette pairs at 4.5:1 and chart series colours at 3:1, and exercises the network link list and packet field tree with the keyboard. Traffic and DNS flow charts provide expandable data tables, and interactive bar-chart rows accept Enter and Space. Additional checks cover the Files view and expanded chart tables. Automated checks do not replace a manual NVDA or VoiceOver screen-reader pass; that requirement remains open in issue #22. See [the accessibility audit](ACCESSIBILITY.md).

## Shared filters

Drag across the Overview chart or the traffic strip in the header to select a time window. Start and end fields beside that strip, and the same fields on Overview, set the window from the keyboard. Values are seconds relative to the first packet, formatted to the capture's timestamp precision while retaining the exact original boundaries when applied unchanged. Selecting a host from Top talkers, Host details, or a Network node applies a host filter across views. Both filters are stored in the URL hash and shown as removable chips.

DNS, HTTP, TLS, DHCP, ARP, ICMP, SSH, QUIC, Files, Hosts, Connections, Network, and the packet list use the shared filters. The Files view matches each object using the packet number Wiregasm reports for that object; a downloaded file remains the complete reassembled object. A correlated exchange is included when any contributing packet falls in the selected window, so its details can include packets outside the window. Packet, byte, host traffic, conversation traffic, and chart totals are recomputed for the selected packets. On Connections, transport counts use the shared-filtered conversations and current protocol/host choices before the transport and quality filters, so transport chips partition that scope. TCP flags and quality indicators remain full-conversation observations; their filter counts are distinct conversations with at least one matching indicator. Conversation packet details include the full conversation even when shared filters are active; the table's search, sort and CSV export apply to the current 500-row page. Host metadata such as MAC addresses, names, ports, peers and protocol labels, plus the protocol hierarchy, remain whole-capture values and are labelled accordingly. Sidebar counts and the shared-filter status show selected and full-capture totals.

Exported files are untrusted capture data. The Files view lists metadata only and never previews content in the page. Payloads remain in the worker's Wiregasm memory until the user selects a file; only that selected payload is sent to the page as an opaque binary download.

## Formats

Supported: anything Wireshark 4.4.5's libwiretap reads — pcap (µs and ns), pcapng (multiple interfaces with different link types and timestamp resolutions), gzip-compressed captures, and other Wireshark formats (snoop, ERF, …). Verified with fixtures: pcap/Ethernet, pcapng with Ethernet + raw IP interfaces and µs/ns resolutions.

Link types: any link type Wireshark dissects is decoded. Address-based features (Hosts, Connections, Network) need IPv4/IPv6; frames without IP (ARP, LLDP…) appear as Non-IP conversations and in the protocol charts. Link types Wireshark cannot dissect show as undecoded frames.

Not supported: live capture and files Wireshark cannot open (the error says so). For inputs whose analyzed data exceeds 1 GiB, only the first 1 GiB is analyzed; the app marks the capture and reports as partial.

## Correctness choices

- Bytes are original frame length (`frame.len`) unless labelled *captured*. Truncated packets (snaplen) are counted and flagged.
- Timestamps keep the file's precision; absolute times are built from the exact epoch string. Non-monotonic timestamps are counted and the timeline starts at the earliest one.
- TCP segmentation and IP fragmentation are handled by Wireshark's reassembly; records list every contributing packet. Retransmissions, spurious retransmissions, out-of-order segments, lost segments and duplicate ACKs are counted from Wireshark's TCP analysis. A spurious retransmission is kept in its own count and is not included in the retransmission total.
- Malformed packets and expert errors are counted; records from them are flagged.
- A cut-short file is analysed up to the last complete packet and marked incomplete.

## Known limitations

- **HTTP/3 is not turned into request rows.** HTTP/2 rows are available when Wireshark reconstructs a request or response header block, including decrypted sessions when a matching key log is supplied.
- **Decryption needs matching secrets.** TLS application data stays encrypted unless a matching key log is supplied. TLS 1.3 certificates remain encrypted unless Wireshark exposes them through the decrypted handshake. QUIC/HTTP/3 request rows and DoH/DoT remain unsupported.
- HTTP uses Wireshark's request/response frame links when available and falls back to stream order otherwise. Disagreements with stream order are flagged; a bad link reported by Wireshark can still mispair a response.
- DNS responses are matched only within 60 s of the query.
- When matching fields to several DNS/HTTP messages, offsets are compared only for matching source Tvbs, or when both source identities are unavailable. If only one field exposes a source, the extractor leaves it unassigned rather than risk attaching it to a message from another reassembly buffer.
- Names are only those seen in the capture (no reverse DNS). Optional DB-IP Lite Country data reports only an approximate country; optional ASN data gives an approximate network owner. They require manually downloaded CSV files and are matched locally, can be incomplete or wrong, and are not observed facts. The app includes no city-level GeoIP. MAC vendors come from Wireshark's offline OUI table and describe the network interface's maker, not the device.
- Ports listed for a host are traffic observations, not open-port confirmations. No OS or device identification is done.
- Performance is roughly 8–10k packets/second on a laptop core; captures above ~1–2 million packets may exhaust the 2 GiB WASM heap.
- Engine download is about 20 MB (compressed). After the first visit the app and engine are kept by a service worker for offline use; in browsers without service workers they are downloaded again per session (HTTP-cached).

## Investigation controls

Analysis shows a fresh elapsed clock for each capture, with separate engine download,
initialization, file reading, indexing, decoding, parsing and summary phases. Percentages
refer to the current download or analysis phase; results become available only when analysis completes.

Hosts keeps optional country/ASN import in an Add/Manage country/ASN data disclosure.
Installed database kinds automatically show their approximate columns; Show country/ASN
columns reveals both even without data. Hiding a column affects presentation only: search,
sort and CSV export retain all host fields. Address-registry dates and inference caveats
remain in About host evidence and address ranges. Imports and matches remain local.

Network offers host search/focus, Fit graph, Reset viewport and keyboard zoom buttons.
Fit and Reset affect only pan/zoom; graph and shared filters remain active. Clear host
focus resets graph focus and its search, keeping protocol and shared filters. Layout
refits after resizing, includes label bounds and packs disconnected components. Automatic
fit stays capped at 1.2 to keep small captures sensibly sized. Selected hosts have a
readable label and retain the accessible host/link tables.

## Capture workflow and navigation

Returning from comparison reanalyzes the original capture and restores its view,
shared filters, table search/sort, selected record and compatible scroll positions.
The original File and any applied TLS key log are retained only in tab memory;
comparison closes its worker before restoration opens another. Failed restoration
has retry and return-to-start actions. Comparison from the landing page returns there.

The TLS keys disclosure distinguishes staged files (results unchanged) from active
keys and the actual decrypted-session count. Apply keys to current capture and Remove
active keys reanalyze the current original File. Returning to previous analysis cancels
an update and restores prior keys/results. Capture replacement and Close capture clear keys.

One Export menu labels whole-capture HTML, current-selection HTML and whole-capture
aggregate/detailed JSON. JSON always uses whole-capture data, with detailed redaction
on by default. Selected HTML uses shared time/host filters while labelling retained
whole-capture metadata. CSV remains view-local: current searched rows, current sort
order and all exportable columns, including columns hidden on screen.

The compact capture toolbar contains filename/counts, Export, Capture actions, Theme,
Help, a labelled traffic/time strip, TLS key status and removable shared-filter chips.
Capture actions, Help, Export and TLS keys dismiss from their trigger, Escape, or a
pointer outside the panel, and focus returns to the trigger. Capture actions is a
short menu: Open another carries the note that replacement clears the investigation
and its TLS keys, Compare captures is a separate row, and Close capture sits below
a divider as the action that leaves the investigation.
The toolbar scrolls with the page so it cannot cover focused table controls or packet drawers.
Help exposes the full filename, local-processing statement and licence limitations.

Navigation groups Overview, Hosts, Connections, Network and Packet list under
Investigation, and protocol views separately. Protocols with no whole-capture records
have an Absent protocols disclosure on desktop; a filtered zero remains visible when
the capture contains that protocol. Files remains available without eager inventory
scanning. Below 861px, a labelled grouped Current view selector exposes every route,
including absent protocols, without horizontal tab scrolling.
