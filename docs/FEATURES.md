# Features and known limitations

## Views

| View | What it shows | Source of truth |
|---|---|---|
| Overview | Packets, duration, bytes on wire vs captured, file size, hosts, conversations, time range (UTC, file precision), interfaces, traffic over time (bytes or packets, stacked by top protocol), protocol distribution, top talkers, largest conversations, protocol hierarchy, data-quality notes; shared time-window and host filters | Every packet |
| DNS | DNS / mDNS / LLMNR / NBNS tabs; transactions with client, server, name, type, response code, answers, status, response time; counts by name, type, response code; unanswered and repeated queries; client→resolver diagram | `dns.*`, `nbns.*` fields |
| HTTP | HTTP/1.x and HTTP/2 requests: method, host, path, status, content type/length, request and response headers, pairing state; HTTP/2 stream IDs; decrypted TLS messages are marked; counts by host, method, status; explanations for encrypted or undecoded traffic | `http.*` and decoded `http2.*` header fields |
| Files | Reassembled DICOM, HTTP, IMF, SMB and TFTP objects; protocol, server host, filename, content type, size and packet; explicit download action | Wiregasm export-object taps |
| TLS | ClientHello SNI, offered versions, ALPN and cipher suites; ServerHello negotiated version (and where it came from), cipher, ALPN; cleartext certificates; per-session status for decrypted, still-encrypted, or absent application data | `tls.handshake.*`, `tls.app_data`, and the packet protocol stack |
| QUIC | Per UDP conversation: versions in long headers, versions listed by Version Negotiation, SNI and offered ALPN from the Initial ClientHello, packet count; matching TLS key logs can expose decrypted QUIC stream packets | `quic.version`, `quic.supported_version`, `quic.stream_data`, `tls.handshake.*` |
| SSH | Client and server identification strings per TCP session | `ssh.protocol`, `ssh.direction` |
| DHCP | DHCPv4 exchanges by transaction ID + client MAC: message sequence, outcome (ACK, NAK, offer only, no server reply), client host name, requested/offered/assigned address, server, lease time, subnet mask, routers, DNS servers | `dhcp.*` fields |
| ARP | Every request/reply (sender and target, gratuitous flag); per IPv4 address the MACs ARP senders stated, in time order, with the number of changes. Probes (sender 0.0.0.0) state no mapping | `arp.*` fields |
| ICMP | ICMP and ICMPv6 messages with type and code names; echo requests paired with replies; error messages with the quoted packet's addresses and ports, linked to that captured TCP/UDP conversation | `icmp.*`, `icmpv6.*`, inner `ip`/`ipv6`/`tcp`/`udp` fields |
| Hosts | IPv4/IPv6 addresses, address range, source MACs (with the registered vendor of the address prefix from Wireshark's built-in table, or "locally administered") and ARP MACs, sent/received packets and bytes, peers, ports peers used (with evidence), names learned with source and observed/inferred label | Packets, conversations, DNS/mDNS/NBNS/DHCP/SNI/Host |
| Connections | TCP/UDP sessions by stream index, other IP and non-IP groups; directional packets/bytes; start and duration; TCP flags seen and analysis counts; drill-down into the conversation's DNS/HTTP/TLS records and packets | Packets |
| Network | Force-directed host graph, edge width = log bytes, edge colour = main protocol; protocol filter, host focus, node limit with "Other hosts" aggregation; node and edge details | Conversations |
| Packet list | Wireshark's columns for every packet, Wireshark display filters, paged | Wiregasm `getFrames` |
| Packet drawer | For any record: its source packet numbers; for the chosen packet the exact timestamp, Wireshark's full field tree and a hex dump with field highlighting | Wiregasm `getFrame` |

Exports: CSV from every table (rows as currently searched/sorted), JSON summary of the whole model, and a self-contained HTML report of whole-capture aggregates. The HTML report opens offline and makes no external requests. It includes names and addresses observed in the capture, but excludes packet bytes, payloads, stream contents, packet-by-packet details, TLS key logs, certificate details, the Files view inventory and downloaded file contents. Reports and other exports are browser downloads.

## Shared filters

Drag across the Overview chart or the traffic strip in the header to select a time window. The Overview also provides keyboard-accessible start/end inputs in seconds relative to the first packet. Selecting a host from Top talkers, Host details, or a Network node applies a host filter across views. Both filters are stored in the URL hash and shown as removable chips.

DNS, HTTP, TLS, DHCP, ARP, ICMP, SSH, QUIC, Files, Hosts, Connections, Network, and the packet list use the shared filters. The Files view matches each object using the packet number Wiregasm reports for that object; a downloaded file remains the complete reassembled object. A correlated exchange is included when any contributing packet falls in the selected window, so its details can include packets outside the window. Packet, byte, host traffic, conversation traffic, and chart totals are recomputed for the selected packets. Host metadata such as MAC addresses, names, ports, peers and protocol labels, plus the protocol hierarchy, remain whole-capture values and are labelled accordingly. Sidebar counts and the shared-filter status show selected and full-capture totals.

Exported files are untrusted capture data. The Files view lists metadata only and never previews content in the page. Payloads remain in the worker's Wiregasm memory until the user selects a file; only that selected payload is sent to the page as an opaque binary download.

## Formats

Supported: anything Wireshark 4.4.5's libwiretap reads — pcap (µs and ns), pcapng (multiple interfaces with different link types and timestamp resolutions), gzip-compressed captures, and other Wireshark formats (snoop, ERF, …). Verified with fixtures: pcap/Ethernet, pcapng with Ethernet + raw IP interfaces and µs/ns resolutions.

Link types: any link type Wireshark dissects is decoded. Address-based features (Hosts, Connections, Network) need IPv4/IPv6; frames without IP (ARP, LLDP…) appear as Non-IP conversations and in the protocol charts. Link types Wireshark cannot dissect show as undecoded frames.

Not supported: live capture, files over 1 GiB (refused), files Wireshark cannot open (the error says so).

## Correctness choices

- Bytes are original frame length (`frame.len`) unless labelled *captured*. Truncated packets (snaplen) are counted and flagged.
- Timestamps keep the file's precision; absolute times are built from the exact epoch string. Non-monotonic timestamps are counted and the timeline starts at the earliest one.
- TCP segmentation and IP fragmentation are handled by Wireshark's reassembly; records list every contributing packet. Retransmissions, out-of-order segments, lost segments and duplicate ACKs are counted from Wireshark's TCP analysis.
- Malformed packets and expert errors are counted; records from them are flagged.
- A cut-short file is analysed up to the last complete packet and marked incomplete.

## Known limitations

- **HTTP/3 is not turned into request rows.** HTTP/2 rows are available when Wireshark reconstructs a request or response header block, including decrypted sessions when a matching key log is supplied.
- **Decryption needs matching secrets.** TLS application data stays encrypted unless a matching key log is supplied. TLS 1.3 certificates remain encrypted unless Wireshark exposes them through the decrypted handshake. QUIC/HTTP/3 request rows and DoH/DoT remain unsupported.
- HTTP uses Wireshark's request/response frame links when available and falls back to stream order otherwise. Disagreements with stream order are flagged; a bad link reported by Wireshark can still mispair a response.
- DNS responses are matched only within 60 s of the query.
- In the rare case of several DNS/HTTP messages in one packet where a field has no source Tvb, its offset cannot be checked against a specific reassembly buffer and may be assigned ambiguously.
- Names are only those seen in the capture (no reverse DNS, no GeoIP). MAC vendors come from Wireshark's offline OUI table and describe the network interface's maker, not the device.
- Ports listed for a host are traffic observations, not open-port confirmations. No OS or device identification is done.
- Performance is roughly 8–10k packets/second on a laptop core; captures above ~1–2 million packets may exhaust the 2 GiB WASM heap.
- Engine download is about 20 MB (compressed). After the first visit the app and engine are kept by a service worker for offline use; in browsers without service workers they are downloaded again per session (HTTP-cached).
