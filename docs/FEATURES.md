# Features and known limitations

## Views

| View | What it shows | Source of truth |
|---|---|---|
| Overview | Packets, duration, bytes on wire vs captured, file size, hosts, conversations, time range (UTC, file precision), interfaces, traffic over time (bytes or packets, stacked by top protocol), protocol distribution, top talkers, largest conversations, protocol hierarchy, data-quality notes | Every packet |
| DNS | DNS / mDNS / LLMNR / NBNS tabs; transactions with client, server, name, type, response code, answers, status, response time; counts by name, type, response code; unanswered and repeated queries; client→resolver diagram | `dns.*`, `nbns.*` fields |
| HTTP | HTTP/1.x requests: method, host, path, status, content type/length, request and response headers, pairing state; counts by host, method, status; explanations for encrypted or undecoded traffic | `http.*` fields after Wireshark reassembly |
| TLS | ClientHello SNI, offered versions, ALPN and cipher suites; ServerHello negotiated version (and where it came from), cipher, ALPN; cleartext certificates (subject, issuer, validity, SAN, serial, algorithms, SHA-256) | `tls.handshake.*` fields, also in QUIC Initial packets |
| QUIC | Per UDP conversation: versions in long headers, versions listed by Version Negotiation, SNI and offered ALPN from the Initial ClientHello, QUIC packet count | `quic.version`, `quic.supported_version`, `tls.handshake.*` |
| SSH | Client and server identification strings per TCP session | `ssh.protocol`, `ssh.direction` |
| DHCP | DHCPv4 exchanges by transaction ID + client MAC: message sequence, outcome (ACK, NAK, offer only, no server reply), client host name, requested/offered/assigned address, server, lease time, subnet mask, routers, DNS servers | `dhcp.*` fields |
| ARP | Every request/reply (sender and target, gratuitous flag); per IPv4 address the MACs ARP senders stated, in time order, with the number of changes. Probes (sender 0.0.0.0) state no mapping | `arp.*` fields |
| ICMP | ICMP and ICMPv6 messages with type and code names; echo requests paired with replies; error messages with the quoted packet's addresses and ports, linked to that captured TCP/UDP conversation | `icmp.*`, `icmpv6.*`, inner `ip`/`ipv6`/`tcp`/`udp` fields |
| Hosts | IPv4/IPv6 addresses, address range, source MACs (with the registered vendor of the address prefix from Wireshark's built-in table, or "locally administered") and ARP MACs, sent/received packets and bytes, peers, ports peers used (with evidence), names learned with source and observed/inferred label | Packets, conversations, DNS/mDNS/NBNS/DHCP/SNI/Host |
| Connections | TCP/UDP sessions by stream index, other IP and non-IP groups; directional packets/bytes; start and duration; TCP flags seen and analysis counts; drill-down into the conversation's DNS/HTTP/TLS records and packets | Packets |
| Network | Force-directed host graph, edge width = log bytes, edge colour = main protocol; protocol filter, host focus, node limit with "Other hosts" aggregation; node and edge details | Conversations |
| Packet list | Wireshark's columns for every packet, Wireshark display filters, paged | Wiregasm `getFrames` |
| Packet drawer | For any record: its source packet numbers; for the chosen packet the exact timestamp, Wireshark's full field tree and a hex dump with field highlighting | Wiregasm `getFrame` |

Exports: CSV from every table (rows as currently searched/sorted), JSON summary of the whole model. Both are browser downloads.

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

- **HTTP/2 and HTTP/3 are not turned into request rows.** Cleartext HTTP/2 packets are counted and can be inspected in the packet list; HTTP/3 is inside QUIC encryption.
- **No decryption.** TLS application data, TLS 1.3 certificates, QUIC beyond the Initial packets, DoH/DoT stay encrypted. No key-log support yet.
- HTTP pairing is FIFO per TCP stream; if a request is missing from the capture, later pairs in that stream can shift. Streams with gaps are called out.
- DNS responses are matched only within 60 s of the query.
- In the rare case of several DNS/HTTP messages in one packet spread across different reassembled buffers, the field-to-message split uses byte offsets and could mis-assign fields.
- Names are only those seen in the capture (no reverse DNS, no GeoIP). MAC vendors come from Wireshark's offline OUI table and describe the network interface's maker, not the device.
- Ports listed for a host are traffic observations, not open-port confirmations. No OS or device identification is done.
- Performance is roughly 8–10k packets/second on a laptop core; captures above ~1–2 million packets may exhaust the 2 GiB WASM heap.
- Engine download is about 20 MB (compressed). After the first visit the app and engine are kept by a service worker for offline use; in browsers without service workers they are downloaded again per session (HTTP-cached).
