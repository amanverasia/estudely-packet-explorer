#!/usr/bin/env python3
"""Generate small synthetic capture fixtures with known expected contents.

All traffic is fabricated with scapy between documentation/private addresses,
so the fixtures carry no third-party data and can be redistributed freely.
Run: python3 fixtures/generate.py   (requires scapy and cryptography)
"""
import datetime
import os
import struct

from scapy.all import (DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, IPv6, Raw,
                       fragment, wrpcap)
from scapy.layers.netbios import NBNS_ADD_ENTRY, NBNSHeader, NBNSQueryRequest, NBNSQueryResponse
from scapy.layers.tls.all import (TLS, TLSCertificate, TLSClientHello,
                                  TLSServerHello, TLSServerHelloDone)
from scapy.layers.tls.cert import Cert
from scapy.layers.tls.extensions import (ProtocolName, ServerName, TLS_Ext_ALPN,
                                         TLS_Ext_ServerName,
                                         TLS_Ext_SupportedVersion_CH,
                                         TLS_Ext_SupportedVersion_SH)

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1700000000.0

MAC_CLIENT = "02:00:00:00:00:05"
MAC_RESOLVER = "02:00:00:00:00:53"
MAC_SERVER = "02:00:00:00:00:80"


class Clock:
    def __init__(self, start=T0):
        self.t = start

    def tick(self, dt=0.01):
        self.t += dt
        return self.t


def stamp(pkts_with_times):
    out = []
    for p, t in pkts_with_times:
        p.time = t
        out.append(p)
    return out


def eth(src, dst):
    return Ether(src=src, dst=dst)


# --------------------------------------------------------------------------- DNS
def dns_fixture():
    c = Clock()
    P = []
    cli, res = "10.0.0.5", "10.0.0.53"

    def q(txid, name, qtype, sport=50000, t=None):
        return (eth(MAC_CLIENT, MAC_RESOLVER) / IP(src=cli, dst=res) / UDP(sport=sport, dport=53)
                / DNS(id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype)), t or c.tick())

    def r(txid, name, qtype, rcode=0, an=None, sport=50000, t=None):
        return (eth(MAC_RESOLVER, MAC_CLIENT) / IP(src=res, dst=cli) / UDP(sport=53, dport=sport)
                / DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an),
                t or c.tick())

    # 1-2 A example.com -> NOERROR
    P += [q(0x1111, "example.com", "A"), r(0x1111, "example.com", "A", an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300))]
    # 3-4 NXDOMAIN
    P += [q(0x2222, "nonexistent.example", "A", sport=50001), r(0x2222, "nonexistent.example", "A", rcode=3, sport=50001)]
    # 5 unanswered
    P += [q(0x3333, "timeout.example", "A", sport=50002)]
    # 6-8 repeated query (retransmission, same id) then a single response
    P += [q(0x4444, "repeat.example", "A", sport=50003), (q(0x4444, "repeat.example", "A", sport=50003)[0], c.tick(1.0)),
          r(0x4444, "repeat.example", "A", sport=50003, an=DNSRR(rrname="repeat.example", type="A", rdata="192.0.2.44"))]
    # 9-10 transaction id 0x1111 reused for a different name: must be a separate transaction
    P += [q(0x1111, "other.example", "A"), r(0x1111, "other.example", "A", an=DNSRR(rrname="other.example", type="A", rdata="192.0.2.10"))]
    # 11-12 IPv6 AAAA
    P += [(eth(MAC_CLIENT, MAC_RESOLVER) / IPv6(src="fd00::5", dst="fd00::53") / UDP(sport=50004, dport=53)
           / DNS(id=0x5555, rd=1, qd=DNSQR(qname="example.com", qtype="AAAA")), c.tick()),
          (eth(MAC_RESOLVER, MAC_CLIENT) / IPv6(src="fd00::53", dst="fd00::5") / UDP(sport=53, dport=50004)
           / DNS(id=0x5555, qr=1, ra=1, qd=DNSQR(qname="example.com", qtype="AAAA"),
                 an=DNSRR(rrname="example.com", type="AAAA", rdata="2001:db8::1946")), c.tick())]
    # 13-14 SERVFAIL for MX
    P += [q(0x6666, "example.org", "MX", sport=50005), r(0x6666, "example.org", "MX", rcode=2, sport=50005)]
    # 15-16 CNAME chain
    P += [q(0x7777, "www.example.com", "A", sport=50006),
          r(0x7777, "www.example.com", "A", sport=50006,
            an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com"), DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")])]

    # 17-26 DNS over TCP: handshake, query split across two segments, response, teardown
    sp, seq_c, seq_s = 41000, 1000, 5000
    msg = bytes(DNS(id=0x8888, rd=1, qd=DNSQR(qname="tcp.example", qtype="TXT")))
    framed = struct.pack("!H", len(msg)) + msg
    rsp = bytes(DNS(id=0x8888, qr=1, ra=1, qd=DNSQR(qname="tcp.example", qtype="TXT"),
                    an=DNSRR(rrname="tcp.example", type="TXT", rdata="hello\tworld")))
    rframed = struct.pack("!H", len(rsp)) + rsp

    def tc(flags, seq, ack, payload=b""):
        return (eth(MAC_CLIENT, MAC_RESOLVER) / IP(src=cli, dst=res) / TCP(sport=sp, dport=53, flags=flags, seq=seq, ack=ack) / Raw(payload), c.tick())

    def ts(flags, seq, ack, payload=b""):
        return (eth(MAC_RESOLVER, MAC_CLIENT) / IP(src=res, dst=cli) / TCP(sport=53, dport=sp, flags=flags, seq=seq, ack=ack) / Raw(payload), c.tick())

    P += [tc("S", seq_c, 0), ts("SA", seq_s, seq_c + 1), tc("A", seq_c + 1, seq_s + 1)]
    P += [tc("PA", seq_c + 1, seq_s + 1, framed[:10]), tc("PA", seq_c + 11, seq_s + 1, framed[10:])]
    P += [ts("PA", seq_s + 1, seq_c + 1 + len(framed), rframed)]
    P += [tc("FA", seq_c + 1 + len(framed), seq_s + 1 + len(rframed)), ts("FA", seq_s + 1 + len(rframed), seq_c + 2 + len(framed)),
          tc("A", seq_c + 2 + len(framed), seq_s + 2 + len(rframed))]

    # 26-27 mDNS query + unsolicited-style response
    P += [(eth(MAC_CLIENT, "01:00:5e:00:00:fb") / IP(src=cli, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
           / DNS(id=0, qd=DNSQR(qname="_http._tcp.local", qtype="PTR")), c.tick()),
          (eth("02:00:00:00:00:09", "01:00:5e:00:00:fb") / IP(src="10.0.0.9", dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
           / DNS(id=0, qr=1, aa=1, qd=[], an=DNSRR(rrname="printer.local", type="A", rdata="10.0.0.9", ttl=120)), c.tick())]
    # 28-29 NBNS name query (broadcast) + response
    P += [(eth(MAC_CLIENT, "ff:ff:ff:ff:ff:ff") / IP(src=cli, dst="10.0.0.255") / UDP(sport=137, dport=137)
           / NBNSHeader(NAME_TRN_ID=0x0abc, NM_FLAGS=0x11, QDCOUNT=1) / NBNSQueryRequest(QUESTION_NAME="FILESERVER", QUESTION_TYPE="NB"), c.tick()),
          (eth("02:00:00:00:00:20", MAC_CLIENT) / IP(src="10.0.0.20", dst=cli) / UDP(sport=137, dport=137)
           / NBNSHeader(NAME_TRN_ID=0x0abc, RESPONSE=1, NM_FLAGS=0x50, QDCOUNT=0, ANCOUNT=1)
           / NBNSQueryResponse(RR_NAME="FILESERVER", ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS="10.0.0.20")]), c.tick())]
    wrpcap(os.path.join(HERE, "dns.pcap"), stamp(P))


# -------------------------------------------------------------------------- HTTP
def tcp_flow(c, cmac, smac, cip, sip, sport, dport, exchanges, ipv6=False, isn=(100, 9000), close=True):
    """Build a TCP session. exchanges: list of (direction, payload, [split sizes])."""
    L3 = (lambda s, d: IPv6(src=s, dst=d)) if ipv6 else (lambda s, d: IP(src=s, dst=d))
    cs, ss = isn
    P = []

    def cli(flags, payload=b""):
        nonlocal cs
        p = eth(cmac, smac) / L3(cip, sip) / TCP(sport=sport, dport=dport, flags=flags, seq=cs, ack=ss) / Raw(payload)
        return p

    def srv(flags, payload=b""):
        p = eth(smac, cmac) / L3(sip, cip) / TCP(sport=dport, dport=sport, flags=flags, seq=ss, ack=cs) / Raw(payload)
        return p

    P.append((eth(cmac, smac) / L3(cip, sip) / TCP(sport=sport, dport=dport, flags="S", seq=cs), c.tick()))
    cs += 1
    P.append((eth(smac, cmac) / L3(sip, cip) / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=cs), c.tick()))
    ss += 1
    P.append((cli("A"), c.tick()))
    for direction, payload, splits in exchanges:
        chunks, off = [], 0
        for n in splits or [len(payload)]:
            chunks.append(payload[off:off + n])
            off += n
        if off < len(payload):
            chunks.append(payload[off:])
        for ch in chunks:
            if direction == "c":
                P.append((cli("PA", ch), c.tick()))
                cs += len(ch)
            else:
                P.append((srv("PA", ch), c.tick()))
                ss += len(ch)
    if close:
        P.append((cli("FA"), c.tick()))
        cs += 1
        P.append((srv("FA"), c.tick()))
        ss += 1
        P.append((cli("A"), c.tick()))
    return P


def http_fixture():
    c = Clock()
    P = []
    req1 = b"GET /index.html HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: fixture-agent/1.0\r\nAccept: */*\r\n\r\n"
    body1 = b"<html><script>alert('captured content must not run')</script><b>hello</b></html>"
    rsp1 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: fixture-server\r\nContent-Length: %d\r\n\r\n" % len(body1)) + body1
    req2 = b"POST /api/login HTTP/1.1\r\nHost: www.example.test\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"user\":\"alice\"}\n"
    rsp2 = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
    # Session 1: request split across two segments, two requests on one connection
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "10.0.0.5", "10.0.0.80", 40000, 80,
                  [("c", req1, [20]), ("s", rsp1, None), ("c", req2, None), ("s", rsp2, None)])
    # Session 2: 404 on a different host name
    req3 = b"GET /missing HTTP/1.1\r\nHost: static.example.test\r\n\r\n"
    rsp3 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "10.0.0.5", "10.0.0.80", 40001, 80, [("c", req3, None), ("s", rsp3, None)])
    # Session 3: same 4-tuple as session 1, reused after close -> must be a distinct TCP session
    c.tick(5)
    req4 = b"GET /again HTTP/1.1\r\nHost: www.example.test\r\n\r\n"
    rsp4 = b"HTTP/1.1 304 Not Modified\r\n\r\n"
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "10.0.0.5", "10.0.0.80", 40000, 80, [("c", req4, None), ("s", rsp4, None)], isn=(7000, 3000))
    # Session 4: HTTP over IPv6, request with no response (capture ends)
    req5 = b"GET /v6 HTTP/1.1\r\nHost: v6.example.test\r\n\r\n"
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "fd00::5", "fd00::80", 40002, 8080, [("c", req5, None)], ipv6=True, close=False)
    wrpcap(os.path.join(HERE, "http.pcap"), stamp(P))


# --------------------------------------------------------------------------- TLS
def make_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "www.example.com"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fixture Org")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture Test CA")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
            .serial_number(0x1234ABCD)
            .not_valid_before(datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("www.example.com"), x509.DNSName("example.com")]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def tls_fixture():
    c = Clock()
    P = []
    ch12 = TLS(msg=[TLSClientHello(
        version=0x0303, ciphers=[0xc02f, 0xc030, 0x009c],
        ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"www.example.com")]),
             TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2"), ProtocolName(protocol=b"http/1.1")])])])
    der = make_cert()
    sh12 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xc02f,
                                   ext=[TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")])]),
                    TLSCertificate(certs=[Cert(der)]), TLSServerHelloDone()])
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "10.0.0.5", "198.51.100.10", 43000, 443,
                  [("c", bytes(ch12), None), ("s", bytes(sh12), None)])
    # TLS 1.3: advertised versions 1.3+1.2, negotiated 1.3 via supported_versions; certificate is encrypted
    ch13 = TLS(msg=[TLSClientHello(
        version=0x0303, ciphers=[0x1301, 0x1302, 0xc02f],
        ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"api.example.net")]),
             TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]),
             TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"http/1.1")])])])
    sh13 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0x1301, ext=[TLS_Ext_SupportedVersion_SH(version=0x0304)])])
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "fd00::5", "2001:db8::443", 43001, 443,
                  [("c", bytes(ch13), None), ("s", bytes(sh13), None), ("s", b"\x17\x03\x03\x00\x10" + b"\xaa" * 16, None)], ipv6=True)
    # ClientHello only, no server reply observed
    ch_only = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x1301],
                                      ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"noreply.example.org")])])])
    P += tcp_flow(c, MAC_CLIENT, MAC_SERVER, "10.0.0.5", "203.0.113.7", 43002, 443, [("c", bytes(ch_only), None)], close=False)
    wrpcap(os.path.join(HERE, "tls.pcap"), stamp(P))


# ---------------------------------------------------------- malformed / truncated
def edge_fixture():
    c = Clock()
    P = []
    # 1 malformed DNS: header claims one question but the payload ends early
    P.append((eth(MAC_CLIENT, MAC_RESOLVER) / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=50100, dport=53)
              / Raw(b"\x99\x99\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07exa"), c.tick()))
    # 2-3 large DNS response fragmented at the IP layer
    big = DNS(id=0x9999, qr=1, ra=1, qd=DNSQR(qname="frag.example", qtype="TXT"),
              an=[DNSRR(rrname="frag.example", type="TXT", rdata="x" * 200), DNSRR(rrname="frag.example", type="TXT", rdata="y" * 200)])
    pkt = IP(src="10.0.0.53", dst="10.0.0.5", id=777) / UDP(sport=53, dport=50101) / big
    for frag in fragment(pkt, fragsize=256):
        P.append((eth(MAC_RESOLVER, MAC_CLIENT) / frag, c.tick()))
    # 4 an ordinary packet whose capture will be truncated (snaplen) -- see below
    P.append((eth(MAC_CLIENT, MAC_SERVER) / IP(src="10.0.0.5", dst="10.0.0.80") / UDP(sport=50102, dport=9999) / Raw(b"z" * 400), c.tick()))
    path = os.path.join(HERE, "edge.pcap")
    wrpcap(path, stamp(P))
    # Rewrite the last record so captured length is 60 while original length stays 442
    data = bytearray(open(path, "rb").read())
    off = 24
    recs = []
    while off < len(data):
        ts_s, ts_us, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        recs.append((off, incl, orig))
        off += 16 + incl
    last_off, incl, orig = recs[-1]
    header = struct.pack("<IIII", *struct.unpack("<II", data[last_off:last_off + 8]), 60, orig)
    data = data[:last_off] + header + data[last_off + 16:last_off + 16 + 60]
    open(path, "wb").write(bytes(data))
    # Same capture, cut in the middle of the last record (incomplete file)
    open(os.path.join(HERE, "cut.pcap"), "wb").write(bytes(data[:-30]))
    # Not a capture at all
    open(os.path.join(HERE, "not-a-capture.pcap"), "wb").write(b"This is plain text, not a packet capture.\n" * 4)


# ------------------------------------------------------------------------ PCAPNG
def pcapng_fixture():
    """Two interfaces: Ethernet with microsecond and raw IPv4 with nanosecond timestamps."""
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total)

    def opt(code, value):
        pad = (-len(value)) % 4
        return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opt(0, b""))
    idb0 = block(0x00000001, struct.pack("<HHI", 1, 0, 65535) + opt(2, b"eth0") + opt(9, bytes([6])) + opt(0, b""))
    idb1 = block(0x00000001, struct.pack("<HHI", 101, 0, 65535) + opt(2, b"tun0") + opt(9, bytes([9])) + opt(0, b""))

    def epb(iface, ts_units, pkt):
        raw = bytes(pkt)
        return block(0x00000006, struct.pack("<IIIII", iface, ts_units >> 32, ts_units & 0xFFFFFFFF, len(raw), len(raw)) + raw)

    q = Ether(src=MAC_CLIENT, dst=MAC_RESOLVER) / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=50200, dport=53) / DNS(id=0xAAAA, rd=1, qd=DNSQR(qname="ng.example"))
    r = IP(src="10.8.0.1", dst="10.8.0.2") / UDP(sport=53, dport=50201) / DNS(id=0xBBBB, qr=1, qd=DNSQR(qname="tun.example"), an=DNSRR(rrname="tun.example", rdata="10.8.0.53"))
    body = shb + idb0 + idb1
    body += epb(0, int(T0 * 1_000_000) + 123456, q)               # 1700000000.123456
    body += epb(1, int(T0) * 1_000_000_000 + 123456789, r)        # 1700000000.123456789
    open(os.path.join(HERE, "multi-iface.pcapng"), "wb").write(body)


if __name__ == "__main__":
    dns_fixture()
    http_fixture()
    tls_fixture()
    edge_fixture()
    pcapng_fixture()
    print("fixtures written to", HERE)
