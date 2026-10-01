// Shared analysis model. Produced once per capture inside the worker and
// consumed by every view, so tabs never re-parse the file.
//
// Conventions:
// - `t` / `start` / `end` values are seconds relative to the first packet
//   (CaptureInfo.startEpoch). Relative values keep full timestamp precision.
// - Byte counts are original frame lengths ("bytes on wire", frame.len)
//   unless a field name says `captured`.
// - `null` means the value was not present in the capture (shown as
//   "unavailable"), never a guess.

export type Proto = string;

export interface Provenance {
  /** Frame (packet) numbers that this record was derived from, ascending. */
  frames: number[];
}

export interface InterfaceInfo {
  id: number | null;
  linkType: string;
  name: string;
  packets: number;
}

export interface CaptureInfo {
  fileName: string;
  fileSize: number;
  fileType: string;
  linkType: string;
  packetCount: number;
  /** Absolute time of the first packet, as decimal epoch seconds string (exact). */
  startEpoch: string | null;
  duration: number;
  /** Finest timestamp precision observed in the file: 0 = seconds ... 9 = nanoseconds. */
  timestampDigits: number;
  /** Packets whose timestamp is earlier than the previous packet's. */
  nonMonotonicTimestamps: number;
  interfaces: InterfaceInfo[];
  wireBytes: number;
  capturedBytes: number;
  truncatedPackets: number;
  malformedPackets: number;
  expertErrorPackets: number;
  fragmentPackets: number;
  retransmissions: number;
  outOfOrder: number;
  lostSegments: number;
  duplicateAcks: number;
  /** Set when the file ended early or could only be read partially. */
  incomplete: string | null;
  warnings: string[];
  engine: { wireshark: string; wiregasm: string };
  analysisMs: number;
}

export interface ProtoStat {
  proto: Proto;
  packets: number;
  bytes: number;
}

export interface TimelineSeries {
  key: string;
  packets: number[];
  bytes: number[];
}

export interface Timeline {
  /** Relative time of the first bin (negative if some timestamps precede the first packet). */
  origin: number;
  binSeconds: number;
  bins: number;
  series: TimelineSeries[];
}

export type NameSource =
  | 'DNS answer'
  | 'DNS answer (CNAME alias)'
  | 'mDNS'
  | 'LLMNR'
  | 'NBNS'
  | 'DHCP host name'
  | 'TLS SNI'
  | 'HTTP Host header';

export interface LearnedName {
  name: string;
  source: NameSource;
  /** observed: the capture states this mapping. inferred: a client used this name when talking to the address. */
  kind: 'observed' | 'inferred';
  frame: number;
}

export interface ServicePort {
  transport: 'TCP' | 'UDP';
  port: number;
  /** What was actually seen for connections to this port on this host. */
  evidence: 'handshake completed' | 'SYN-ACK sent' | 'SYN received, no SYN-ACK seen' | 'mid-stream traffic' | 'UDP traffic received';
  conversations: number;
  peers: number;
}

export interface Host {
  addr: string;
  ipVersion: 4 | 6;
  scope: string;
  macs: { mac: string; packets: number }[];
  arpMacs: string[];
  txPackets: number;
  txBytes: number;
  rxPackets: number;
  rxBytes: number;
  peers: number;
  conversations: number;
  firstSeen: number;
  lastSeen: number;
  names: LearnedName[];
  /** Ports on this host that peers directed traffic to (as responder). */
  servicePorts: ServicePort[];
  /** Number of distinct local source ports this host used as initiator. */
  clientPortCount: number;
  protocols: string[];
}

export type Transport = 'TCP' | 'UDP' | 'IP' | 'Non-IP';

export interface Conversation {
  id: number;
  transport: Transport;
  /** Wireshark stream index (tcp.stream / udp.stream) when available. Separates reused 4-tuples. */
  stream: number | null;
  a: string;
  aPort: number | null;
  b: string;
  bPort: number | null;
  /** How endpoint A was chosen: TCP SYN sender, or simply the first packet's sender. */
  initiator: 'SYN' | 'first packet';
  packetsAB: number;
  bytesAB: number;
  packetsBA: number;
  bytesBA: number;
  start: number;
  end: number;
  firstFrame: number;
  lastFrame: number;
  protocols: string[];
  appProtocol: string;
  tcp: null | {
    synSeen: boolean;
    synAckSeen: boolean;
    finSeen: boolean;
    rstSeen: boolean;
    retransmissions: number;
    outOfOrder: number;
    lostSegments: number;
    payloadBytesAB: number;
    payloadBytesBA: number;
  };
  truncatedPackets: number;
  malformedPackets: number;
  records: { dns: number; http: number; tls: number };
}

export interface DnsAnswer {
  section: 'answer' | 'authority' | 'additional';
  name: string;
  type: string;
  ttl: number | null;
  value: string;
}

export type DnsProto = 'DNS' | 'mDNS' | 'LLMNR' | 'NBNS';

export type DnsStatus =
  | 'answered'
  | 'unanswered'
  | 'retransmitted'
  | 'response without query'
  | 'duplicate response'
  | 'multicast query'
  | 'multicast response';

export interface DnsTransaction extends Provenance {
  id: number;
  proto: DnsProto;
  transport: 'UDP' | 'TCP';
  convId: number | null;
  client: string;
  clientPort: number | null;
  server: string;
  serverPort: number | null;
  txid: number | null;
  qname: string | null;
  qtype: string | null;
  opcode: number | null;
  queryFrame: number | null;
  queryTime: number | null;
  responseFrame: number | null;
  responseTime: number | null;
  rtt: number | null;
  rcode: string | null;
  answers: DnsAnswer[];
  status: DnsStatus;
  /** Transaction row this one duplicates (retransmitted query or duplicate response). */
  relatedTo: number | null;
  truncatedFlag: boolean;
  malformed: boolean;
}

export interface HttpExchange extends Provenance {
  id: number;
  stream: number | null;
  convId: number | null;
  client: string;
  clientPort: number | null;
  server: string;
  serverPort: number | null;
  method: string | null;
  host: string | null;
  uri: string | null;
  version: string | null;
  userAgent: string | null;
  requestHeaders: string[];
  requestFrame: number | null;
  requestTime: number | null;
  requestContentType: string | null;
  status: number | null;
  phrase: string | null;
  responseVersion: string | null;
  responseHeaders: string[];
  contentType: string | null;
  contentLength: string | null;
  serverHeader: string | null;
  location: string | null;
  responseFrame: number | null;
  responseTime: number | null;
  state: 'complete' | 'no response seen' | 'response without request';
}

export interface Certificate {
  frame: number;
  index: number;
  subject: string | null;
  issuer: string | null;
  commonName: string | null;
  serial: string | null;
  notBefore: string | null;
  notAfter: string | null;
  san: string[];
  signatureAlgorithm: string | null;
  publicKeyAlgorithm: string | null;
  sha256: string | null;
  error: string | null;
}

export interface TlsSession extends Provenance {
  id: number;
  carrier: 'TCP' | 'QUIC';
  stream: number | null;
  convId: number | null;
  client: string;
  clientPort: number | null;
  server: string;
  serverPort: number | null;
  sni: string | null;
  clientHelloFrame: number | null;
  clientHelloTime: number | null;
  offered: {
    legacyVersion: string | null;
    supportedVersions: string[];
    alpn: string[];
    cipherSuites: string[];
  } | null;
  serverHelloFrame: number | null;
  negotiated: {
    version: string | null;
    versionSource: 'supported_versions extension' | 'ServerHello version field';
    alpn: string | null;
    cipherSuite: string | null;
  } | null;
  certificates: Certificate[];
  certificateStatus: 'decoded' | 'encrypted (TLS 1.3)' | 'not observed';
}

export interface Unsupported {
  /** TCP conversations on common cleartext HTTP ports with payload but no decoded HTTP. */
  httpPortsUndecoded: number[];
  /** TLS/QUIC conversations: application data stays encrypted. */
  encryptedConversations: number;
  quicConversations: number;
  http2Packets: number;
  /** Conversations with decoded HTTP where loss or truncation may hide messages. */
  httpWithGaps: number[];
}

export interface AnalysisModel {
  capture: CaptureInfo;
  protocolHierarchy: ProtoStat[];
  topProtocols: ProtoStat[];
  timeline: Timeline;
  hosts: Host[];
  conversations: Conversation[];
  dns: DnsTransaction[];
  http: HttpExchange[];
  tls: TlsSession[];
  arp: { frame: number; op: string; mac: string; ip: string }[];
  unsupported: Unsupported;
}

/** Packet row kept in the worker; sent on demand for drill-downs. */
export interface PacketRow {
  frame: number;
  t: number;
  len: number;
  caplen: number;
  src: string;
  dst: string;
  sport: number | null;
  dport: number | null;
  protocol: string;
  flags: string;
  iface: number | null;
}

export interface ProtoTreeNode {
  label: string;
  filter: string;
  start: number;
  length: number;
  source: number;
  children: ProtoTreeNode[];
}

export interface FrameDetails {
  number: number;
  epoch: string | null;
  tree: ProtoTreeNode[];
  sources: { name: string; bytes: Uint8Array }[];
  comments: string[];
  truncatedTree: boolean;
}

export interface PacketListPage {
  columns: string[];
  rows: { number: number; columns: string[] }[];
  matched: number;
}
