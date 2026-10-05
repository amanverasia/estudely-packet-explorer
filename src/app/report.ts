// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Builds a static, aggregate-only HTML snapshot. Keep this deliberately
// separate from JSON export: packet-level and content-bearing fields do not
// belong in a shareable report.
import type { AnalysisModel, ProtoStat } from '../engine/types';

const escapeHtml = (value: unknown): string => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#39;');

const number = (value: number): string => Math.round(value).toLocaleString('en-US');
const bytes = (value: number): string => {
  if (!Number.isFinite(value)) return 'unavailable';
  if (value < 1000) return `${number(value)} B`;
  const units = ['kB', 'MB', 'GB', 'TB'];
  let n = value;
  let unit = -1;
  do { n /= 1000; unit += 1; } while (n >= 1000 && unit < units.length - 1);
  return `${n.toFixed(n < 10 ? 2 : 1)} ${units[unit]}`;
};

function table(title: string, headers: string[], rows: unknown[][], empty = 'No records in this capture.'): string {
  const head = headers.map((label) => `<th scope="col">${escapeHtml(label)}</th>`).join('');
  const body = rows.length
    ? rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value)}</td>`).join('')}</tr>`).join('\n')
    : `<tr><td class="empty" colspan="${headers.length}">${escapeHtml(empty)}</td></tr>`;
  return `<section><h2>${escapeHtml(title)}</h2><div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div></section>`;
}

function groupRows<T>(items: T[], keyOf: (item: T) => string[], countLabel: string): unknown[][] {
  const groups = new Map<string, { values: string[]; count: number }>();
  for (const item of items) {
    const values = keyOf(item);
    const key = JSON.stringify(values);
    const current = groups.get(key);
    if (current) current.count += 1;
    else groups.set(key, { values, count: 1 });
  }
  return [...groups.values()]
    .sort((a, b) => b.count - a.count || a.values.join('\0').localeCompare(b.values.join('\0')))
    .map(({ values, count }) => [...values, `${number(count)} ${countLabel}${count === 1 ? '' : 's'}`]);
}

function protoRows(items: ProtoStat[]): unknown[][] {
  return [...items]
    .sort((a, b) => b.bytes - a.bytes || a.proto.localeCompare(b.proto))
    .map((item) => [item.proto, number(item.packets), bytes(item.bytes)]);
}

/** Returns a self-contained HTML document containing whole-capture aggregates only. */
export function htmlReport(model: AnalysisModel): string {
  const c = model.capture;
  const generatedAt = new Date().toISOString();
  const start = c.startEpoch ? new Date(Number(c.startEpoch) * 1000).toISOString() : 'Unavailable';
  const captureRows = [
    ['Capture file', c.fileName],
    ['Format', `${c.fileType} · ${c.linkType}`],
    ['File size', bytes(c.fileSize)],
    ['Analysis coverage', c.partial ? `Partial — first ${bytes(c.analyzedBytes)} analyzed` : `Complete — ${bytes(c.analyzedBytes)} analyzed`],
    ['Capture start (UTC)', start],
    ['Duration', `${c.duration.toFixed(3)} s`],
    ['Interfaces', c.interfaces.length],
    ['Wireshark', c.engine.wireshark],
  ];
  const qualityRows = [
    ['Truncated packets', c.truncatedPackets],
    ['Malformed packets', c.malformedPackets],
    ['Expert error packets', c.expertErrorPackets],
    ['Fragment packets', c.fragmentPackets],
    ['TCP retransmissions', c.retransmissions],
    ['Out-of-order segments', c.outOfOrder],
    ['Lost segments', c.lostSegments],
    ['Duplicate ACKs', c.duplicateAcks],
    ...(c.incomplete ? [['Capture status', c.incomplete]] : []),
  ];
  const interfaceRows = c.interfaces.map((iface) => [
    iface.id === null ? 'Unavailable' : number(iface.id), iface.name || 'Unnamed', iface.linkType, number(iface.packets),
  ]);
  const cards = [
    ['Packets', number(c.packetCount)],
    ['Bytes on wire', bytes(c.wireBytes)],
    ['Captured bytes', bytes(c.capturedBytes)],
    ['Hosts', number(model.hosts.length)],
    ['Conversations', number(model.conversations.length)],
  ].map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('');

  const hosts = [...model.hosts]
    .sort((a, b) => b.txBytes + b.rxBytes - (a.txBytes + a.rxBytes) || a.addr.localeCompare(b.addr))
    .map((host) => [
      host.addr,
      host.names.map((name) => `${name.name} (${name.source})`).join('; ') || '—',
      host.macs.map((mac) => mac.mac).join('; ') || host.arpMacs.join('; ') || '—',
      `${number(host.txPackets)} / ${bytes(host.txBytes)}`,
      `${number(host.rxPackets)} / ${bytes(host.rxBytes)}`,
      host.protocols.join(', ') || '—',
    ]);
  const conversations = [...model.conversations]
    .sort((a, b) => (b.bytesAB + b.bytesBA) - (a.bytesAB + a.bytesBA))
    .map((conv) => [
      `${conv.a}${conv.aPort === null ? '' : `:${conv.aPort}`} ↔ ${conv.b}${conv.bPort === null ? '' : `:${conv.bPort}`}`,
      conv.transport,
      conv.appProtocol || conv.protocols.join(', ') || '—',
      number(conv.packetsAB + conv.packetsBA),
      bytes(conv.bytesAB + conv.bytesBA),
      `${conv.start.toFixed(3)}–${conv.end.toFixed(3)} s`,
    ]);
  const dns = groupRows(model.dns, (item) => [item.proto, item.qname ?? 'Name unavailable', item.qtype ?? 'Type unavailable', item.status, item.rcode ?? '—'], 'transaction');
  const http = groupRows(model.http, (item) => [item.host ?? 'Host unavailable', item.method ?? 'Method unavailable', item.status === null ? 'Status unavailable' : String(item.status), item.contentType ?? 'Type unavailable', item.state, item.decrypted ? 'Decrypted' : 'Not marked decrypted'], 'exchange');
  const tls = groupRows(model.tls, (item) => [item.carrier, item.sni ?? 'Name unavailable', item.negotiated?.version ?? 'Version unavailable', item.negotiated?.alpn ?? item.offered?.alpn.join(', ') ?? 'ALPN unavailable', item.decryptionStatus], 'session');
  const dhcp = groupRows(model.dhcp, (item) => [item.outcome, item.messages.map((message) => message.type).join(', ') || 'Message unavailable'], 'exchange');
  const arp = model.arpBindings.map((binding) => [binding.ip, binding.macs.join(', '), number(binding.changes), number(binding.periods.reduce((sum, period) => sum + period.messages, 0))]);
  const icmp = groupRows(model.icmp, (item) => [`IPv${item.version}`, item.typeName ?? `Type ${item.type}`, item.codeName ?? (item.code === null ? 'Code unavailable' : `Code ${item.code}`), item.kind, item.echo?.status ?? '—'], 'message');
  const ssh = groupRows(model.ssh, (item) => [item.clientVersion ?? 'Client version unavailable', item.serverVersion ?? 'Server version unavailable'], 'session');
  const quic = groupRows(model.quic, (item) => [item.sni ?? 'Name unavailable', item.versions.join(', ') || 'Version unavailable', item.alpn.join(', ') || 'ALPN unavailable'], 'connection');

  const sections = [
    table('Capture details', ['Property', 'Value'], captureRows),
    table('Capture interfaces', ['Interface ID', 'Name', 'Link type', 'Packets'], interfaceRows),
    table('Protocol totals', ['Protocol', 'Packets', 'Bytes on wire'], protoRows(model.topProtocols)),
    table('Protocol hierarchy', ['Protocol', 'Packets', 'Bytes on wire'], protoRows(model.protocolHierarchy)),
    table('Hosts', ['Address', 'Observed or inferred names', 'MAC addresses', 'Sent packets / bytes', 'Received packets / bytes', 'Protocols'], hosts),
    table('Conversations', ['Endpoints', 'Transport', 'Observed protocol', 'Packets', 'Bytes on wire', 'Relative time'], conversations),
    table('DNS activity', ['Protocol', 'Query name', 'Query type', 'Status', 'Response code', 'Transactions'], dns),
    table('HTTP activity', ['Host', 'Method', 'Status', 'Content type', 'Exchange state', 'Decryption', 'Exchanges'], http),
    table('TLS activity', ['Carrier', 'Server name', 'Negotiated version', 'ALPN', 'Decryption status', 'Sessions'], tls),
    table('DHCP activity', ['Outcome', 'Observed message types', 'Exchanges'], dhcp),
    table('ARP address mappings', ['IPv4 address', 'MAC addresses stated by senders', 'Mapping changes', 'ARP messages'], arp),
    table('ICMP activity', ['IP version', 'Type', 'Code', 'Kind', 'Echo status', 'Messages'], icmp),
    table('SSH activity', ['Client version', 'Server version', 'Sessions'], ssh),
    table('QUIC activity', ['Server name', 'Versions', 'ALPN', 'Connections'], quic),
    table('Data quality', ['Measure', 'Count or status'], qualityRows.map(([label, value]) => [label, typeof value === 'number' ? number(value) : value])),
  ].join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Estudely Packet Explorer">
<title>Packet capture report — ${escapeHtml(c.fileName)}</title>
<style>
:root{color-scheme:light;--ink:#18212b;--muted:#526170;--line:#d9e0e7;--panel:#f3f6f9;--accent:#145c77;--warning:#fff2d6}*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:1200px;margin:0 auto;padding:32px 22px 60px}h1{font-size:clamp(1.8rem,4vw,2.7rem);line-height:1.15;margin:0 0 8px;overflow-wrap:anywhere}h2{font-size:1.35rem;margin:28px 0 12px}.meta{color:var(--muted);margin:0 0 22px}.notice{background:var(--warning);border:1px solid #e2c47c;border-radius:8px;padding:16px 18px;margin:20px 0 24px}.notice p{margin:5px 0}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:13px 15px}.metric span{display:block;color:var(--muted);font-size:.84rem}.metric strong{display:block;font-size:1.2rem;margin-top:2px}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:.91rem}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{background:var(--panel);font-weight:650;white-space:nowrap}tbody tr:last-child td{border-bottom:0}.empty{color:var(--muted);font-style:italic}.footer{margin-top:30px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:.87rem}@media print{main{max-width:none;padding:0}.notice{break-inside:avoid}section{break-inside:avoid-page}.table-wrap{overflow:visible}table{font-size:8.5pt}th,td{padding:5px}}@media(prefers-color-scheme:dark){:root{color-scheme:light}}
</style>
</head>
<body><main>
<header><h1>Packet capture report</h1><p class="meta">${escapeHtml(c.fileName)} · Generated ${escapeHtml(generatedAt)} · Whole-capture aggregates</p></header>
<aside class="notice" aria-label="Report contents and privacy"><strong>What this report contains</strong><p>Aggregate capture and protocol summaries, including names and network addresses observed in the capture. These can identify people or systems; share this file carefully.</p><p>It does not contain packet bytes, payloads, stream contents, packet-by-packet details, TLS key logs, certificate details, or the Files view inventory or downloaded file contents. Current app filters do not change this whole-capture report.</p><p>This is a self-contained static HTML file. It uses no scripts, external assets, or network requests and can be opened offline.</p></aside>
<div class="metrics" aria-label="Capture totals">${cards}</div>
${sections}
<footer class="footer">Created locally by Estudely Packet Explorer. Times in conversation rows are relative to the first packet. Byte totals use original frame lengths unless labelled captured.</footer>
</main></body></html>`;
}
