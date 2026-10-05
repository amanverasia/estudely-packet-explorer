// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Local exports: files are built in memory and saved through a browser
// download. Nothing is sent anywhere.
import type { AnalysisModel } from '../engine/types';

export function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  let s = Array.isArray(v) ? v.join('; ') : String(v);
  // Neutralise spreadsheet formula injection from captured strings.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(headers: string[], rows: unknown[][]): string {
  return [headers, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

export function downloadCsv(name: string, headers: string[], rows: unknown[][]): void {
  downloadBlob(name, new Blob(['﻿' + toCsv(headers, rows)], { type: 'text/csv;charset=utf-8' }));
}

export interface JsonExportOptions {
  mode: 'aggregate' | 'detailed';
  /** Redacts known identifying and content-like string fields in detailed mode. */
  redactSensitive?: boolean;
}

const SENSITIVE_FIELD_KEYS = new Set([
  'a', 'addr', 'arpmacs', 'assignedip', 'b', 'client', 'clientmac', 'clientversion', 'contenttype',
  'commonname', 'dnsservers', 'dst', 'fileName', 'hostname', 'host', 'incomplete', 'ip', 'issuer',
  'location', 'mac', 'macs', 'name', 'offeredip', 'phrase', 'qname', 'requestedip', 'requestcontenttype',
  'requestheaders', 'responseheaders', 'routers', 'san', 'sni', 'server', 'serverheader',
  'serverversion', 'sha256', 'src', 'startepoch', 'subject', 'subnetmask', 'leasetime', 'targetip', 'targetmac', 'txid', 'uri',
  'useragent', 'value', 'warnings', 'xid', 'serial', 'ident', 'notbefore', 'notafter',
].map((key) => key.toLowerCase()));

const SENSITIVE_CATEGORIES = [
  'Capture file name and exact start time',
  'IP addresses, MAC addresses, host names, and DNS names',
  'HTTP hosts, request paths, locations, user-agent strings, and headers',
  'TLS server names and certificate identity values',
  'DHCP client identifiers, assigned addresses, and network configuration',
  'SSH identification strings',
];

const NEVER_EXPORTED = [
  'Packet bytes, packet hex dumps, and decoded packet trees',
  'Reassembled TCP/UDP stream payloads',
  'TLS key-log files and session secrets',
  'Exported-file inventory and downloaded file contents',
];

const REDACTION_LIMITS = 'Redaction replaces values in known sensitive fields. Frame numbers, relative timings, ports, traffic sizes, protocol labels, and counts remain. These details can still identify or describe a capture, so redaction is not anonymization; review the file before sharing.';

function exportHeader(mode: JsonExportOptions['mode'], redactSensitive: boolean) {
  return {
    generator: 'Estudely Packet Explorer',
    generatedAt: new Date().toISOString(),
    export: {
      schemaVersion: 2,
      mode,
      redaction: mode === 'aggregate' ? 'not applicable (aggregate allowlist)' : redactSensitive ? 'known sensitive fields replaced with [REDACTED]' : 'not applied',
      sensitiveData: SENSITIVE_CATEGORIES,
      neverIncluded: NEVER_EXPORTED,
      redactionLimits: mode === 'detailed' ? REDACTION_LIMITS : 'The aggregate export uses an explicit allowlist and omits the sensitive categories listed above.',
    },
    note: 'In detailed mode, times are seconds relative to the exact capture.startEpoch. Byte counts are original frame lengths unless named captured. Exports are generated locally in this browser.',
  };
}

function aggregateExport(model: AnalysisModel) {
  const c = model.capture;
  return {
    capture: {
      fileSize: c.fileSize,
      analyzedBytes: c.analyzedBytes,
      partial: c.partial,
      fileType: c.fileType,
      linkType: c.linkType,
      packetCount: c.packetCount,
      duration: c.duration,
      timestampDigits: c.timestampDigits,
      nonMonotonicTimestamps: c.nonMonotonicTimestamps,
      interfaceCount: c.interfaces.length,
      wireBytes: c.wireBytes,
      capturedBytes: c.capturedBytes,
      truncatedPackets: c.truncatedPackets,
      malformedPackets: c.malformedPackets,
      expertErrorPackets: c.expertErrorPackets,
      fragmentPackets: c.fragmentPackets,
      retransmissions: c.retransmissions,
      outOfOrder: c.outOfOrder,
      lostSegments: c.lostSegments,
      duplicateAcks: c.duplicateAcks,
      incomplete: c.incomplete !== null,
      engine: { wireshark: c.engine.wireshark, wiregasm: c.engine.wiregasm },
      analysisMs: c.analysisMs,
    },
    protocolHierarchy: model.protocolHierarchy.map(({ proto, packets, bytes }) => ({ proto, packets, bytes })),
    topProtocols: model.topProtocols.map(({ proto, packets, bytes }) => ({ proto, packets, bytes })),
    recordCounts: {
      hosts: model.hosts.length,
      conversations: model.conversations.length,
      dns: model.dns.length,
      http: model.http.length,
      tls: model.tls.length,
      arp: model.arp.length,
      arpBindings: model.arpBindings.length,
      dhcp: model.dhcp.length,
      icmp: model.icmp.length,
      ssh: model.ssh.length,
      quic: model.quic.length,
    },
    limitations: {
      httpPortsUndecoded: model.unsupported.httpPortsUndecoded.length,
      encryptedConversations: model.unsupported.encryptedConversations,
      quicConversations: model.unsupported.quicConversations,
      http2Packets: model.unsupported.http2Packets,
      httpWithGaps: model.unsupported.httpWithGaps.length,
    },
  };
}

function redactKnownFields(value: unknown, key = ''): unknown {
  if (SENSITIVE_FIELD_KEYS.has(key.toLowerCase())) {
    if (Array.isArray(value) && value.length === 0) return value;
    if (value === '') return value;
    return value === null || value === undefined ? value : '[REDACTED]';
  }
  if (Array.isArray(value)) return value.map((item) => redactKnownFields(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redactKnownFields(childValue, childKey)]));
  }
  return value;
}

/**
 * JSON summary with a conservative aggregate allowlist by default. Detailed
 * mode serializes analysis tables but never the internal packet filter index;
 * optional redaction clones the selected data and never changes the live model.
 */
export function summaryJson(model: AnalysisModel, options: JsonExportOptions = { mode: 'aggregate' }): string {
  const redactSensitive = options.mode === 'detailed' && options.redactSensitive !== false;
  const header = exportHeader(options.mode, redactSensitive);
  if (options.mode === 'aggregate') return JSON.stringify({ ...header, ...aggregateExport(model) }, null, 2);

  const detailed = {
    ...header,
    capture: model.capture,
    protocolHierarchy: model.protocolHierarchy,
    topProtocols: model.topProtocols,
    timeline: model.timeline,
    hosts: model.hosts,
    conversations: model.conversations,
    dns: model.dns,
    http: model.http,
    tls: model.tls,
    arp: model.arp,
    arpBindings: model.arpBindings,
    dhcp: model.dhcp,
    icmp: model.icmp,
    ssh: model.ssh,
    quic: model.quic,
    limitations: model.unsupported,
  };
  return JSON.stringify(redactSensitive ? redactKnownFields(detailed) : detailed, null, 2);
}

export function safeBase(fileName: string): string {
  return fileName.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'capture';
}
