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

export function safeBase(fileName: string): string {
  return fileName.replace(/\.[^.]+$/, '').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'capture';
}

/** JSON summary: capture facts and aggregate tables (no packet bytes). */
export function summaryJson(model: AnalysisModel): string {
  const m = model;
  return JSON.stringify({
    generator: 'Estudely Packet Explorer',
    generatedAt: new Date().toISOString(),
    note: 'Times are seconds relative to capture.startEpoch. Byte counts are original frame lengths unless named captured.',
    capture: m.capture,
    protocolHierarchy: m.protocolHierarchy,
    topProtocols: m.topProtocols,
    hosts: m.hosts,
    conversations: m.conversations,
    dns: m.dns,
    http: m.http,
    tls: m.tls,
    arp: m.arp,
    limitations: m.unsupported,
  }, null, 2);
}
