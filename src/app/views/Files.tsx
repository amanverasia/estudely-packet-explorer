// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useMemo, useState } from 'react';
import type { ExportObjectRow } from '../../engine/session';
import { DataTable, type Column } from '../components/DataTable';
import { Note, ViewHead } from '../components/bits';
import { useApp } from '../context';
import { downloadBlob } from '../download';
import { bytes, num } from '../format';

export function Files() {
  const { engine, filter } = useApp();
  const [objects, setObjects] = useState<ExportObjectRow[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    engine.exportObjects().then((rows) => {
      if (!active) return;
      setObjects(rows);
      setLoading(false);
    }).catch((e: Error) => {
      if (!active) return;
      setError(e.message);
      setLoading(false);
    });
    return () => { active = false; };
  }, [engine]);

  const rows = useMemo(() => (objects ?? []).filter((row) => {
    if (filter.start !== null && filter.end !== null && (row.relativeTime === null || row.relativeTime < filter.start || row.relativeTime > filter.end)) return false;
    if (filter.host && !row.hostAddresses.includes(filter.host)) return false;
    return true;
  }), [objects, filter.start, filter.end, filter.host]);

  const save = async (row: ExportObjectRow) => {
    setDownloading(row.token);
    setDownloadError(null);
    try {
      const file = await engine.downloadExportObject(row.token);
      const name = safeObjectFilename(file.fileName || row.name || '', row.protocol, row.packet);
      downloadBlob(name, new Blob([file.bytes], { type: 'application/octet-stream' }));
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : String(e));
    } finally {
      setDownloading(null);
    }
  };

  const columns: Column<ExportObjectRow>[] = [
    { key: 'protocol', header: 'Protocol', width: '100px', value: (row) => row.protocol },
    { key: 'host', header: 'Host', width: 'minmax(180px, 1fr)', value: (row) => row.host },
    { key: 'name', header: 'Name', width: 'minmax(180px, 1.4fr)', value: (row) => row.name },
    { key: 'type', header: 'Type', width: 'minmax(140px, 1fr)', value: (row) => row.contentType },
    { key: 'size', header: 'Size', width: '100px', align: 'right', value: (row) => row.size, render: (row) => bytes(row.size) },
    { key: 'packet', header: 'Packet', width: '82px', align: 'right', value: (row) => row.packet },
    { key: 'download', header: 'Save file', width: '110px', noSearch: true, value: () => '', render: (row) => (
      <button className="btn small" disabled={downloading !== null} onClick={() => void save(row)} aria-label={`Download ${row.name || `${row.protocol} file from packet ${row.packet}`}`}>
        {downloading === row.token ? 'Saving…' : 'Download'}
      </button>
    ) },
  ];

  return (
    <>
      <ViewHead title="Files">
        Opening this view scans and reassembles objects with Wireshark’s DICOM, HTTP, IMF, SMB and TFTP export-object taps. The bytes stay in the worker until you choose Download; large captures with many transfers can use significant memory.
      </ViewHead>
      <Note kind="warn"><b>Captured files are untrusted.</b> They may contain malware or sensitive data. Download them only if you trust the source. This view shows metadata only; it never previews or runs a file. Downloads are saved to your device.</Note>
      {objects && (filter.start !== null || filter.host) && <Note>
        {num(rows.length)} of {num(objects?.length ?? 0)} objects match the shared filters. Time and host matching use the packet number reported for each object; downloading still saves the complete reassembled file.
      </Note>}
      {downloadError && <Note kind="crit">{downloadError}</Note>}
      {error && <Note kind="crit">Could not scan the capture for exported files: {error}</Note>}
      {loading ? (
        <section className="panel empty">Scanning the capture for reassembled files…</section>
      ) : error ? (
        <section className="panel empty"><strong>Could not list exported files.</strong> Check the error above and try another capture if the issue persists.</section>
      ) : objects && objects.length === 0 ? (
        <section className="panel empty"><strong>No exported file objects were found.</strong> Supported protocols are DICOM, HTTP, IMF, SMB and TFTP.</section>
      ) : rows.length === 0 ? (
        <section className="panel empty"><strong>No files match the shared filters.</strong> Clear the time or host filter to see all exported objects.</section>
      ) : (
        <section className="panel">
          <DataTable stateId="files.exported" label="Exported files" exportName="exported-files" rows={rows} columns={columns} rowKey={(row) => row.token} searchPlaceholder="Search protocol, host, name or type" />
        </section>
      )}
    </>
  );
}

function safeObjectFilename(name: string, protocol: string, packet: number): string {
  const leaf = name.replace(/\\/g, '/').split('/').pop() ?? '';
  let safe = leaf.replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_').trim().replace(/^\.+/, '').slice(0, 180);
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(safe)) safe = `_${safe}`;
  return safe || `${protocol.toLowerCase()}-packet-${packet}.bin`;
}
