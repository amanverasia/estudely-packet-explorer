// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useRef, useState } from 'react';
import type { LocalIpDataKind, LocalIpDatabase } from '../localIpData';
import { deleteLocalIpDatabase, readLocalIpDatabase, writeLocalIpDatabase } from '../localIpStorage';
import { num } from '../format';
import { Note, Panel } from './bits';

type Databases = Record<LocalIpDataKind, LocalIpDatabase | null>;
type Progress = Partial<Record<LocalIpDataKind, string>>;
type Props = { databases: Databases; onChange: (kind: LocalIpDataKind, database: LocalIpDatabase | null) => void };

export function LocalIpDataPanel({ databases, onChange }: Props) {
  const [progress, setProgress] = useState<Progress>({});
  const [busy, setBusy] = useState<LocalIpDataKind | null>(null);
  const [error, setError] = useState<string | null>(null);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([readLocalIpDatabase('country'), readLocalIpDatabase('asn')]).then(([country, asn]) => {
      if (active) { onChange('country', country); onChange('asn', asn); }
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : String(reason));
    });
    return () => { active = false; workerRef.current?.terminate(); };
  }, [onChange]);

  const importFile = (kind: LocalIpDataKind, file: File) => {
    if (file.size > 100 * 1024 * 1024) {
      setError('Choose a DB-IP Lite CSV file smaller than 100 MB.');
      return;
    }
    workerRef.current?.terminate();
    setError(null);
    setBusy(kind);
    setProgress((old) => ({ ...old, [kind]: `Reading ${file.name}…` }));
    const worker = new Worker(new URL('../localIpData.worker.ts', import.meta.url), { type: 'module', name: 'estudely-local-ip-data' });
    workerRef.current = worker;
    worker.onmessage = async (event: MessageEvent<{ type: string; message?: string; database?: LocalIpDatabase }>) => {
      const message = event.data;
      if (message.type === 'progress') {
        setProgress((old) => ({ ...old, [kind]: message.message ?? 'Importing…' }));
        return;
      }
      worker.terminate();
      workerRef.current = null;
      setBusy(null);
      if (message.type === 'error' || !message.database) {
        setError(message.message ?? 'The selected database could not be imported.');
        setProgress((old) => ({ ...old, [kind]: '' }));
        return;
      }
      try {
        await writeLocalIpDatabase(message.database);
        onChange(kind, message.database);
        setProgress((old) => ({ ...old, [kind]: '' }));
      } catch (reason) {
        setProgress((old) => ({ ...old, [kind]: '' }));
        setError(reason instanceof Error ? reason.message : String(reason));
      }
    };
    worker.onerror = (event) => {
      worker.terminate();
      workerRef.current = null;
      setBusy(null);
      setProgress((old) => ({ ...old, [kind]: '' }));
      setError(event.message || 'The local database import failed.');
    };
    worker.postMessage({ kind, file });
  };

  const remove = async (kind: LocalIpDataKind) => {
    setError(null);
    try {
      await deleteLocalIpDatabase(kind);
      onChange(kind, null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  return (
    <Panel title="Optional offline IP data" sub="Local DB-IP Lite files">
      <p style={{ marginTop: 0 }}>
        Add approximate country and network-owner details using DB-IP Lite CSV files (currently around 30 MB each). Download either file from DB-IP, then import it here; the app compacts the selected file into a range index stored in this browser for offline use. Capture addresses are matched locally and are never sent to DB-IP.
      </p>
      <div className="actions" style={{ justifyContent: 'flex-start', flexWrap: 'wrap' }}>
        <a className="btn small" href="https://db-ip.com/db/download/ip-to-country-lite" target="_blank" rel="noreferrer">Get Country CSV from DB-IP</a>
        <a className="btn small" href="https://db-ip.com/db/download/ip-to-asn-lite" target="_blank" rel="noreferrer">Get ASN CSV from DB-IP</a>
        <FileImport kind="country" busy={busy !== null} onFile={(file) => importFile('country', file)} />
        <FileImport kind="asn" busy={busy !== null} onFile={(file) => importFile('asn', file)} />
      </div>
      <dl className="kv" style={{ marginBottom: 0 }}>
        <DatabaseStatus kind="country" database={databases.country} progress={progress.country} onRemove={() => remove('country')} />
        <DatabaseStatus kind="asn" database={databases.asn} progress={progress.asn} onRemove={() => remove('asn')} />
      </dl>
      {error && <p className="note crit" role="alert" style={{ marginBottom: 0 }}>{error}</p>}
      <Note>
        DB-IP Lite data is updated monthly and can be incomplete or wrong. Country is only an approximate IP registration location; AS ownership is approximate and does not identify a person, device, or the traffic's physical path. <a href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a> · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noreferrer">CC BY 4.0</a>.
      </Note>
    </Panel>
  );
}

function FileImport({ kind, busy, onFile }: { kind: LocalIpDataKind; busy: boolean; onFile: (file: File) => void }) {
  const label = kind === 'country' ? 'Import Country CSV' : 'Import ASN CSV';
  return (
    <label className={`btn small${busy ? ' disabled' : ''}`}>
      {label}
      <input className="sr-only" type="file" accept=".csv,.gz,text/csv,application/gzip" disabled={busy} aria-label={label}
        onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ''; if (file) onFile(file); }} />
    </label>
  );
}

function DatabaseStatus({ kind, database, progress, onRemove }: { kind: LocalIpDataKind; database: LocalIpDatabase | null; progress?: string; onRemove: () => void }) {
  const label = kind === 'country' ? 'Country' : 'ASN';
  return (
    <div style={{ display: 'contents' }}>
      <dt>{label} data</dt>
      <dd>
        {progress || (database
          ? `Ready offline${database.release ? ` · release ${database.release}` : ''} · ${num(database.recordCount)} ranges`
          : 'Not installed')}
        {database && <button className="btn small ghost" style={{ marginLeft: 8 }} onClick={onRemove}>Remove</button>}
      </dd>
    </div>
  );
}
