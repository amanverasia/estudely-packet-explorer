// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
import type { LocalIpDataKind, LocalIpDatabase } from './localIpData';

const DB_NAME = 'estudely-local-ip-data';
const STORE = 'databases';

function open(): Promise<IDBDatabase> {
  if (!('indexedDB' in globalThis)) return Promise.reject(new Error('This browser does not support local database storage.'));
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Could not open local database storage.'));
  });
}

export async function readLocalIpDatabase(kind: LocalIpDataKind): Promise<LocalIpDatabase | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(kind);
    request.onsuccess = () => { db.close(); resolve((request.result as LocalIpDatabase | undefined) ?? null); };
    request.onerror = () => { db.close(); reject(request.error ?? new Error('Could not read the local database.')); };
  });
}

export async function writeLocalIpDatabase(database: LocalIpDatabase): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE, 'readwrite');
    transaction.objectStore(STORE).put(database, database.kind);
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); reject(transaction.error ?? new Error('Could not save the local database.')); };
    transaction.onabort = () => { db.close(); reject(transaction.error ?? new Error('Saving the local database was cancelled.')); };
  });
}

export async function deleteLocalIpDatabase(kind: LocalIpDataKind): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE, 'readwrite');
    transaction.objectStore(STORE).delete(kind);
    transaction.oncomplete = () => { db.close(); resolve(); };
    transaction.onerror = () => { db.close(); reject(transaction.error ?? new Error('Could not remove the local database.')); };
  });
}
