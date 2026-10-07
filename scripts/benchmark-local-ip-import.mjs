// Copyright (C) 2026 Estudely and contributors
// SPDX-License-Identifier: GPL-2.0-or-later
// Linux process-tree PSS/RSS benchmark, including worker transfer and IndexedDB.
// Run: node scripts/benchmark-local-ip-import.mjs [baseline-ref] [output.json]
import { build } from 'esbuild';
import { chromium } from '@playwright/test';
import { createServer } from 'node:http';
import { createReadStream, createWriteStream, readFileSync, readdirSync, writeFileSync, mkdtempSync, mkdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { once } from 'node:events';

const baseline = execFileSync('git', ['rev-parse', process.argv[2] ?? '02d8d0adb86b00ac3d88a3ea12a930a66273fca7'], { encoding: 'utf8' }).trim();
const outputPath = resolve(process.argv[3] ?? '/tmp/local-ip-import-memory.json');
const root = mkdtempSync(join(tmpdir(), 'ip-import-memory-'));
const before = join(root, 'before');
mkdirSync(before);
for (const name of ['localIpData.ts', 'localIpData.worker.ts']) {
  writeFileSync(join(before, name), execFileSync('git', ['show', `${baseline}:src/app/${name}`]));
}
await build({ entryPoints: [join(before, 'localIpData.worker.ts')], bundle: true, format: 'esm', outfile: join(root, 'before.js') });
await build({ entryPoints: ['src/app/localIpData.worker.ts'], bundle: true, format: 'esm', outfile: join(root, 'after.js') });
await build({ stdin: { contents: `import {writeLocalIpDatabase,readLocalIpDatabase} from './src/app/localIpStorage'; window.persist=writeLocalIpDatabase; window.read=readLocalIpDatabase;`, resolveDir: process.cwd(), loader: 'ts' }, bundle: true, format: 'esm', outfile: join(root, 'main.js') });
writeFileSync(join(root, 'index.html'), `<script type="module" src="/main.js"></script><input type="file"><script>
window.phase='idle'; window.result=null;
document.querySelector('input').onchange=()=>{
const start=performance.now(); const file=document.querySelector('input').files[0];
const worker=new Worker('/'+new URL(location.href).searchParams.get('mode')+'.js',{type:'module'});
window.phase='worker';
worker.onmessage=async({data})=>{
if(data.type==='error'){window.result={error:data.message};worker.terminate();return;}
if(data.type!=='complete')return;
window.phase='persist';worker.terminate();
const db=data.database;
const numeric=Object.values(db).filter(v=>v instanceof Uint32Array).reduce((n,v)=>n+v.byteLength,0);
await window.persist(db);
window.phase='reload';const reloaded=await window.read('asn');
window.result={elapsedMs:performance.now()-start,rows:reloaded.recordCount,numericBytes:numeric,values:reloaded.values.length,longestLabel:Math.max(...reloaded.values.map(x=>x.length))};
window.phase='done';
};worker.postMessage({file,kind:'asn'});
};</script>`);
const server = createServer((request, response) => {
  const name = new URL(request.url, 'http://localhost').pathname;
  const path = join(root, name === '/' ? 'index.html' : name);
  if (!path.startsWith(root)) { response.writeHead(403).end(); return; }
  try { statSync(path); response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : 'text/html'); createReadStream(path).pipe(response); }
  catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

async function fixture(sizeMiB, reversed = false) {
  const path = join(root, `asn-${sizeMiB}-${reversed}.csv`);
  const writer = createWriteStream(path);
  const limit = sizeMiB * 1024 * 1024;
  let bytes = 0, rows = 0, v4 = 0, v6 = 0, buffer = '';
  while (bytes < limit) {
    const n = reversed ? 4_000_000 - rows : rows;
    const ip = rows % 5 ? `1.${n >>> 16 & 255}.${n >>> 8 & 255}.${n & 255}` : `2001:db8::${(n >>> 16).toString(16)}:${(n & 65535).toString(16)}`;
    const label = `Representative network organization ${String(rows % 64).padStart(2, '0')}`;
    const row = `${ip},${ip},${64500 + rows % 64},${label}\n`;
    if (bytes + row.length > limit) break;
    bytes += row.length; rows++;
    if (rows % 5 === 1) v6++; else v4++;
    buffer += row;
    if (buffer.length > 65536) { if (!writer.write(buffer)) await once(writer, 'drain'); buffer = ''; }
  }
  writer.end(buffer); await once(writer, 'finish');
  const gzip = `${path}.gz`;
  await pipeline(createReadStream(path), createGzip(), createWriteStream(gzip));
  return { path: gzip, decodedBytes: bytes, compressedBytes: statSync(gzip).size, rows, ipv4Rows: v4, ipv6Rows: v6, reversed };
}

// PSS avoids counting shared library pages once per browser process.
function memory(pid) {
  const children = new Map();
  for (const entry of readdirSync('/proc')) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const status = readFileSync(`/proc/${entry}/status`, 'utf8');
      const parent = Number(/^PPid:\s+(\d+)/m.exec(status)[1]);
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(Number(entry));
    } catch {}
  }
  let rss = 0, pss = 0;
  const pending = [pid];
  while (pending.length) {
    const current = pending.pop();
    pending.push(...(children.get(current) ?? []));
    try {
      const text = readFileSync(`/proc/${current}/smaps_rollup`, 'utf8');
      rss += Number(/^Rss:\s+(\d+)/m.exec(text)[1]) * 1024;
      pss += Number(/^Pss:\s+(\d+)/m.exec(text)[1]) * 1024;
    } catch {}
  }
  return { rss, pss };
}

const fixtures = [await fixture(30), await fixture(149), await fixture(30, true)];
const results = [];
try {
  for (const input of fixtures) for (const mode of ['before', 'after']) {
    const launched = await chromium.launchServer({ headless: true });
    const browser = await chromium.connect(launched.wsEndpoint());
    const page = await browser.newPage();
    page.setDefaultTimeout(240_000);
    await page.goto(`http://127.0.0.1:${port}/?mode=${mode}`);
    await page.waitForFunction(() => typeof window.persist === 'function');
    const initial = memory(launched.process().pid);
    let peak = { ...initial }, samples = 0;
    const timer = setInterval(() => {
      const current = memory(launched.process().pid);
      peak.pss = Math.max(peak.pss, current.pss); peak.rss = Math.max(peak.rss, current.rss); samples++;
    }, 20);
    try {
      await page.locator('input').setInputFiles(input.path);
      await page.waitForFunction(() => window.result !== null, undefined, { timeout: 240_000 });
      const result = await page.evaluate(() => window.result);
      const row = { mode, baseline, browser: browser.version(), input, initial, peak, samples, ...result };
      results.push(row); writeFileSync(outputPath, JSON.stringify(results, null, 2));
      console.log(JSON.stringify(row));
      if (result.error) throw new Error(result.error);
    } finally { clearInterval(timer); await browser.close(); await launched.close(); }
  }
} finally { server.close(); }
console.log(`Saved ${outputPath}; generated fixtures/harness retained at ${root}`);
