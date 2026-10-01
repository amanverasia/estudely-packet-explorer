// Copies the Wiregasm runtime (Wireshark compiled to WebAssembly) out of
// node_modules into public/wiregasm so it is self-hosted with the app.
// The WASM and data package are shipped gzip-compressed and decompressed in
// the browser with DecompressionStream, so hosting works without any special
// server compression configuration.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const pkgDir = dirname(require.resolve('@goodtools/wiregasm/package.json'));
const dist = join(pkgDir, 'dist');
const out = join(root, 'public', 'wiregasm');
mkdirSync(out, { recursive: true });

const version = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')).version;

// The emscripten loader is a UMD script that declares `var loadWiregasm`.
// Appending an ESM export lets a module worker import() it directly.
const loader = readFileSync(join(dist, 'wiregasm.js'), 'utf8');
writeFileSync(join(out, 'wiregasm.mjs'), `${loader}\nexport default loadWiregasm;\n`);

for (const f of ['wiregasm.wasm.gz', 'wiregasm.data.gz']) {
  const src = join(dist, f);
  const dst = join(out, f);
  if (!existsSync(dst) || statSync(dst).size !== statSync(src).size) copyFileSync(src, dst);
}
copyFileSync(join(pkgDir, 'LICENSE'), join(out, 'LICENSE-GPL-2.0.txt'));
writeFileSync(
  join(out, 'manifest.json'),
  JSON.stringify({ package: '@goodtools/wiregasm', version, wireshark: '4.4.5' }, null, 2),
);
console.log(`wiregasm ${version} prepared in public/wiregasm`);
