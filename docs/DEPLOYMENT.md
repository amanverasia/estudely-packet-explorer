# Deployment

The build output (`dist/`) is a static site: HTML, JS, CSS, fonts, and `wiregasm/` (engine JS, gzipped WASM, gzipped data package, GPL licence text). No server code.

```bash
npm ci
npm run build
```

## Custom domain or subdirectory

`vite.config.ts` uses `base: './'`, and the app uses hash routes (`#/dns`), so the same `dist/` works at `https://packets.example.com/` or `https://example.com/tools/packet-explorer/` with no rebuild and no rewrite rules. Verified by serving `dist/` under `/tools/packet-explorer/` with `python3 -m http.server`.

## Hosting notes

- **MIME types**: `.mjs` and `.js` must be served as JavaScript (all common hosts do). The engine files are fetched as bytes, so `.gz` needs no special type.
- **Compression**: the WASM and data package are already gzipped and are decompressed in the browser with `DecompressionStream`. If a server adds `Content-Encoding: gzip` for `.gz` files, the browser decodes it and the app detects the missing gzip header and uses the bytes as-is. Either way works.
- **Caching**: cache `assets/*` (content-hashed names) for a year. Cache `wiregasm/*` for a long time too, but change the URL or purge when upgrading Wiregasm. Don't cache `index.html` aggressively.
- **No COOP/COEP needed**: the engine does not use threads or SharedArrayBuffer.
- **Size**: about 21 MB in total, almost all of it the engine (downloaded on first capture open, not on page load).

## Recommended headers

The built `index.html` includes a CSP meta tag. Workers take their policy from HTTP headers, so if your host lets you set headers, add this for every file to enforce the same policy in the worker:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
```

Netlify / Cloudflare Pages: put these in `dist/_headers` under `/*`. GitHub Pages cannot set headers; the meta tag still protects the page itself.

If you add analytics or error reporting to the host page later, keep it off this app: the privacy promise depends on there being no third-party scripts.

## GitHub Pages example

```bash
npm run build
npx gh-pages -d dist      # or upload dist/ with the Pages action
```
