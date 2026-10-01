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

## Live deployment: trace.esdy.cc (Cloudflare)

Production is served by Cloudflare as static files (Workers static assets, no Worker script) on the custom domain `trace.esdy.cc`, configured in `wrangler.jsonc`:

```bash
npx wrangler login     # once
npm run deploy         # build + wrangler deploy
```

`public/_headers` (copied into `dist/`) sets the security headers. Cloudflare and Netlify both read it.

### Cloudflare zone settings that must stay off

Cloudflare can inject scripts into pages at the edge. For this app they would break the "no analytics" promise. The CSP blocks them, so nothing is sent, but they should be switched off for `esdy.cc` (or at least `trace.esdy.cc`):

- **Web Analytics automatic setup** (Analytics & Logs, then Web Analytics; the RUM beacon from `static.cloudflareinsights.com`).
- **Bot Fight Mode / JavaScript detections** (Security, then Bots), which injects an inline `__CF$cv$params` script.
- Rocket Loader, Email Address Obfuscation and Zaraz, if they are ever enabled.

Check with: `curl -s https://trace.esdy.cc/ | grep -c "<script"` should print `1`.

## Recommended headers (any host)

The page gets a strict policy. The analysis worker needs `'unsafe-eval'`, because the Wiregasm engine's Emscripten/embind glue builds helper functions with `new Function` at start-up. `connect-src 'self'` still applies inside the worker, so it cannot send capture data anywhere. The meta tag in `index.html` covers only the page; workers take their policy from HTTP headers. Without headers the worker runs with no CSP at all.

```
# every file
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff

# /assets/analysis.worker-*.js only (replace the policy above)
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval'; connect-src 'self'; object-src 'none'; base-uri 'self'
```

If two policies reach the worker, the browser enforces both and the worker fails. `public/_headers` uses `! Content-Security-Policy` to replace the global one for the worker path.

## GitHub Pages example

```bash
npm run build
npx gh-pages -d dist      # or upload dist/ with the Pages action
```
