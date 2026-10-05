# Supported browsers

| Browser | Minimum version | Tested |
|---|---|---|
| Chrome, Edge and other Chromium browsers | 94 | Every change, in Playwright's Chromium |
| Firefox | 114 | Every change, in Playwright's Firefox |
| Safari | 16.4 | Every change, in Playwright's WebKit (Linux build; not Safari on macOS or iOS itself) |

Desktop browsers are the target. Phones and tablets work for small captures (the layout is tested at phone and tablet widths) but have far less memory to give a page.

The minimum versions come from feature support tables, not from testing old releases. They are set by:

- **Module workers** (`new Worker(url, { type: 'module' })`): Chrome 80, Firefox 114, Safari 15.
- **`DecompressionStream`**: the engine ships gzip-compressed and is unpacked in the worker. Chrome 80, Firefox 113, Safari 16.4.
- **The ES2022 build target** (`vite.config.ts`), whose newest syntax (class static blocks) needs Chrome 94, Firefox 93, Safari 16.4.

Two styling details of the Follow stream view (`color-mix()`, `:has()`) need newer browsers; without them the view still works, with plainer styling.

## What was checked in each engine

Checked in Chromium 153, Firefox 155 and WebKit 26.6 (the versions bundled with Playwright 1.63). The checks marked "every change" are browser tests that run in all three Playwright projects; the large capture was checked once by hand.

| Check | Chromium | Firefox | WebKit |
|---|---|---|---|
| Whole browser suite (`e2e/*.spec.ts`), every change | passes | passes | passes |
| `DecompressionStream('gzip')` unpacks the engine in the worker (every capture in the suite) | yes | yes | yes |
| A compiled `WebAssembly.Module` posted to the next capture's worker, so the engine is downloaded and compiled once (`e2e/browsers.spec.ts`) | yes | yes | yes |
| A worker's `WebAssembly.Memory` grows to the engine's 2 GiB maximum (`e2e/browsers.spec.ts`) | yes | yes | yes |
| Service worker: installs, caches the app and engine, works offline, offers updates (`e2e/pwa.spec.ts`) | yes | yes | yes |
| 191 MiB pcap (861,494 DNS packets) opens, one-off check on a desktop | yes, 167 s | yes, 201 s | yes, 169 s |

No engine needed a fallback for any of these. In WebKit the offline test makes the test server unreachable instead of using Playwright's `setOffline`, because in Playwright's WebKit that (and request routing) also blocks requests the service worker would answer. This is a limitation of the test harness: with the server really gone, WebKit serves the app from the service worker like the other engines.

## Fallbacks

- **No `DecompressionStream`, `WebAssembly` or `Worker`:** checked before a worker is started (`src/app/support.ts`). The page names the missing feature and the browsers that work, and nothing is downloaded. The worker repeats the `DecompressionStream` check on its own.
- **Module workers not supported:** older browsers throw when the worker is created. The page catches it and shows the same kind of explanation instead of failing silently.
- **The browser refuses to post the compiled module** (`DataCloneError`; allowed by the spec, not seen in any current engine): the message is sent without the module (`src/worker/compat.ts`) and the next worker downloads (from the service worker or HTTP cache) and compiles its own copy. The capture still opens.
- **Out of memory:** each capture runs in its own worker, which is terminated on close, so a failed capture frees everything and the next one starts clean. At most 1 GiB of uncompressed capture data is streamed into Wiregasm; larger inputs are analyzed as a clearly marked prefix.

No current engine lacks these features, so the browser tests force each fallback by removing or wrapping the browser API in an init script.

## Running the browser tests

```bash
npx playwright install chromium firefox webkit     # once; CI adds --with-deps
npm run e2e                                        # all three
npm run e2e -- --project=webkit                    # one
```

On Linux, WebKit needs system libraries that `npx playwright install-deps` (sudo) installs. CI installs them with `--with-deps`.
