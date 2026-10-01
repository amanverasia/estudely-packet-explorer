# Estudely Packet Explorer

Open a `.pcap` or `.pcapng` file and explore it through protocol dashboards: **Overview, DNS, HTTP, TLS, Hosts, Connections and a Network graph**, plus a Wireshark-style packet list and per-packet decode drawer.

**Your capture is processed locally in your browser.** Decoding runs in Wireshark 4.4.5 compiled to WebAssembly ([Wiregasm](https://github.com/good-tools/wiregasm)) inside a Web Worker. There is no backend, no uploads, no analytics and no online lookups. The site is plain static files.

## Quick start

```bash
npm install
npm run dev        # http://localhost:5173
npm test           # engine tests: real Wiregasm against fixtures/
npm run e2e        # build, serve from a subdirectory, run browser tests (Playwright)
npm run build      # static site in dist/
npm run preview    # serve dist/ locally
```

Requires Node 20+ (developed on Node 26). Browser tests need Chromium once: `npx playwright install chromium`. `npm run prepare-wasm` (run automatically by dev/build/test) copies the engine from `node_modules/@goodtools/wiregasm` into `public/wiregasm/`.

To regenerate the test captures: `python3 fixtures/generate.py` (needs `scapy` and `cryptography`).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the engine, worker and shared model fit together, and the Wiregasm evaluation.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — static hosting, subdirectories, headers, caching.
- [docs/FEATURES.md](docs/FEATURES.md) — what each view shows, supported formats, known limitations.
- [docs/LICENSES.md](docs/LICENSES.md) — dependency attribution and GPL obligations for the distributed WASM.
- [docs/COMPLETION-REPORT.md](docs/COMPLETION-REPORT.md) — what works, what was tested, what is incomplete.

## Licence

Copyright (C) 2026 Estudely and contributors.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version. It is distributed WITHOUT ANY WARRANTY; see [LICENSE](LICENSE).

The bundled Wireshark/Wiregasm engine is GPL-2.0. Its corresponding source, including every library compiled into it, is in the [`engine-source-1.9.1` release](https://github.com/amanverasia/estudely-packet-explorer/releases/tag/engine-source-1.9.1). See [docs/LICENSES.md](docs/LICENSES.md).
