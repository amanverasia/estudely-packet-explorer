# Issue #57: foreground Hosts records

Validated on 7 October 2026 with the synthetic `fixtures/ip-data.pcap` fixture, Chromium, and the production subdirectory build. The original source rendered an expanded import panel, two full explanatory notes, and empty country/ASN columns before the host records. The new default keeps import and evidence explanations in keyboard-accessible native disclosures. Country/ASN columns appear individually when their database is installed, or together when explicitly requested. Hidden columns remain available to search, sorting, and CSV export, preserving the CSV schema.

## Evidence and acceptance criteria

- **No database:** all five fixture hosts remain the main content beneath the compact “Add country/ASN data” and evidence disclosures. No empty country/ASN columns. The existing capture toolbar still occupies space above the Hosts view on mobile; the table itself supports horizontal scrolling.
- **Installed/loading/error/clear:** the collapsed summary reports saved-data loading, import progress, or installed kinds. Expanded statuses include release and range count, with named Remove controls. Import progress and errors also remain outside the disclosure. Gzip ASN import, IndexedDB typed-range persistence, three invalid replacements retaining installed data, reload, removal, and a second reload all pass automated checks. Import/remove controls remain disabled through database persistence.
- **Local privacy:** country/ASN import uses the existing local Worker and IndexedDB range indexes. The viewport tests assert that capture parsing, import, and navigation make no external HTTP requests. Download links require an explicit user action.
- **Accessible caveats:** the expanded database disclosure retains DB-IP attribution and CC BY 4.0 licensing and approximate-location/ownership caveats. The evidence disclosure retains registry snapshot dates, matching exclusions, and name/vendor/port inference limitations. Individual host evidence and source-packet buttons are unchanged.
- **Investigation flows:** automated tests select a host, apply the shared host filter, navigate to Connections, and check filter persistence at desktop/tablet/mobile widths. Address-family controls, host metadata, and packet-provenance handlers are unchanged.
- **Keyboard/layout:** native disclosure Enter handling, optional-column checkbox, imports and clears pass at 1440×900, 960×900, and 390×844. CSV retains country/ASN headers even when hidden.

## Screenshots

These are final-state screenshots; no image is claimed as a baseline before image.

| Viewport | No database | Country data imported, disclosure expanded |
| --- | --- | --- |
| 1440×900 | [Hosts without optional data](screenshots/issue-57/no-data-1440.png) | [Country imported](screenshots/issue-57/imported-1440.png) |
| 960×900 | [Hosts without optional data](screenshots/issue-57/no-data-960.png) | [Country imported](screenshots/issue-57/imported-960.png) |
| 390×844 | [Hosts without optional data](screenshots/issue-57/no-data-390.png) | [Country imported](screenshots/issue-57/imported-390.png) |

## Reproduce

1. Build with `npm run build` and serve with `node scripts/serve-subdir.mjs`.
2. Open the subdirectory app in a fresh browser profile; import `fixtures/ip-data.pcap` and select Hosts.
3. Open “Add country/ASN data” with Enter. Import a local file named `country-2026-10.csv` containing `8.8.8.0,8.8.8.255,US`; verify the country column and local ready status.
4. Remove Country data, verify the column disappears, and reload to verify removal persists.
5. Run `npx playwright test e2e/local-ip-import.spec.ts --project=chromium --workers=2` for the gzip/error/persistence/filter/keyboard/layout and CSV checks.

The focused Chromium run passed all four tests. `npm run typecheck` and `git diff --check` passed. The parent task coordinates the engine suite, production build, broader browser checks, and CI.
