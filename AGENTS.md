# Agent guide

## Project shape

- This is a browser-only packet capture explorer. Captures are decoded locally with Wiregasm/Wireshark in a Web Worker; preserve that privacy boundary.
- The Lua postdissector in `src/engine/extractor.lua` emits compact tab-separated records. `src/engine/records.ts` parses them, `src/engine/analyze.ts` builds the shared model, and React views under `src/app/` render it.
- Update `docs/ARCHITECTURE.md`, `docs/FEATURES.md`, or `README.md` when observable behavior or supported features change.
- Synthetic capture fixtures are generated in `fixtures/generate.py`; engine and browser tests are under `tests/`.

## Working conventions

- Inspect `git status` and the current diff before editing. Preserve existing user changes; do not reset or discard unrelated work.
- Keep capture data local. Do not add upload, analytics, or network lookup behavior without explicit direction.
- Keep record tags unique between Lua output and `parseRecords`. In particular, `Q` is already the QUIC record tag; HTTP/2 currently uses `J`.
- For Wireshark fields, verify field names against the bundled Wireshark version or its official reference. Reassembled field offsets must only be compared within the same `FieldInfo.source` when that source is available.
- Close GitHub issues after their fixes are merged to the default branch and their acceptance criteria and required evidence are complete. Do not close unresolved issues or post issue comments unless asked.

## Useful commands

- `npm test` runs the engine tests against synthetic captures.
- `npm run typecheck` runs the TypeScript compiler.
- `npm run e2e` builds the app and runs Playwright browser tests (Playwright browsers must be installed first).
- `npm run build` creates the production build; it also runs TypeScript compilation.
- `npm run fixtures` regenerates captures and requires Python with Scapy and cryptography.

Choose checks that match the change, and report clearly when a check was not run or could not run.
