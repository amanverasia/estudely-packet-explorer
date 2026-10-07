# Local IP import memory

Local CSV/gzip imports decode UTF-8 directly into a stateful CSV tokenizer in the
short-lived import worker. Decoded chunks are never collected or joined into a
whole-file string. The tokenizer carries the unfinished row, including quoted
newlines, escaped quotes and CRLF across chunks. The final range index still
scales with row count and unique organization labels; this is not constant-memory
parsing. No record or organization-label length limit was added.

The original 100 MiB selected-file guard and 150 MiB **decompressed** byte guard
remain. Invalid UTF-8, incomplete gzip streams, malformed CSV, reversed ranges,
and inclusive overlaps fail before publication. The stream reader is cancelled
on failure and its lock is always released. The installed database is replaced
only after parsing and IndexedDB persistence succeed. Storage schema remains 1.
Progress updates contain decoded bytes and accepted rows and are throttled to
one per 250 ms, plus a final update.

## Numeric allocation budget

Let `N4` and `N6` be the accepted row counts and
`P = 16 × N4 + 40 × N6` bytes be the final numeric payload.

- Four typed columns per family grow in fixed blocks of 16,384 rows. Builder
  capacity is at most `P + 917,448` bytes (the unused tail of one block per
  family). There are no whole-column geometric growth copies or ordinary
  JavaScript number arrays holding the index.
- Finalization allocates the schema-1 typed arrays once. Its conservative live
  numeric budget is `2 × P + 917,448` bytes. Each family's blocks are released
  after packing; reclamation timing belongs to the browser.
- Already ordered rows need no permutation. Unordered rows allocate a
  `Uint32Array` permutation and sort it with in-place heapsort, with constant
  sorting scratch. The conservative budget becomes
  `2 × P + 917,448 + 4 × max(N4, N6)` bytes. Value IDs and ASNs move together with
  their ranges. Both paths check inclusive overlap after ordering.
- Transfer moves the final eight ArrayBuffers to the main thread without a
  numeric payload copy. IndexedDB serialization and subsequent reads can create
  copies; the benchmark below includes both operations.

These formulas bound the application's simultaneously live **numeric buffers**,
not total browser memory. Additional costs include decoded stream chunks,
tokenizer strings for the largest unfinished record, the unique-label array and
Map, transient IP parsing objects, garbage awaiting collection, the selected
compressed file, gzip internals, and browser/IndexedDB allocations. JavaScript
string slicing may retain backing chunk strings. The longest record and unique
label count can approach the decompressed limit; there is no universal total
browser ceiling for every accepted CSV. Do not interpret the fixture budget as
an enforceable cap for adversarial long labels or millions of unique labels.

## Reproducible browser measurement

Run with installed development dependencies on Linux:

```sh
node scripts/benchmark-local-ip-import.mjs \
  02d8d0adb86b00ac3d88a3ea12a930a66273fca7 \
  /tmp/local-ip-import-memory.json
```

The script generates approximately 30 MiB and 149 MiB ASN CSV inputs with 80%
IPv4 / 20% IPv6, 64 reused labels, and a longest label of 38 characters, then
compresses them. A third 30 MiB input reverses the address ordering to exercise
the permutation fallback. All gzip files satisfy the selected-file size guard.
Each case launches a fresh headless Chromium, uses the actual old/new import
worker, transfers the index to the main thread, writes it with the production
IndexedDB storage helper, and reads it back. The harness omits the rest of the
React application and capture-analysis engine, so it measures the whole **IP
import pipeline**, not the memory of an already loaded large capture.

A Linux `/proc` sampler collects RSS and PSS for the browser process and all its
children at a requested 20 ms interval, from before selection through IndexedDB
readback. PSS apportions shared pages; RSS counts them in each process. Neither
is a JavaScript-heap-only measurement. Sampling can miss short-lived peaks, and
scheduling, other browsers, shared pages and garbage collection affect the
results. Stop other browser tests when repeating. Times include decompression,
parsing, finalization, transfer, persistence and readback.

Baseline source is pinned to `02d8d0adb86b00ac3d88a3ea12a930a66273fca7`;
new source is the implementation in this change. Results were collected on
2026-10-07 using Chromium 153.0.8010.12 and Node.js 26.8.2 on Linux.

| Input / order | IPv4 / IPv6 rows | Numeric index | Before peak PSS / RSS | After peak PSS / RSS | Before / after time |
| --- | ---: | ---: | ---: | ---: | ---: |
| 30.0 MiB / ordered | 361,641 / 90,411 | 9.0 MiB | 380.3 / 647.9 MiB | 263.3 / 531.0 MiB | 1.61 / 1.37 s |
| 149.0 MiB / ordered | 1,762,319 / 440,580 | 43.7 MiB | 912.2 / 1180.2 MiB | 401.1 / 669.9 MiB | 7.82 / 5.79 s |
| 30.0 MiB / reversed | 351,278 / 87,820 | 8.7 MiB | 360.0 / 625.4 MiB | 262.7 / 531.4 MiB | 1.71 / 1.59 s |

For these generated inputs, plan for **256 MiB additional browser memory above
idle**: the largest measured increase was 226.5 MiB RSS / 221.8 MiB PSS for the
149 MiB import. Its idle browser used 443.5 MiB RSS / 179.3 MiB PSS. This is a
conservative planning budget for the measured fixture distribution, not a
universal import cap. Its live numeric-buffer bound is 88.3 MiB; the remaining
measured cost includes parsing, browser and IndexedDB allocations. The 30 MiB
unordered case additionally requires at most 1.34 MiB for the typed permutation.
The near-limit peak fell from 912.2 to 401.1 MiB PSS (about 56%) and from 1180.2
to 669.9 MiB RSS (about 43%).

Exact byte counts, compressed sizes, row counts, idle readings, sample counts,
and timings are in [IP_IMPORT_MEMORY.results.json](IP_IMPORT_MEMORY.results.json).
The generated files are synthetic ASN-format datasets, not a downloaded DB-IP
release. Country data, other label distributions, Firefox/WebKit memory, and
imports alongside large captures were not memory-benchmarked.

Validation includes 26 focused parser/decoder tests and browser coverage for
gzip, typed-array transfer, lookup, persistence/reload, and failed replacements.
The focused browser case passed Chromium and Firefox. WebKit could not launch
locally because `libavif.so.16` is absent; its browser behavior remains for CI
verification.
