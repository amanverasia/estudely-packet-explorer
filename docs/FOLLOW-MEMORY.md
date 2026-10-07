# Follow Stream memory limits

The preview retains at most 512 KiB and 5,000 segment descriptors. Save raw
retains at most 64 MiB and 100,000 segment descriptors, across both directions
before applying the direction selection. A save reports when selected bytes
were omitted, or when the combined stream reached a save limit even though all
selected-direction bytes were saved. Stream byte and segment totals still
describe the complete follower output, including data outside these limits.

These limits bound the retained decoded payload and application segment
metadata. **They do not bound Wiregasm's internal follower allocation or the
size of an individual base64 string copied through Embind. Issue #28 remains
partially implemented until an upstream bounded follower exists.**

## What the local collector bounds

`src/engine/follow-payloads.ts` first visits the vector for exact direction
totals and a prefix plan containing only packet numbers, direction flags,
offsets and lengths. It retains no array of full base64 records. A second pass
fetches only retained nonempty records and decodes the needed prefix directly
into one exact-sized output buffer. Base64 chunks contain complete quartets;
each decode uses at most 65,536 encoded characters and 49,152 binary-string
characters. A cap inside a record never decodes its entire oversized contents.
The vector is deleted in `finally`, including getter, allocation and decode
failure paths. Zero caps decode no bytes. Caps must be nonnegative safe
integers; Infinity is an explicit opt-out supported for internal callers and
tests. The UI uses finite byte and segment caps for both preview and save.

Save raw reuses the returned buffer for both directions. A single-direction
save allocates one buffer containing only selected retained segments; it no
longer builds display runs and then copies their contents a second time. Blob
creation and browser downloads may involve additional browser-owned copies.
Preview rendering and search likewise build data derived from the bounded
preview. The limits above describe application payload retention, not a
universal browser heap ceiling.

## Remaining upstream dependency

The installed `@goodtools/wiregasm` 1.9.1 declarations expose only
`follow(follow, filter)`, with full base64 strings in a payload vector. There
is no metadata-only record accessor, cursor or byte/segment limit argument.
In the pinned [Wiregasm follower implementation](https://github.com/good-tools/wiregasm/blob/v1.9.1/lib/wiregasm/lib.cpp#L596),
the registered Wireshark tap collects a full stream during `wg_retap`, then
base64-encodes every follower record into the returned vector. Consequently,
the first totals pass still copies each complete record string transiently.
Upstream numeric `sbytes`/`cbytes` cannot safely replace this scan: their
direction labels disagree with payload direction flags in existing fixtures.

Full completion requires numeric totals separate from capped payload,
metadata-only access, a maximum serialized record size, and a proven limit in
the follower collection path itself. A limit applied only after full retap
would leave its raw follower list proportional to stream size. The solution
must preserve Wireshark TCP reassembly, packet numbers and direction order;
filtering arbitrary packet prefixes or concatenating raw TCP packet payloads
does not establish equivalent behavior.

## Reproducible measurement

Run `node --expose-gc scripts/measure-follow-memory.mjs` with installed project
dependencies. The script generates TCP captures locally, loads the pinned
real Wiregasm runtime, and runs a baseline collector and the new collector in
fresh processes for 1, 8 and 32 MiB streams, with fixed 512 KiB preview and
64 MiB save caps. Captures stay in the in-memory filesystem. Individual runs
are supported, for example
`node --expose-gc scripts/measure-follow-memory.mjs improved 32 524288`.

The script samples Node JS heap and ArrayBuffer usage after follower return,
vector getters, base64 decodes, and output construction. This is a sampled
high-water increase above a post-load baseline, **not a guaranteed instantaneous
peak**. Garbage collection and runtime setup affect the samples. WASM figures
are reserved linear-memory capacity before and after follow, not live C++
allocation totals; capacity cannot shrink after freed allocations. No browser
process, download Blob or render/search memory is included.

Measured on 2026-10-07 with Node 26.8.2 and Wiregasm 1.9.1 (MiB):

| Stream | Operation | Sampled JS heap: baseline → new | Sampled JS ArrayBuffers: baseline → new | WASM capacity before → after, both collectors |
| --- | --- | --- | --- | --- |
| 1 | Preview | 6.16 → 8.16 | 1.00 → 0.50 | 128 → 128 |
| 1 | Save | 6.81 → 8.15 | 2.00 → 1.00 | 128 → 128 |
| 8 | Preview | 20.60 → 16.22 | 1.00 → 0.50 | 128 → 128 |
| 8 | Save | 21.45 → 16.67 | 16.00 → 8.00 | 128 → 128 |
| 32 | Preview | 60.76 → 32.32 | 1.00 → 0.50 | 128 → 221.25 |
| 32 | Save | 75.82 → 18.09 | 64.00 → 32.00 | 128 → 221.25 |

The fixed preview output does not prevent WASM growth at 32 MiB. Small-stream
JS heap samples also increased despite fewer retained payload copies. These
results support reduced decoded copying and removal of full-record retention;
they do not support a hard bound on total JS/WASM memory. Save captures in this
sweep are below the 64 MiB cap; correctness of an intra-record cutoff and
segment cutoffs is covered separately by focused tests.

## Checks

`tests/follow-payloads.test.ts` covers exact and zero caps, cap validation,
oversized single records with bounded decode input, base64 padding, empty and
many tiny records, malformed base64, cleanup after getters/decoders fail,
and repeated preview/save collection. `tests/engine.test.ts` verifies actual
TCP/UDP direction totals, byte/segment cutoffs, missing streams and repeated
zero/preview/save requests. `tests/follow.test.ts` checks selected-direction
saves when the shared cap partially or wholly excludes that direction.

The three focused test files passed (84 tests), and TypeScript compilation
passed. The integrated project test run passed 137 tests, and the Chromium and
Firefox browser suite passed 86 tests, including existing save/truncation checks.
