# Fuzz harnesses

Five libFuzzer-ABI harnesses over Vexor's untrusted-input wire-format parsers —
the byte-decode layer that runs on data received from peers (shreds, gossip
packets, transactions) before any consensus or execution logic sees it. This
is the surface class implicated in the slot-422359406 truncated-block
incident: a malformed or adversarial buffer reaching one of these parsers
must fail cleanly (a returned error), never panic, overflow, or read out of
bounds.

Each `fuzz_*.zig` file is a plain module — no `main`, no driver code — that
exports the standard OSS-Fuzz/libFuzzer C ABI entry point:

```zig
pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int
```

and nothing else beyond a thin `fuzzOne` wrapper calling the real production
parser. That split (pure harness vs. driver) is deliberate: a real
OSS-Fuzz/libFuzzer toolchain should be able to build these files unchanged.

## Targets

| File | Target symbol | Surface |
|---|---|---|
| `fuzz_shred_parse.zig` | `vex_network/shred_parse.zig: parseShred` + `Shred.*` accessors + `merkleRoot`/`merkleRoot32`/`chainedMerkleRoot` | Shred wire-format decode: common header, variant byte, Merkle-proof reconstruction — the parsing layer a received shred goes through before FEC/replay logic runs. |
| `fuzz_entry_batch.zig` | `vex_svm/entry.zig: readEntryCount/readEntryHeader` + `vex_svm/tx_ingest.zig: parse` (self-contained instruction-list skip reimplemented in the harness) | The deshredded entry-batch buffer walk `replayEntries` performs after FEC reassembly — same raw-buffer surface as the 422359406 incident. |
| `fuzz_gossip_protocol.zig` | `vex_network/crds.zig: Protocol.deserialize` (+ `CrdsValue.verify` on the `PullRequest` path) | Gossip wire decode: `Protocol` tag dispatch into `PullRequest`/`PullResponse`/`PushMessage`/`PruneMessage`/`Ping`/`Pong`, and — for `PullRequest` — the full `CrdsValue`/`CrdsData` union (`ContactInfo`, `LegacyContactInfo`, `Vote`, `EpochSlots`, `DuplicateShred`, ...). |
| `fuzz_tx_ingest.zig` | `vex_svm/tx_ingest.zig: parse` + `verifySignatures` | Transaction wire decode + sanitize: the "accept a tx off the wire" stage shared by RPC `sendTransaction`/`simulateTransaction` and TPU ingest. |
| `fuzz_compute_budget.zig` | `vex_svm/compute_budget.zig: parsePriorityFeeFromWire` / `parseComputeUnitPriceFromWire` / `parsePrecompileSigCountFromWire` | Compute-budget instruction parse, driven with the same `keys_offset`/`instructions_offset` `tx_ingest.parse` computes for the identical buffer — the real integrated call shape used on the fee path. |

A sixth candidate (bincode-based account/sysvar decode) was considered and
dropped: the only public byte-buffer entry points in that area either require
a filesystem path (`snapshot_manifest.parseManifest` opens
`<dir>/snapshots/<slot>/<slot>`) or a live `AppendVec` (`readRecord` needs a
constructed/mmap'd `self`) — both violate the "pure in-memory decode, no
filesystem state" constraint every other harness here holds to.

None of the five require network access, filesystem state, or a running
validator — each is a pure `[]const u8 -> parse result | error` call.

## Seed corpus

`fuzz/seeds/<target>/*.bin` — small, structurally-valid inputs generated from
the documented wire formats (not captured from the live cluster; this repo
doesn't commit runtime captures). Each parses successfully as a starting
point for mutation: a zeroed Merkle data-shred header, a minimal
single-signer legacy transaction (with and without a `SetComputeUnitLimit`
ComputeBudget instruction), a two-entry batch (one tick-only, one carrying
that transaction), and two gossip `Protocol` messages (`PingMessage`, and a
`PullRequest` wrapping a `LegacyContactInfo` `CrdsValue`).

## Building and running locally

The Zig 0.15.2 toolchain on this box cannot produce a binary a stock
libFuzzer runtime will actually drive in coverage-guided mode — see
"OSS-Fuzz readiness" below. `fuzz/runner.zig` is a small local substitute:
a fork-per-input mutation driver linked directly against the harness's
`fuzzOne`, so the exact same parsing logic gets exercised today without a
libFuzzer runtime.

```sh
zig build fuzz-shred-parse       # or fuzz-entry-batch / fuzz-gossip-protocol /
zig build fuzz-tx-ingest         # fuzz-compute-budget
zig build fuzz                   # build all five

./zig-out/bin/fuzz-shred-parse -max_total_time=180 -rss_limit_mb=2048 fuzz/seeds/shred_parse
```

`-max_total_time=<seconds>` and `-rss_limit_mb=<mb>` are recognized (the
latter enforced via `setrlimit(RLIMIT_AS, ...)` in the forked child, plus an
unconditional 5s `RLIMIT_CPU` per-input hang guard); any other non-flag
argument is treated as a seed-corpus directory. A crash — the child killed by
a signal (Zig `ReleaseSafe` safety panics lower to `@trap()` via
`std.debug.simple_panic`, delivered as `SIGILL`/`SIGTRAP`, same as a real
memory-safety fault) — is saved to `fuzz/crashes/<harness>-sig<N>-<i>-<hash>`
and logged to stdout.

Each harness's module also compiles under `b.addTest` (`zig build
test-fuzz-shred-parse`, etc.) as a plain smoke test, and carries a
`std.testing.fuzz`-based `test` block so `zig build test --fuzz` (Zig's own
in-process coverage-guided fuzzer/web-UI engine) can drive it too — a free
second local option, not the vehicle the bounded run above uses.

## Findings

A ~3-minute bounded run of `fuzz-shred-parse` (`-max_total_time=180
-rss_limit_mb=2048`, single-threaded) found a real out-of-bounds read within
seconds: `ShredCommonHeader.fromBytes` (`src/vex_network/shred_parse.zig`)
checked `data.len < 83` as its only length floor, but unconditionally reads
`data[83..85]` for `parent_offset` whenever the variant byte marks a *data*
shred (a *code* shred's fields do end at byte 83 — the check was written for
that case and never widened for data shreds). A data-shred-variant buffer of
exactly 83 or 84 bytes passes the floor check, then panics on the
out-of-bounds slice instead of returning a parse error. Confirmed
independently by replaying the saved reproducers (`fuzz/crashes/shred_parse-
crash-83b.bin`, `-84b.bin`) through a standalone driver outside the fuzzer.
Fixed by widening the floor to `data.len < 85` when `variant.is_data` (see
the fix in `ShredCommonHeader.fromBytes`); a post-fix 180s/~3M-execution
re-run of the same harness found nothing further.

Note: the fuzzer's own crash log attributes some of these same crashes to
`bmtree.zig:174` in its auto-printed backtrace (the process's installed
segfault handler symbolicating the trapping `SIGILL`/`SIGABRT`) — that
attribution is misleading, not a second bug. Replaying every saved
reproducer through a plain, non-forked standalone driver (no signal-handler
backtrace involved) showed all of them hitting the same single
`shred_parse.zig` line. Trust direct reproduction over an
optimized-build signal-handler backtrace when the two disagree.

The other four harnesses (`entry-batch`, `gossip-protocol`, `tx-ingest`,
`compute-budget`) each ran a clean 180s bounded session with no crashes:

| Harness | Execs | Execs/s | Crashes |
|---|---|---|---|
| shred-parse (post-fix) | 2,977,118 | 16,539 | 0 |
| entry-batch | 2,704,534 | 15,025 | 0 |
| gossip-protocol | 2,191,609 | 12,175 | 0 |
| tx-ingest | 2,294,097 | 12,744 | 0 |
| compute-budget | 2,664,213 | 14,801 | 0 |

~12.8M total executions across the five harnesses in this pass. Absence of
further crashes here is not a correctness proof — the mutator is a plain
byte-level operator set with no coverage-guided corpus promotion (see
"Building and running locally" above) — but it is a real signal for a first
pass, and the one bug it did find was a genuine memory-safety issue in a
"REAL"-untrusted-input surface, not a fuzz-harness artifact.

## OSS-Fuzz readiness — known gap

**These harnesses are not turnkey OSS-Fuzz-submittable yet.** The concrete
gap, found empirically on this box:

- `zig build-obj -fsanitize-coverage-trace-pc-guard` compiles and emits real
  `__sanitizer_cov_trace_pc_guard[_init]` calls — Zig 0.15.2 does expose
  *bare* guard-only SanitizerCoverage instrumentation.
- Linking that object against a system libFuzzer runtime (clang-14's
  `libclang_rt.fuzzer`) fails at *runtime*: `-fsanitize-coverage=trace-pc-guard
  is no longer supported by libFuzzer. Please either migrate to a compiler
  that supports -fsanitize=fuzzer or use an older version of libFuzzer`.
  Modern libFuzzer requires the fuller `-fsanitize=fuzzer` instrumentation
  (8-bit counters + PC table, not just guards), and Zig 0.15.2's CLI exposes
  no flag for that — `-ffuzz` instruments for Zig's own fuzzer engine
  (cmp/switch tracing, no `trace_pc_guard`), and there is no `-mllvm`
  passthrough to add the missing SanitizerCoverage modes by hand.

An OSS-Fuzz `build.sh` for this project would need one of:

1. A newer Zig toolchain that exposes full `-fsanitize=fuzzer` codegen
   (tracked upstream in Zig's own compiler; not available as of 0.15.2), or
2. A build step that emits Zig's LLVM IR/bitcode (`-femit-llvm-bc`) and runs
   it through a matching-version `opt`/`clang` SanitizerCoverage pass before
   linking against libFuzzer — nontrivial to keep in sync with whatever LLVM
   version Zig's codegen backend targets, and not attempted here.

The rest of the standard OSS-Fuzz scaffolding (`project.yaml`, `Dockerfile`,
`build.sh` calling into `zig build fuzz-*` and copying the resulting
binaries + `fuzz/seeds/*` as the seed corpus into `$OUT`) is otherwise
straightforward once (1) or (2) lands — deliberately not added here, since
actually submitting to OSS-Fuzz is operator-gated and happens after the repo
goes public.
