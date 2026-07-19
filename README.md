# Vexor

An independent, Zig-native Solana validator — built from the ground up in Zig,
**byte-for-byte behavior-compatible with the Agave validator** by design.

Vexor runs its own pure-Zig cryptography (ed25519, blake3, bn254/alt_bn128,
poseidon, LtHash — no Firedancer FFI), a clean-room Zig sBPF interpreter, a
conflict-DAG parallel executor, AF_XDP zero-copy networking, and its own
VexLedger blockstore.

**Status: testnet-only, 0.9.x pre-production.** Mainnet is out of scope —
Vexor does not run there. `1.0.0` is reserved for the production-grade
milestone.

## Attribution

Vexor is an **original reimplementation**, not a fork. Its Agave-compatible
behavior was achieved by using these Apache-2.0 projects as **reference
implementations and differential test oracles** — reimplementing their behavior
in Zig and verifying bit-for-bit against their output:

- **[Agave](https://github.com/anza-xyz/agave)** (Anza) — primary behavioral reference.
- **[Firedancer](https://github.com/firedancer-io/firedancer)** (Jump Crypto) — leaf-crypto reference; **no longer linked** (crypto is now pure-Zig).
- **[Sig](https://github.com/Syndica/sig)** (Syndica) — Zig-idiomatic structure reference during bring-up.

Vexor links none of their code at runtime. Full credit and per-subsystem
provenance:

- **[`NOTICE`](./NOTICE)** — project-level attribution.
- **[`PROVENANCE.md`](./PROVENANCE.md)** — the fine-grained ledger mapping each
  Vexor file/function to the upstream source it reimplements (keyed by stable
  `@prov:` IDs, not line numbers).

"Agave", "Firedancer", "Sig", and "Solana" are trademarks of their respective owners.

## Building

1. Install **Zig 0.15.2** (pinned — other versions are not supported). See
   [ziglang.org/download](https://ziglang.org/download/).
2. Clone this repository.
3. Build:
   ```
   zig build -Dprod -Dpure_zig --release=safe
   ```
   `-Dprod` bundles the canonical production feature-flag set (each flag
   remains individually overridable, e.g. `-Dprod -Dfec_dedup=false`).
   `-Dpure_zig` is accepted for compatibility with existing recipes but is a
   no-op — crypto is pure-Zig unconditionally. A production deploy also pins
   `-Dcpu=znver4` for the target hardware; portable builds (including CI) use
   the default target or an explicit `-Dcpu=x86_64_v2` baseline — see
   `.github/workflows/build.yml`.
4. Debug builds are unsuitable for testnet use; always build `--release=safe`
   for anything that touches the live cluster.

## Testing

```
zig build test-migrated
```

Runs the full aggregate KAT (known-answer-test) suite across every migrated
subsystem. Individual subsystems also expose their own narrower `zig build
test-<name>` steps (see `build.zig`) for faster iteration on one area.

## Live-proven capabilities

Numbers below are cluster-attested, not benchmarks:

- Voting: **~98.7% of maximum vote credits** (measured vs. the theoretical
  16/slot ceiling).
- Block production: **~97%+ of leader slots produced and cluster-accepted**
  (empty blocks). Transaction-bearing block production is **under live
  testing** on testnet — currently restricted to a narrow transaction
  whitelist, with an automatic in-process fallback to empty-block production
  if a produce-parity check fails. Do not treat it as shipped or
  production-ready.
- Vote execution: Vexor's vote program executes vote instructions in
  **~1.9–2.0 µs**, **4.7× faster** than the reference transplant it replaced,
  measured over 990k+ live instructions with byte-identical results.
- Byte-fidelity methodology: every consensus-affecting change passes an
  **offline golden replay** (1992 canonical slots spanning an epoch
  boundary, bank hashes byte-identical to the live cluster's) before deploy.
- Networking: AF_XDP zero-copy RX on Mellanox ConnectX-6 Dx, io_uring
  snapshot writes, tile/core-pinned architecture.

## Conformance

Vexor is regularly measured against the ecosystem's own conformance tooling
([`firedancer-io/solana-conformance`](https://github.com/firedancer-io/solana-conformance)
with the [`firedancer-io/test-vectors`](https://github.com/firedancer-io/test-vectors)
instruction-fixture corpus), executed live against a **version-matched** Agave
reference — not against baked-in expected outputs. Latest full-corpus run
(47,240 fixtures):

- **85.80% raw** (40,533/47,240) and **92.73% under the harness's
  consensus-compatibility mode** (`-c`, which normalizes error-code encoding).
- Several families pass **100% raw**: `system` (7,400/7,400), `compute-budget`
  (2,627/2,627), `precompile` (19,292/19,292).
- The raw gap is dominated by **disclosed known gaps**: the BPF-loader-owned
  ELF-loading fixture families (~2,900 fixtures) are not yet implemented to
  byte-match, and most of the remaining `vote`/`vm-programs` raw failures are
  error-code/CU-encoding differences that the harness's consensus mode
  recovers.
- One genuine discrepancy surfaced by this run — a small set of `zk_sdk`
  fixtures where Vexor reports sysvar account data on certain failure paths
  that Agave does not — is acknowledged and being fixed. Numbers here are
  reported honestly, including the unflattering ones.

## Acknowledgments

Vexor exists because other teams built great validator clients in the open.
Beyond the reference-oracle relationships credited in
[`NOTICE`](./NOTICE)/[`PROVENANCE.md`](./PROVENANCE.md) (Agave, Firedancer,
Sig), we're grateful to the wider Solana client ecosystem — including
**[Jito-Solana](https://github.com/jito-foundation/jito-solana)** (Jito Labs)
and **[Mithril](https://github.com/Overclock-Validator/mithril)** (Overclock)
— whose public code, tooling, and client-diversity work shaped how Vexor was
built and tested.

## License

Vexor is licensed under the [Apache License 2.0](./LICENSE).
