<p align="center">
  <img src=".github/vexor-banner.svg" alt="" width="100%">
</p>

# Vexor

<p align="center">
  <a href="https://github.com/DavidB-77/vexor/releases"><img src="https://img.shields.io/github/v/tag/DavidB-77/vexor?label=release&color=38BDF8" alt="latest release tag"></a>
  <a href="https://ziglang.org/"><img src="https://img.shields.io/badge/zig-0.15.2-F7A41D" alt="zig 0.15.2"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="license Apache-2.0"></a>
  <a href="https://docs.vexornode.xyz/reliability/conformance/"><img src="https://img.shields.io/badge/conformance-85.82%25%20raw%20%C2%B7%2092.74%25%20consensus-brightgreen" alt="conformance: official harness, version-matched"></a>
  <br>
  <a href="https://www.validators.app/validators/3J2jADiEoKMaooCQbkyr9aLnjAb5ApDWfVvKgzyK2fbP?network=testnet"><img src="https://img.shields.io/badge/testnet-live%20%C2%B7%20voting-EC4899" alt="live and voting on Solana testnet — independently tracked"></a>
  <a href="https://docs.vexornode.xyz/design/why-byte-faithful/"><img src="https://img.shields.io/badge/deploy%20gate-1%2C992%2F1%2C992%20slots%20byte--identical-brightgreen" alt="every deploy replays 1,992 canonical slots byte-identical"></a>
  <a href="./SECURITY.md"><img src="https://img.shields.io/badge/security-reporting%20policy-8B5CF6" alt="security reporting policy"></a>
  <a href="https://x.com/vexornode"><img src="https://img.shields.io/badge/@vexornode-000000?logo=x&logoColor=white" alt="Vexor Node on X"></a>
  <a href="https://vexornode.xyz"><img src="https://img.shields.io/badge/vexornode.xyz-website-3EC5FF" alt="vexornode.xyz"></a>
  <br>
  <a href="https://github.com/DavidB-77/vexor/actions/workflows/build.yml"><img src="https://github.com/DavidB-77/vexor/actions/workflows/build.yml/badge.svg?branch=main" alt="build"></a>
  <a href="https://github.com/DavidB-77/vexor/actions/workflows/test.yml"><img src="https://github.com/DavidB-77/vexor/actions/workflows/test.yml/badge.svg?branch=main" alt="test"></a>
  <a href="https://github.com/DavidB-77/vexor/actions/workflows/lint.yml"><img src="https://github.com/DavidB-77/vexor/actions/workflows/lint.yml/badge.svg?branch=main" alt="lint"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/DavidB-77/vexor"><img src="https://api.scorecard.dev/projects/github.com/DavidB-77/vexor/badge" alt="OpenSSF Scorecard"></a>
</p>

<!-- Badge policy: every badge above states something true and verifiable today.
     Scorecard is a real, unfakeable, ecosystem-standard signal (branch
     protection, SAST, pinned deps, token perms, etc.) computed by
     scorecard.dev, not asserted by this README.
     Post-flip additions worth enrolling for next: OpenSSF Best Practices
     badge (bestpractices.dev self-assessment), codecov once coverage CI
     exists. -->

An independent, Zig-native Solana validator — **byte-for-byte
behavior-compatible with the Agave validator** by design. The majority of the
tree is original Vexor work; every ported subsystem is declared in
[`NOTICE`](./NOTICE) and [`PROVENANCE.md`](./PROVENANCE.md).

Vexor runs its own pure-Zig cryptography (ed25519, blake3, bn254/alt_bn128,
poseidon, LtHash — no Firedancer FFI), a Zig sBPF interpreter stack (the
legacy interpreter was originally ported from Sig and since heavily reworked;
the vex_bpf2 rebuild is an independent spec-for-spec implementation — see
`PROVENANCE.md`), a conflict-DAG parallel executor, AF_XDP zero-copy
networking, and its own VexLedger blockstore.

**Status: testnet-only, 0.9.x pre-production.** Mainnet is out of scope —
Vexor does not run there. `1.0.0` is reserved for the production-grade
milestone.

## Attribution

Vexor is an **independent implementation, not a fork**, reimplemented from
scratch using these Apache-2.0 projects as **reference oracles** (not
compiled-in code) — except where a subsystem is declared a **port** in
`NOTICE`:

- **[Agave](https://github.com/anza-xyz/agave)** (Anza) — primary reference; no Agave code compiled in.
- **[Firedancer](https://github.com/firedancer-io/firedancer)** (Jump) — leaf-crypto reference (no C linked); several SVM/networking modules are declared ports.
- **[Sig](https://github.com/Syndica/sig)** (Syndica) — structure reference; zk-ElGamal and the legacy sBPF interpreter carry declared Sig lineage.

Full provenance: [`NOTICE`](./NOTICE) · [`PROVENANCE.md`](./PROVENANCE.md) ·
docs site [Attribution & License](https://docs.vexornode.xyz/project/attribution-and-license/).

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

Cluster-attested, not benchmarks — full detail, methodology, and citations:
[What We've Accomplished](https://docs.vexornode.xyz/status/accomplished/).

- **Voting**: ~98.7–99% of the 16-credits/slot Timely-Vote-Credit ceiling
  while operating, on par with the epoch's top validators.
- **Block production**: ~97%+ of leader slots/full epoch, 100% while up.
  Blocks are currently empty; transaction-bearing production is under live
  testing, not shipped.
- **Vote execution**: ~1.9–2.0 µs/instruction, ~4.4× faster than the
  predecessor it replaced, byte-identical over 20M+ live instructions with
  zero mismatches.
- **Byte-fidelity gate**: every consensus-affecting change passes an offline
  golden replay (1,992 canonical slots) bank-hash-identical to the cluster
  before deploy.
- **Networking**: AF_XDP zero-copy RX, io_uring snapshot writes, tile/core-
  pinned architecture.

## Conformance

Measured live against the ecosystem's own
[`firedancer-io/solana-conformance`](https://github.com/firedancer-io/solana-conformance)
harness and a **version-matched** Agave reference — not baked-in expected
outputs. Full methodology, per-family breakdown, and disclosed known gaps:
[Conformance](https://docs.vexornode.xyz/reliability/conformance/).

- **Instruction corpus** (47,240 fixtures): **85.82% raw**, **92.74%** under
  the harness's consensus-compatibility mode. `system`, `compute-budget`,
  `precompile`, and `zk_sdk` pass 100% raw; the gap is dominated by disclosed
  known gaps (BPF-loader ELF-loading not yet byte-matched) plus error-code/CU
  encoding differences the consensus mode recovers.
- **Syscall/crypto corpus** (7,571 fixtures): **99.62% non-known-gap**.

## Hardware

Vexor is developed and operated on a single reference machine: AMD EPYC 9374F
(32 Zen 4 cores), 512 GB RAM, separate NVMe drives for ledger and snapshots,
accounts held on a RAM-backed filesystem, and a Mellanox ConnectX-6 Dx NIC
(AF_XDP receive path). **Minimum requirements have not been characterized** —
treat the reference configuration as the only proven one. In particular, the
accounts store currently assumes a large-RAM machine, and the AF_XDP fast path
assumes a NIC with XDP zero-copy support (there is a standard-socket fallback).

## Acknowledgments

Vexor exists because Agave (Anza), Firedancer (Jump), and Sig (Syndica) were
built in the open — studying their source is how we learned how a live
Solana validator really works, and their implementations served as
reference oracles for byte-for-byte verification. Declared ports/adaptations
are cited in [`NOTICE`](./NOTICE) and [`PROVENANCE.md`](./PROVENANCE.md);
everything else is independent, from-scratch work.

Vexor aims to stand alongside the ecosystem's other independent clients,
such as **[Jito-Solana](https://github.com/jito-foundation/jito-solana)**,
each taking its own path.

## License

Vexor is licensed under the [Apache License 2.0](./LICENSE).

---

Follow Vexor: [vexornode.xyz](https://vexornode.xyz) · [X @vexornode](https://x.com/vexornode)
