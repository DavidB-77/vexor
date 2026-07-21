<p align="center">
  <img src=".github/vexor-banner.svg" alt="" width="100%">
</p>

# Vexor

<p align="center">
  <a href="https://github.com/DavidB-77/vexor/releases"><img src="https://img.shields.io/badge/release-v0.9.1-38BDF8" alt="release v0.9.1"></a>
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
</p>

<!-- Badge policy: every badge above states something true and verifiable today.
     The release badge is static until the repo is public (shields.io cannot read
     private repos) — swap to img.shields.io/github/v/tag/DavidB-77/vexor at flip.
     Post-flip additions worth enrolling for (not fakeable, must be earned):
     OpenSSF Scorecard + Best Practices badge, codecov once coverage CI exists. -->

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

Vexor is an **independent implementation**, not a fork. Most of its
Agave-compatible behavior was achieved by using these Apache-2.0 projects as
**reference implementations and differential test oracles** — reimplementing
their behavior in Zig and verifying bit-for-bit against their output. Some
subsystems are instead declared **ports**, and every one is enumerated in
`NOTICE` and `PROVENANCE.md`:

- **[Agave](https://github.com/anza-xyz/agave)** (Anza) — primary behavioral reference; no Agave (Rust) code is compiled into Vexor.
- **[Firedancer](https://github.com/firedancer-io/firedancer)** (Jump Crypto) — leaf-crypto reference (**no C linked** — crypto is pure-Zig), plus declared whole-file Zig ports of several SVM-core and networking modules (executor, runtime, system/vote/nonce programs, rewards, hashes, scheduler, and more — see `NOTICE`).
- **[Sig](https://github.com/Syndica/sig)** (Syndica) — Zig-idiomatic structure reference during bring-up; the zk-ElGamal proof subsystem (`src/vex_bpf2/zksdk/`) is a Vexor re-implementation of Sig's, and the legacy sBPF interpreter has Sig lineage (see `NOTICE`).

Full credit and per-subsystem provenance:

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

- Voting: while operating, Vexor lands votes at **~98.7–99% of the
  theoretical 16-credits/slot Timely-Vote-Credit ceiling** — measured
  side-by-side against the epoch's top validators (16.00/slot) on the public
  RPC oracle. Full-epoch credit totals are lower whenever the testnet box is
  deliberately taken down for development windows; the shortfall is downtime,
  not missed or late votes.
- Block production: **~97%+ of leader slots produced and cluster-accepted
  over a full epoch** (best cluster-attested epoch: 152/156 via
  `getBlockProduction`), and **100% of leader slots while the node is up**
  (every skip on record falls in a deliberate maintenance window or a gated
  experiment). Blocks are currently empty; transaction-bearing block
  production is **under live testing** on testnet — restricted to a narrow
  transaction whitelist, with an automatic in-process fallback to empty-block
  production if a produce-parity check fails. Do not treat it as shipped or
  production-ready.
- Vote execution: Vexor's from-scratch vote program executes live vote
  instructions in **~1.9–2.0 µs**, **~4.4× faster** than the reference
  transplant it replaced (2,017 ns vs 8,909 ns over the same 990k-instruction
  replay) — and verified byte-identical against that reference over **20M+
  live instructions in a single session with zero mismatches**.
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

- **85.82% raw** (40,542/47,240) and **92.74% under the harness's
  consensus-compatibility mode** (`-c`, which normalizes error-code encoding).
- Several families pass **100% raw**: `system` (7,400/7,400), `compute-budget`
  (2,627/2,627), `precompile` (19,292/19,292), `zk_sdk` (3,124/3,124).
- The raw gap is dominated by **disclosed known gaps**: the BPF-loader-owned
  ELF-loading fixture families (~2,900 fixtures) are not yet implemented to
  byte-match, and most of the remaining `vote`/`vm-programs` raw failures are
  error-code/CU-encoding differences that the harness's consensus mode
  recovers.
- One genuine discrepancy surfaced by this run — a small set of `zk_sdk`
  fixtures where Vexor reported sysvar account data on certain failure paths
  that Agave does not — was root-caused to a missing effects-encoding rule,
  fixed at the shared execution seam, and re-validated: 3,124/3,124 with every
  other family byte-identical. Numbers here are reported honestly, including
  the unflattering ones while they lasted.

## Hardware

Vexor is developed and operated on a single reference machine: AMD EPYC 9374F
(32 Zen 4 cores), 512 GB RAM, separate NVMe drives for ledger and snapshots,
accounts held on a RAM-backed filesystem, and a Mellanox ConnectX-6 Dx NIC
(AF_XDP receive path). **Minimum requirements have not been characterized** —
treat the reference configuration as the only proven one. In particular, the
accounts store currently assumes a large-RAM machine, and the AF_XDP fast path
assumes a NIC with XDP zero-copy support (there is a standard-socket fallback).

## Acknowledgments

Vexor exists because other teams built great validator clients in the open.
We learned how a Solana validator really works — how consensus, replay,
gossip, and block production behave on a live cluster — in large part by
studying the open source of **[Agave](https://github.com/anza-xyz/agave)**
(Anza), **[Firedancer](https://github.com/firedancer-io/firedancer)** (Jump),
and **[Sig](https://github.com/Syndica/sig)** (Syndica), and by using their
implementations as reference oracles to verify Vexor's behavior
byte-for-byte. We're grateful for that openness; without it, building an
independent client would have been immeasurably harder.

Where Vexor directly ports or adapts specific code or algorithms, that
lineage is declared explicitly — with upstream commits and licenses — in
[`NOTICE`](./NOTICE) and [`PROVENANCE.md`](./PROVENANCE.md). Everything else
is an independent, from-scratch implementation written to match the
network's canonical *behavior*, not the reference code.

Vexor aims to stand alongside the ecosystem's other production clients, such
as **[Jito-Solana](https://github.com/jito-foundation/jito-solana)** —
another independent client serving the same network — with Vexor taking its
own path on efficiency, performance, and self-containment.

## License

Vexor is licensed under the [Apache License 2.0](./LICENSE).

---

Follow Vexor: [vexornode.xyz](https://vexornode.xyz) · [X @vexornode](https://x.com/vexornode)
