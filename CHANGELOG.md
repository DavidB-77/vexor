# Changelog

All notable changes to Vexor will be documented in this file.

Please follow the [guidance](#adding-to-this-changelog) at the bottom of this file when making changes.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Vexor is testnet-only, pre-production software; `1.0.0` is reserved for the
production-grade milestone. Entries here stay at the *user-facing* level
(validator, program, and RPC changes an operator would notice). Fine-grained
per-file behavior provenance against upstream Agave, Firedancer, and Sig lives
in [`PROVENANCE.md`](./PROVENANCE.md) rather than being duplicated here.

## Unreleased

## 0.9.2
### Validator
#### Changes
* The validator binary is now named `vexor` (previously `vex-fd`), including its help and startup output.
* Consensus: the non-advancing vote-retarget fallback now withholds instead of voting the local fork tip when fork choice has selected a different fork. Previously, during cluster fork events the fallback could repeatedly extend the local fork's tower lockouts against the canonical fork, in the worst case locking the validator out long enough to go delinquent. A known-answer test pins the fork topology from the live incident, and the fix is verified against a live cluster fork event.
* Snapshot boot: the snapshot-source deny-list is now configured via the VEX_SNAPSHOT_DENY_HOSTS environment variable (comma-separated hosts, all ports denied) instead of a hardcoded list. The built-in list ships empty; operators co-locating other validators should set it to keep boot state isolated.

### RPC
#### Changes
* The identity endpoint no longer falls back to a hardcoded address when no public IP is configured; it now returns the unspecified address (0.0.0.0), consistent with the rest of the configuration surface.

## 0.9.1-a
### Validator
#### Changes
* Consensus: added a first-root attestation latch that guards against a dead-fork root-divergence class (voting onto a rooted fork the cluster had skipped), together with vote-threshold shadow wiring.
* Consensus: widened vote-stake percentage math to `u128` to prevent an overflow at high aggregate stake; caught by the deploy-gate golden replay before shipping, with a regression known-answer test added.
* Networking: the QUIC/TPU server now emits the `original_destination_connection_id` transport parameter (RFC 9000 §18.2). Standards-strict clients (quinn/Agave) previously aborted the TPU handshake with a transport-parameter error; real-client transaction ingest now completes.
* Block production: synced the transaction-bearing block-production stack and a wave-formation singleton bypass from the deployed lineage.

### Programs
#### Changes
* The ZK ElGamal Proof program (`src/vex_bpf2/zksdk/`) is now a native, from-scratch Zig re-implementation of Sig's — Pedersen/ElGamal, Merlin transcripts, sigma proofs, Bulletproofs range proofs, and grouped-ciphertext validity. No verbatim Sig code remains in the build; results are byte-parity verified against the conformance corpus.

## 0.9.1
### Validator
#### Changes
* Networking: widened the data-shred length floor so the `parent_offset` field is always covered by a bounds check before it is read (untrusted-wire-parser hardening).

## 0.9.0
### Validator
#### Changes
* Initial public release: an independent, Zig-native Solana validator client, byte-for-byte behavior-compatible with Agave by design.
* Pure-Zig cryptography (ed25519, blake3, bn254/alt_bn128, poseidon, LtHash) — no Firedancer FFI dependency.
* Zig sBPF interpreter stack and CPI dispatch (legacy interpreter originally ported from Sig and since heavily reworked; the `vex_bpf2` rebuild is an independent spec-for-spec implementation — see `PROVENANCE.md`).
* Conflict-DAG parallel transaction executor.
* AF_XDP zero-copy networking (receive path).
* VexLedger: a Zig-native append-segment blockstore.

### Programs
#### Changes
* Vexor-authored vote program (`src/vex_svm/voteforge/`) shipped as the sole vote executor.

<a name="adding-to-this-changelog"></a>
## Adding to this changelog
When you make a user-facing change, add a bullet to the `## Unreleased` block at
the top, under the matching subsystem heading (`### Validator`, `### Programs`,
`### RPC`, `### CLI`), inside `#### Breaking`, `#### Deprecations`, or
`#### Changes`. On release, the `## Unreleased` block is renamed to the version
number. Keep entries at the operator level; per-file upstream provenance belongs
in `PROVENANCE.md`, not here.
