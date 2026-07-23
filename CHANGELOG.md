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

## 0.9.3-e
### Validator
#### Changes
* Release: tagged release binaries are now built and attached to the GitHub Release as downloadable assets, alongside a keyless cosign signature, a Fulcio-issued signing certificate, a Rekor transparency-log entry, and a sha256 checksum file. No signing key is stored in the repo; trust is rooted in the release workflow's own OIDC identity, so anyone downloading a release binary can independently verify it was built and signed by this repository's release pipeline rather than trusting an unsigned download. The attached binary is a portable `x86_64_v2` baseline for broad compatibility, not the CPU-tuned build used in the reference deployment; operators who want a tuned build should build from source. No change to validator behavior.

## 0.9.3-d
### Validator
#### Fixed
* Consensus: the `--wait-for-supermajority` restart gate's observed-stake calculation now excludes gossip peers on a different shred version than expected, matching Agave's shred-version-pure stake accounting. Previously the gate summed stake for every staked node identity in gossip regardless of shred version; during a coordinated cluster restart (where the shred version changes) this counted nodes still on the pre-restart chain toward the new chain's supermajority, over-reporting observed stake and risking the gate resuming before real supermajority was reached. Validated on a live testnet coordinated restart against an Agave reference node and independent RPC ground truth: observed stake went from a ~21-point overcount to within ~2 points of both references. No-op when `--expected-shred-version` is unset, so non-restart boots are unchanged.
* The version-report string (gossip client-id advertisement and boot banner) now reads `0.9.3-d`, matching this release.

## 0.9.3-c
### Validator
#### Fixed
* Consensus/replay: fixed a livelock between the fast-wake and far-ahead deferral gates that could recur when the last-frozen slot moves non-monotonically (out-of-order catchup churn). The far-ahead gate is now keyed on a monotonic high-water mark of the highest slot ever frozen instead of the volatile last-frozen slot, so it can no longer contradict a parent-frozen fact the fast-wake gate already certified; the deferral path taken from the far-ahead gate no longer re-triggers fast-wake, structurally closing the recursion. Live-proven on testnet with a known-answer regression test pinned to the incident's exact slot numbers.

#### Changes
* Housekeeping: removed internal-repository path references and legacy pre-rename naming (`vex-fd`, `fix105`) from source comments, a runtime diagnostics log banner, and `zig build -l`/`--help` test-step descriptions. No behavior change.
* The version-report string (gossip client-id advertisement and boot banner) now reads `0.9.3-c`, matching this release.

## 0.9.3-b
### Validator
#### Changes
* Networking: the TPU-ingest QUIC server, mempool, and leader block-production path now emit stat counters and rate-limited warning-level log lines covering the full chain from QUIC handshake through mempool admission to a produced slot (handshakes, streams, bytes, parse ok/fail, mempool admit ok/reject with a reason breakdown, and per-slot received/queued/packed deltas). Previously this chain was either uninstrumented or logged only at a level release builds compile out, so a stall anywhere along it produced no trace. Also adds a one-time boot notice that TPU-ingest mempool admission is not gated to leader slots. Observability only; no change to validator behavior.
* The version-report string (gossip client-id advertisement and boot banner) now reads `0.9.3-b`, matching this release.

## 0.9.3-a
### Validator
#### Changes
* Networking: the TPU-ingest QUIC server now reuses the pending connection for a client Initial packet retransmitted before the handshake completes, instead of minting a second connection object. Previously a retransmitted Initial (normal client behavior under WAN jitter or a burst of simultaneous handshakes) could clobber the peer-address routing table entry, orphaning the connection the client actually completed its handshake against; the client reported a successful handshake while every subsequent packet, including the transaction stream, was silently dropped.
* The version-report string (gossip client-id advertisement and boot banner) now reads `0.9.3-a`, matching this release.

## 0.9.3
### Validator
#### Changes
* Networking: on dual-NIC hosts, the TPU-ingest QUIC server now binds to the advertised TPU network interface instead of the wildcard address. Previously the handshake reply's source IP was chosen by the kernel's destination-route lookup instead of the advertised interface, so external clients rejected the off-source reply and every handshake timed out; QUIC transaction ingest on dual-NIC hosts now completes. Also corrects the TPU-ingest boot banner, which previously reported no broadcast even when broadcast was enabled.

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
