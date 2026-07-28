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

## 0.9.3-j
### Validator
#### Fixed
* Block production: leader-slot production now executes through the same instruction-dispatch ladder replay uses, retiring the reduced block executor that understood only two System-program instruction shapes. With the reduced executor, a candidate transaction could be packed on the strength of an execution model the cluster does not share; the block would then be rejected wholesale. Production and replay now agree byte-for-byte on what a transaction does before it is packed.

#### Changes
* Block production: a pre-admission oracle checks each candidate against a scratch child bank before packing — fee-payer balance, program-account existence, already-processed status, and recent-blockhash validity. A candidate the cluster would reject is refused up front instead of being packed blind, and each refusal is counted per reason in the leader-slot ingest log line.
* Consensus: vote arming reads SlotHashes fork-aware. The previous read could observe a sibling fork's SlotHashes through the rooted-cache path; arming on the wrong fork's state risks voting against the chain the cluster converges on. Not arming for one slot costs one slot of vote throughput; arming on a sibling fork's SlotHashes costs the chain — the read now refuses rather than guesses.

## 0.9.3-i
### Validator
#### Fixed
* Consensus: the live vote executor now propagates allocation failure instead of reporting it as success. `0.9.3-h` described this fix, but the released code did not contain it — the seven failure paths were still returning success. They now return the error. A dropped account write carries that account's lattice-hash delta, so losing one froze the slot with a missing contribution and produced a `bank_hash` no other node would agree with, leaving nothing behind but a counter in a debug line. This entry supersedes the corresponding `0.9.3-h` entry, which was accurate about the intent and wrong about the shipped code.
* Block production: transactions that were already processed in a recent block can no longer be packed into a new one. The producer consults a cache of recently committed signatures, but that cache was only populated by the serial replay path. With parallel execution selected, every commit went through the wave path, which did not record anything — so the cache stayed empty, the producer's check never refused a candidate, and an already-processed transaction could be included. The rest of the cluster rejects such a block outright. The wave path now records committed signatures on its success branch, on the replay thread after the wave drains, which is where the cache's single-threaded contract holds.

#### Changes
* Block production: a leader slot now packs for the whole slot rather than taking a single batch. Production previously drained the pending-transaction queue exactly once per slot and packed at most one batch's worth, which bounded a block far below what the queue held. It now drains repeatedly until the queue is empty, a wall-clock budget elapses, or a scan cap is reached — the same shape Agave's scheduler uses. Two new environment variables bound it: `VEX_PACK_BUDGET_MS` (default `60`) caps time spent collecting, and `VEX_PACK_MAX_SCAN` (default `100000`) caps candidates examined. Both have working defaults and need not be set.
* Consensus: the vote-threshold percentage calculation is computed in 128-bit arithmetic. The multiply by 100 overflowed 64 bits once cluster-voted stake exceeded roughly 184.5 million SOL in lamports, which is below the stake already present on live clusters. The path is currently reached only with a zero operand, so no incorrect threshold has been computed, but the overflow would arm as soon as real stake values are supplied.

#### Build
* The production optimize mode is **ReleaseFast**, changed from ReleaseSafe for performance. Note that `--release=fast|safe|small` are all inert while `build.zig` sets a preferred optimize mode — the value is ignored, though *omitting* `--release` still yields a Debug build. A Debug binary is also smaller than a ReleaseFast one here, so binary size cannot be used to detect the mistake. Verify from the artifact instead: ReleaseFast strips Zig's safety-check panic strings, so `strings <binary> | grep -c "reached unreachable code"` must be `0`.
* `scripts/check-single-ladder.sh` added: an anti-drift guard requiring exactly one program-id dispatch ladder in the tree. Separate executors for production and replay are what caused blocks to be produced without vote transactions; the guard fails the tree if a second reduced router appears, closing the class rather than the instance.

#### Removed
* Two `.orig` files — pre-fix copies of `instruction_dispatch.zig` and `replay_stage.zig`, about 1.0 MB — were tracked in the repository alongside the fixed originals and have been removed. They also contained a duplicate program-id dispatch ladder.

#### Diagnostics
* The validator now warns ahead of the epoch-stake coverage cliff. Stake data loaded from a snapshot covers a bounded range of slots and is never refreshed; past the end of that range the clock estimate, the leader schedule and fork choice all degrade without raising an error. The warning does the arithmetic on a log line that already carried the numbers, and escalates to error level under twelve hours remaining. This makes the deadline visible; it does not extend the coverage.

## 0.9.3-h
### Validator
#### Fixed
* Consensus: Ed25519 signature verification on the consensus path now uses strict verification, matching Agave. Agave's `Signature::verify` resolves to dalek's `verify_strict`, which rejects signatures whose `R` or `A` component lies in a small-order subgroup; Vexor used the cofactored variant, which accepts them. Any such signature was therefore valid to Vexor and invalid to the cluster, so a transaction carrying one would execute locally and be rejected everywhere else, producing an attacker-constructible `bank_hash` divergence. The in-tree comment had asserted the opposite of Agave's actual behavior and is corrected with source citations.
* Consensus: vote instructions that verify a BLS proof of possession (SIMD-0387) are now charged the additional 34,500 compute units Agave charges, on top of the flat vote-instruction default. Vexor charged only the flat amount, so any block containing such a vote computed a different total consumed compute — divergent block cost accounting against the rest of the cluster. The charge is applied in Agave's order: after the preceding validity checks and before the signature check, so a vote that fails an earlier check is not billed for verification it never performed.
* Consensus: allocation failures in the epoch-boundary reward computation now abort the boundary instead of being silently absorbed. Ten container insertions along that path — the vote-account index, per-vote metadata, the owned epoch-credits slice, the reward accumulator, stake delegations, and both reward-distribution account writes — discarded the value on allocation failure and continued. Each feeds the inflation-reward calculation whose output becomes account writes and therefore the boundary bank's `accounts_lt_hash` and `bank_hash`, so a single failure silently dropped a validator's rewards, produced a `bank_hash` no other node would agree with, and logged nothing at all. They now propagate; the caller abandons the slot without freezing it, so the node stalls on that fork rather than publishing a hash it cannot compute correctly. Sites that skip malformed account data are deliberate, match Agave, and are unchanged.
* Consensus: the live vote executor no longer reports failed vote executions as successful. Seven failure paths — five allocation and table-construction sites, an inverted error branch that propagated every instruction error *except* out-of-memory, and the account-commit loop — incremented a debug counter and returned success. No caller branches on those counters; each is read only by a debug print, so none could prevent a slot from freezing. A dropped account write in the commit loop carries the account's lattice-hash delta, so losing it froze the slot with a missing contribution: a wrong `bank_hash` whose only trace was a counter in a log line.

#### Changes
* Diagnostics: a slot abandoned because replay failed is now logged at error level and states that the slot was left unfrozen. It was previously logged at debug level — invisible in a production configuration — despite leaving the slot unfrozen and orphaning its children, which is a top-tier operational event.
* Diagnostics: failure to record a dead slot, and failure to append to the lattice-hash write-capture buffer used by the write-carrier localizer, are now both reported. Neither was previously distinguishable from the success path, and in the latter case a dropped entry makes the localizer report a false dropped write — precisely the signal an operator arms it to read.

## 0.9.3-g
### Validator
#### Fixed
* Networking: fixed a UMEM frame leak in the AF_XDP copy-mode receive fallback, which consumed a frame from the RX ring, copied the packet out, and never returned the frame to the free reservoir or the fill ring. Because that path never acquires the frame, the loss was invisible in the held-frame counter while the free pool drained monotonically — roughly 24,000 frames per hour from a 131,072-frame pool under sustained catch-up load. The failure was self-accelerating: a depleted reservoir pushes more traffic onto the same fallback. Terminal state was mass receive-shedding, dropped shreds, slots that never completed, and a replay stalled far behind the cluster tip while the node still appeared partly alive. Fixed by returning the frame to the free ring directly, since the refcount-based release path can't be used when the frame was never acquired. Validated on live testnet: free-pool depth flat versus a ~24k/hour decline, zero receive-shed events versus 144.9 million previously, and the node at chain tip and voting.
* Networking: the frame-accounting invariant check on the AF_XDP UMEM pool is now a leak detector that reports sustained growth in unaccounted frames rather than asserting exact equality, since frames in flight inside the kernel are not observable from userspace and a healthy node always sits a constant amount below full accounting.

#### Changes
* Diagnostics: the parent-slot diagnostic probe is now gated behind an environment variable and off by default; ungated, it produced many gigabytes of logs per day and competed with replay for I/O.

## 0.9.3-f
### Validator
#### Fixed
* Consensus: fixed the lattice-hash (`accounts_lt_hash`) delta computed for a modified account, which previously computed the account's pre-state hash with the `executable` field hardcoded to `false` instead of the account's real pre-execution value. This was invisible for ordinary (non-executable) accounts, but for an executable (program) account it subtracted the lattice hash of a state that never existed, corrupting `accounts_lt_hash` — and therefore `bank_hash` — for any slot containing a write to a program account (for example, a plain lamport transfer into a program account). In the field this surfaced as a silent fork: replay stayed at the chain tip while every vote was rejected with `SlotHashMismatch`, leaving the validator delinquent with no other error surfaced. Verified by deterministic offline replay of the affected slot against the cluster's canonical bank hash.

## 0.9.3-e
### Validator
#### Fixed
* Release: fixed the cosign signing step in the release workflow, which had started failing on every tag push because the pinned cosign version now defaults to its new bundle format and silently ignores the separate signature/certificate output flags. Release assets now include a single `.sigstore.json` bundle (signature + certificate + Rekor entry) in place of the separate `.sig`/`.pem` files. No change to validator behavior.

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
