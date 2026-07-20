# Changelog

All notable changes to Vexor are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project uses [Semantic Versioning](https://semver.org/) with a
`v`-prefixed tag (`v0.9.0`, `v0.9.1`, ... `v1.0.0`).

Entries here stay at the *user-facing* level (RPC/Validator/build-flag
changes visible to an operator). Fine-grained per-file behavior provenance
against upstream Agave/Firedancer/Sig lives in [`PROVENANCE.md`](./PROVENANCE.md)
instead of being duplicated here.

## [0.9.0] - Initial public release

### Added

- Initial public release of Vexor: an independent, Zig-native Solana
  validator client, byte-for-byte behavior-compatible with Agave by design.
- Pure-Zig cryptography (ed25519, blake3, bn254/alt_bn128, poseidon, LtHash)
  — no Firedancer FFI dependency.
- Zig sBPF interpreter stack and CPI dispatch (legacy interpreter originally
  ported from Sig, since heavily reworked; the vex_bpf2 rebuild is an
  independent spec-for-spec implementation — see `PROVENANCE.md`).
- Conflict-DAG parallel transaction executor.
- AF_XDP zero-copy networking (receive path).
- VexLedger: a Zig-native append-segment blockstore.
- Vexor-authored vote program (`src/vex_svm/voteforge/`) as the sole vote
  executor.

[0.9.0]: https://github.com/DavidB-77/vexor/releases/tag/v0.9.0
