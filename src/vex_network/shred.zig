//! Thin aggregator — SPLIT module 57 (2026-07-07). The original monolithic
//! `shred.zig` (2,573 LoC) split into `shred_parse.zig` (wire-format: parse
//! + Merkle-root types, ~380 LoC) and `shred_assembler.zig` (the receive-side
//! `ShredAssembler`/`SlotAssembly` engine, ~2,180 LoC), mirroring the
//! module-25 `accounts.zig` SPLIT precedent. This file exists purely so
//! every pre-split `@import("shred.zig")` call site (fix105: `tvu.zig`,
//! `verify_tile.zig`, `repair_abandon.zig`, `fec_chained_recovery_kat.zig`,
//! `shredder.zig` (DELETE), `main.zig`'s `shred_pub` re-export) keeps
//! resolving unchanged once those files migrate. See REBUILD-LEDGER.md
//! module 57 for the full split rationale and fidelity proof.
const shred_parse = @import("shred_parse.zig");
const shred_assembler = @import("shred_assembler.zig");

pub const SHRED_PAYLOAD_SIZE = shred_parse.SHRED_PAYLOAD_SIZE;
pub const SHRED_HEADER_SIZE = shred_parse.SHRED_HEADER_SIZE;
pub const ShredType = shred_parse.ShredType;
pub const ShredVariant = shred_parse.ShredVariant;
pub const ShredCommonHeader = shred_parse.ShredCommonHeader;
pub const Shred = shred_parse.Shred;
pub const isUnexpectedDataComplete = shred_parse.isUnexpectedDataComplete;
pub const parseShred = shred_parse.parseShred;

pub const UmemFrameRef = shred_assembler.UmemFrameRef;
pub const UmemFrameManager = shred_assembler.UmemFrameManager;
pub const ShredAssembler = shred_assembler.ShredAssembler;
