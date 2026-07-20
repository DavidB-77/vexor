//! fix/small-parity-batch-2026-07-17 — pure decision predicate for the
//! ELF-resolution-failure hardening in `instruction_dispatch.dispatchBpfExecution`.
//!
//! Factored into its own zero-dependency file (only `std`) so the narrow
//! "should this fail loud instead of silently falling through to the legacy
//! V1 stub table" decision is unit-testable in isolation, without pulling in
//! the full `vex_svm`/`replay_stage.zig` module graph that
//! `instruction_dispatch.zig` itself requires (that graph has no standalone
//! test root today — see build.zig's `e1_test_root_replay_siblings.zig`
//! comment on why several §E-phase siblings are compile-gated only, not
//! test-discovered).
//!
//! Context (full reasoning + Agave citations at the call site,
//! `instruction_dispatch.zig:dispatchBpfExecution`): when
//! `elf_version.resolveProgramSbpfVersion` returns null for a program_id that
//! reached `dispatchBpfExecution` (i.e. NOT a pre-filtered native/builtin —
//! replay_stage.zig routes those elsewhere before ever calling
//! `dispatchBpfExecution`), the null cause is either a missing account, a
//! genuinely non-BPF-owned account, or a real sBPF ELF-load failure on an
//! executable BPF-loader-owned account. Only the last case must fail loud
//! (mirroring Agave's `InstructionError::UnsupportedProgramId` for a
//! tombstoned program cache entry, `programs/bpf_loader/src/lib.rs:136-141`)
//! instead of silently falling through to the legacy, syscall-stubbed V1
//! table. This predicate identifies exactly that case.

const std = @import("std");

/// True only for an executable account owned by one of the three BPF loaders
/// passed in (upgradeable/v2/deprecated). Any other combination (missing
/// account modeled by the caller never invoking this, non-executable, or a
/// non-BPF-loader owner) returns false, preserving today's fallthrough
/// behavior unchanged.
pub fn isFatalBpfElfResolutionFailure(
    executable: bool,
    owner: [32]u8,
    bpf_loader_upgradeable: [32]u8,
    bpf_loader_v2: [32]u8,
    bpf_loader_deprecated: [32]u8,
) bool {
    return executable and
        (std.mem.eql(u8, &owner, &bpf_loader_upgradeable) or
            std.mem.eql(u8, &owner, &bpf_loader_v2) or
            std.mem.eql(u8, &owner, &bpf_loader_deprecated));
}

const UPGRADEABLE: [32]u8 = [_]u8{0x01} ** 32;
const V2: [32]u8 = [_]u8{0x02} ** 32;
const DEPRECATED: [32]u8 = [_]u8{0x03} ** 32;
const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;

test "isFatalBpfElfResolutionFailure: executable + each BPF loader owner -> fatal" {
    try std.testing.expect(isFatalBpfElfResolutionFailure(true, UPGRADEABLE, UPGRADEABLE, V2, DEPRECATED));
    try std.testing.expect(isFatalBpfElfResolutionFailure(true, V2, UPGRADEABLE, V2, DEPRECATED));
    try std.testing.expect(isFatalBpfElfResolutionFailure(true, DEPRECATED, UPGRADEABLE, V2, DEPRECATED));
}

test "isFatalBpfElfResolutionFailure: non-executable -> never fatal (even if BPF-loader-owned)" {
    try std.testing.expect(!isFatalBpfElfResolutionFailure(false, UPGRADEABLE, UPGRADEABLE, V2, DEPRECATED));
    try std.testing.expect(!isFatalBpfElfResolutionFailure(false, V2, UPGRADEABLE, V2, DEPRECATED));
    try std.testing.expect(!isFatalBpfElfResolutionFailure(false, DEPRECATED, UPGRADEABLE, V2, DEPRECATED));
}

test "isFatalBpfElfResolutionFailure: executable but not BPF-loader-owned -> not fatal (preserves existing fallthrough, e.g. natives)" {
    try std.testing.expect(!isFatalBpfElfResolutionFailure(true, SYSTEM_PROGRAM_ID, UPGRADEABLE, V2, DEPRECATED));
    const some_other_owner: [32]u8 = [_]u8{0xAB} ** 32;
    try std.testing.expect(!isFatalBpfElfResolutionFailure(true, some_other_owner, UPGRADEABLE, V2, DEPRECATED));
}
