//! REBUILD-NATIVE compile-smoke for the migrated `core` module (session 1).
//!
//! origin-tree has no dedicated test target covering config.zig / keypair.zig /
//! types.zig (the exe and downstream targets compile them there). Until those
//! consumers migrate, this root forces analysis of the core module graph so a
//! migration mistake fails at `zig build test-migrated`, not sessions later.
//! In-file KATs of the core files themselves (keypair sign/verify, config
//! parse, base58 round-trip) still run where origin-tree runs them; this is a
//! compile/wiring gate, not a behavior gate.

const std = @import("std");
const core = @import("core");

test "core module graph: root decls analyze" {
    std.testing.refAllDecls(core);
}

test "core module graph: canonical scalar types" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(core.Pubkey));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(core.Hash));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(core.Signature));
    try std.testing.expectEqual(u64, core_scalar(core.Slot));
    try std.testing.expectEqual(u64, core_scalar(core.Epoch));
}

fn core_scalar(comptime T: type) type {
    return T;
}
