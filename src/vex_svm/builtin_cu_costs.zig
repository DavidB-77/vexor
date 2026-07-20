//! Builtin-program default compute-unit cost table.
//!
//! Faithful port of Agave's `BUILTIN_INSTRUCTION_COSTS` map
//! (`builtins-default-costs/src/lib.rs`) plus the per-program
//! `DEFAULT_COMPUTE_UNITS` constants each native processor consumes.
//!
//! WHY: SB-1 `executeOnBank` dispatches native (builtin) instructions through
//! Vexor's Zig handlers, but those handlers currently charge ZERO compute
//! units. Agave's native processors each `consume_checked(DEFAULT_COMPUTE_UNITS)`
//! at entry, so a Vexor `simulateTransaction` (and the cost model) under-reports
//! consumed CU for any builtin instruction — a simulate divergence. This table
//! is the single source of truth for that per-instruction builtin cost.
//!
//! `getBuiltinCost(program_id)` returns:
//!   - Some(cost)  — `program_id` is a known native builtin; charge `cost` CU
//!                   for each top-level invocation of that program.
//!   - null        — not a known builtin ⇒ it's a BPF program, metered normally
//!                   by the VM (per-opcode), so no flat builtin charge applies.
//!
//! Precompiles (secp256k1, ed25519) are present in Agave's map with cost 0:
//! they are verified directly in the bank during sanitization and do NOT
//! consume execution CU. They return Some(0) here (distinct from null) so the
//! caller can recognize them as builtins that legitimately charge nothing.
//!
//! std-ONLY: this file imports nothing from core/svm so it self-verifies via
//! `zig test src/vex_svm/builtin_cu_costs.zig`.
//!
//! Program IDs are base58-decoded at comptime from their canonical strings
//! (see `decodeBase58Id`) — never hand-typed bytes — so a typo cannot silently
//! ship a wrong key (it fails to decode to 32 bytes at compile time).
//!
//! ── Agave source citations (per-program DEFAULT_COMPUTE_UNITS) ──────────────
//! Re-cited 2026-07-06 (rebuild module 10) against the canonical pin
//! agave-4.1.0-rc.1-full — every value AND line number below was
//! re-verified byte-identical at this pin (values unchanged from the prior
//! 4.1.0-beta.3 citation; only the path label was stale). All paths below are
//! under agave-4.1.0-rc.1-full unless noted:
//!   system            150   programs/system/src/system_processor.rs:317
//!   compute_budget    150   programs/compute-budget/src/lib.rs:4
//!   vote            2_100   programs/vote/src/vote_processor.rs:101
//!   bpf_loader        570   programs/bpf_loader/src/lib.rs:33  (DEFAULT_LOADER_COMPUTE_UNITS)
//!   bpf_loader_deprecated
//!                   1_140   programs/bpf_loader/src/lib.rs:35  (DEPRECATED_LOADER_COMPUTE_UNITS)
//!   bpf_loader_upgradeable
//!                   2_370   programs/bpf_loader/src/lib.rs:37  (UPGRADEABLE_LOADER_COMPUTE_UNITS)
//!   secp256k1           0   builtins-default-costs (precompile, "run directly in bank")
//!   ed25519             0   builtins-default-costs (precompile, "run directly in bank")
//!
//! ── FIX #6 (2026-07-12, re-verified against Agave 4.2.0-beta.0) ────────────
//! Stake / Config / AddressLookupTable are FULLY core-BPF migrated as of 4.2:
//! `find .../programs -maxdepth 1` in agave-4.2.0-beta.0-src shows
//! there is no `programs/stake`, `programs/config`, or
//! `programs/address-lookup-table` directory AT ALL any more — no native Rust
//! processor exists, so there is no DEFAULT_COMPUTE_UNITS entry-charge concept
//! for them. Confirmed independently via `builtins-default-costs/src/lib.rs`
//! (4.2.0-beta.0): `BUILTIN_INSTRUCTION_COSTS` = `MIGRATING_BUILTINS_COSTS`
//! (only `vote`, gated by `bls_pubkey_management_in_vote_account`) ∪
//! `NON_MIGRATING_BUILTINS_COSTS` (system, compute_budget, bpf_loader,
//! bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4, secp256k1,
//! ed25519) — 9 entries total (`TOTAL_COUNT_BUILTINS = 9`, lib.rs:87). Stake,
//! Config, and AddressLookupTable are NOT in either list — they are ordinary
//! BPF programs now, metered like any other non-builtin (the caller's
//! requested/derived compute-unit budget, not a flat entry charge). Their rows
//! are REMOVED from BUILTIN_CU_TABLE below so `getBuiltinCost` correctly
//! returns `null` for them (⇒ "BPF, metered normally" at every call site,
//! matching `block_produce.zig`'s FIX #3 producer-cost estimate which treats
//! `getBuiltinCost(..) == null` as the 200,000-CU-default bucket instead of
//! the 3,000-CU-flat-builtin bucket).
//!
//! LoaderV4 remains in NON_MIGRATING_BUILTINS_COSTS (still classified
//! "builtin" for the flat-3,000 default-cost-limit bucket, SIMD-170) even
//! though its processor directory has also moved/renamed in this source tree
//! — kept here at its real DEFAULT_COMPUTE_UNITS=2,000 (last confirmed at
//! Agave commit 66ea0a1, programs/loader-v4/src/lib.rs:26) since that value is
//! for the DISTINCT real-execution-entry-charge purpose this table exists for
//! (see WHY above), not the producer cost-model estimate (which only consults
//! getBuiltinCost's Optional-ness, not this value — see block_produce.zig).

const std = @import("std");

// ── Comptime base58 → 32-byte pubkey decoder ───────────────────────────────
// Mirrors src/vex_bpf2/builtins/mod.zig::decodeBase58Pubkey. Kept local so this
// file stays std-only and self-verifying.

const BASE58_ALPHABET: *const [58]u8 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58CharToDigit(comptime c: u8) u8 {
    inline for (BASE58_ALPHABET, 0..) |a, i| {
        if (a == c) return @intCast(i);
    }
    @compileError("invalid base58 char in comptime decode");
}

/// Decode a 32-byte pubkey from its canonical base58 string at comptime.
/// Output is canonical 32-byte big-endian on-chain layout.
fn decodeBase58Id(comptime s: []const u8) [32]u8 {
    @setEvalBranchQuota(20000);
    var bytes: [64]u8 = .{0} ** 64;
    var bytes_len: usize = 0;

    inline for (s) |c| {
        var carry: u32 = b58CharToDigit(c);
        var idx: usize = 0;
        while (idx < bytes_len or carry != 0) : (idx += 1) {
            if (idx < bytes_len) carry += @as(u32, bytes[idx]) * 58;
            bytes[idx] = @intCast(carry & 0xff);
            if (idx >= bytes_len) bytes_len = idx + 1;
            carry >>= 8;
        }
    }

    var leading_ones: usize = 0;
    inline for (s) |c| {
        if (c != '1') break;
        leading_ones += 1;
    }

    const total = leading_ones + bytes_len;
    if (total != 32) @compileError("base58 pubkey did not decode to 32 bytes: " ++ s);

    var out: [32]u8 = .{0} ** 32;
    // Leading zero bytes correspond to leading '1' chars (already 0).
    var i: usize = 0;
    while (i < bytes_len) : (i += 1) {
        out[leading_ones + i] = bytes[bytes_len - 1 - i];
    }
    return out;
}

// ── Canonical program IDs (verified via solana-sdk-ids 3.1.0) ──────────────

pub const SYSTEM_PROGRAM_ID = decodeBase58Id("11111111111111111111111111111111");
pub const VOTE_PROGRAM_ID = decodeBase58Id("Vote111111111111111111111111111111111111111");
pub const STAKE_PROGRAM_ID = decodeBase58Id("Stake11111111111111111111111111111111111111");
pub const CONFIG_PROGRAM_ID = decodeBase58Id("Config1111111111111111111111111111111111111");
pub const COMPUTE_BUDGET_PROGRAM_ID = decodeBase58Id("ComputeBudget111111111111111111111111111111");
pub const ADDRESS_LOOKUP_TABLE_PROGRAM_ID = decodeBase58Id("AddressLookupTab1e1111111111111111111111111");
pub const BPF_LOADER_DEPRECATED_ID = decodeBase58Id("BPFLoader1111111111111111111111111111111111");
pub const BPF_LOADER_ID = decodeBase58Id("BPFLoader2111111111111111111111111111111111");
pub const BPF_LOADER_UPGRADEABLE_ID = decodeBase58Id("BPFLoaderUpgradeab1e11111111111111111111111");
pub const LOADER_V4_ID = decodeBase58Id("LoaderV411111111111111111111111111111111111");
pub const SECP256K1_PROGRAM_ID = decodeBase58Id("KeccakSecp256k11111111111111111111111111111");
pub const ED25519_PROGRAM_ID = decodeBase58Id("Ed25519SigVerify111111111111111111111111111");

// ── The cost table ─────────────────────────────────────────────────────────

const BuiltinCost = struct { id: [32]u8, cost: u64, name: []const u8 };

/// Per-instruction builtin compute-unit costs. Mirrors Agave's
/// BUILTIN_INSTRUCTION_COSTS (see file header for per-row citations).
/// FIX #6: stake/config/address_lookup_table rows REMOVED — core-BPF migrated
/// away in 4.2, no longer in Agave's builtin set at all (see file header).
pub const BUILTIN_CU_TABLE = [_]BuiltinCost{
    .{ .id = SYSTEM_PROGRAM_ID, .cost = 150, .name = "system" },
    .{ .id = COMPUTE_BUDGET_PROGRAM_ID, .cost = 150, .name = "compute_budget" },
    .{ .id = VOTE_PROGRAM_ID, .cost = 2_100, .name = "vote" },
    .{ .id = BPF_LOADER_UPGRADEABLE_ID, .cost = 2_370, .name = "bpf_loader_upgradeable" },
    .{ .id = BPF_LOADER_DEPRECATED_ID, .cost = 1_140, .name = "bpf_loader_deprecated" },
    .{ .id = BPF_LOADER_ID, .cost = 570, .name = "bpf_loader" },
    .{ .id = LOADER_V4_ID, .cost = 2_000, .name = "loader_v4" },
    // Precompiles: verified directly in bank during sanitization, consume 0 CU.
    .{ .id = SECP256K1_PROGRAM_ID, .cost = 0, .name = "secp256k1" },
    .{ .id = ED25519_PROGRAM_ID, .cost = 0, .name = "ed25519" },
};

/// Return the per-instruction builtin compute-unit cost for `program_id`, or
/// `null` if it is not a known builtin (then it is a BPF program, metered
/// normally by the VM). Precompiles return `0`, NOT `null` — they are builtins
/// that charge no execution CU.
pub fn getBuiltinCost(program_id: *const [32]u8) ?u64 {
    inline for (BUILTIN_CU_TABLE) |row| {
        if (std.mem.eql(u8, program_id, &row.id)) return row.cost;
    }
    return null;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test "known builtin costs" {
    try std.testing.expectEqual(@as(?u64, 150), getBuiltinCost(&SYSTEM_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, 150), getBuiltinCost(&COMPUTE_BUDGET_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, 2_100), getBuiltinCost(&VOTE_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, 2_370), getBuiltinCost(&BPF_LOADER_UPGRADEABLE_ID));
    try std.testing.expectEqual(@as(?u64, 1_140), getBuiltinCost(&BPF_LOADER_DEPRECATED_ID));
    try std.testing.expectEqual(@as(?u64, 570), getBuiltinCost(&BPF_LOADER_ID));
    try std.testing.expectEqual(@as(?u64, 2_000), getBuiltinCost(&LOADER_V4_ID));
}

test "FIX #6: stake/config/address_lookup_table are core-BPF migrated — NOT builtins" {
    // Agave 4.2.0-beta.0 builtins-default-costs/src/lib.rs: BUILTIN_INSTRUCTION_COSTS has
    // exactly 9 entries (TOTAL_COUNT_BUILTINS=9), and stake/config/ALT are not among them —
    // their program directories don't even exist in the 4.2 source tree any more (core-BPF).
    // getBuiltinCost must return null (⇒ "BPF, metered normally", the 200k-default bucket at
    // the producer-cost-estimate call site) for all three.
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&STAKE_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&CONFIG_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&ADDRESS_LOOKUP_TABLE_PROGRAM_ID));
}

test "precompiles charge 0 (Some, not null)" {
    // Distinct from the unknown→null path: precompiles are builtins that
    // legitimately consume no execution CU.
    try std.testing.expectEqual(@as(?u64, 0), getBuiltinCost(&SECP256K1_PROGRAM_ID));
    try std.testing.expectEqual(@as(?u64, 0), getBuiltinCost(&ED25519_PROGRAM_ID));
}

test "unknown program returns null" {
    // A plausible non-builtin (random/BPF) program id must NOT be in the table.
    var unknown: [32]u8 = .{0xAB} ** 32;
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&unknown));

    // The all-0xFF sentinel is also not a builtin.
    const all_ff: [32]u8 = .{0xFF} ** 32;
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&all_ff));

    // Mutating one byte of a real builtin id makes it unknown.
    unknown = SYSTEM_PROGRAM_ID;
    unknown[31] ^= 0x01;
    try std.testing.expectEqual(@as(?u64, null), getBuiltinCost(&unknown));
}

test "program id sanity: System is all-zero, others are not" {
    // base58 "111...1" decodes to all-zero bytes — the classic decode footgun.
    try std.testing.expectEqual([_]u8{0} ** 32, SYSTEM_PROGRAM_ID);

    // Every other builtin id must be non-zero and unique.
    const ids = [_][32]u8{
        VOTE_PROGRAM_ID,                 STAKE_PROGRAM_ID,
        CONFIG_PROGRAM_ID,               COMPUTE_BUDGET_PROGRAM_ID,
        ADDRESS_LOOKUP_TABLE_PROGRAM_ID, BPF_LOADER_DEPRECATED_ID,
        BPF_LOADER_ID,                   BPF_LOADER_UPGRADEABLE_ID,
        LOADER_V4_ID,                    SECP256K1_PROGRAM_ID,
        ED25519_PROGRAM_ID,
    };
    for (ids, 0..) |a, i| {
        try std.testing.expect(!std.mem.eql(u8, &a, &([_]u8{0} ** 32)));
        for (ids[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, &a, &b));
        }
    }
}
