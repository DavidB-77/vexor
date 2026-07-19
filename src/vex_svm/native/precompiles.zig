//! Vexor Precompile Dispatcher
//!
//! Routes incoming transactions to the appropriate cryptographic precompile based
//! on program ID: Ed25519, secp256k1 (ECDSA-Keccak256), or secp256r1 (NIST P-256).
//!
//! Precompiles run *before* the SVM executes other instructions.  A single failure
//! aborts the entire transaction with InstructionError{ index, Custom(0) }.
//!
//! @prov:precompile.module-map — Firedancer/Sig/Agave cross-references for
//! the dispatcher, table, and transaction-level verification below.

const std = @import("std");

const vex_crypto = @import("vex_crypto");
const secp256k1_mod = vex_crypto.secp256k1;
const secp256r1_mod = vex_crypto.secp256r1;
const ed25519_pre_mod = vex_crypto.ed25519_precompile;
const features = @import("../features.zig");

// ─────────────────────────────────────────────────────────────────────────────
// Compute-unit costs. @prov:precompile.cu-costs
// ─────────────────────────────────────────────────────────────────────────────

/// Cluster-averaged CU→µs conversion ratio (30 µs per CU).
pub const CU_TO_US: u64 = 30;

/// CU cost per Ed25519 signature verification (non-strict). @prov:precompile.cu-costs
pub const ED25519_VERIFY_COST: u64 = CU_TO_US * 76;

/// CU cost per Ed25519 signature verification (strict mode). @prov:precompile.cu-costs
pub const ED25519_VERIFY_STRICT_COST: u64 = CU_TO_US * 80;

/// CU cost per secp256k1 ECDSA-Keccak256 verification. @prov:precompile.cu-costs
pub const SECP256K1_VERIFY_COST: u64 = CU_TO_US * 223;

/// CU cost per secp256r1 P-256/SHA-256 verification. @prov:precompile.cu-costs
pub const SECP256R1_VERIFY_COST: u64 = CU_TO_US * 160;

// ─────────────────────────────────────────────────────────────────────────────
// secp256r1 precompile activation
//
// SIMD-0075's enable_secp256r1_precompile feature
// (srremy31J5Y25FrAApwVb9kZcfXbusYMMsvTK9aWv5q == features.ENABLE_SECP256R1_PRECOMPILE)
// is universally activated on every live cluster and has been "cleaned up" upstream.
// @prov:precompile.secp256r1-gate — canonical Agave and Firedancer both register
// secp256r1 as always-enabled/ungated; Vexor matches both: the secp256r1
// precompile is UNGATED (required_feature = null in PRECOMPILES below).
//
// HISTORY (module-31 rebuild verification, 2026-07-06 → fixed 2026-07-10, ported
// from origin-tree branch fix/secp256r1-gate-2026-07-07): the removed
// FEATURE_SECP256R1 constant carried WRONG bytes — base58
// FMeV86fqwX6RxVPUEkmzg6uMEP1A1sC94kDAy6hqfv7B, a placeholder matching neither the
// real feature key (srremy31J5…) nor its own in-file comment (Ew1HRpg9…). Because
// that bogus key was never present in the FeatureSet, isActive() always returned
// false and secp256r1 verification was SILENTLY SKIPPED for every tx — an
// accept-invalid execution-divergence carrier vs Agave/FD, which reject an
// invalid-signature secp256r1 tx with Custom(0). Wrong-hand-typed-pubkey bug class
// (same as the ALT PROGRAM_ID carrier); ungating removes the constant entirely.
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Precompile table. @prov:precompile.module-map
// ─────────────────────────────────────────────────────────────────────────────

/// A registered precompile program.
pub const Precompile = struct {
    /// 32-byte program ID.
    program_id: [32]u8,
    /// Optional feature gate: if non-null, this precompile is inactive until the
    /// feature with this pubkey is activated on-chain.
    /// @prov:precompile.secp256r1-gate
    required_feature: ?[32]u8,
    /// Verification function pointer.
    verify_fn: *const fn (
        data: []const u8,
        all_instr_datas: []const []const u8,
    ) anyerror!void,
};

/// Registered precompile programs — evaluated in order during verifyPrecompiles.
/// @prov:precompile.module-map
pub const PRECOMPILES = [_]Precompile{
    .{
        .program_id = ed25519_pre_mod.PROGRAM_ID,
        .required_feature = null, // always active
        .verify_fn = dispatchEd25519,
    },
    .{
        .program_id = secp256k1_mod.PROGRAM_ID,
        .required_feature = null, // always active
        .verify_fn = dispatchSecp256k1,
    },
    .{
        .program_id = secp256r1_mod.PROGRAM_ID,
        // Ungated — always enabled. @prov:precompile.secp256r1-gate —
        // SIMD-0075's enable_secp256r1_precompile is universally activated +
        // cleaned up upstream.
        .required_feature = null,
        .verify_fn = dispatchSecp256r1,
    },
};

// Thin wrappers that adapt the generic (data, all_instr_datas) signature to
// each module's specific API. Ed25519 no longer takes a strict_mode
// parameter either (P0-1, 2026-07-11). @prov:precompile.ed25519-verify-strict
// — no branch left to thread through — matching secp256k1/secp256r1, which
// never had one.

fn dispatchEd25519(
    data: []const u8,
    all_instr_datas: []const []const u8,
) anyerror!void {
    return ed25519_pre_mod.verify(data, all_instr_datas);
}

fn dispatchSecp256k1(
    data: []const u8,
    all_instr_datas: []const []const u8,
) anyerror!void {
    return secp256k1_mod.verify(data, all_instr_datas);
}

fn dispatchSecp256r1(
    data: []const u8,
    all_instr_datas: []const []const u8,
) anyerror!void {
    return secp256r1_mod.verify(data, all_instr_datas);
}

// ─────────────────────────────────────────────────────────────────────────────
// Transaction-level verification. @prov:precompile.module-map
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when a precompile fails: the instruction index and error code.
pub const PrecompileFailure = struct {
    /// 0-based index of the failing instruction within the transaction.
    instruction_index: usize,
    /// Always 0 for precompile failures (Solana convention: Custom(0)).
    custom_error: u32,
};

/// A transaction representation sufficient for precompile checking.
/// Callers provide this; it avoids coupling to a full transaction type.
pub const TxForPrecompiles = struct {
    /// All account pubkeys in the transaction (32 bytes each).
    account_keys: []const [32]u8,
    /// Instructions in execution order.
    instructions: []const TxInstruction,
};

/// Minimal instruction descriptor for precompile dispatch.
pub const TxInstruction = struct {
    /// Index into TxForPrecompiles.account_keys identifying the program.
    program_index: usize,
    /// Raw instruction data bytes.
    data: []const u8,
};

/// Verify all precompile instructions in a transaction.
///
/// Iterates every instruction in order.  For each instruction whose program ID
/// matches a registered (and currently enabled) precompile, runs that precompile's
/// verify function with the full transaction's instruction data slice.
///
/// On first failure returns PrecompileFailure.  Returns null on success.
/// @prov:precompile.module-map
pub fn verifyPrecompiles(
    allocator: std.mem.Allocator,
    tx: *const TxForPrecompiles,
    feature_set: *const features.FeatureSet,
    slot: u64,
) error{OutOfMemory}!?PrecompileFailure {
    // Lazily build the flat instruction-data slice (one alloc for the whole tx).
    // @prov:precompile.module-map
    var instr_datas: ?[]const []const u8 = null;
    defer if (instr_datas) |ids| allocator.free(ids);

    for (tx.instructions, 0..) |instr, idx| {
        if (instr.program_index >= tx.account_keys.len) continue;
        const prog_id = tx.account_keys[instr.program_index];

        for (PRECOMPILES) |precompile| {
            if (!std.mem.eql(u8, &prog_id, &precompile.program_id)) continue;

            // Check optional feature gate. @prov:precompile.secp256r1-gate
            if (precompile.required_feature) |feat_key| {
                if (!feature_set.isActive(feat_key, slot)) continue;
            }

            // Build the instruction-data slice on first need.
            const all_datas = instr_datas orelse blk: {
                const buf = try allocator.alloc([]const u8, tx.instructions.len);
                for (tx.instructions, 0..) |ins, j| buf[j] = ins.data;
                instr_datas = buf;
                break :blk buf;
            };

            precompile.verify_fn(instr.data, all_datas) catch {
                return PrecompileFailure{
                    .instruction_index = idx,
                    .custom_error = 0,
                };
            };
        }
    }

    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Compute-unit cost estimation. @prov:precompile.cu-costs
// ─────────────────────────────────────────────────────────────────────────────

/// Estimate the compute-unit cost of executing all precompile instructions.
///
/// Only Ed25519 and secp256k1 are counted (per current Agave cost model).
/// secp256r1 is gated behind a feature and not counted here yet.
/// @prov:precompile.cu-costs
pub fn computeUnitCost(tx: *const TxForPrecompiles) u64 {
    var n_secp256k1: u64 = 0;
    var n_ed25519: u64 = 0;

    for (tx.instructions) |instr| {
        if (instr.data.len == 0) continue;
        if (instr.program_index >= tx.account_keys.len) continue;

        const prog_id = tx.account_keys[instr.program_index];
        const count: u64 = instr.data[0];

        if (std.mem.eql(u8, &prog_id, &secp256k1_mod.PROGRAM_ID)) {
            n_secp256k1 +|= count;
        }
        if (std.mem.eql(u8, &prog_id, &ed25519_pre_mod.PROGRAM_ID)) {
            n_ed25519 +|= count;
        }
    }

    return n_secp256k1 *| SECP256K1_VERIFY_COST +|
        n_ed25519 *| ED25519_VERIFY_COST;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

test "empty transaction succeeds" {
    const allocator = std.testing.allocator;
    const tx: TxForPrecompiles = .{ .account_keys = &.{}, .instructions = &.{} };
    var fs = features.FeatureSet.init();
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expectEqual(null, result);
}

test "non-precompile instruction ignored" {
    const allocator = std.testing.allocator;
    const random_key: [32]u8 = @splat(0xAB);
    const tx: TxForPrecompiles = .{
        .account_keys = &.{random_key},
        .instructions = &.{.{ .program_index = 0, .data = "hello world" }},
    };
    var fs = features.FeatureSet.init();
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expectEqual(null, result);
}

test "bad ed25519 instruction returns failure" {
    const allocator = std.testing.allocator;
    const tx: TxForPrecompiles = .{
        .account_keys = &.{ed25519_pre_mod.PROGRAM_ID},
        // data is "hello" — not a valid ed25519 instruction header
        .instructions = &.{.{ .program_index = 0, .data = "hello" }},
    };
    var fs = features.FeatureSet.init();
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(0, result.?.instruction_index);
    try std.testing.expectEqual(0, result.?.custom_error);
}

test "bad secp256k1 instruction returns failure" {
    const allocator = std.testing.allocator;
    const tx: TxForPrecompiles = .{
        .account_keys = &.{secp256k1_mod.PROGRAM_ID},
        .instructions = &.{.{ .program_index = 0, .data = "hello" }},
    };
    var fs = features.FeatureSet.init();
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(0, result.?.instruction_index);
}

test "secp256r1 is ungated: invalid instruction FAILS even with empty feature set" {
    // REGRESSION GATE for the FEATURE_SECP256R1 wrong-constant bug (module-31
    // rebuild verification 2026-07-06, fixed 2026-07-10). secp256r1 is UNGATED
    // (Agave 4.1.0-rc.1/4.2.0-beta.0 None / FD NO_ENABLE_FEATURE_ID), so an
    // invalid-data secp256r1 instruction must FAIL regardless of the FeatureSet.
    //
    // FAIL-PRE / PASS-POST: with the old bogus FEATURE_SECP256R1 gate this returned
    // null (verification silently skipped = accept-invalid divergence carrier).
    // With the ungating fix it must return a PrecompileFailure at instr 0.
    const allocator = std.testing.allocator;
    const tx: TxForPrecompiles = .{
        .account_keys = &.{secp256r1_mod.PROGRAM_ID},
        .instructions = &.{.{ .program_index = 0, .data = "garbage data that is invalid" }},
    };
    var fs = features.FeatureSet.init(); // deliberately EMPTY — gate must not matter
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(0, result.?.instruction_index);
    try std.testing.expectEqual(0, result.?.custom_error);
}

test "secp256r1 valid signature PASSES through the dispatcher" {
    // Guards the other direction of newly-enabling verification: a well-formed,
    // low-S P-256 signature must be ACCEPTED (returns null), so ungating cannot
    // start rejecting valid secp256r1 txs. Instruction layout mirrors
    // secp256r1.zig's round-trip KAT (SIMD-0075 canonical serialization).
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const P256 = std.crypto.ecc.P256;
    const allocator = std.testing.allocator;
    const message = "vexor secp256r1 dispatch KAT";

    const keypair = EcdsaP256.KeyPair.generate();
    const raw_sig = try keypair.sign(message, null);

    // Enforce low-S (SIMD-0075) so the verifier accepts it.
    var s = try P256.scalar.Scalar.fromBytes(raw_sig.s, .big);
    const s_big: u256 = @byteSwap(@as(u256, @bitCast(raw_sig.s)));
    const half_order: u256 = (0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 - 1) / 2;
    if (s_big > half_order) s = s.neg();
    const signature: EcdsaP256.Signature = .{ .r = raw_sig.r, .s = s.toBytes(.big) };

    const pubkey_off: u16 = secp256r1_mod.DATA_START;
    const sig_off: u16 = pubkey_off + secp256r1_mod.PUBKEY_SIZE;
    const msg_off: u16 = sig_off + secp256r1_mod.SIGNATURE_SIZE;

    const offsets: secp256r1_mod.SignatureOffsets = .{
        .sig_offset = sig_off,
        .sig_instr_idx = std.math.maxInt(u16),
        .pubkey_offset = pubkey_off,
        .pubkey_instr_idx = std.math.maxInt(u16),
        .msg_offset = msg_off,
        .msg_size = @intCast(message.len),
        .msg_instr_idx = std.math.maxInt(u16),
    };

    const total = msg_off + message.len;
    const buf = try allocator.alloc(u8, total);
    defer allocator.free(buf);
    @memset(buf, 0);
    buf[0] = 1; // n_sigs
    @memcpy(buf[secp256r1_mod.OFFSETS_START..][0..secp256r1_mod.OFFSETS_SERIALIZED_SIZE], std.mem.asBytes(&offsets));
    @memcpy(buf[pubkey_off..][0..secp256r1_mod.PUBKEY_SIZE], &keypair.public_key.toCompressedSec1());
    @memcpy(buf[sig_off..][0..secp256r1_mod.SIGNATURE_SIZE], &signature.toBytes());
    @memcpy(buf[msg_off..][0..message.len], message);

    const tx: TxForPrecompiles = .{
        .account_keys = &.{secp256r1_mod.PROGRAM_ID},
        .instructions = &.{.{ .program_index = 0, .data = buf }},
    };
    var fs = features.FeatureSet.init();
    defer fs.deinit(allocator);
    const result = try verifyPrecompiles(allocator, &tx, &fs, 0);
    try std.testing.expectEqual(null, result); // valid sig accepted
}

test "compute unit cost: ed25519 and secp256k1" {
    const Ed25519 = std.crypto.sign.Ed25519;

    const message = "test";
    const keypair = Ed25519.KeyPair.generate();
    const sig = try keypair.sign(message, null);

    // Build a minimal valid ed25519 instruction header with n_sigs = 2.
    var ed_buf: [ed25519_pre_mod.DATA_START]u8 = @splat(0);
    ed_buf[0] = 2; // n_sigs

    const tx: TxForPrecompiles = .{
        .account_keys = &.{ ed25519_pre_mod.PROGRAM_ID, secp256k1_mod.PROGRAM_ID },
        .instructions = &.{
            .{ .program_index = 0, .data = &ed_buf },
            // secp256k1 with 1 sig (data[0] = 1)
            .{ .program_index = 1, .data = &.{1} },
        },
    };

    _ = sig; // used to keep the keypair alive

    const cost = computeUnitCost(&tx);
    // 2 ed25519 + 1 secp256k1
    const expected = 2 * ED25519_VERIFY_COST + 1 * SECP256K1_VERIFY_COST;
    try std.testing.expectEqual(expected, cost);
}
