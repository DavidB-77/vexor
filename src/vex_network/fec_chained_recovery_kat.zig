//! #61 CHAINED-MERKLE FEC RECOVERY — real-vector KAT.
//!
//! Gate for the chained-recovery fix (fec_resolver.recoverWithSigMethod). Drives a REAL,
//! ed25519-signed, chained merkle FEC set through the SAME encoder used by block production
//! (shred_encoder.assembleFecSet — Vandermonde RS M=V·inv(top(V)) over GF(2^8)/0x11D, the
//! cluster-byte-identical matrix the live receive path recovers with), erases some DATA shreds,
//! feeds the survivors into the resolver, triggers RS recovery, and asserts:
//!   1. recovery succeeds (root-equality gate PASSES — the rebuilt 64-leaf tree root == the
//!      surviving leader-signed root),
//!   2. every recovered data shred's bytes == the original wire shred (RS region + chained_root
//!      + merkle proof + signature),
//!   3. merkleRoot32() and chainedMerkleRoot() of each recovered shred == the originals.
//!
//! Also asserts the NEGATIVE path: a corrupted survivor (wrong chained_root) makes the rebuilt
//! root differ → the gate REJECTS the whole set (recovery returns failure, NOTHING inserted).
//!
//! Run: zig build test-fec-chained-recovery

const std = @import("std");
const encoder = @import("shred_encoder.zig");
const fec = @import("fec_resolver.zig");
const shred_mod = @import("shred.zig");

const Ed25519 = std.crypto.sign.Ed25519;

const SLOT: u64 = 415_300_000;
const VERSION: u16 = 57087;
const FEC_SET_IDX: u32 = 0;
const N: usize = 32; // data shreds
const M: usize = 32; // parity shreds

fn buildSet(allocator: std.mem.Allocator, resigned: bool) !struct {
    set: encoder.FecSetShreds,
    chained_root: [32]u8,
    pubkey: [32]u8,
} {
    // Deterministic keypair.
    var seed: [32]u8 = undefined;
    for (0..32) |i| seed[i] = @intCast((i * 7 + 3) & 0xff);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const secret = kp.secret_key.toBytes();
    const pubkey = kp.public_key.toBytes();

    // A deterministic chained_root (previous FEC set's root).
    var chained_root: [32]u8 = undefined;
    for (0..32) |i| chained_root[i] = @intCast((i * 13 + 5) & 0xff);

    // Deterministic payload that fills the whole set.
    const dpp: usize = if (resigned) 899 else 963;
    const payload = try allocator.alloc(u8, N * dpp);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 31 + 17) & 0xff);

    const params = encoder.FecSetParams{
        .slot = SLOT,
        .version = VERSION,
        .fec_set_idx = FEC_SET_IDX,
        .data_start_idx = FEC_SET_IDX,
        .code_start_idx = 0,
        .parent_off = 1,
        .reference_tick = 5,
        .data_complete = true,
        .slot_complete = resigned,
        .is_resigned = resigned,
    };
    const set = try encoder.assembleFecSet(allocator, params, payload, chained_root, secret);
    return .{ .set = set, .chained_root = chained_root, .pubkey = pubkey };
}

/// Drive a chained FEC set through the resolver with `erase_data` data shreds dropped.
/// Returns the recovered data-shred buffers (caller owns nothing — the resolver owns them;
/// we read them under the resolver lifetime).
fn recoverScenario(
    allocator: std.mem.Allocator,
    resigned: bool,
    erase: []const usize,
    corrupt_survivor_chained_root: bool,
) !void {
    var built = try buildSet(allocator, resigned);
    defer built.set.deinit(allocator);

    var resolver = fec.FecResolver.initWithSimd(allocator, 64, VERSION);
    defer resolver.deinit();

    // Optionally corrupt one surviving data shred's chained_root tail (negative path).
    if (corrupt_survivor_chained_root) {
        // shred 1 is always a survivor in our erase sets; flip a byte in its chained_root.
        const suffix: usize = if (resigned) 64 else 0;
        const proof_bytes: usize = 120; // depth 6
        const data_sz: usize = 1203;
        const chain_off = data_sz - suffix - 32 - proof_bytes;
        built.set.data[1][chain_off] ^= 0xff;
    }

    const erased = std.StaticBitSet(64).initEmpty();
    var erased_mut = erased;
    for (erase) |e| erased_mut.set(e);

    var last_result: fec.FecResolver.AddResult = .pending;

    // Feed surviving DATA shreds (skip erased ones).
    for (0..N) |i| {
        if (erased_mut.isSet(i)) continue;
        const d = built.set.data[i];
        last_result = try resolver.addShred(
            SLOT,
            FEC_SET_IDX + @as(u32, @intCast(i)),
            FEC_SET_IDX,
            true,
            d,
            VERSION,
            @intCast(N),
            @intCast(M),
            0,
        );
    }
    // Feed ALL parity shreds.
    for (0..M) |j| {
        const c = built.set.code[j];
        last_result = try resolver.addShred(
            SLOT,
            FEC_SET_IDX + @as(u32, @intCast(N + j)), // global code index
            FEC_SET_IDX,
            false,
            c,
            VERSION,
            @intCast(N),
            @intCast(M),
            @intCast(j),
        );
    }

    const key = fec.FecResolver.makeKey(SLOT, FEC_SET_IDX);
    const set_ptr = resolver.active_sets.get(key) orelse return error.SetMissing;

    if (corrupt_survivor_chained_root) {
        // NEGATIVE: gate must reject — the set must NOT be complete, and the erased
        // data shred slots must remain empty (nothing poisoned in).
        try std.testing.expect(!set_ptr.is_complete);
        for (erase) |e| {
            try std.testing.expect(set_ptr.data_shreds[e] == null);
        }
        return;
    }

    // POSITIVE: recovery completed.
    try std.testing.expectEqual(fec.FecResolver.AddResult.complete, last_result);
    try std.testing.expect(set_ptr.is_complete);

    // Every recovered (erased) data shred must byte-match the original wire shred.
    for (erase) |e| {
        const recovered = set_ptr.data_shreds[e] orelse return error.NotRecovered;
        const original = built.set.data[e];
        try std.testing.expectEqual(original.len, recovered.len);
        try std.testing.expectEqualSlices(u8, original, recovered);

        // And merkleRoot32 / chainedMerkleRoot of the recovered shred == originals.
        const rec_shred = try shred_mod.parseShred(recovered);
        const orig_shred = try shred_mod.parseShred(original);
        const rr = rec_shred.merkleRoot32() orelse return error.NoRoot;
        const orr = orig_shred.merkleRoot32() orelse return error.NoRoot;
        try std.testing.expectEqualSlices(u8, &orr, &rr);
        const rcr = rec_shred.chainedMerkleRoot() orelse return error.NoChained;
        try std.testing.expectEqualSlices(u8, &built.chained_root, &rcr);
    }
}

test "#61 chained recovery: erase 4 data shreds, recover from parity (non-resigned)" {
    const erase = [_]usize{ 0, 5, 17, 31 };
    try recoverScenario(std.testing.allocator, false, &erase, false);
}

test "#61 chained recovery: erase 16 data shreds (max half), recover (non-resigned)" {
    var erase: [16]usize = undefined;
    for (0..16) |i| erase[i] = i * 2; // even indices 0,2,...,30
    try recoverScenario(std.testing.allocator, false, &erase, false);
}

test "#61 chained+resigned recovery: erase 3 data shreds, recover + restamp retransmitter sig" {
    const erase = [_]usize{ 2, 9, 30 };
    try recoverScenario(std.testing.allocator, true, &erase, false);
}

test "#61 root-gate REJECT: corrupted surviving chained_root → no recovery, nothing inserted" {
    const erase = [_]usize{ 0, 7, 20 };
    try recoverScenario(std.testing.allocator, false, &erase, true);
}
