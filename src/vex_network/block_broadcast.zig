//! M2 — empty-block shred BROADCAST driver + self-replay gate (OFFLINE/UNWIRED, leader_mode-gated).
//!
//! Turns one empty (tick-only) slot into the on-wire shred set the cluster validates. The byte-exact
//! ENCODER (shred_encoder.assembleFecSet) is pcap-proven (512/512 vs FD demo-shreds.pcap) and its
//! per-shred merkle-reconstruct + ed25519 + resigned-variant correctness are KAT'd in shred_encoder.zig.
//! This module is the DRIVER (correct params for an empty block) + the SELF-REPLAY GATE (the produced
//! shreds deshred back to the exact KAT'd-correct entry batch, and validate via the SAME merkle
//! primitive the receiver uses).
//!
//! Empty 64-tick slot entry batch = 8 + 64*48 = 3080 B → fits ONE FEC set (≤ 32*899=28768 resigned).
//! So an empty block = ONE assembleFecSet: fec_set_idx 0, is_resigned (block's last set), data_complete
//! + slot_complete on the last data shred, chained_root = parent bank.block_id (SIMD-0340), signed with
//! the LEADER IDENTITY secret, version = LIVE shred_version.
//!
//! reference_tick = 63: Agave sets it to `max_ticks_in_slot` (=ticks_per_slot=64) for the slot-
//! completing shred (turbine/.../standard_broadcast_run.rs:147), which `from_reference_tick` saturates
//! to SHRED_TICK_REFERENCE_MASK = 63 (ledger/src/shred.rs:166-167). Vexor's encoder masks
//! reference_tick & 0x3f, so passing 63 reproduces Agave's saturated value (passing 64 would mask→0).

const std = @import("std");
const bprod = @import("block_produce");
const enc = @import("shred_encoder.zig");
const hdr = @import("shred_header.zig");
const bmtree = @import("bmtree.zig");
const layout = @import("shred_layout.zig");

pub const Hash = [32]u8;

/// Usable data bytes per FEC set. UNSIGNED (intermediate) sets carry 30816 B (963 B/shred × 32);
/// the block's LAST set is RESIGNED and carries 28768 B (899 B/shred × 32). Mirrors Agave
/// merkle.rs:1036-1046 (ShredData::capacity(proof_size, resigned) × DATA_SHREDS_PER_FEC_BLOCK).
pub const UNSIGNED_FEC_SET_BYTES: usize = layout.CHAINED_FEC_SET_PAYLOAD_SZ; // 30816
pub const RESIGNED_FEC_SET_BYTES: usize = layout.RESIGNED_FEC_SET_PAYLOAD_SZ; // 28768
/// Shreds per FEC set (32 data + 32 code) and Agave's hard slot ceilings (shred.rs:118-129).
pub const DATA_SHREDS_PER_FEC_SET: u32 = @intCast(layout.FEC_SHRED_CNT); // 32
pub const MAX_FEC_SETS_PER_SLOT: usize = 1024; // Agave shred.rs MAX_FEC_SETS_PER_SLOT
pub const MAX_DATA_SHREDS_PER_SLOT: usize = 32768; // Agave shred.rs MAX_DATA_SHREDS_PER_SLOT

/// All FEC sets of one produced block + the block_id (= the LAST set's merkle root, SIMD-0340 — this
/// becomes the next slot's parent chained_root). Owns every set's 32 data + 32 code buffers.
pub const BlockShreds = struct {
    /// One entry per FEC set, in transmit order. sets[0] is chained to the parent block_id; sets[k]
    /// is chained to sets[k-1].root. The last set is the RESIGNED (slot-completing) set.
    sets: []enc.FecSetShreds,
    /// block_id = sets[sets.len-1].root (the merkle root of the block's last data shred). SIMD-0340.
    block_id: [32]u8,

    pub fn deinit(self: *BlockShreds, allocator: std.mem.Allocator) void {
        for (self.sets) |*s| s.deinit(allocator);
        allocator.free(self.sets);
    }

    /// Total data shreds across all sets (= 32 × number_of_sets).
    pub fn dataShredCount(self: *const BlockShreds) usize {
        return self.sets.len * layout.FEC_SHRED_CNT;
    }
};

/// reference_tick for a slot-completing shred = Agave max_ticks_in_slot saturated (see file header).
pub const COMPLETE_SLOT_REFERENCE_TICK: u8 = 63;

/// Produce the on-wire shreds (32 data + 32 code) for one EMPTY (tick-only) slot. Caller deinits.
/// `chained_root` = parent block's last-FEC merkle root (= parent bank.block_id). `secret_key` = the
/// leader IDENTITY ed25519 secret (64 B seed‖pubkey). `out_blockhash` (optional) = the slot blockhash.
pub fn produceEmptySlotShreds(
    allocator: std.mem.Allocator,
    slot: u64,
    parent_slot: u64,
    seed: Hash,
    shred_version: u16,
    chained_root: [32]u8,
    secret_key: [64]u8,
    hashes_per_tick: u64,
    ticks_per_slot: u64,
    out_blockhash: ?*Hash,
) !BlockShreds {
    const payload = try bprod.produceEmptySlotBytes(allocator, seed, hashes_per_tick, ticks_per_slot, out_blockhash);
    defer allocator.free(payload);
    return shredsFromEntryBytes(allocator, payload, slot, parent_slot, shred_version, chained_root, secret_key);
}

/// Shred a PRE-PRODUCED single-batch (whole-slot) entry payload into one OR MORE chained FEC sets, the
/// faithful Agave port of make_shreds_from_data with is_last_in_slot=true (merkle.rs:1017-1199).
///
/// The live leader path produces the bytes once (for the loopback freeze) then hands them here to shred
/// + broadcast, so the broadcast and the loopback carry byte-identical entries. Any payload size up to
/// MAX_DATA_SHREDS_PER_SLOT worth of data is handled (was capped to one resigned set before).
///
/// SPLIT (merkle.rs:1085-1163, is_last_in_slot=true): the FINAL set is RESIGNED and holds the LAST
/// min(len, 28768) bytes; everything before it is carved into UNSIGNED sets of 30816 B, where only the
/// last unsigned set may be partial (zero-padded by assembleFecSet). A payload ≤ 28768 B → exactly one
/// resigned set — byte-identical to the prior single-set behavior (verified by test-block-broadcast).
///
/// CHAIN (SIMD-0340): set[0].chained_root = the parent block_id (`chained_root` arg); set[k].chained_root
/// = set[k-1].root, threaded serially. FLAGS: data_complete + slot_complete land ONLY on the LAST set's
/// last data shred — Agave sets LAST_SHRED_IN_SLOT (⊃ DATA_COMPLETE) once on the block's final data shred
/// (merkle.rs:1165-1176); intermediate sets carry neither. INDICES: fec_set_idx / data_start_idx /
/// code_start_idx advance by 32 (DATA_SHREDS_PER_FEC_SET) per set (Agave uses the running data index as
/// fec_set_index). The returned block_id = the LAST set's root.
pub fn shredsFromEntryBytes(
    allocator: std.mem.Allocator,
    payload: []const u8,
    slot: u64,
    parent_slot: u64,
    shred_version: u16,
    chained_root: [32]u8,
    secret_key: [64]u8,
) !BlockShreds {
    const parent_off: u16 = @intCast(slot - parent_slot);

    // ── Determine the split (Agave merkle.rs:1085-1106, is_last_in_slot=true). ──
    // Reserve the last min(len, R) bytes for the single RESIGNED set; the prefix is unsigned.
    const resigned_len: usize = @min(payload.len, RESIGNED_FEC_SET_BYTES);
    const unsigned_len: usize = payload.len - resigned_len; // >0 only when payload > R
    // unsigned sets = ceil(unsigned_len / 30816) (a sub-30816 remainder is its own partial set); the
    // resigned set is always exactly one more. Matches Agave: number_of_fec_sets = unsigned_sets + 1.
    const unsigned_sets: usize = (unsigned_len + UNSIGNED_FEC_SET_BYTES - 1) / UNSIGNED_FEC_SET_BYTES;
    const number_of_sets: usize = unsigned_sets + 1;

    // Guard the Agave hard ceilings (shred.rs:118-129). A block this large is a packing bug, not a
    // legal slot — fail loudly rather than emit a block the cluster will reject.
    if (number_of_sets > MAX_FEC_SETS_PER_SLOT or number_of_sets * layout.FEC_SHRED_CNT > MAX_DATA_SHREDS_PER_SLOT) {
        return error.BlockTooLarge;
    }

    var sets = try allocator.alloc(enc.FecSetShreds, number_of_sets);
    var built: usize = 0;
    // On any mid-loop failure, free every set already assembled (no leak / no double-free).
    errdefer {
        for (sets[0..built]) |*s| s.deinit(allocator);
        allocator.free(sets);
    }

    var prev_root: [32]u8 = chained_root; // set[0] chains to the parent block_id
    var next_idx: u32 = 0; // running data index = fec_set_index for the current set
    var off: usize = 0; // byte offset into `payload` for the current set's chunk

    for (0..number_of_sets) |k| {
        const is_last = (k == number_of_sets - 1);
        // Intermediate sets take a full 30816-byte unsigned chunk (or the partial remainder for the
        // last unsigned set); the final set takes the reserved resigned tail.
        const chunk: []const u8 = if (is_last)
            payload[off .. off + resigned_len]
        else
            payload[off .. off + @min(UNSIGNED_FEC_SET_BYTES, unsigned_len - off)];

        const params = enc.FecSetParams{
            .slot = slot,
            .version = shred_version,
            .fec_set_idx = next_idx,
            .data_start_idx = next_idx,
            .code_start_idx = next_idx,
            .parent_off = parent_off,
            .reference_tick = COMPLETE_SLOT_REFERENCE_TICK,
            // Agave sets DATA_COMPLETE/SLOT_COMPLETE ONCE, on the block's final data shred only.
            .data_complete = is_last,
            .slot_complete = is_last,
            .is_resigned = is_last, // only the block's last set is resigned
        };
        sets[k] = try enc.assembleFecSet(allocator, params, chunk, prev_root, secret_key);
        built += 1;

        prev_root = sets[k].root; // next set chains to this set's root
        next_idx += DATA_SHREDS_PER_FEC_SET; // +32 per set
        off += chunk.len;
    }

    return .{ .sets = sets, .block_id = prev_root };
}

/// Deshred the data shreds back to the entry-batch payload: each data shred carries its un-padded
/// payload in [DATA_HEADER_SZ .. size] (size from the header). Concatenate in index order. Caller owns.
pub fn deshredDataPayload(allocator: std.mem.Allocator, data_shreds: []const []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);
    for (data_shreds) |d| {
        const h = try hdr.DataHeader.parse(d);
        const size: usize = h.size;
        std.debug.assert(size >= hdr.DATA_HEADER_SZ and size <= d.len);
        try buf.appendSlice(allocator, d[hdr.DATA_HEADER_SZ..size]);
    }
    return buf.toOwnedSlice(allocator);
}

/// Reconstruct the full block payload from a multi-set BlockShreds: deshred every set's data shreds in
/// FEC-set order (sets in transmit order, shreds in index order). Round-trips shredsFromEntryBytes.
/// Caller owns the returned buffer.
pub fn deshredBlock(allocator: std.mem.Allocator, block: *const BlockShreds) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);
    for (block.sets) |s| {
        for (s.data) |d| {
            const h = try hdr.DataHeader.parse(d);
            const size: usize = h.size;
            std.debug.assert(size >= hdr.DATA_HEADER_SZ and size <= d.len);
            try buf.appendSlice(allocator, d[hdr.DATA_HEADER_SZ..size]);
        }
    }
    return buf.toOwnedSlice(allocator);
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — driver param correctness + SELF-REPLAY GATE. Run: zig build test-block-broadcast
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "empty-block shreds: 32+32, correct headers, last shred DATA+SLOT complete, root nonzero" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;

    const slot: u64 = 415207452;
    const parent: u64 = 415207451;
    const seed: Hash = [_]u8{0x5A} ** 32;
    const chained: [32]u8 = [_]u8{0xC1} ** 32; // stand-in for parent bank.block_id
    const ver: u16 = 57087; // testnet shred_version (live value at deploy)
    const hpt: u64 = 8; // small for KAT speed (cadence identical at 62500)
    const tps: u64 = 64;

    var bh: Hash = undefined;
    var block = try produceEmptySlotShreds(a, slot, parent, seed, ver, chained, sk, hpt, tps, &bh);
    defer block.deinit(a);

    // empty 3080-B block → exactly ONE (resigned) FEC set, byte-identical to the prior single-set path.
    try testing.expectEqual(@as(usize, 1), block.sets.len);
    const set = block.sets[0];
    try testing.expectEqual(@as(usize, 32), set.data.len);
    try testing.expectEqual(@as(usize, 32), set.code.len);

    // headers: slot/version/fec_set_idx/idx; flags on the last data shred.
    for (set.data, 0..) |d, i| {
        const h = try hdr.DataHeader.parse(d);
        try testing.expectEqual(slot, h.common.slot);
        try testing.expectEqual(ver, h.common.version);
        try testing.expectEqual(@as(u32, 0), h.common.fec_set_idx);
        try testing.expectEqual(@as(u32, @intCast(i)), h.common.idx);
        try testing.expectEqual(@as(u16, @intCast(slot - parent)), h.parent_off);
        if (i == 31) {
            try testing.expect(h.isDataComplete());
            try testing.expect(h.isSlotComplete());
        }
    }

    // returned block_id (= this block's last-set root) is non-zero and equals the only set's root.
    try testing.expect(!std.mem.eql(u8, &block.block_id, &([_]u8{0} ** 32)));
    try testing.expectEqualSlices(u8, &set.root, &block.block_id);
}

test "SELF-REPLAY GATE: produced shreds deshred to the EXACT KAT-correct empty-block bytes" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const seed: Hash = [_]u8{0x77} ** 32;
    const chained: [32]u8 = [_]u8{0x09} ** 32;
    const hpt: u64 = 10;
    const tps: u64 = 64;

    // expected = the KAT'd-correct empty-slot entry batch (block_produce.zig is KAT-green).
    const expected = try bprod.produceEmptySlotBytes(a, seed, hpt, tps, null);
    defer a.free(expected);

    var block = try produceEmptySlotShreds(a, 100, 99, seed, 57087, chained, sk, hpt, tps, null);
    defer block.deinit(a);

    // deshred the data shreds → must byte-equal the expected entry batch (round-trip through the
    // on-wire shred payload regions = the bytes the cluster's deshred path reconstructs).
    const recon = try deshredBlock(a, &block);
    defer a.free(recon);
    try testing.expectEqualSlices(u8, expected, recon);
}

test "SELF-REPLAY GATE: every data shred's leaf+proof reconstructs to the signed root (receiver primitive)" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const seed: Hash = [_]u8{0x21} ** 32;
    const chained: [32]u8 = [_]u8{0x42} ** 32;

    var block = try produceEmptySlotShreds(a, 7, 6, seed, 57087, chained, sk, 8, 64, null);
    defer block.deinit(a);
    const set = block.sets[0]; // empty block = one resigned set

    // Resigned data shred: depth-6 proof of 120 bytes sits just before the 64-byte retransmitter
    // suffix; merkle leaf region is [64 .. proof_start]. reconstructRootFull is the SAME function the
    // live receiver uses to validate inbound shreds (shred_encoder.zig:319-321 / bmtree).
    const data_sz = set.data[0].len; // 1203
    const proof_bytes: usize = 6 * bmtree.MERKLE_NODE_SIZE; // 120
    const suffix: usize = 64; // resigned retransmitter sig
    const proof_start = data_sz - suffix - proof_bytes;
    for (set.data, 0..) |d, i| {
        const leaf = bmtree.MerkleTree.hashMerkleLeaf32(d[64..proof_start]);
        const r = bmtree.MerkleTree.reconstructRootFull(leaf, d[proof_start..][0..proof_bytes], @intCast(i));
        try testing.expectEqualSlices(u8, &set.root, &r);
    }
}

test "SELF-REPLAY GATE: every shred's ed25519 signature verifies over the root under the leader pubkey" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const seed: Hash = [_]u8{0x33} ** 32;
    const chained: [32]u8 = [_]u8{0x55} ** 32;

    var block = try produceEmptySlotShreds(a, 9, 8, seed, 57087, chained, sk, 8, 64, null);
    defer block.deinit(a);
    const set = block.sets[0]; // empty block = one resigned set

    // The encoder signs the 32-byte merkle root and writes the same 64-byte sig into EVERY shred
    // (shred_encoder.zig:173-177). The cluster verifies this under the leader's identity pubkey —
    // a bad sig = every peer drops the shred. Verify all 64 shreds round-trip.
    for (set.data) |d| {
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(d[0..64].*);
        try sig.verify(&set.root, kp.public_key);
    }
    for (set.code) |c| {
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(c[0..64].*);
        try sig.verify(&set.root, kp.public_key);
    }
}

test "MULTI-SLOT LEADER WINDOW: each produced slot's block_id chains the next (chaining-fix invariant)" {
    // Verifies the byte-level invariant the 2026-06-19 chaining fix relies on: a produced slot's
    // block_id (= last-FEC merkle root, exactly what tvu.computeProducedBlockId returns and
    // self_produced_block_id stashes) is a NON-ZERO, deterministic value that the NEXT slot of our
    // leader window chains to. We reproduce the produce-path feed-forward (slot N's block_id → slot
    // N+1's chained_root) and assert each slot's shreds EMBED the prior slot's block_id as their
    // chained_root. (The replay-stage stash/freeze plumbing that performs this feed-forward live is
    // verified by code review + the live 4-slot-window loopback run; this KAT pins the bytes.)
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const ver: u16 = 1516;
    const hpt: u64 = 10;
    const tps: u64 = 64;
    const proof_bytes: usize = 6 * bmtree.MERKLE_NODE_SIZE; // 120
    const W = 4;
    const parent_slot: u64 = 416415903; // slot before a 4-slot window
    const cluster_parent_id: [32]u8 = [_]u8{0xC1} ** 32; // cluster's last block_id before our window

    var ids: [W][32]u8 = undefined;
    var chained: [32]u8 = cluster_parent_id;
    var k: usize = 0;
    while (k < W) : (k += 1) {
        const slot = parent_slot + 1 + k;
        const psl = parent_slot + k;
        const seed: Hash = [_]u8{@as(u8, @intCast(0x40 + k))} ** 32;
        const bytes = try bprod.produceEmptySlotBytes(a, seed, hpt, tps, null);
        defer a.free(bytes);
        var block = try shredsFromEntryBytes(a, bytes, slot, psl, ver, chained, sk);
        defer block.deinit(a);

        // empty block = ONE resigned set; its embedded chained_root MUST equal what we fed forward
        // (slot 0 → cluster parent; slot N+1 → slot N's block_id). This is the chaining fix's effect.
        const s0 = block.sets[0];
        const chain_off = s0.data[0].len - 64 - 32 - proof_bytes; // resigned suffix = 64
        try testing.expectEqualSlices(u8, &chained, s0.data[0][chain_off..][0..32]);

        // block_id = last set's root, NON-ZERO → a usable chained_root for the next slot (the value
        // that was null pre-fix, causing slot N+1 to skip).
        try testing.expectEqualSlices(u8, &block.sets[block.sets.len - 1].root, &block.block_id);
        try testing.expect(!std.mem.eql(u8, &block.block_id, &([_]u8{0} ** 32)));

        ids[k] = block.block_id;
        chained = block.block_id; // FEED FORWARD — exactly what self_produced_block_id does live
    }

    // all W block_ids distinct (each slot is a distinct block → distinct root; a degenerate reuse fails here).
    var x: usize = 0;
    while (x < W) : (x += 1) {
        var y: usize = x + 1;
        while (y < W) : (y += 1) try testing.expect(!std.mem.eql(u8, &ids[x], &ids[y]));
    }

    // DETERMINISM: re-running the window yields identical block_ids (computeProducedBlockId is a pure
    // fn of bytes+chained_root+key+version) → the value replay stashes == what broadcast transmits ==
    // what slot N+1 chains to. (If it weren't deterministic, the loopback chain ≠ the broadcast chain.)
    var chained2: [32]u8 = cluster_parent_id;
    k = 0;
    while (k < W) : (k += 1) {
        const slot = parent_slot + 1 + k;
        const psl = parent_slot + k;
        const seed: Hash = [_]u8{@as(u8, @intCast(0x40 + k))} ** 32;
        const bytes = try bprod.produceEmptySlotBytes(a, seed, hpt, tps, null);
        defer a.free(bytes);
        var block = try shredsFromEntryBytes(a, bytes, slot, psl, ver, chained2, sk);
        defer block.deinit(a);
        try testing.expectEqualSlices(u8, &ids[k], &block.block_id);
        chained2 = block.block_id;
    }
}

// ─── MULTI-FEC-SET gate: payload > 30816 B forces ≥ 2 chained FEC sets (the full-fix replacement for
//     the single-FEC-set 20 KB band-aid cap). Faithful Agave merkle.rs:1085-1199 port. ───

test "MULTI-FEC: >30816 B payload → ≥2 chained sets, +32 indices, last-set-only SLOT_COMPLETE, round-trips" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const slot: u64 = 415300000;
    const parent: u64 = 415299998; // parent_off = 2
    const parent_block_id: [32]u8 = [_]u8{0xAB} ** 32; // stand-in for the parent bank.block_id
    const ver: u16 = 57087;

    // 100_000 B payload → split last 28768 (resigned) + prefix 71232 → ceil(71232/30816)=3 unsigned
    // → 4 sets (UUUR), payloads [30816, 30816, 9600, 28768]. >30816 forces ≥2 (here 4).
    const total: usize = 100_000;
    const payload = try a.alloc(u8, total);
    defer a.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast((i * 251 + 13) & 0xFF); // distinct, non-zero pattern

    var block = try shredsFromEntryBytes(a, payload, slot, parent, ver, parent_block_id, sk);
    defer block.deinit(a);

    // (a) number_of_sets == ceil split (UUUR = 4). Generic recompute mirrors the impl's formula.
    const resigned_len = @min(total, RESIGNED_FEC_SET_BYTES);
    const unsigned_len = total - resigned_len;
    const expect_sets = ((unsigned_len + UNSIGNED_FEC_SET_BYTES - 1) / UNSIGNED_FEC_SET_BYTES) + 1;
    try testing.expectEqual(@as(usize, 4), expect_sets);
    try testing.expectEqual(expect_sets, block.sets.len);

    // (b) each set has exactly 32 data + 32 code.
    for (block.sets) |s| {
        try testing.expectEqual(@as(usize, 32), s.data.len);
        try testing.expectEqual(@as(usize, 32), s.code.len);
    }

    // (c) SIMD-0340 chain: set[0].chained_root == parent block_id; set[k].chained_root == set[k-1].root.
    //     The chained_root is embedded at chain_off in EVERY data shred (= shred[chain_off..+32]); read it
    //     back from data shred 0 of each set and compare to the expected prior root.
    const proof_bytes: usize = 6 * bmtree.MERKLE_NODE_SIZE; // 120
    for (block.sets, 0..) |s, k| {
        const is_last = (k == block.sets.len - 1);
        const suffix: usize = if (is_last) 64 else 0; // resigned tail only on the last set
        const chain_off = s.data[0].len - suffix - 32 - proof_bytes;
        const embedded = s.data[0][chain_off..][0..32];
        const expected_prior: [32]u8 = if (k == 0) parent_block_id else block.sets[k - 1].root;
        try testing.expectEqualSlices(u8, &expected_prior, embedded);
    }
    // block_id == the LAST set's root (the next slot's parent chained_root).
    try testing.expectEqualSlices(u8, &block.sets[block.sets.len - 1].root, &block.block_id);

    // (d) ONLY the last set's last data shred carries SLOT_COMPLETE (Agave sets it once on the block's
    //     final data shred). No intermediate set's shreds carry DATA_COMPLETE or SLOT_COMPLETE.
    for (block.sets, 0..) |s, k| {
        const is_last_set = (k == block.sets.len - 1);
        for (s.data, 0..) |d, i| {
            const h = try hdr.DataHeader.parse(d);
            const want_complete = is_last_set and (i == 31);
            try testing.expectEqual(want_complete, h.isSlotComplete());
            try testing.expectEqual(want_complete, h.isDataComplete());
        }
    }

    // indices: fec_set_idx / idx advance by 32 per set; data shred j of set k has idx = 32*k + j.
    for (block.sets, 0..) |s, k| {
        const base: u32 = @intCast(32 * k);
        for (s.data, 0..) |d, i| {
            const h = try hdr.DataHeader.parse(d);
            try testing.expectEqual(base, h.common.fec_set_idx);
            try testing.expectEqual(base + @as(u32, @intCast(i)), h.common.idx);
        }
        for (s.code, 0..) |c, j| {
            const ch = try hdr.CodeHeader.parse(c);
            try testing.expectEqual(base, ch.common.fec_set_idx);
            try testing.expectEqual(base + @as(u32, @intCast(j)), ch.common.idx);
        }
    }

    // (e) the LAST set is resigned (variant 0xB6 on its data shreds; intermediate sets are 0x96).
    for (block.sets, 0..) |s, k| {
        const is_last_set = (k == block.sets.len - 1);
        const want_variant: u8 = if (is_last_set) 0xB6 else 0x96; // resigned-data / chained-data
        try testing.expectEqual(want_variant, s.data[0][64]);
    }

    // every shred reconstructs to its set's signed root, and the sig verifies (consensus receive path).
    for (block.sets) |s| {
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(s.data[0][0..64].*);
        try sig.verify(&s.root, kp.public_key);
        // data leaves (resigned vs unsigned differ only in the 64-byte suffix offset).
        const is_resigned_set = std.mem.eql(u8, &s.root, &block.block_id);
        const dsuffix: usize = if (is_resigned_set) 64 else 0;
        const dproof_start = s.data[0].len - dsuffix - proof_bytes;
        for (s.data, 0..) |d, i| {
            const leaf = bmtree.MerkleTree.hashMerkleLeaf32(d[64..dproof_start]);
            const r = bmtree.MerkleTree.reconstructRootFull(leaf, d[dproof_start..][0..proof_bytes], @intCast(i));
            try testing.expectEqualSlices(u8, &s.root, &r);
        }
    }

    // (f) reconstructing the block from ALL sets' data shreds round-trips the original payload exactly.
    const recon = try deshredBlock(a, &block);
    defer a.free(recon);
    try testing.expectEqualSlices(u8, payload, recon);
}

test "MULTI-FEC: exactly-28768 B (resigned boundary) stays ONE resigned set; 28769 B → two sets" {
    const a = testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    const sk: [64]u8 = kp.secret_key.bytes;
    const pid: [32]u8 = [_]u8{0x07} ** 32;

    // Exactly R = 28768 → one resigned set (boundary: must NOT spill into a second set).
    const p1 = try a.alloc(u8, RESIGNED_FEC_SET_BYTES);
    defer a.free(p1);
    for (p1, 0..) |*b, i| b.* = @intCast((i * 31 + 7) & 0xFF);
    var b1 = try shredsFromEntryBytes(a, p1, 50, 49, 57087, pid, sk);
    defer b1.deinit(a);
    try testing.expectEqual(@as(usize, 1), b1.sets.len);
    try testing.expect(std.mem.eql(u8, &b1.sets[0].root, &b1.block_id));
    const r1 = try deshredBlock(a, &b1);
    defer a.free(r1);
    try testing.expectEqualSlices(u8, p1, r1);

    // R+1 = 28769 → 1 unsigned (1 byte, padded) + 1 resigned = 2 sets (UR).
    const p2 = try a.alloc(u8, RESIGNED_FEC_SET_BYTES + 1);
    defer a.free(p2);
    for (p2, 0..) |*b, i| b.* = @intCast((i * 17 + 3) & 0xFF);
    var b2 = try shredsFromEntryBytes(a, p2, 50, 49, 57087, pid, sk);
    defer b2.deinit(a);
    try testing.expectEqual(@as(usize, 2), b2.sets.len);
    // chain: set[1] chains to set[0].root; set[0] chains to the parent.
    try testing.expect(std.mem.eql(u8, &b2.sets[1].root, &b2.block_id));
    const r2 = try deshredBlock(a, &b2);
    defer a.free(r2);
    try testing.expectEqualSlices(u8, p2, r2);
}
