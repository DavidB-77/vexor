//! Canonical Solana Entry module — PoH entry hashing + entry-batch wire (de)serialization.
//!
//! This is SB-3 (the "shared blocker" Entry module) from BLOCK-PRODUCTION-STAGING-2026-06-10.md.
//! It is OFFLINE / STAGED ONLY — nothing here is wired into the live validator path. It exists so
//! the block producer can EMIT entries byte-exactly (and so RPC `getBlock` can DECODE them) once
//! wiring is explicitly enabled after net_hash removal.
//!
//! Ground truth: Agave 4.1.0-beta.3 (git tag v4.1.0-beta.3), verified file:line:
//!   - merkle-tree/src/merkle_tree.rs : LEAF_PREFIX=[0], INTERMEDIATE_PREFIX=[1],
//!         leaf = sha256([0] ‖ item); intermediate = sha256([1] ‖ L ‖ R);
//!         odd level → duplicate last node; next_level_len(1)=0 else div_ceil(2);
//!         root = last node; empty tree → get_root()==None.
//!   - entry/src/entry.rs:317-324 `hash_signatures`: MerkleTree over the signature byte slices;
//!         empty → Hash::default() (all-zero).
//!   - entry/src/entry.rs:326-333 `hash_transactions`: flat-map every tx's signatures, then hash_signatures.
//!   - entry/src/entry.rs:335-367 `next_hash`/`next_hash_with_signatures`:
//!         if num_hashes==0 && num_txs==0 → start_hash;
//!         else poh.hash(num_hashes-1); if num_txs==0 → poh.tick() (one more sha256)
//!                                       else → poh.record(hash_signatures(sigs)) = sha256(hash ‖ root).
//!   - entry/src/poh.rs:64-75 `hash(n)` = sha256 applied n times; :77-91 `record(mixin)` = sha256(hash ‖ mixin);
//!         :128-131 `tick()` = one more sha256.
//!
//! Entry-batch wire format (the inverse of the replay-side parser at
//! src/vex_svm/replay_stage.zig:4133-4135):
//!   batch = u64 LE entry_count, then per entry:
//!     u64 LE num_hashes, [32]u8 hash, u64 LE num_txs, then num_txs concatenated
//!     VersionedTransaction bincode blobs.
//! (A produced slot is one logical Entry stream; the shredder chunks it into shred-sized batches.)

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const HASH_BYTES: usize = 32;
pub const Hash = [HASH_BYTES]u8;
pub const ZERO_HASH: Hash = [_]u8{0} ** HASH_BYTES;

/// Solana MerkleTree prefixes (merkle_tree.rs:6-7).
const LEAF_PREFIX: [1]u8 = .{0};
const INTERMEDIATE_PREFIX: [1]u8 = .{1};

/// sha256 over the concatenation of `parts` (the `solana_sha256_hasher::hashv` shape).
pub fn hashv(parts: []const []const u8) Hash {
    var h = Sha256.init(.{});
    for (parts) |p| h.update(p);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

/// sha256 applied once.
inline fn hashOnce(input: Hash) Hash {
    return hashv(&.{&input});
}

/// merkle_tree.rs:63-68 next_level_len.
inline fn nextLevelLen(level_len: usize) usize {
    if (level_len == 1) return 0;
    return (level_len + 1) / 2; // div_ceil(2)
}

/// Solana MerkleTree root over `items` (each item hashed as a leaf).
/// Mirrors merkle_tree.rs:94-136 `MerkleTree::new` + get_root. Empty → ZERO_HASH
/// (matches `hash_signatures`: get_root()==None → Hash::default()).
///
/// `items` are arbitrary byte slices; for `hash_signatures` they are the 64-byte signatures.
pub fn merkleRoot(allocator: std.mem.Allocator, items: []const []const u8) !Hash {
    if (items.len == 0) return ZERO_HASH;
    if (items.len == 1) return hashv(&.{ &LEAF_PREFIX, items[0] });

    var nodes: std.ArrayListUnmanaged(Hash) = .{};
    defer nodes.deinit(allocator);

    // Level 0: leaves.
    for (items) |item| {
        try nodes.append(allocator, hashv(&.{ &LEAF_PREFIX, item }));
    }

    var level_len = nextLevelLen(items.len);
    var level_start: usize = items.len;
    var prev_level_len: usize = items.len;
    var prev_level_start: usize = 0;
    while (level_len > 0) {
        var i: usize = 0;
        while (i < level_len) : (i += 1) {
            const prev_idx = 2 * i;
            const lsib = nodes.items[prev_level_start + prev_idx];
            const rsib = if (prev_idx + 1 < prev_level_len)
                nodes.items[prev_level_start + prev_idx + 1]
            else
                nodes.items[prev_level_start + prev_idx]; // odd → duplicate last
            try nodes.append(allocator, hashv(&.{ &INTERMEDIATE_PREFIX, &lsib, &rsib }));
        }
        prev_level_start = level_start;
        prev_level_len = level_len;
        level_start += level_len;
        level_len = nextLevelLen(level_len);
    }

    return nodes.items[nodes.items.len - 1]; // get_root = last node
}

/// entry.rs:317-324 hash_signatures.
pub fn hashSignatures(allocator: std.mem.Allocator, signatures: []const []const u8) !Hash {
    return merkleRoot(allocator, signatures);
}

/// entry.rs:326-333 hash_transactions: flat-map every tx's signatures, then hash_signatures.
/// `tx_signatures[i]` is the list of one transaction's signatures (each a 64-byte slice).
pub fn hashTransactions(allocator: std.mem.Allocator, tx_signatures: []const []const []const u8) !Hash {
    var flat: std.ArrayListUnmanaged([]const u8) = .{};
    defer flat.deinit(allocator);
    for (tx_signatures) |tx_sigs| {
        for (tx_sigs) |sig| try flat.append(allocator, sig);
    }
    return merkleRoot(allocator, flat.items);
}

/// entry.rs:335-367 next_hash / next_hash_with_signatures.
/// Computes the PoH hash AFTER an entry: `num_hashes` sha256 steps from `start_hash`, with the
/// final step being either a plain tick (no txs) or a record-mixin of the signature merkle root.
///
/// `signatures` is the flat list of all of this entry's transactions' signatures (already flattened
/// by the caller, exactly as Agave flat-maps in next_hash).
pub fn nextHash(
    allocator: std.mem.Allocator,
    start_hash: Hash,
    num_hashes: u64,
    num_transactions: usize,
    signatures: []const []const u8,
) !Hash {
    if (num_hashes == 0 and num_transactions == 0) return start_hash;

    // poh.hash(num_hashes - 1): sha256 applied (num_hashes-1) times (saturating at 0).
    var poh = start_hash;
    var remaining: u64 = if (num_hashes > 0) num_hashes - 1 else 0;
    while (remaining > 0) : (remaining -= 1) poh = hashOnce(poh);

    if (num_transactions == 0) {
        return hashOnce(poh); // tick(): one more sha256
    }
    const root = try hashSignatures(allocator, signatures);
    return hashv(&.{ &poh, &root }); // record(mixin): sha256(hash ‖ root)
}

// ── Entry-batch wire (de)serialization ──────────────────────────────────────

/// One entry as the producer holds it: the PoH header plus the raw bincode bytes of each
/// VersionedTransaction. `transactions[i]` is one tx's already-serialized wire bytes.
pub const Entry = struct {
    num_hashes: u64,
    hash: Hash,
    transactions: []const []const u8,
};

/// Serialize a slice of entries into the replay-parser wire format
/// (u64 count, then per entry: u64 num_hashes, [32] hash, u64 num_txs, tx bytes...).
/// Caller owns the returned buffer.
pub fn serializeEntries(allocator: std.mem.Allocator, entries: []const Entry) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(allocator);

    try appendU64LE(&buf, allocator, @intCast(entries.len));
    for (entries) |e| {
        try appendU64LE(&buf, allocator, e.num_hashes);
        try buf.appendSlice(allocator, &e.hash);
        try appendU64LE(&buf, allocator, @intCast(e.transactions.len));
        for (e.transactions) |tx| try buf.appendSlice(allocator, tx);
    }
    return buf.toOwnedSlice(allocator);
}

/// A parsed entry header. Transaction bytes are NOT sliced here: VersionedTransaction is
/// self-delimiting bincode, so determining each tx's length requires the tx parser (owned by
/// the replay path). `txs_offset` is the byte offset in the source buffer where this entry's
/// `num_txs` transaction blobs begin.
pub const EntryHeader = struct {
    num_hashes: u64,
    hash: Hash,
    num_txs: u64,
    txs_offset: usize,
};

pub const ParseError = error{ Truncated, TooManyEntries };

/// Parse just the batch count + the FIRST entry's header (the part entry.zig fully owns without a
/// tx parser). For entries with num_txs==0 the next entry begins immediately after the header, so
/// `parseEntryHeaders` can walk a whole tick-only batch; tx-bearing batches need the replay tx
/// parser to advance past each tx (see replay_stage.zig:4141). Returns the entry count.
pub fn readEntryCount(data: []const u8) ParseError!u64 {
    if (data.len < 8) return error.Truncated;
    return std.mem.readInt(u64, data[0..8], .little);
}

/// Read one entry header starting at `offset`. Returns the header (with txs_offset pointing past
/// the header). Does NOT advance over transaction bytes.
pub fn readEntryHeader(data: []const u8, offset: usize) ParseError!EntryHeader {
    if (offset + 8 + HASH_BYTES + 8 > data.len) return error.Truncated;
    var o = offset;
    const num_hashes = std.mem.readInt(u64, data[o..][0..8], .little);
    o += 8;
    var hash: Hash = undefined;
    @memcpy(&hash, data[o..][0..HASH_BYTES]);
    o += HASH_BYTES;
    const num_txs = std.mem.readInt(u64, data[o..][0..8], .little);
    o += 8;
    return .{ .num_hashes = num_hashes, .hash = hash, .num_txs = num_txs, .txs_offset = o };
}

inline fn appendU64LE(buf: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, v: u64) !void {
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u64, &tmp, v, .little);
    try buf.appendSlice(allocator, &tmp);
}

// ════════════════════════════════════════════════════════════════════════════
// KATs — gated against Agave 4.1.0-beta.3 golden values. Run: `zig build test-entry`.
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "merkle: empty -> ZERO_HASH (hash_signatures get_root None)" {
    const root = try hashSignatures(testing.allocator, &.{});
    try testing.expectEqual(ZERO_HASH, root);
}

test "merkle: single leaf == sha256([0] ‖ item) (merkle_tree.rs:192-198)" {
    const item: []const u8 = "test";
    const root = try merkleRoot(testing.allocator, &.{item});
    const expected = hashv(&.{ &LEAF_PREFIX, item });
    try testing.expectEqual(expected, root);
}

test "merkle: 11-leaf golden vector (merkle_tree.rs:200-212 test_tree_from_many)" {
    // TEST = ["my","very","eager","mother","just","served","us","nine","pizzas","make","prime"]
    const items = [_][]const u8{
        "my", "very", "eager", "mother", "just", "served", "us", "nine", "pizzas", "make", "prime",
    };
    const root = try merkleRoot(testing.allocator, &items);
    // Agave golden root (hex).
    var expected: Hash = undefined;
    _ = try std.fmt.hexToBytes(&expected, "b40c847546fdceea166f927fc46c5ca33c3638236a36275c1346d3dffb84e1bc");
    try testing.expectEqual(expected, root);
}

test "nextHash: identity when num_hashes==0 && num_txs==0" {
    const start: Hash = [_]u8{0xAB} ** 32;
    const h = try nextHash(testing.allocator, start, 0, 0, &.{});
    try testing.expectEqual(start, h);
}

test "nextHash: tick (no txs) — num_hashes sha256 steps from start" {
    const start: Hash = [_]u8{0x11} ** 32;
    // num_hashes=1, txs=0: poh.hash(0) then tick() = one sha256(start).
    const h1 = try nextHash(testing.allocator, start, 1, 0, &.{});
    try testing.expectEqual(hashOnce(start), h1);
    // num_hashes=3, txs=0: hash twice then tick = sha256^3(start).
    const h3 = try nextHash(testing.allocator, start, 3, 0, &.{});
    try testing.expectEqual(hashOnce(hashOnce(hashOnce(start))), h3);
}

test "nextHash: record (with txs) — sha256(poh ‖ merkle_root(sigs))" {
    const start: Hash = [_]u8{0x22} ** 32;
    const sig_a: [64]u8 = [_]u8{0xAA} ** 64;
    const sig_b: [64]u8 = [_]u8{0xBB} ** 64;
    const sigs = [_][]const u8{ &sig_a, &sig_b };
    // num_hashes=1, txs=1: poh.hash(0) = start, then record(root).
    const root = try hashSignatures(testing.allocator, &sigs);
    const expected = hashv(&.{ &start, &root });
    const h = try nextHash(testing.allocator, start, 1, 1, &sigs);
    try testing.expectEqual(expected, h);
    // record is NOT per-signature: a 2-sig entry uses ONE mixin of the merkle root, not two hashes.
    try testing.expect(!std.mem.eql(u8, &h, &hashv(&.{ &start, &sig_a, &sig_b })));
}

test "wire: serialize -> readEntryCount/readEntryHeader round-trip (tick-only batch)" {
    const h0: Hash = [_]u8{0x01} ** 32;
    const h1: Hash = [_]u8{0x02} ** 32;
    const entries = [_]Entry{
        .{ .num_hashes = 5, .hash = h0, .transactions = &.{} },
        .{ .num_hashes = 12500, .hash = h1, .transactions = &.{} },
    };
    const bytes = try serializeEntries(testing.allocator, &entries);
    defer testing.allocator.free(bytes);

    try testing.expectEqual(@as(u64, 2), try readEntryCount(bytes));

    const e0 = try readEntryHeader(bytes, 8);
    try testing.expectEqual(@as(u64, 5), e0.num_hashes);
    try testing.expectEqual(h0, e0.hash);
    try testing.expectEqual(@as(u64, 0), e0.num_txs);

    // tick-only entry: next entry begins immediately after this header.
    const e1 = try readEntryHeader(bytes, e0.txs_offset);
    try testing.expectEqual(@as(u64, 12500), e1.num_hashes);
    try testing.expectEqual(h1, e1.hash);
    try testing.expectEqual(@as(u64, 0), e1.num_txs);
}

test "wire: byte layout matches replay_stage parser (count, then num_hashes|hash|num_txs)" {
    const h0: Hash = [_]u8{0x09} ** 32;
    const tx: [3]u8 = .{ 0xDE, 0xAD, 0xBE }; // opaque tx blob (one tx)
    const entries = [_]Entry{
        .{ .num_hashes = 1, .hash = h0, .transactions = &.{&tx} },
    };
    const bytes = try serializeEntries(testing.allocator, &entries);
    defer testing.allocator.free(bytes);

    // [count=1][num_hashes=1][hash:32][num_txs=1][tx:3] = 8 + (8+32+8) + 3 = 59 bytes
    try testing.expectEqual(@as(usize, 59), bytes.len);
    try testing.expectEqual(@as(u64, 1), try readEntryCount(bytes));
    const e0 = try readEntryHeader(bytes, 8);
    try testing.expectEqual(@as(u64, 1), e0.num_hashes);
    try testing.expectEqual(@as(u64, 1), e0.num_txs);
    try testing.expectEqualSlices(u8, &tx, bytes[e0.txs_offset..][0..3]);
}
