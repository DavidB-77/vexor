//! Streaming Proof-of-History generator for block production (the producer-side engine).
//!
//! STAGED / MODULAR: not wired to the live path. Gated behind -Dleader_mode at the call site.
//! This module owns the byte-exact PoH HASH CADENCE (hash/record/tick bookkeeping). Real-time
//! pacing (target_poh_time wall-clock), the FD 6-state leader machine, grace ticks, and skipped-
//! slot publishing are a separate WIRING concern (they decide WHEN to advance, not WHAT hash an
//! advance produces) and are deliberately omitted here so the offline KAT is deterministic.
//!
//! Ground truth: Agave 4.1.0-beta.3 entry/src/poh.rs (faithful port of `Poh`):
//!   hash(max): n = min(remaining_until_tick-1, max); sha256 n times; returns remaining==1.
//!   record(mixin): if remaining==1 -> null (must tick first); else hash=sha256(hash‖mixin),
//!                  entry.num_hashes = num_hashes+1; num_hashes=0; remaining-=1.
//!   tick(): hash=sha256(hash); num_hashes+=1; remaining-=1; emit a tick entry only when
//!           remaining hits 0 (or low-power), then remaining=hashes_per_tick; num_hashes=0.
//!
//! hashes_per_tick is supplied by the CALLER (e.g. 62500 effective testnet, read from the snapshot
//! manifest — NOT the genesis 12500; see task #28). Tests use a small value for speed.

const std = @import("std");
const entry = @import("entry.zig");
const Hash = entry.Hash;

/// LOW_POWER_MODE — when hashes_per_tick == this, every tick() emits (poh.rs:9,135).
pub const LOW_POWER_MODE: u64 = std.math.maxInt(u64);

pub const PohEntry = struct {
    num_hashes: u64,
    hash: Hash,
};

pub const Poh = struct {
    hash: Hash,
    num_hashes: u64 = 0,
    hashes_per_tick: u64,
    remaining_hashes_until_tick: u64,
    tick_number: u64 = 0,

    pub fn init(seed: Hash, hashes_per_tick: u64) Poh {
        std.debug.assert(hashes_per_tick > 1);
        return .{
            .hash = seed,
            .num_hashes = 0,
            .hashes_per_tick = hashes_per_tick,
            .remaining_hashes_until_tick = hashes_per_tick,
            .tick_number = 0,
        };
    }

    /// reset to a new seed (next slot start = previous slot's last tick hash). poh.rs:45-49.
    pub fn reset(self: *Poh, seed: Hash, hashes_per_tick: u64) void {
        self.* = Poh.init(seed, hashes_per_tick);
    }

    inline fn sha256(input: Hash) Hash {
        return entry.hashv(&.{&input});
    }

    /// hash up to `max_num_hashes` (clamped to just before the tick boundary).
    /// Returns true if the caller must tick() next (remaining == 1). poh.rs:64-75.
    pub fn hashN(self: *Poh, max_num_hashes: u64) bool {
        const n = @min(self.remaining_hashes_until_tick - 1, max_num_hashes);
        var i: u64 = 0;
        while (i < n) : (i += 1) self.hash = sha256(self.hash);
        self.num_hashes += n;
        self.remaining_hashes_until_tick -= n;
        std.debug.assert(self.remaining_hashes_until_tick > 0);
        return self.remaining_hashes_until_tick == 1;
    }

    /// record a microblock mixin (= merkle root of the entry's tx signatures). poh.rs:77-91.
    /// Returns null if at a tick boundary (caller must tick() first).
    pub fn record(self: *Poh, mixin: Hash) ?PohEntry {
        if (self.remaining_hashes_until_tick == 1) return null;
        self.hash = entry.hashv(&.{ &self.hash, &mixin });
        const nh = self.num_hashes + 1;
        self.num_hashes = 0;
        self.remaining_hashes_until_tick -= 1;
        return .{ .num_hashes = nh, .hash = self.hash };
    }

    /// emit a tick if at the boundary. poh.rs:128-146.
    pub fn tick(self: *Poh) ?PohEntry {
        self.hash = sha256(self.hash);
        self.num_hashes += 1;
        self.remaining_hashes_until_tick -= 1;
        if (self.hashes_per_tick != LOW_POWER_MODE and self.remaining_hashes_until_tick != 0) return null;
        const nh = self.num_hashes;
        self.remaining_hashes_until_tick = self.hashes_per_tick;
        self.num_hashes = 0;
        self.tick_number += 1;
        return .{ .num_hashes = nh, .hash = self.hash };
    }
};

/// A microblock the producer wants to record this slot: the flat signature-merkle-root mixin.
/// (Empty microblocks are skipped by the producer; only tx-bearing entries are recorded.)
pub const Microblock = struct { mixin: Hash };

/// Drive ONE full slot offline: hash to each tick boundary, recording queued microblocks where they
/// fit, emitting `ticks_per_slot` ticks. Appends every produced entry (record + tick) to `out` in
/// PoH order. Returns the slot's final hash (= blockhash, the last tick's hash). Deterministic — no
/// wall clock. This is the byte-exact core the wired producer will pace with a real clock.
pub fn produceSlot(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(PohEntry),
    seed: Hash,
    hashes_per_tick: u64,
    ticks_per_slot: u64,
    microblocks: []const Microblock,
) !Hash {
    var poh = Poh.init(seed, hashes_per_tick);
    var mb_i: usize = 0;
    var ticks: u64 = 0;
    while (ticks < ticks_per_slot) {
        // Record any queued microblocks that fit before the next tick boundary.
        while (mb_i < microblocks.len) {
            if (poh.record(microblocks[mb_i].mixin)) |e| {
                try out.append(allocator, e);
                mb_i += 1;
            } else break; // at tick boundary → tick first
        }
        // Hash forward to the tick boundary, then tick.
        _ = poh.hashN(hashes_per_tick); // clamps to remaining-1
        if (poh.tick()) |t| {
            try out.append(allocator, t);
            ticks += 1;
        }
    }
    return poh.hash;
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — streaming PoH cadence vs entry.nextHash (the verifier). Run: zig build test-leader-poh
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

fn sha256once(input: Hash) Hash {
    return entry.hashv(&.{&input});
}

test "pure-tick slot: final == sha256^(ticks*hpt)(seed) AND == nextHash chain" {
    const seed: Hash = [_]u8{0x33} ** 32;
    const hpt: u64 = 8; // small for speed
    const tps: u64 = 64;

    var out: std.ArrayListUnmanaged(PohEntry) = .{};
    defer out.deinit(testing.allocator);
    const final = try produceSlot(testing.allocator, &out, seed, hpt, tps, &.{});

    // exactly ticks_per_slot tick entries, each num_hashes == hpt.
    try testing.expectEqual(@as(usize, tps), out.items.len);
    for (out.items) |e| try testing.expectEqual(hpt, e.num_hashes);

    // manual: sha256 applied tps*hpt times.
    var manual = seed;
    var k: u64 = 0;
    while (k < tps * hpt) : (k += 1) manual = sha256once(manual);
    try testing.expectEqual(manual, final);

    // cross-check vs entry.nextHash (tick entries: num_txs=0, num_hashes=hpt).
    var running = seed;
    for (out.items) |e| {
        running = try entry.nextHash(testing.allocator, running, e.num_hashes, 0, &.{});
        try testing.expectEqual(e.hash, running);
    }
    try testing.expectEqual(final, running);
}

test "record a microblock: produced entry hash == nextHash(running, nh, num_txs>0, sigs)" {
    const seed: Hash = [_]u8{0x44} ** 32;
    const hpt: u64 = 16;

    // a single 2-signature microblock recorded after a few hashes.
    const sig_a: [64]u8 = [_]u8{0xAA} ** 64;
    const sig_b: [64]u8 = [_]u8{0xBB} ** 64;
    const sigs = [_][]const u8{ &sig_a, &sig_b };
    const mixin = try entry.hashSignatures(testing.allocator, &sigs);

    var poh = Poh.init(seed, hpt);
    _ = poh.hashN(3); // advance 3 hashes (num_hashes=3, remaining=hpt-3)
    const e = poh.record(mixin).?;
    try testing.expectEqual(@as(u64, 4), e.num_hashes); // 3 + 1

    // entry.nextHash with num_hashes=4, num_txs=2 (record path), sigs flat.
    const expected = try entry.nextHash(testing.allocator, seed, 4, 2, &sigs);
    try testing.expectEqual(expected, e.hash);
}

test "mixed slot (ticks + tx entries): streaming entries reproduce via nextHash chain end-to-end" {
    const seed: Hash = [_]u8{0x55} ** 32;
    const hpt: u64 = 32;
    const tps: u64 = 8;

    // three microblocks with distinct sigs.
    const sa: [64]u8 = [_]u8{1} ** 64;
    const sb: [64]u8 = [_]u8{2} ** 64;
    const sc: [64]u8 = [_]u8{3} ** 64;
    const m0 = try entry.hashSignatures(testing.allocator, &.{&sa});
    const m1 = try entry.hashSignatures(testing.allocator, &.{ &sb, &sc });
    const m2 = try entry.hashSignatures(testing.allocator, &.{&sc});
    const mbs = [_]Microblock{ .{ .mixin = m0 }, .{ .mixin = m1 }, .{ .mixin = m2 } };

    var out: std.ArrayListUnmanaged(PohEntry) = .{};
    defer out.deinit(testing.allocator);
    const final = try produceSlot(testing.allocator, &out, seed, hpt, tps, &mbs);

    var ticks: usize = 0;
    // Chain entry.nextHash over the produced entries. For record entries we know num_txs>0 and the
    // sigs; for ticks num_txs==0. We reconstruct the (num_txs, sigs) per entry by replaying the
    // producer's microblock order: the FIRST `mbs.len` non-tick entries are the records in order.
    var running = seed;
    var rec_i: usize = 0;
    const sigs_by_rec = [_][]const []const u8{
        &.{&sa},
        &.{ &sb, &sc },
        &.{&sc},
    };
    for (out.items) |e| {
        // Determine if this entry is a record (matches the next expected record hash) or a tick.
        if (rec_i < sigs_by_rec.len) {
            const try_rec = try entry.nextHash(testing.allocator, running, e.num_hashes, @intCast(countSigs(sigs_by_rec[rec_i])), sigs_by_rec[rec_i]);
            if (std.mem.eql(u8, &try_rec, &e.hash)) {
                running = try_rec;
                rec_i += 1;
                ticks += 0;
                continue;
            }
        }
        // else it's a tick.
        running = try entry.nextHash(testing.allocator, running, e.num_hashes, 0, &.{});
        try testing.expectEqual(e.hash, running);
        ticks += 1;
    }
    try testing.expectEqual(final, running); // full chain reproduced the producer's final hash
    try testing.expectEqual(@as(usize, tps), ticks); // exactly ticks_per_slot ticks
    try testing.expectEqual(sigs_by_rec.len, rec_i); // all microblocks recorded
}

fn countSigs(tx_sig_sets: []const []const u8) usize {
    return tx_sig_sets.len;
}
