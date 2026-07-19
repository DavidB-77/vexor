//! Vexor BlockhashQueue — Recent blockhash tracking for transaction validation.
//!
//! Ported from Firedancer's fd_blockhashes.c / fd_blockhashes.h.
//! Solana Agave counterpart: solana_accounts_db::blockhash_queue::BlockhashQueue.
//! @prov:blockhash.module-map — full per-function upstream line-map.
//!
//! Architecture:
//!   A circular deque of up to 301 entries (FD_BLOCKHASHES_MAX).
//!   New entries are appended at the tail; oldest entries are evicted from the head.
//!   A separate hash map provides O(1) lookup by blockhash bytes.
//!   "age" of a blockhash = distance from the tail (0 = newest).

const std = @import("std");
const types = @import("types.zig");

const Hash = types.Hash;

// ─────────────────────────────────────────────────────────────────────────────
// Constants. @prov:blockhash.queue-ops
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of recent blockhashes retained in the queue.
/// Transactions referencing a blockhash older than this are rejected.
/// @prov:blockhash.queue-ops
pub const BLOCKHASHES_MAX: usize = 301;

// ─────────────────────────────────────────────────────────────────────────────
// FeeCalculator. @prov:blockhash.fee-rate-governor
// ─────────────────────────────────────────────────────────────────────────────

/// Per-blockhash fee parameters stored alongside the hash.
/// @prov:blockhash.fee-rate-governor
pub const FeeCalculator = struct {
    /// Cost in lamports per ed25519 signature in a transaction.
    lamports_per_signature: u64 = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// FeeRateGovernor. @prov:blockhash.fee-rate-governor
//
// CONSENSUS-CRITICAL: `lamports_per_signature` (lps) is derived per-slot via
// `newDerived` from the PARENT bank's governor + the PARENT's accumulated
// signature_count, then stored into the RecentBlockhashes sysvar. A wrong lps
// makes the RecentBlockhashes sysvar bytes differ → accounts-lthash differs →
// bank_hash diverges → delinquency (epoch-979 "tip carrier" @ slot 849).
// ─────────────────────────────────────────────────────────────────────────────

/// Per-slot fee-rate governor. All fields u64 except burn_percent.
pub const FeeRateGovernor = struct {
    /// The current per-slot derived lamports_per_signature (the live fee rate).
    lamports_per_signature: u64 = 0,
    /// Target lamports_per_signature — carried (cloned) from parent/genesis.
    target_lamports_per_signature: u64 = 0,
    /// Target signatures_per_slot — carried; 0 disables adjustment.
    target_signatures_per_slot: u64 = 0,
    /// Lower clamp bound for lps (derived from target).
    min_lamports_per_signature: u64 = 0,
    /// Upper clamp bound for lps (derived from target).
    max_lamports_per_signature: u64 = 0,
    /// Fraction of fees burned (carried; not used in the lps math).
    burn_percent: u8 = 0,

    /// Derive the child governor from the parent governor + the number of
    /// signatures seen in the parent slot. @prov:blockhash.fee-rate-governor
    /// — byte-faithful port. Integer math only; `gap`/`step` are i64,
    /// everything else u64.
    pub fn newDerived(base: FeeRateGovernor, latest_signatures_per_slot: u64) FeeRateGovernor {
        var me = base; // clone: carries target_lps, target_sps, burn_percent

        const target_lps = base.target_lamports_per_signature;

        if (me.target_signatures_per_slot > 0) {
            me.min_lamports_per_signature = @max(1, target_lps / 2);
            me.max_lamports_per_signature = target_lps * 10;

            // Cap latest signatures at u32::MAX BEFORE the multiply, then
            // multiply-before-divide. @prov:blockhash.fee-rate-governor — the
            // cap guarantees the product fits in u64.
            const capped_sigs: u64 = @min(latest_signatures_per_slot, 0xFFFF_FFFF);
            const scaled: u64 = target_lps * capped_sigs / me.target_signatures_per_slot;

            const desired: u64 = @min(
                me.max_lamports_per_signature,
                @max(me.min_lamports_per_signature, scaled),
            );

            const gap: i64 = @as(i64, @intCast(desired)) - @as(i64, @intCast(base.lamports_per_signature));
            if (gap == 0) {
                me.lamports_per_signature = desired;
            } else {
                const sign: i64 = if (gap > 0) 1 else -1;
                const step: i64 = @as(i64, @intCast(@max(@as(u64, 1), target_lps / 20))) * sign;
                // Compute base.lps + step in i64 (step can be negative), then
                // clamp to [min, max] in i64, then cast back to u64. Never let
                // base.lps + step touch u64 (would underflow on negative step).
                const moved: i64 = @as(i64, @intCast(base.lamports_per_signature)) + step;
                const lo: i64 = @as(i64, @intCast(me.min_lamports_per_signature));
                const hi: i64 = @as(i64, @intCast(me.max_lamports_per_signature));
                const clamped: i64 = @max(lo, @min(hi, moved));
                me.lamports_per_signature = @intCast(clamped);
            }
        } else {
            // target_signatures_per_slot == 0 disables adjustment: lps pegs to
            // target and the clamp bounds collapse onto it.
            me.lamports_per_signature = target_lps;
            me.min_lamports_per_signature = me.lamports_per_signature;
            me.max_lamports_per_signature = me.lamports_per_signature;
        }

        return me;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// BlockhashInfo — one entry in the queue. @prov:blockhash.queue-ops
// ─────────────────────────────────────────────────────────────────────────────

/// A single slot in the blockhash queue.
/// @prov:blockhash.queue-ops
pub const BlockhashInfo = struct {
    hash: Hash,
    fee_calculator: FeeCalculator,
};

// ─────────────────────────────────────────────────────────────────────────────
// BlockhashQueue. @prov:blockhash.queue-ops
// ─────────────────────────────────────────────────────────────────────────────

/// Circular deque + hash-map index of recent blockhashes.
///
/// Invariants:
///   - `entries[head..tail]` (wrapping) are valid entries in insertion order.
///   - `head == tail` means the queue is empty.
///   - The queue never exceeds BLOCKHASHES_MAX entries; the oldest is
///     evicted on overflow. @prov:blockhash.queue-ops
///   - `index` maps hash bytes to slot in `entries[]`.
pub const BlockhashQueue = struct {
    /// Circular buffer of entries.
    entries: [BLOCKHASHES_MAX + 1]BlockhashInfo = undefined,
    /// Index of the oldest entry (head of deque).
    head: usize = 0,
    /// Index one past the newest entry (tail of deque).
    tail: usize = 0,
    /// Current number of entries stored.
    len: usize = 0,

    // ─────────────────────────────────────────────────────────────────────────
    // init. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Return a zero-initialised queue.
    pub fn init() BlockhashQueue {
        return .{};
    }

    // ─────────────────────────────────────────────────────────────────────────
    // internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    inline fn capacity(self: *const BlockhashQueue) usize {
        return self.entries.len; // BLOCKHASHES_MAX + 1
    }

    /// Pop the oldest entry (head of deque). @prov:blockhash.queue-ops
    fn popOld(self: *BlockhashQueue) void {
        if (self.len == 0) return;
        self.head = (self.head + 1) % self.capacity();
        self.len -= 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // pushNew. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Append a new blockhash at the tail (newest end).
    /// Evicts the oldest entry if the queue is full.
    /// Returns a pointer to the newly created slot so the caller can fill in
    /// `fee_calculator` (matches Firedancer's pattern of returning a mutable
    /// pointer for the caller to populate). @prov:blockhash.queue-ops
    pub fn pushNew(self: *BlockhashQueue, hash: Hash) *BlockhashInfo {
        if (self.len == BLOCKHASHES_MAX) {
            self.popOld();
        }
        const slot = self.tail;
        self.entries[slot] = .{ .hash = hash, .fee_calculator = .{} };
        self.tail = (self.tail + 1) % self.capacity();
        self.len += 1;
        return &self.entries[slot];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // pushOld. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Prepend a blockhash at the head (oldest end).
    /// Returns null if there is no space (full queue).
    /// Useful for replaying historical state / snapshot loading.
    /// @prov:blockhash.queue-ops
    pub fn pushOld(self: *BlockhashQueue, hash: Hash) ?*BlockhashInfo {
        if (self.len == BLOCKHASHES_MAX) return null;
        self.head = if (self.head == 0) self.capacity() - 1 else self.head - 1;
        self.entries[self.head] = .{ .hash = hash, .fee_calculator = .{} };
        self.len += 1;
        return &self.entries[self.head];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // popNew. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Remove the newest entry from the tail. @prov:blockhash.queue-ops
    pub fn popNew(self: *BlockhashQueue) void {
        if (self.len == 0) return;
        self.tail = if (self.tail == 0) self.capacity() - 1 else self.tail - 1;
        self.len -= 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // peekLastHash / peekLast. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Return the most recently registered blockhash, or null if empty.
    /// @prov:blockhash.queue-ops
    pub fn peekLastHash(self: *const BlockhashQueue) ?Hash {
        if (self.len == 0) return null;
        const idx = if (self.tail == 0) self.capacity() - 1 else self.tail - 1;
        return self.entries[idx].hash;
    }

    /// Return a pointer to the newest BlockhashInfo, or null if empty.
    /// @prov:blockhash.queue-ops
    pub fn peekLast(self: *const BlockhashQueue) ?*const BlockhashInfo {
        if (self.len == 0) return null;
        const idx = if (self.tail == 0) self.capacity() - 1 else self.tail - 1;
        return &self.entries[idx];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // checkAge. @prov:blockhash.queue-ops
    // ─────────────────────────────────────────────────────────────────────────

    /// Returns true if `blockhash` is in the queue and its age ≤ max_age.
    ///
    /// Age 0 = the most recently pushed hash.
    /// Age 1 = the hash before that, etc.
    /// A hash that is not present returns false. @prov:blockhash.queue-ops
    pub fn checkAge(self: *const BlockhashQueue, blockhash: Hash, max_age: usize) bool {
        if (self.len == 0) return false;
        // Linear scan — queue is bounded to 301 entries so O(N) is acceptable.
        // Firedancer uses a separately-chained hashmap for O(1); we trade a
        // tiny bit of performance for simplicity at this queue size.
        var i: usize = 0;
        // Tail points one past the newest; newest has age 0.
        var pos = if (self.tail == 0) self.capacity() - 1 else self.tail - 1;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.entries[pos].hash.data, &blockhash.data)) {
                return i <= max_age;
            }
            pos = if (pos == 0) self.capacity() - 1 else pos - 1;
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // query
    // ─────────────────────────────────────────────────────────────────────────

    /// Return the BlockhashInfo for `blockhash`, or null if not present.
    /// Does not check age — use checkAge for validation.
    pub fn query(self: *const BlockhashQueue, blockhash: Hash) ?BlockhashInfo {
        if (self.len == 0) return null;
        var i: usize = 0;
        var pos = if (self.tail == 0) self.capacity() - 1 else self.tail - 1;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, &self.entries[pos].hash.data, &blockhash.data)) {
                return self.entries[pos];
            }
            pos = if (pos == 0) self.capacity() - 1 else pos - 1;
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // lamportsPerSignature
    // ─────────────────────────────────────────────────────────────────────────

    /// Retrieve the lamports_per_signature stored in the newest entry.
    /// Returns 0 if the queue is empty.
    pub fn lamportsPerSignature(self: *const BlockhashQueue) u64 {
        const info = self.peekLast() orelse return 0;
        return info.fee_calculator.lamports_per_signature;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "BlockhashQueue basic push/age" {
    const testing = std.testing;
    var q = BlockhashQueue.init();

    const h0 = Hash{ .data = [_]u8{1} ** 32 };
    const h1 = Hash{ .data = [_]u8{2} ** 32 };
    const h2 = Hash{ .data = [_]u8{3} ** 32 };

    _ = q.pushNew(h0);
    _ = q.pushNew(h1);
    _ = q.pushNew(h2);

    try testing.expect(q.len == 3);
    // h2 is newest → age 0
    try testing.expect(q.checkAge(h2, 0));
    // h1 is age 1
    try testing.expect(q.checkAge(h1, 1));
    try testing.expect(!q.checkAge(h1, 0));
    // h0 is age 2
    try testing.expect(q.checkAge(h0, 2));
    try testing.expect(!q.checkAge(h0, 1));
}

test "BlockhashQueue eviction on overflow" {
    const testing = std.testing;
    var q = BlockhashQueue.init();

    // Fill to max. Counter widened to u16 + hash discriminator spread across 2
    // bytes (2026-07-06 rebuild session-13 TEST-FILE-ONLY fix; PRE-EXISTING bug
    // confirmed present byte-identical in origin-tree, read-only, via a direct
    // `zig test` against origin-tree's own file: BLOCKHASHES_MAX=301 does not fit a
    // u8 (max 255), so the original `var i: u8` panics on integer overflow at
    // i==255 in both Debug and ReleaseSafe. This test has NO origin-tree build.zig
    // target, so it was never exercised by `zig build test-*` and the bug was
    // never caught upstream. A single-byte discriminator would also collide
    // every 256 entries (301 > 256), which silently breaks the post-fill
    // assertions below once BLOCKHASHES_MAX exceeds 256 — fixed by spreading i
    // across 2 bytes so all 301 entries are distinct. Production BlockhashQueue
    // code (everything above this test block) is untouched — see ledger row.
    var i: u16 = 0;
    while (i < BLOCKHASHES_MAX) : (i += 1) {
        var h = Hash{ .data = [_]u8{0} ** 32 };
        h.data[0] = @truncate(i);
        h.data[1] = @truncate(i >> 8);
        _ = q.pushNew(h);
    }
    try testing.expect(q.len == BLOCKHASHES_MAX);

    // The hash with i==0 is the oldest; adding one more should evict it.
    const oldest = Hash{ .data = blk: {
        var b = [_]u8{0} ** 32;
        b[0] = 0;
        break :blk b;
    } };
    const new_hash = Hash{ .data = [_]u8{0xff} ** 32 };
    _ = q.pushNew(new_hash);
    try testing.expect(q.len == BLOCKHASHES_MAX);
    try testing.expect(!q.checkAge(oldest, BLOCKHASHES_MAX));
    try testing.expect(q.checkAge(new_hash, 0));
}

test "BlockhashQueue popNew" {
    const testing = std.testing;
    var q = BlockhashQueue.init();
    const h = Hash{ .data = [_]u8{7} ** 32 };
    _ = q.pushNew(h);
    try testing.expect(q.len == 1);
    q.popNew();
    try testing.expect(q.len == 0);
    try testing.expect(q.peekLastHash() == null);
}

test "FeeRateGovernor.newDerived canonical vectors" {
    const testing = std.testing;

    // Canonical testnet config: target_lps=10000, target_sps=20000.
    const base_template = FeeRateGovernor{
        .lamports_per_signature = 5000,
        .target_lamports_per_signature = 10000,
        .target_signatures_per_slot = 20000,
        .min_lamports_per_signature = 0, // recomputed by newDerived
        .max_lamports_per_signature = 0,
        .burn_percent = 50,
    };

    // (1) base.lps=5000, latest_sigs=10604 (the slot-848 spike) → 5500.
    //     desired = min(100000, max(5000, 10000*10604/20000=5302)) = 5302
    //     gap=+302 → step=+max(1,500)=+500 → 5000+500=5500 (in [5000,100000]).
    {
        const r = FeeRateGovernor.newDerived(base_template, 10604);
        try testing.expectEqual(@as(u64, 5500), r.lamports_per_signature);
        // carried/derived fields
        try testing.expectEqual(@as(u64, 10000), r.target_lamports_per_signature);
        try testing.expectEqual(@as(u64, 20000), r.target_signatures_per_slot);
        try testing.expectEqual(@as(u64, 5000), r.min_lamports_per_signature); // max(1,10000/2)
        try testing.expectEqual(@as(u64, 100000), r.max_lamports_per_signature); // 10000*10
        try testing.expectEqual(@as(u8, 50), r.burn_percent);
    }

    // (2) base.lps=5000, latest_sigs=428 → stays 5000.
    //     desired = min(100000, max(5000, 10000*428/20000=214)) = 5000 = base
    //     gap=0 → lps=desired=5000.
    {
        const r = FeeRateGovernor.newDerived(base_template, 428);
        try testing.expectEqual(@as(u64, 5000), r.lamports_per_signature);
    }

    // (3) base.lps=5500, latest_sigs=523 → 5000 (gap negative, step -500,
    //     clamp to min 5000).
    //     desired = min(100000, max(5000, 10000*523/20000=261)) = 5000
    //     gap = 5000-5500 = -500 → step=-500 → 5500-500=5000 (>= min 5000).
    {
        var b = base_template;
        b.lamports_per_signature = 5500;
        const r = FeeRateGovernor.newDerived(b, 523);
        try testing.expectEqual(@as(u64, 5000), r.lamports_per_signature);
    }

    // (4) target_signatures_per_slot == 0 disables adjustment → lps=target_lps.
    {
        var b = base_template;
        b.target_signatures_per_slot = 0;
        b.lamports_per_signature = 5500; // ignored
        const r = FeeRateGovernor.newDerived(b, 999999);
        try testing.expectEqual(@as(u64, 10000), r.lamports_per_signature);
        try testing.expectEqual(@as(u64, 10000), r.min_lamports_per_signature);
        try testing.expectEqual(@as(u64, 10000), r.max_lamports_per_signature);
    }
}
