//! Repair-request INFLIGHT table — Firedancer fd_inflight.{h,c} port
//! (v0.1004.40101, src/discof/repair/fd_inflight.c) for the VEX_REPAIR_INFLIGHT
//! repair-pacing lever (2026-07-06).
//!
//! Tracks every nonce'd WindowIndex repair request we send so the repair tile
//! can (a) match a returning shred response to the exact request it answers
//! (nonce + slot + idx → RTT + per-peer credit), and (b) TIMEOUT-drain the
//! oldest outstanding requests and re-request the still-missing shreds from a
//! DIFFERENT peer immediately — instead of waiting for the 200ms dedup TTL and
//! re-hitting the same non-holder (the ~13s-per-singleton slow-convergence
//! stall class). Mirrors FD's fd_inflights_request_insert / _request_match /
//! _request_pop; Agave's analog is outstanding_requests_lru (repair_service.rs).
//!
//! DESIGN (allocation-free after init — repair hot path):
//!   - fixed Entry pool (POOL_CAP = 1<<14; FD uses 1<<20, we track only
//!     WindowIndex requests so a far smaller pool suffices — see POOL_CAP note
//!     for the cache-locality sizing),
//!   - AutoHashMapUnmanaged(nonce -> pool idx), capacity reserved at init
//!     (nonces come from a monotonic per-tile counter so the key is unique
//!     across the pool's lifetime window; remove() still verifies slot+idx
//!     because a response echoes whatever nonce the peer saw — nonce alone
//!     is NOT proof the response answers THIS request),
//!   - intrusive doubly-linked FIFO (next/prev index arrays) in insert order
//!     == timestamp order, so expiry checks are head-of-FIFO O(1) and a
//!     matched response can unlink from the middle O(1).
//!
//! THREADING: single-owner. All calls run on the repair tile thread (AF_XDP,
//! core 30) or inline on the recv thread (kernel-UDP fallback) — insert on the
//! send path, remove on the response path, pop on the timeout drain; the
//! tvu.zig drivers guarantee send+response run on the SAME thread in both
//! configurations (repair_tile_active gates exactly one driver). NO locks.
//!
//! Everything here is ADVISORY repair pacing: it changes only WHOM we re-ask
//! and WHEN — never what shreds are accepted (verified ingest path unchanged).

const std = @import("std");

/// Fixed pool capacity. FD: FD_INFLIGHT_REQ_MAX = 1<<20 (fd_inflight.h:23);
/// Vexor tracks only type-8 WindowIndex requests (HWI/Orphan untracked). The
/// per-cycle send budget (AGAVE_MAX_REPAIR_LENGTH=512 at 20Hz, 150ms timeout)
/// bounds steady-state outstanding at ~512·20·0.15 ≈ 1.5k. LIVE MEASUREMENT
/// (2026-07-09, real-identity node): 330-570 outstanding at tip, 1130 historical
/// PEAK across catch-ups. The old 1<<17 (131072) was ~115× that peak — and the
/// nonce→index map reserves capacity at POOL_CAP, so at 1<<17 the map's backing
/// arrays are ~2.3 MiB while ~99.7% empty. `getIndex` then cache-MISSES into a
/// cold 2.3 MiB structure on every repair insert/match, which profiled as ~26%
/// of live self-time (the #1 live hot spot, confirmed repair not BPF by an
/// offline cross-check where the folded getIndex symbol was 0.03%). 1<<14
/// (16384) is 14× the observed peak yet shrinks the map to ~288 KiB — it fits in
/// L2 (znver4 = 1 MiB L2/core), turning the miss into an L2 hit. Evict-oldest
/// still never fires in practice (14× headroom) and is advisory even if it does.
pub const POOL_CAP: u32 = 1 << 14;

/// Sentinel "no index" link value.
const NIL: u32 = std.math.maxInt(u32);

/// One outstanding repair request (FD fd_inflight_t analog: key {slot,
/// shred_idx, nonce} + timestamp_ns + peer pubkey).
pub const Entry = struct {
    slot: u64,
    idx: u32,
    nonce: u32,
    peer_pk: [32]u8,
    ts_ns: i64,
};

pub const InflightTable = struct {
    allocator: std.mem.Allocator,
    /// Fixed entry pool (POOL_CAP entries, allocated once at init).
    pool: []Entry,
    /// Intrusive links: for OUTSTANDING entries next/prev form the FIFO;
    /// for FREE entries next[] chains the free list (prev[] unused).
    next: []u32,
    prev: []u32,
    /// FIFO head = OLDEST outstanding (timeout candidates), tail = newest.
    head: u32 = NIL,
    tail: u32 = NIL,
    /// Singly-linked free list threaded through next[].
    free_head: u32,
    /// Number of outstanding entries.
    len: u32 = 0,
    /// nonce -> pool index. Capacity reserved at init; puts use
    /// putAssumeCapacity (count <= pool capacity is a structural invariant:
    /// every mapped nonce owns exactly one pool entry).
    map: std.AutoHashMapUnmanaged(u32, u32) = .empty,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return initCapacity(allocator, POOL_CAP);
    }

    /// Capacity-parameterized init so the KATs can exercise the full/evict
    /// discipline with a tiny pool. Production uses init() == POOL_CAP.
    pub fn initCapacity(allocator: std.mem.Allocator, cap: u32) !Self {
        std.debug.assert(cap > 0 and cap < NIL);
        const pool = try allocator.alloc(Entry, cap);
        errdefer allocator.free(pool);
        const next = try allocator.alloc(u32, cap);
        errdefer allocator.free(next);
        const prev = try allocator.alloc(u32, cap);
        errdefer allocator.free(prev);
        // Free list: 0 -> 1 -> ... -> cap-1 -> NIL.
        for (next, 0..) |*n, i| {
            n.* = if (i + 1 < cap) @intCast(i + 1) else NIL;
        }
        var self = Self{
            .allocator = allocator,
            .pool = pool,
            .next = next,
            .prev = prev,
            .free_head = 0,
        };
        try self.map.ensureTotalCapacity(allocator, cap);
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.map.deinit(self.allocator);
        self.allocator.free(self.prev);
        self.allocator.free(self.next);
        self.allocator.free(self.pool);
        self.* = undefined;
    }

    /// Outstanding request count (the [REPAIR-INFLIGHT] `outstanding` stat).
    pub fn count(self: *const Self) u32 {
        return self.len;
    }

    /// Unlink an OUTSTANDING entry from the FIFO (does not touch map/free list).
    fn unlink(self: *Self, i: u32) void {
        const p = self.prev[i];
        const n = self.next[i];
        if (p != NIL) self.next[p] = n else self.head = n;
        if (n != NIL) self.prev[n] = p else self.tail = p;
        self.len -= 1;
    }

    /// Push an entry index onto the free list.
    fn release(self: *Self, i: u32) void {
        self.next[i] = self.free_head;
        self.free_head = i;
    }

    /// Record a just-sent request. `now_ns` must be non-decreasing across calls
    /// (single-owner thread, std.time.nanoTimestamp) so FIFO order == age order.
    /// Pool full ⇒ evict the OLDEST outstanding entry (FD fd_inflight.c:58-74:
    /// "possible we could still make progress if this request comes back" —
    /// eviction loses only advisory pacing state, never a shred). A reused
    /// nonce (u32 counter wrap) first evicts the stale same-nonce entry so the
    /// map stays 1:1 nonce->entry.
    pub fn insert(self: *Self, nonce: u32, slot: u64, idx: u32, peer_pk: [32]u8, now_ns: i64) void {
        // Nonce reuse (counter wrapped onto a still-outstanding entry): drop
        // the stale entry — its response could no longer be attributed anyway.
        if (self.map.fetchRemove(nonce)) |kv| {
            self.unlink(kv.value);
            self.release(kv.value);
        }
        var i: u32 = undefined;
        if (self.free_head != NIL) {
            i = self.free_head;
            self.free_head = self.next[i];
        } else {
            // Full: evict oldest (head). len>0 is guaranteed (cap>0 and no
            // free entries ⇒ all cap entries are outstanding).
            i = self.head;
            _ = self.map.remove(self.pool[i].nonce);
            self.unlink(i);
        }
        self.pool[i] = .{ .slot = slot, .idx = idx, .nonce = nonce, .peer_pk = peer_pk, .ts_ns = now_ns };
        // Push tail (newest).
        self.prev[i] = self.tail;
        self.next[i] = NIL;
        if (self.tail != NIL) self.next[self.tail] = i else self.head = i;
        self.tail = i;
        self.len += 1;
        self.map.putAssumeCapacity(nonce, i);
    }

    /// Match a repair response to its request (FD fd_inflights_request_match).
    /// Returns the RTT in ns and removes the entry, or null when no entry has
    /// this nonce OR the entry's (slot, idx) disagree with the response —
    /// nonce alone is insufficient (a stale/echoed nonce on a different shred
    /// must not be credited). A mismatch leaves the entry outstanding. On a
    /// match, `peer_out` (FD's peer_out param) receives the pubkey the request
    /// was sent to so the caller can credit that peer's score.
    pub fn remove(self: *Self, nonce: u32, slot: u64, idx: u32, now_ns: i64, peer_out: ?*[32]u8) ?i64 {
        const i = self.map.get(nonce) orelse return null;
        const e = self.pool[i];
        if (e.slot != slot or e.idx != idx) return null;
        _ = self.map.remove(nonce);
        self.unlink(i);
        self.release(i);
        if (peer_out) |po| po.* = e.peer_pk;
        return now_ns - e.ts_ns;
    }

    /// Pop the OLDEST outstanding entry iff it has been outstanding longer
    /// than `timeout_ns` (FD fd_inflights_should_drain + _request_pop, folded:
    /// Vexor re-requests immediately so no POPPED shadow list is needed).
    /// Head-of-FIFO only — entries expire strictly in insert order.
    pub fn popExpired(self: *Self, now_ns: i64, timeout_ns: i64) ?Entry {
        if (self.head == NIL) return null;
        const i = self.head;
        const e = self.pool[i];
        if (now_ns - e.ts_ns < timeout_ns) return null;
        _ = self.map.remove(e.nonce);
        self.unlink(i);
        self.release(i);
        return e;
    }
};

// ═══════════════════════════════ KATs ═══════════════════════════════════════

const testing = std.testing;

const PK_A: [32]u8 = .{0xAA} ** 32;
const PK_B: [32]u8 = .{0xBB} ** 32;

test "insert + matched remove returns RTT and clears the entry" {
    var t = try InflightTable.initCapacity(testing.allocator, 8);
    defer t.deinit();

    t.insert(7, 1000, 42, PK_A, 1_000_000);
    try testing.expectEqual(@as(u32, 1), t.count());

    // Matched response 3ms later → RTT = 3_000_000 ns.
    var peer: [32]u8 = undefined;
    const rtt = t.remove(7, 1000, 42, 4_000_000, &peer);
    try testing.expectEqual(@as(i64, 3_000_000), rtt.?);
    try testing.expectEqualSlices(u8, &PK_A, &peer); // peer_out credited to the asked peer
    try testing.expectEqual(@as(u32, 0), t.count());

    // Second remove of the same nonce: entry is gone.
    try testing.expectEqual(@as(?i64, null), t.remove(7, 1000, 42, 5_000_000, null));
}

test "popExpired drains oldest-first and stops at the first unexpired entry" {
    var t = try InflightTable.initCapacity(testing.allocator, 8);
    defer t.deinit();

    t.insert(1, 100, 0, PK_A, 0);
    t.insert(2, 100, 1, PK_A, 50);
    t.insert(3, 101, 0, PK_B, 900);

    // now=1000, timeout=150: entries at ts 0 and 50 are expired, 900 is not.
    const e1 = t.popExpired(1000, 150).?;
    try testing.expectEqual(@as(u32, 1), e1.nonce);
    try testing.expectEqual(@as(u64, 100), e1.slot);
    try testing.expectEqual(@as(u32, 0), e1.idx);
    const e2 = t.popExpired(1000, 150).?;
    try testing.expectEqual(@as(u32, 2), e2.nonce);
    // Head is now ts=900 (age 100 < 150) → nothing more to drain.
    try testing.expectEqual(@as(?Entry, null), t.popExpired(1000, 150));
    try testing.expectEqual(@as(u32, 1), t.count());
}

test "insert when full evicts the OLDEST outstanding entry (FD discipline)" {
    var t = try InflightTable.initCapacity(testing.allocator, 3);
    defer t.deinit();

    t.insert(1, 10, 0, PK_A, 100);
    t.insert(2, 11, 0, PK_A, 200);
    t.insert(3, 12, 0, PK_A, 300);
    try testing.expectEqual(@as(u32, 3), t.count());

    // Pool full → nonce 1 (oldest) is evicted to make room for nonce 4.
    t.insert(4, 13, 0, PK_B, 400);
    try testing.expectEqual(@as(u32, 3), t.count());
    try testing.expectEqual(@as(?i64, null), t.remove(1, 10, 0, 500, null));
    // Survivors still match, oldest-first expiry order preserved (2, 3, 4).
    const e = t.popExpired(10_000, 100).?;
    try testing.expectEqual(@as(u32, 2), e.nonce);
    try testing.expectEqual(@as(i64, 100), t.remove(4, 13, 0, 500, null).?);
    try testing.expectEqual(@as(i64, 200), t.remove(3, 12, 0, 500, null).?);
    try testing.expectEqual(@as(u32, 0), t.count());
}

test "remove with mismatched slot/idx is rejected and leaves the entry outstanding" {
    var t = try InflightTable.initCapacity(testing.allocator, 4);
    defer t.deinit();

    t.insert(9, 5000, 260, PK_A, 1000);
    // Same nonce, wrong slot → not our request's response.
    try testing.expectEqual(@as(?i64, null), t.remove(9, 5001, 260, 2000, null));
    // Same nonce+slot, wrong idx → rejected too.
    try testing.expectEqual(@as(?i64, null), t.remove(9, 5000, 261, 2000, null));
    try testing.expectEqual(@as(u32, 1), t.count());
    // The true response still matches afterwards.
    try testing.expectEqual(@as(i64, 1000), t.remove(9, 5000, 260, 2000, null).?);
}

test "nonce reuse is safe: newest entry owns the nonce, stale entry is dropped" {
    var t = try InflightTable.initCapacity(testing.allocator, 4);
    defer t.deinit();

    t.insert(5, 100, 1, PK_A, 1000);
    // Counter wrapped: same nonce reissued for a different (slot, idx).
    t.insert(5, 200, 2, PK_B, 2000);
    try testing.expectEqual(@as(u32, 1), t.count()); // stale entry dropped, no leak

    // A late response for the OLD request no longer credits anything.
    try testing.expectEqual(@as(?i64, null), t.remove(5, 100, 1, 3000, null));
    // The new request matches normally.
    try testing.expectEqual(@as(i64, 1000), t.remove(5, 200, 2, 3000, null).?);
    try testing.expectEqual(@as(u32, 0), t.count());
}

test "unknown nonce returns null; empty table popExpired returns null" {
    var t = try InflightTable.initCapacity(testing.allocator, 2);
    defer t.deinit();

    try testing.expectEqual(@as(?i64, null), t.remove(123, 1, 1, 1000, null));
    try testing.expectEqual(@as(?Entry, null), t.popExpired(1_000_000, 1));

    // Fill, drain fully via expiry, then reuse the recycled pool slots.
    t.insert(1, 1, 0, PK_A, 0);
    t.insert(2, 2, 0, PK_A, 1);
    _ = t.popExpired(1000, 10).?;
    _ = t.popExpired(1000, 10).?;
    try testing.expectEqual(@as(u32, 0), t.count());
    t.insert(3, 3, 0, PK_B, 2000);
    t.insert(4, 4, 0, PK_B, 2001);
    try testing.expectEqual(@as(u32, 2), t.count());
    try testing.expectEqual(@as(i64, 5), t.remove(3, 3, 0, 2005, null).?);
}
