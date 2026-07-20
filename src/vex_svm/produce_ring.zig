//! Lock-free single-producer / single-consumer control-record rings for the
//! BLOCK-PRODUCTION TILE isolation (2026-06-16).
//!
//! WHY: today block production runs INLINE on the replay tile (core 16):
//! onSlotFrozen → produceAndBroadcastEmptySlot → banking.drainBatch +
//! produceSlotBytes/produceEmptySlotBytes + shred + broadcast. That drain+pack+
//! PoH+shred work steals replay cycles → under VEX_TPU_INGEST load it pushed the
//! validator delinquent (the QUIC-TPU-ingest soak failure). Firedancer keeps
//! block production OFF the replay/consensus core entirely: replay only EMITS a
//! become-leader frag and CONSUMES a slot-ended frag; the block is built
//! downstream on pack→execle→poh→shred tiles (fd_poh_tile.c:158 comment
//! "the become_leader message makes it from replay→pack→execle→poh").
//!
//! Vexor mirrors that with a dedicated PRODUCE tile (a thread pinned to core 20,
//! free per replay_stage.zig:241 dead parallel-SVM pool) connected to the replay
//! tile by two strict-SPSC rings:
//!   - Ring A (replay→produce, "become-leader"): replay snapshots the build
//!     inputs at the isLeader(next_slot) detection and pushes a BecomeLeader
//!     record, then RETURNS immediately — no drain/pack/PoH on the replay thread.
//!   - Ring B (produce→replay, "slot-done"): the produce tile builds the block
//!     off the snapshotted inputs (zero shared-Bank deref), broadcasts it, and
//!     pushes a SlotDone record carrying the finished entry-bytes back so replay
//!     runs the EXISTING loopback self-replay (pushSlotForReplayWithParent) and
//!     the G1 self-vote guard — both stay replay-thread-owned.
//!
//! The algorithm is cloned verbatim from src/vex_network/spsc_ring.zig (the
//! proven AF_XDP verify-handoff ring): free-running u32 head/tail (wrap via
//! &mask), producer publishes head with .release after the slot write, consumer
//! reads head with .acquire before the slot read and advances tail with
//! .release; producer reads tail with .acquire to test fullness. The records
//! here are plain VALUE structs (no pointers into mutable replay/Bank state) so
//! that the produce tile dereferences ZERO shared mutable state to build a block.
//!
//! Capacity is tiny (64): there is at most one in-flight leader slot at a time
//! (we are leader for a contiguous window, and a slot's block must loop back and
//! freeze before the next can be produced), so 64 is far more than enough; a
//! full ring just means production fell behind, which is logged and the slot is
//! skipped exactly as the inline path skips a slot it cannot build.
//!
//! 2026-07-17 (M2b, produce-tile SAFE GATING — task #25's tile flip-blocker):
//! BecomeLeaderRecord now also carries a bounded, VALUE-copied snapshot of the
//! exact frozen-parent-state inputs `admitTxSeq`'s inclusion gate needs
//! (`recent_blockhashes` + a per-fee-payer balance snapshot `fee_snapshot` +
//! a cross-block-AlreadyProcessed flag list `already_processed_sigs`), extending
//! the SAME "replay reads live state, tile gets values only" discipline this file
//! already used for `chained_root`/`seed`/`secret` — NOT a new principle, a wider
//! application of it. `accounts_db` stays exclusively replay-thread-owned (never
//! dereferenced by the tile, before or after this change); the tile's own
//! zero-shared-mutable-state invariant (banner above) is unchanged. See
//! replay_stage.zig `dispatchLeaderToProduceTile` (builder) and
//! `tileAdmitTxForBroadcast` (consumer) for the mechanism.

const std = @import("std");

/// Per-ring capacity (power of 2). 64 control records ≈ a few KB total.
pub const PRODUCE_RING_CAPACITY: u32 = 64;

/// Bound on both the distinct-fee-payer balance snapshot and the peeked/
/// cross-block-dedup-checked signature list (M2b). Sized above the mempool's
/// pack batch_size (banking_stage.zig BankingConfig.batch_size = 128) with
/// slack for the votes+txs split drainBatch takes; NOT a hard correctness bound
/// — a mempool deeper than this at snapshot time degrades gracefully (excess
/// distinct payers are simply not snapshotted, so a tx touching one is dropped
/// by the gate's existing "cannot verify ⇒ absent" fallback, never wrongly
/// admitted). Explicitly out of scope for the low/throttled volumes M1-M3
/// target (plan §5); would need revisiting for mainnet-scale mempool depth.
pub const FEE_SNAPSHOT_CAP: u32 = 256;

/// One fee-payer's frozen-parent-state balance view, VALUE-copied from
/// `accounts_db.getAccountInSlot` on the replay thread (see
/// replay_stage.zig `dispatchLeaderToProduceTile`). Field shape mirrors
/// `block_produce.FeePayerView` deliberately (trivial to convert at the two
/// use sites) but is NOT the same type — produce_ring.zig stays std-only
/// (imports nothing beyond `std`, verified fresh at every KAT wiring; see
/// build.zig's "zero addImports required" note for `test-produce-ring`), so
/// this is a local duplicate rather than a cross-module import.
pub const FeePayerSnapshotEntry = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    data_len: u64,
};

/// Ring A record — replay→produce "become-leader". Carries ALL build inputs as
/// VALUES, snapshotted on the replay thread at the same point the inline path
/// reads them (replay_stage.zig:3502-3505). The produce tile therefore never
/// dereferences a *Bank or `self.identity_secret` (which is nulled/restored on
/// the replay thread by the suspend-voting path, replay_stage.zig:6308-6459 — a
/// tile reading it live would be a torn read). Snapshotting closes that race.
pub const BecomeLeaderRecord = struct {
    /// Our leader slot to produce.
    slot: u64,
    /// The parent slot (= the just-frozen slot whose bank we build on).
    parent_slot: u64,
    /// SIMD-0340 parent block_id = first FEC set's chained merkle root.
    /// Snapshot of `parent_bank.block_id`. The inline path skips production when
    /// the parent block_id is null; we encode that as `chained_root_valid=false`
    /// so the tile skips identically (no orphan, no wasted broadcast).
    chained_root: [32]u8,
    chained_root_valid: bool,
    /// PoH seed = snapshot of `parent_bank.poh_hash.data`.
    seed: [32]u8,
    /// Snapshot of `self.identity_secret` (ed25519 secret) for the shred signer.
    secret: [64]u8,
    /// Live shred_version (`self.shred_version_bp`).
    shred_version: u16,
    /// Whether VEX_TPU_INGEST is on AND a mempool is wired → pack drained txs
    /// (produceSlotBytes); else the empty tick-only path (produceEmptySlotBytes).
    /// Snapshotted so the tile makes the SAME branch the inline path would.
    tpu_ingest_on: bool,

    // ── M2b gate-input snapshot (all VALUES; replay-thread-computed) ────────

    /// Snapshot of `parent_bank.recent_blockhashes.constSlice()` (≤150 entries,
    /// Agave MAX_PROCESSING_AGE). Feeds `admitTxSeq`'s BlockhashNotFound check
    /// exactly as `bankAdmitTxForBroadcast` reads it from the live bank inline.
    recent_blockhashes: [150][32]u8 = undefined,
    recent_blockhashes_len: u8 = 0,

    /// Per-distinct-fee-payer frozen-parent balance, for every fee-payer pubkey
    /// observed in the mempool at dispatch time (a non-destructive peek —
    /// `banking_stage.peekEach`) that `accounts_db.getAccountInSlot` resolved to
    /// a present, non-zero-lamport account. A pubkey NOT in this list (absent
    /// from the DB, OR simply not seen by the peek — e.g. arrived in the gap
    /// between this snapshot and the tile's later `drainBatch`) is
    /// indistinguishable from "unverifiable" to the consumer and is dropped by
    /// the gate's existing conservative fallback — same fail-closed posture the
    /// inline path already uses for a genuinely-absent account.
    fee_snapshot: [FEE_SNAPSHOT_CAP]FeePayerSnapshotEntry = undefined,
    fee_snapshot_len: u16 = 0,

    /// First-signatures of peeked txs the REPLAY-thread-owned `RecentSigCache`
    /// (cross-block AlreadyProcessed dedup) flagged as recently committed, as of
    /// this snapshot. Only meaningful when `status_cache_checked` is true
    /// (mirrors `ReplayStage.statusCacheActive()`); when false, cross-block
    /// dedup was not evaluated for this slot — same as the inline path passing
    /// `recent_sigs = null` when the status cache is dormant, NOT a new gap.
    already_processed_sigs: [FEE_SNAPSHOT_CAP][64]u8 = undefined,
    already_processed_len: u16 = 0,
    status_cache_checked: bool = false,
};

/// Ring B record — produce→replay "slot-done". The produce tile built the block
/// and (when broadcast is enabled) already shipped its shreds; it hands the
/// finished entry-bytes back so REPLAY runs the existing loopback self-replay.
/// Ownership contract (mirrors the inline dupe/free at replay_stage.zig:1286):
///   - The tile allocates `block_bytes` with the replay allocator (c_allocator,
///     thread-safe) and TRANSFERS ownership to replay via this record.
///   - Replay frees `block_bytes` iff pushSlotForReplayWithParent returns false
///     (the loopback path takes ownership on true), exactly like the inline path.
/// `status` lets the tile signal a build/skip outcome without a bytes transfer.
pub const SlotDoneRecord = struct {
    slot: u64,
    parent_slot: u64,
    /// Owned entry-bytes for loopback; empty/`undefined` slice when status != ok.
    block_bytes: []u8,
    status: Status,
    /// 2026-06-19 (multi-slot leader-window chaining): the produced block's last-FEC
    /// merkle root (= next slot's chained_root). Computed on the tile (off replay) so
    /// replay can stash slot→block_id and feed it forward as bank.block_id. Only valid
    /// when has_block_id (compute may fail / be unwired → then slot N+1 skips, as before).
    block_id: [32]u8 = [_]u8{0} ** 32,
    has_block_id: bool = false,
    /// M3 auto-safe-off tripwire (2026-07-17): true iff the tile actually packed
    /// drained txs into this block (mirrors the inline path's `pack_tx_bearing`
    /// local). Replay's `drainProduceTileRingB` uses this to mark
    /// `self_produced_tx_bearing` — computed on the TILE thread (the only place
    /// this decision is made for the tile path) and carried across Ring B as a
    /// plain value, same "values only, zero shared mutable state" discipline as
    /// every other field here. An empty (tick-only) self-produced slot leaves
    /// this false, so the tripwire's consecutive-fail counter correctly never
    /// sees it (see txbearing_tripwire.zig's threshold-reasoning doc: an empty
    /// self-produced slot is neither a failure nor a clean reset).
    tx_bearing: bool = false,

    pub const Status = enum(u8) {
        /// Block built; `block_bytes` carries the loopback copy (transfer).
        ok,
        /// Tile could not build (null chained root, produce error, etc.) — no
        /// bytes transferred; replay just clears its in-flight marker.
        skipped,
    };
};

/// Generic strict-SPSC ring over a plain value record type `T`. One producer
/// thread, one consumer thread. `capacity` must be a power of two.
pub fn ProduceRing(comptime T: type) type {
    return struct {
        entries: []T,
        capacity: u32,
        mask: u32,
        head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // producer cursor
        tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // consumer cursor

        // Stats (monotonic; depth_max is a racy high-water mark, fine for a gauge).
        pushed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        popped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        overrun: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        depth_max: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, capacity: u32) !*Self {
            std.debug.assert(std.math.isPowerOfTwo(capacity));
            const ring = try allocator.create(Self);
            const entries = try allocator.alloc(T, capacity);
            ring.* = Self{
                .entries = entries,
                .capacity = capacity,
                .mask = capacity - 1,
            };
            return ring;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.entries);
            allocator.destroy(self);
        }

        /// PRODUCER-ONLY. Returns false if the ring is full (counts an overrun).
        pub fn tryPush(self: *Self, entry: T) bool {
            const head = self.head.load(.monotonic); // producer owns head
            const tail = self.tail.load(.acquire); // observe consumer progress
            const depth = head -% tail;
            if (depth >= self.capacity) {
                _ = self.overrun.fetchAdd(1, .monotonic);
                return false; // full
            }
            self.entries[head & self.mask] = entry;
            self.head.store(head +% 1, .release); // publish the slot write
            _ = self.pushed.fetchAdd(1, .monotonic);
            const d = depth + 1;
            if (d > self.depth_max.load(.monotonic)) self.depth_max.store(d, .monotonic);
            return true;
        }

        /// CONSUMER-ONLY. Returns false if empty.
        pub fn tryPop(self: *Self, out: *T) bool {
            const tail = self.tail.load(.monotonic); // consumer owns tail
            const head = self.head.load(.acquire); // observe producer publish
            if (head == tail) return false; // empty
            out.* = self.entries[tail & self.mask];
            self.tail.store(tail +% 1, .release);
            _ = self.popped.fetchAdd(1, .monotonic);
            return true;
        }

        pub fn len(self: *const Self) u32 {
            return self.head.load(.monotonic) -% self.tail.load(.monotonic);
        }
    };
}

pub const BecomeLeaderRing = ProduceRing(BecomeLeaderRecord);
pub const SlotDoneRing = ProduceRing(SlotDoneRecord);

// ═══════════════════════════════════════════════════════════════════════════════
// KATs — `zig build test` picks these up via the module's test block.
// ═══════════════════════════════════════════════════════════════════════════════

fn testBL(slot: u64) BecomeLeaderRecord {
    return .{
        .slot = slot,
        .parent_slot = slot -| 1,
        .chained_root = [_]u8{0} ** 32,
        .chained_root_valid = true,
        .seed = [_]u8{0} ** 32,
        .secret = [_]u8{0} ** 64,
        .shred_version = 57087,
        .tpu_ingest_on = false,
    };
}

test "ProduceRing: fill/drain FIFO, full→false, empty→false" {
    const a = std.testing.allocator;
    const cap: u32 = 8;
    const ring = try BecomeLeaderRing.init(a, cap);
    defer ring.deinit(a);

    var out: BecomeLeaderRecord = undefined;
    try std.testing.expect(!ring.tryPop(&out)); // empty

    var i: u64 = 0;
    while (i < cap) : (i += 1) try std.testing.expect(ring.tryPush(testBL(1000 + i)));
    try std.testing.expectEqual(@as(u32, cap), ring.len());

    try std.testing.expect(!ring.tryPush(testBL(9999))); // full → no overwrite
    try std.testing.expectEqual(@as(u64, 1), ring.overrun.load(.monotonic));

    i = 0;
    while (i < cap) : (i += 1) {
        try std.testing.expect(ring.tryPop(&out));
        try std.testing.expectEqual(@as(u64, 1000 + i), out.slot);
    }
    try std.testing.expectEqual(@as(u32, 0), ring.len());
    try std.testing.expect(!ring.tryPop(&out));
}

test "ProduceRing: wraparound preserves FIFO + conservation" {
    const a = std.testing.allocator;
    const cap: u32 = 16;
    const ring = try BecomeLeaderRing.init(a, cap);
    defer ring.deinit(a);

    var next_push: u64 = 0;
    var next_expect: u64 = 0;
    var round: u64 = 0;
    while (round < 100_000) : (round += 1) {
        var p: u32 = 0;
        while (p < 3) : (p += 1) {
            if (ring.tryPush(testBL(next_push))) next_push += 1;
        }
        var q: u32 = 0;
        var out: BecomeLeaderRecord = undefined;
        while (q < 2) : (q += 1) {
            if (ring.tryPop(&out)) {
                try std.testing.expectEqual(next_expect, out.slot);
                next_expect += 1;
            }
        }
        try std.testing.expect(ring.len() <= cap);
    }
    var out: BecomeLeaderRecord = undefined;
    while (ring.tryPop(&out)) {
        try std.testing.expectEqual(next_expect, out.slot);
        next_expect += 1;
    }
    try std.testing.expectEqual(next_push, next_expect);
    try std.testing.expectEqual(ring.pushed.load(.monotonic), ring.popped.load(.monotonic));
}

test "ProduceRing: threaded SPSC — every record delivered exactly once" {
    const a = std.testing.allocator;
    const cap: u32 = 64; // production capacity
    const ring = try BecomeLeaderRing.init(a, cap);
    defer ring.deinit(a);

    const N: u64 = 200_000;

    const Consumer = struct {
        fn run(r: *BecomeLeaderRing, n: u64, seen_sum: *u64, count: *u64) void {
            var got: u64 = 0;
            var sum: u64 = 0;
            var out: BecomeLeaderRecord = undefined;
            while (got < n) {
                if (r.tryPop(&out)) {
                    sum +%= out.slot;
                    got += 1;
                } else std.atomic.spinLoopHint();
            }
            seen_sum.* = sum;
            count.* = got;
        }
    };

    var seen_sum: u64 = 0;
    var count: u64 = 0;
    const t = try std.Thread.spawn(.{}, Consumer.run, .{ ring, N, &seen_sum, &count });
    var i: u64 = 0;
    while (i < N) {
        if (ring.tryPush(testBL(i))) i += 1 else std.atomic.spinLoopHint();
    }
    t.join();

    try std.testing.expectEqual(N, count);
    try std.testing.expectEqual(N * (N - 1) / 2, seen_sum);
    try std.testing.expectEqual(N, ring.pushed.load(.monotonic));
    try std.testing.expectEqual(N, ring.popped.load(.monotonic));
}

test "SlotDoneRing: round-trip transfers bytes + status" {
    const a = std.testing.allocator;
    const ring = try SlotDoneRing.init(a, 8);
    defer ring.deinit(a);

    const bytes = try a.dupe(u8, "hello-block");
    try std.testing.expect(ring.tryPush(.{ .slot = 42, .parent_slot = 41, .block_bytes = bytes, .status = .ok }));

    var out: SlotDoneRecord = undefined;
    try std.testing.expect(ring.tryPop(&out));
    try std.testing.expectEqual(@as(u64, 42), out.slot);
    try std.testing.expectEqual(SlotDoneRecord.Status.ok, out.status);
    try std.testing.expectEqualStrings("hello-block", out.block_bytes);
    a.free(out.block_bytes); // consumer (replay) owns it after pop

    // skipped status carries no bytes.
    try std.testing.expect(ring.tryPush(.{ .slot = 7, .parent_slot = 6, .block_bytes = &.{}, .status = .skipped }));
    try std.testing.expect(ring.tryPop(&out));
    try std.testing.expectEqual(SlotDoneRecord.Status.skipped, out.status);
}
