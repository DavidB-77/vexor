//! LedgerTile — moves VexLedger I/O off the consensus hot path.
//!
//! The four shred-completion sites (8 verify workers / AF_XDP insert / kernel-UDP
//! recv / repair, all on different threads) ENQUEUE shred + FINISH messages into a
//! bounded MPSC ring. Enqueue is NON-BLOCKING and DROPS on full — the ledger is
//! best-effort and must NEVER stall consensus (a dropped-into slot self-identifies
//! as a gap on offline replay; it just can't be re-replayed). A single dedicated
//! consumer tile, pinned to a cold core, drains the ring and performs
//! putShred/finishSlot — including the fsync — entirely off the consensus threads.
//!
//! Concurrency model: a mutex-guarded MPSC ring. The lock is held ONLY for a
//! ~1.3 KB memcpy (claim + copy a message in/out), never for the fsync — which is
//! the whole point of the tile. With four brief-holding producers + one consumer
//! the contention is negligible vs. the inline fsync it replaces. (A lock-free
//! Vyukov queue would shave the enqueue further, but correctness/auditability wins
//! here — the win is moving fsync off-thread, not enqueue latency.)
//!
//! Gated exactly as the inline path: comptime `-Dvex_ledger` + the `VEX_LEDGER`
//! env. When the tile is wired, the producer enqueues instead of writing inline;
//! the tile owns every VexLedger write. Dormant + byte-identical when off.

const std = @import("std");
const vex_ledger = @import("vex_ledger");
const VexLedger = vex_ledger.VexLedger;
const FinishBlob = vex_ledger.FinishBlob;
const SlotMeta = vex_ledger.SlotMeta;
// Reconciliation backfill (Track 2c): same-directory import, no new module —
// shred_assembler.zig has no reverse dependency on this file, so this is not
// a cycle. `shred.zig` re-exports the identical `ShredAssembler` type
// (`pub const ShredAssembler = shred_assembler.ShredAssembler;`), so this is
// type-identical to what tvu.zig wires via `shred_mod.ShredAssembler`.
const shred_assembler = @import("shred_assembler.zig");
const ShredAssembler = shred_assembler.ShredAssembler;
const RawDataShred = ShredAssembler.RawDataShred;

pub const MSG_DATA: u8 = 0;
pub const MSG_CODE: u8 = 1;
pub const MSG_FINISH: u8 = 2;

/// Inline ring-slot payload bound. Must hold the largest shred wire (~1232 B) and
/// the largest FinishBlob (HEADER_LEN 69 + 4·num_completed). A FINISH that would
/// exceed this is dropped+logged at enqueue (never truncated) — see enqueueFinish.
/// 4096 holds (4096−69)/4 = 1006 completed-data indexes — covers realistic large
/// blocks (LEDG cross-review Q3). Pathological 32k-shred slots still drop, SAFELY:
/// the slot's shreds enqueue fine and offline replay RE-DERIVES SlotMeta from the
/// shreds (Boot-B proved bank-exact without stored SlotMeta) — only the stored
/// meta CF is absent for that big slot. The live FINISH sampler (enqueueFinish)
/// logs the real `completed_data_indexes.len` distribution so we can right-size.
pub const MAX_MSG: usize = 4096;

/// Default ring capacity (messages). One completed slot enqueues N_data_shreds + 1
/// messages; at 4 KB/slot of inline buffers this sizes the disk-hiccup window.
/// 65536 × ~4120 B (RingMsg, 8-byte aligned) ≈ 257.5 MiB heap alloc — absorbs
/// catch-up/repair bursts that peg a smaller ring at 100% and silently drop
/// (SCOPE-2-vexledger-repair-persist-2026-07-17.md §1e: live specimen at the
/// prior 8192 cap pegged 8192/8192 and dropped 5244 msgs in the first stats
/// window during catch-up). Heap-allocated in LedgerTile.init via
/// `allocator.alloc(RingMsg, capacity)` — raising this is a pure sizing change,
/// no stack array, no other fixed-size assumption depends on it. Operator
/// sign-off obtained for the ~32 MiB -> ~256 MiB box-memory cost (node down at
/// time of change, TRACK2-VEXLEDGER-PROGRESS-2026-07-17.log).
pub const DEFAULT_CAPACITY: usize = 65536;

/// Parse a u64 env var; returns 0 when unset or unparseable (the disabled sentinel
/// for the prune knobs — `--limit-ledger-size` is opt-in).
fn parseEnvU64(name: []const u8) u64 {
    const v = std.posix.getenv(name) orelse return 0;
    return std.fmt.parseInt(u64, v, 10) catch 0;
}

const RingMsg = struct {
    kind: u8 = 0,
    slot: u64 = 0,
    index: u32 = 0,
    len: u32 = 0,
    buf: [MAX_MSG]u8 = undefined,
};

pub const LedgerTile = struct {
    ring: []RingMsg,
    head: usize = 0, // consumer dequeues here
    tail: usize = 0, // producer enqueues here
    count: usize = 0,
    mutex: std.Thread.Mutex = .{},
    dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    enqueued: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    applied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Live sampler of completed_data_indexes.len (LEDG Q3): logs each new high so
    /// we can right-size MAX_MSG from the real distribution after the soak.
    max_completed: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    vl: *VexLedger,
    allocator: std.mem.Allocator,
    /// Bounded-ledger prune config (`--limit-ledger-size` semantics). Read ONCE in
    /// init from env; 0 = DISABLED (unbounded — the prior behavior; opt-in safe
    /// default). VEX_LEDGER_MAX_BYTES (disk budget) takes precedence over
    /// VEX_LEDGER_KEEP_SLOTS (slot window). The periodic prune fires from the single
    /// consumer thread (apply→MSG_FINISH), so these are consumer-only (no atomics)
    /// and a prune never races another prune.
    prune_max_bytes: u64 = 0,
    prune_keep_slots: u64 = 0,
    prune_every_slots: u64 = 64, // run a prune at most once per this many completed slots
    finishes_since_prune: u64 = 0,
    pruned_segments_total: u64 = 0,
    pruned_bytes_total: u64 = 0,
    /// Instrumentation (perf-tuning telemetry). ring_high_water = peak ring occupancy
    /// since the last stats window (mutex-protected, written by producers); reset per
    /// window. finishes_total drives the stats cadence (consumer-only).
    ring_high_water: usize = 0,
    finishes_total: u64 = 0,
    /// Per-slot persist latency (finishSlot = serialize meta + append + fsync; the
    /// fsync dominates → this is the fsync-cadence tuning signal). ns, reset per window.
    finish_ns_max: u64 = 0,
    finish_ns_sum: u64 = 0,
    finish_ns_count: u64 = 0,

    // ---- reconciliation backfill (Track 2c) ----
    // See VEXLEDGER-HYBRID-FD-SPEED-AGAVE-COMPLETE-DESIGN-2026-07-17.md C4/C5.
    // VexLedger is a SHADOW writer — the authoritative shred copy lives in
    // `shred_assembler`, so a dropped enqueue loses the shred from DISK only,
    // not from the system. `assembler` (set post-init via setAssembler, wired
    // from tvu.zig's startLedgerTile) lets the cold consumer re-read + re-
    // persist a suspect slot's shreds before it ages out of the assembler's
    // working set (rooted-prune cutoff, `clearRootedSlots`).
    assembler: ?*ShredAssembler = null,
    /// Bounded, deduped-on-the-common-case superset of slots that shed >=1
    /// dropped MSG_DATA/MSG_FINISH (recordSuspectSlot). A SEPARATE mutex from
    /// the ring's — kept apart so the hot ring-enqueue critical section (the
    /// thing already proven safe by the MPSC KATs above) is never widened.
    /// FIFO ring; on overflow the OLDEST entry is evicted and
    /// `suspect_overflow_total` counts it (telemetry, mirrors 2b's gap
    /// counters) — an evicted-while-unbackfilled slot still has repair-fallback
    /// (network re-request) as the outer safety net; it is not silently lost,
    /// only demoted out of the fast reconciliation path.
    suspect_mutex: std.Thread.Mutex = .{},
    suspect_slots: []u64 = &.{},
    suspect_head: usize = 0,
    suspect_tail: usize = 0,
    suspect_len: usize = 0,
    /// Last slot pushed — a cheap O(1) same-burst dedup (a single bad slot
    /// commonly sheds many CONSECUTIVE drops; this collapses that run to one
    /// suspect entry without a full scan or a heap set). Duplicates from a
    /// non-consecutive interleaving are tolerated: backfill is idempotent, so
    /// a duplicate suspect entry only costs a harmless redundant no-op pass.
    suspect_last: u64 = NO_SUSPECT_SLOT,
    suspect_overflow_total: std.atomic.Value(u64) = .init(0),
    /// Consumer-thread-only (only backfillOneSuspect mutates it) — no atomic.
    backfilled_total: u64 = 0,

    /// Suspect-ring capacity: a "few thousand slot numbers" per the design
    /// doc's sizing note (C7) — tens of KB, independent of the main ring.
    pub const SUSPECT_CAPACITY: usize = 4096;
    const NO_SUSPECT_SLOT: u64 = std.math.maxInt(u64);
    /// Bounded lock-hold for one assembler read (the C5 caveat): each call to
    /// getRawDataShredsForSlotChunk holds the assembler mutex — shared with
    /// the hot insert path — for at most this many shreds' worth of dupe+
    /// append, then releases. Chosen small enough that even a full 32768-shred
    /// pathological slot backfills in ~512 short lock/unlock cycles rather
    /// than one multi-thousand-shred hold.
    const BACKFILL_CHUNK: u32 = 64;

    pub fn init(allocator: std.mem.Allocator, vl: *VexLedger, capacity: usize) !*LedgerTile {
        const self = try allocator.create(LedgerTile);
        errdefer allocator.destroy(self);
        const ring = try allocator.alloc(RingMsg, capacity);
        errdefer allocator.free(ring);
        const suspect = try allocator.alloc(u64, SUSPECT_CAPACITY);
        // --limit-ledger-size: bound the on-disk ledger. Unset/0 → pruning DISABLED
        // (unbounded = prior behavior). Whole-segment unlink is O(1) + near-zero
        // write-amp (no compaction). Off the consensus path → bank-hash-neutral.
        const max_bytes = parseEnvU64("VEX_LEDGER_MAX_BYTES");
        const keep_slots = parseEnvU64("VEX_LEDGER_KEEP_SLOTS");
        self.* = .{
            .ring = ring,
            .vl = vl,
            .allocator = allocator,
            .prune_max_bytes = max_bytes,
            .prune_keep_slots = keep_slots,
            .suspect_slots = suspect,
        };
        if (max_bytes != 0 or keep_slots != 0) {
            std.log.warn("[LEDGER-TILE] prune ARMED: max_bytes={d} keep_slots={d} every={d}slots", .{ max_bytes, keep_slots, self.prune_every_slots });
        } else {
            std.log.warn("[LEDGER-TILE] prune DISABLED (VEX_LEDGER_MAX_BYTES / VEX_LEDGER_KEEP_SLOTS unset) — ledger grows unbounded", .{});
        }
        return self;
    }

    pub fn deinit(self: *LedgerTile) void {
        self.allocator.free(self.ring);
        if (self.suspect_slots.len != 0) self.allocator.free(self.suspect_slots);
        self.allocator.destroy(self);
    }

    /// Wire the shred assembler for the reconciliation backfill. Called once,
    /// post-init, before the tile thread is spawned (tvu.zig's
    /// startLedgerTile). Without this, backfillOneSuspect is a no-op — the
    /// tile degrades to the Track 2 stopgap (bigger ring only), never worse.
    pub fn setAssembler(self: *LedgerTile, assembler: *ShredAssembler) void {
        self.assembler = assembler;
    }

    // ---- producer side (any of the 4 completion threads) ----

    /// Claim a ring slot and copy `payload` in. Returns false (no enqueue) if the
    /// payload is oversized or the ring is full. Lock held only for the memcpy.
    fn tryEnqueue(self: *LedgerTile, kind: u8, slot: u64, index: u32, payload: []const u8) bool {
        if (payload.len > MAX_MSG) return false;
        self.mutex.lock();
        if (self.count == self.ring.len) {
            self.mutex.unlock();
            return false;
        }
        const i = self.tail;
        const m = &self.ring[i];
        m.kind = kind;
        m.slot = slot;
        m.index = index;
        m.len = @intCast(payload.len);
        @memcpy(m.buf[0..payload.len], payload);
        self.tail = (i + 1) % self.ring.len;
        self.count += 1;
        if (self.count > self.ring_high_water) self.ring_high_water = self.count; // peak occupancy (under lock)
        self.mutex.unlock();
        _ = self.enqueued.fetchAdd(1, .monotonic);
        return true;
    }

    fn enqueueDrop(self: *LedgerTile, kind: u8, slot: u64, index: u32, payload: []const u8) void {
        if (!self.tryEnqueue(kind, slot, index, payload)) {
            const d = self.dropped.fetchAdd(1, .monotonic) + 1;
            // Track 2c: a dropped DATA or FINISH message means this slot's
            // durable copy may now be short — mark it suspect so the cold
            // consumer's reconciliation pass can re-read + re-persist it from
            // the assembler's authoritative copy. MSG_CODE is excluded: coding
            // shreds have no completion-path feeder today (see the design
            // doc's "Named unknowns" #1) and FEC-recover-from-ledger is not a
            // guarantee this backfill makes.
            if (kind == MSG_DATA or kind == MSG_FINISH) self.recordSuspectSlot(slot);
            if (d % 1000 == 1) {
                std.log.warn("[LEDGER-TILE] dropped {d} msgs (ring full / disk backpressure) — ledger best-effort, consensus unaffected", .{d});
            }
        }
    }

    /// Producer-side (any of the 4 completion threads, via enqueueDrop) push
    /// into the bounded suspect-slot ring. Bounded critical section (a fixed
    /// handful of comparisons + one store) — the same "non-blocking" posture
    /// as tryEnqueue's ring lock: never held for I/O or unbounded work, so it
    /// cannot stall the producer. No-op if the tile was constructed without a
    /// suspect ring (the low-level `testRing` KAT helper below — those tests
    /// exercise the MPSC ring only and never look at suspect state).
    fn recordSuspectSlot(self: *LedgerTile, slot: u64) void {
        if (self.suspect_slots.len == 0) return;
        self.suspect_mutex.lock();
        defer self.suspect_mutex.unlock();
        if (self.suspect_last == slot) return; // same-burst dedup
        self.suspect_last = slot;
        if (self.suspect_len == self.suspect_slots.len) {
            // FIFO eviction: the ring is full — drop the OLDEST suspect entry
            // to make room. That slot isn't lost (repair-fallback still
            // covers it if it truly never gets backfilled), only demoted out
            // of this fast path — count it so a persistently-full suspect
            // ring is visible, exactly like the ring-drop counter above.
            self.suspect_head = (self.suspect_head + 1) % self.suspect_slots.len;
            self.suspect_len -= 1;
            const n = self.suspect_overflow_total.fetchAdd(1, .monotonic) + 1;
            if (n % 100 == 1) {
                std.log.warn("[LEDGER-TILE] suspect-set OVERFLOW ({d} total, cap={d}) — oldest suspect slot evicted, falling back to network repair for it", .{ n, self.suspect_slots.len });
            }
        }
        self.suspect_slots[self.suspect_tail] = slot;
        self.suspect_tail = (self.suspect_tail + 1) % self.suspect_slots.len;
        self.suspect_len += 1;
    }

    /// Cold-consumer-thread-only: pop the oldest suspect slot, if any.
    fn popSuspectSlot(self: *LedgerTile) ?u64 {
        if (self.suspect_slots.len == 0) return null;
        self.suspect_mutex.lock();
        defer self.suspect_mutex.unlock();
        if (self.suspect_len == 0) return null;
        const slot = self.suspect_slots[self.suspect_head];
        self.suspect_head = (self.suspect_head + 1) % self.suspect_slots.len;
        self.suspect_len -= 1;
        // The same-burst dedup in recordSuspectSlot compares against the
        // TAIL of the current queue, not history — once the queue drains to
        // empty there is no tail left to compare against, so a fresh push of
        // this same slot (a genuine new drop, OR backfillOneSuspect's own
        // requeueSuspectSlot for a still-incomplete slot) must NOT be
        // silently deduped away. Without this reset, requeueSuspectSlot would
        // be a permanent no-op the moment its one entry gets popped.
        if (self.suspect_len == 0) self.suspect_last = NO_SUSPECT_SLOT;
        return slot;
    }

    /// Re-queue a suspect slot (still-incomplete-in-the-assembler case below).
    /// Goes through the SAME dedup/FIFO path as a fresh drop — a re-queued
    /// slot moves to the BACK of the queue, so one straggler can never starve
    /// other suspects (fair round-robin).
    fn requeueSuspectSlot(self: *LedgerTile, slot: u64) void {
        self.recordSuspectSlot(slot);
    }

    /// Cold-core reconciliation pass (Track 2c) — called from run() whenever
    /// the main ring is drained (never competes with real-time ring drains).
    /// Pops ONE suspect slot and, if the assembler still holds it complete,
    /// re-reads it in bounded chunks (copy-out-then-release, C5/C6) and
    /// re-persists via the SAME idempotent putShred/finishSlot apply() uses —
    /// so a redundant re-persist of an already-complete slot is a harmless
    /// no-op cost, never a correctness hazard. Best-effort: never fatal, never
    /// blocks (assembler reads bound their own lock hold; VexLedger writes
    /// already catch-swallow, exactly like apply()).
    fn backfillOneSuspect(self: *LedgerTile) void {
        const assembler = self.assembler orelse return;
        const slot = self.popSuspectSlot() orelse return;

        // Only strict-re-persist a slot the assembler has FULLY assembled —
        // matches the design's "expected N vs persisted M, clear only when
        // they match" contract (C4 item 3). A still-in-flight slot is
        // re-queued (fair FIFO, see requeueSuspectSlot) rather than backfilled
        // from a partial view; its eventual real completion will FINISH it
        // through the normal hot path regardless. A slot that is no longer in
        // the assembler at all (rooted-pruned or never actually held any data
        // shreds — e.g. a FINISH-only drop whose shreds all landed fine) has
        // nothing to backfill; the outer guarantee for that case is
        // repair-fallback (network re-request), measured by drop->gap (2b).
        if (!assembler.isSlotComplete(slot)) {
            self.requeueSuspectSlot(slot);
            return;
        }

        var raws = std.ArrayListUnmanaged(RawDataShred){};
        defer {
            for (raws.items) |r| self.allocator.free(r.wire);
            raws.deinit(self.allocator);
        }

        // Copy-out-then-release, chunked (C5/C6 — the critical caveat): each
        // call below acquires+releases the assembler mutex for AT MOST
        // BACKFILL_CHUNK shreds, so the lock is never held across putShred/
        // finishSlot (both run entirely outside this loop) nor across a whole
        // large slot's worth of allocations in one hold.
        var idx: u32 = 0;
        while (true) {
            const chunk = assembler.getRawDataShredsForSlotChunk(self.allocator, slot, idx, BACKFILL_CHUNK) catch break;
            defer self.allocator.free(chunk.shreds); // ownership of each .wire moves into `raws` below
            for (chunk.shreds) |r| {
                raws.append(self.allocator, r) catch {
                    self.allocator.free(r.wire);
                    continue;
                };
            }
            idx = chunk.next_idx;
            if (chunk.done) break;
        }

        if (raws.items.len == 0) return; // slot vanished from the assembler between the two checks above (rare race) — nothing to do

        // Re-persist every shred we hold (idempotent last-wins — apply()'s
        // MSG_DATA path does the exact same putShred call).
        for (raws.items) |r| self.vl.putShred(slot, r.index, r.wire) catch {};

        // Re-derive SlotMeta from the shreds we just re-read — a THIRD mirror
        // of the SAME derivation in tvu.zig's persistCompletedSlotToLedger
        // (:1029-1062) / persistCompletedSlotViaTile (:1082-1108), which are
        // themselves already a deliberate mirror of each other. Kept in
        // lockstep by inspection (no shared helper exists yet for the pair;
        // this is the smallest faithful addition, not a refactor of the
        // existing two call sites — see the operator's "keep the current
        // architecture" constraint on this branch).
        var max_index: u32 = 0;
        var consumed: u32 = 0;
        var completed = std.ArrayListUnmanaged(u32){};
        defer completed.deinit(self.allocator);
        for (raws.items) |r| {
            if (r.index > max_index) max_index = r.index;
            if (r.index == consumed) consumed += 1;
            if (r.wire.len > 85 and (r.wire[85] & 0x40) != 0) {
                completed.append(self.allocator, r.index) catch {};
            }
        }
        const first = raws.items[0].wire;
        const parent_slot: ?u64 = if (first.len >= 85) blk: {
            const po = std.mem.readInt(u16, first[83..][0..2], .little);
            break :blk if (po == 0) null else slot -| @as(u64, po);
        } else null;

        const meta = SlotMeta{
            .parent_slot = parent_slot,
            .received = max_index + 1,
            .consumed = consumed,
            .last_index = max_index,
            .connected_flags = 0,
            .first_shred_timestamp = 0,
            .completed_data_indexes = completed.items,
        };
        self.vl.finishSlot(slot, meta) catch {};
        self.backfilled_total += 1;
    }

    pub fn enqueueShred(self: *LedgerTile, slot: u64, index: u32, wire: []const u8) void {
        self.enqueueDrop(MSG_DATA, slot, index, wire);
    }

    pub fn enqueueCodingShred(self: *LedgerTile, slot: u64, index: u32, wire: []const u8) void {
        self.enqueueDrop(MSG_CODE, slot, index, wire);
    }

    /// Encode the producer-derived SlotMeta into a FINISH message. If the meta is
    /// larger than the inline buffer it is DROPPED+logged (never truncated); the
    /// slot then self-identifies as a gap on replay (received>stored).
    pub fn enqueueFinish(self: *LedgerTile, slot: u64, meta: SlotMeta) void {
        // Sample completed_data_indexes.len — log each new high to right-size MAX_MSG.
        const ncomp: u32 = @intCast(meta.completed_data_indexes.len);
        if (ncomp > self.max_completed.load(.monotonic)) {
            self.max_completed.store(ncomp, .monotonic);
            std.log.warn("[LEDGER-TILE] new max completed_data_indexes={d} (slot {d}); FINISH={d}B, MAX_MSG={d}", .{ ncomp, slot, FinishBlob.encodedLen(meta), MAX_MSG });
        }
        var fbuf: [MAX_MSG]u8 = undefined;
        const enc = FinishBlob.encode(&fbuf, meta) catch {
            const d = self.dropped.fetchAdd(1, .monotonic) + 1;
            std.log.warn("[LEDGER-TILE] FINISH meta slot {d} exceeds {d}B inline buf — dropped (gap on replay); total dropped {d}", .{ slot, MAX_MSG, d });
            return;
        };
        self.enqueueDrop(MSG_FINISH, slot, 0, enc);
    }

    // ---- consumer side (the single tile thread) ----

    /// Copy one message OUT under the lock; the caller applies it (putShred /
    /// finishSlot incl. fsync) OUTSIDE the lock so the I/O never holds the ring.
    fn dequeue(self: *LedgerTile, out: *RingMsg) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.count == 0) return false;
        const i = self.head;
        const m = &self.ring[i];
        out.kind = m.kind;
        out.slot = m.slot;
        out.index = m.index;
        out.len = m.len;
        @memcpy(out.buf[0..m.len], m.buf[0..m.len]);
        self.head = (i + 1) % self.ring.len;
        self.count -= 1;
        return true;
    }

    /// Apply one drained message to VexLedger (off the consensus thread). Errors
    /// are swallowed (best-effort), exactly as the prior inline path did.
    fn apply(self: *LedgerTile, m: *const RingMsg) void {
        switch (m.kind) {
            MSG_DATA => self.vl.putShred(m.slot, m.index, m.buf[0..m.len]) catch {},
            MSG_CODE => self.vl.putCodingShred(m.slot, m.index, m.buf[0..m.len]) catch {},
            MSG_FINISH => {
                const meta = FinishBlob.decode(self.allocator, m.buf[0..m.len]) catch return;
                defer self.allocator.free(meta.completed_data_indexes);
                const t0 = std.time.nanoTimestamp();
                self.vl.finishSlot(m.slot, meta) catch {};
                const dt: u64 = @intCast(@max(0, std.time.nanoTimestamp() - t0));
                self.finish_ns_sum += dt;
                self.finish_ns_count += 1;
                if (dt > self.finish_ns_max) self.finish_ns_max = dt;
                self.maybePrune();
                self.maybeLogStats();
            },
            else => {},
        }
        _ = self.applied.fetchAdd(1, .monotonic);
    }

    /// Perf telemetry, emitted once per 512 completed slots (~3.5 min at 2.5 slots/s).
    /// Consumer-thread-only. Surfaces ring backpressure (high-water vs capacity →
    /// the ring-capacity tuning signal), drop count (producer outran consumer), and
    /// prune reclaim. Logging only — zero effect on ingest or bank_hash.
    fn maybeLogStats(self: *LedgerTile) void {
        self.finishes_total += 1;
        if (self.finishes_total % 512 != 0) return;
        self.mutex.lock();
        const hw = self.ring_high_water;
        self.ring_high_water = self.count; // reset watermark to current for the next window
        self.mutex.unlock();
        const avg_us: u64 = if (self.finish_ns_count != 0) (self.finish_ns_sum / self.finish_ns_count) / 1000 else 0;
        const max_us: u64 = self.finish_ns_max / 1000;
        self.suspect_mutex.lock();
        const suspect_pending = self.suspect_len;
        self.suspect_mutex.unlock();
        // gap_slots/gap_shreds (Phase 2b): cumulative drop->gap reconciliation from
        // VexLedger.finishSlot — measured residual holes, distinct from `dropped`
        // (ring-enqueue-level) since a slot can shed some shreds without going to
        // zero. Read as plain fields: only this consumer thread ever calls
        // finishSlot (mutates them), so no lock/atomic needed for the read here.
        // suspect_pending/backfilled/suspect_overflow (Phase 2c): the
        // reconciliation backfill's own instrumentation — pending = current
        // suspect-ring occupancy, backfilled = cumulative slots re-persisted
        // from the assembler, suspect_overflow = suspect-ring FIFO evictions
        // (the "we couldn't even remember to try" telemetry).
        std.log.warn("[LEDGER-TILE-STATS] slots={d} enq={d} applied={d} dropped={d} ring_high_water={d}/{d} persist_us(avg/max)={d}/{d} pruned={d}seg/{d}MiB gap_slots={d} gap_shreds={d} suspect_pending={d}/{d} backfilled={d} suspect_overflow={d}", .{ self.finishes_total, self.enqueued.load(.monotonic), self.applied.load(.monotonic), self.dropped.load(.monotonic), hw, self.ring.len, avg_us, max_us, self.pruned_segments_total, self.pruned_bytes_total >> 20, self.vl.gap_slots_total, self.vl.gap_shreds_total, suspect_pending, self.suspect_slots.len, self.backfilled_total, self.suspect_overflow_total.load(.monotonic) });
        // reset per-window latency accumulators
        self.finish_ns_max = 0;
        self.finish_ns_sum = 0;
        self.finish_ns_count = 0;
    }

    /// Periodic bounded-ledger prune (`--limit-ledger-size`). Consumer-thread-ONLY
    /// (called from apply→MSG_FINISH), so the counter needs no atomics and a prune
    /// never races another prune. Runs at most once per `prune_every_slots` completed
    /// slots when a limit is configured. Whole-segment unlink is O(1); errors are
    /// swallowed (best-effort, never fatal to ingest) exactly like apply(). The prune
    /// touches the ledger store ONLY (off the consensus path) → bank-hash-neutral.
    /// Reads (repair-serve / RPC) take the shared lock and tolerate a concurrent prune.
    fn maybePrune(self: *LedgerTile) void {
        if (self.prune_max_bytes == 0 and self.prune_keep_slots == 0) return;
        self.finishes_since_prune += 1;
        if (self.finishes_since_prune < self.prune_every_slots) return;
        self.finishes_since_prune = 0;
        const stats = if (self.prune_max_bytes != 0)
            (self.vl.pruneToByteLimit(self.prune_max_bytes) catch return)
        else
            (self.vl.pruneToSlotWindow(self.prune_keep_slots) catch return);
        if (stats.segments_unlinked != 0) {
            self.pruned_segments_total += stats.segments_unlinked;
            self.pruned_bytes_total += stats.bytes_freed;
            std.log.warn("[LEDGER-TILE] prune: unlinked {d} seg ({d} MiB), lowest_kept={?d}; cumulative {d} seg / {d} MiB", .{ stats.segments_unlinked, stats.bytes_freed >> 20, stats.lowest_kept, self.pruned_segments_total, self.pruned_bytes_total >> 20 });
        }
    }

    /// The tile main loop — spawn this on a cold core. Drains until `running` is
    /// cleared AND the ring is fully flushed (graceful shutdown).
    pub fn run(self: *LedgerTile) void {
        var msg: RingMsg = undefined;
        while (true) {
            if (self.dequeue(&msg)) {
                self.apply(&msg);
            } else {
                // Ring is drained — this is exactly the "ring not saturated"
                // window the design reserves for reconciliation (C4 item 3):
                // real-time ring drains always win, backfill only runs when
                // there is nothing waiting to be applied.
                self.backfillOneSuspect();
                if (!self.running.load(.acquire)) break;
                std.Thread.sleep(50 * std.time.ns_per_us); // 50µs idle poll on the cold core
            }
        }
    }

    pub fn stop(self: *LedgerTile) void {
        self.running.store(false, .release);
    }

    fn pinSelf(core_id: u32) void {
        var cpu_set = [_]usize{0} ** 16;
        const idx = core_id / @bitSizeOf(usize);
        const bit: u6 = @intCast(core_id % @bitSizeOf(usize));
        cpu_set[idx] = @as(usize, 1) << bit;
        _ = std.os.linux.syscall3(.sched_setaffinity, 0, @sizeOf(@TypeOf(cpu_set)), @intFromPtr(&cpu_set));
    }

    /// Spawn the consumer loop on its own thread, pinned to `core_id` (a cold core).
    /// Returns the thread handle for a graceful stop()+join at shutdown (Q4).
    pub fn spawnPinned(self: *LedgerTile, core_id: u32) !std.Thread {
        const Entry = struct {
            fn run(t: *LedgerTile, core: u32) void {
                pinSelf(core);
                t.run();
            }
        };
        return std.Thread.spawn(.{}, Entry.run, .{ self, core_id });
    }
};

// ----------------------------------------------------------------------------
// KATs (ring concurrency — the new, consensus-adjacent code). The apply→VexLedger
// path is covered by the module's KAT 25 (tileDrain reference); these prove the
// MPSC ring itself is loss/dup/corruption-free under concurrent producers and
// drops cleanly when full.
// ----------------------------------------------------------------------------

// Construct a ring-only tile (vl unused — these tests never call apply/run).
fn testRing(allocator: std.mem.Allocator, capacity: usize) !*LedgerTile {
    const self = try allocator.create(LedgerTile);
    self.* = .{ .ring = try allocator.alloc(RingMsg, capacity), .vl = undefined, .allocator = allocator };
    return self;
}

test "MPSC ring: concurrent producers — no loss, no dup, no corruption" {
    const A = std.testing.allocator;
    const tile = try testRing(A, 256); // small ring forces wraparound + backpressure
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }

    const NP: u32 = 4;
    const PER: u32 = 5000;

    const Producer = struct {
        fn run(t: *LedgerTile, pid: u32) void {
            var i: u32 = 0;
            while (i < PER) : (i += 1) {
                var payload: [8]u8 = undefined;
                std.mem.writeInt(u32, payload[0..4], pid, .little);
                std.mem.writeInt(u32, payload[4..8], i, .little);
                // retry-until-enqueued so the test asserts ZERO loss under concurrency
                while (!t.tryEnqueue(MSG_DATA, pid, i, &payload)) {
                    std.Thread.yield() catch {};
                }
            }
        }
    };

    var threads: [NP]std.Thread = undefined;
    for (0..NP) |p| threads[p] = try std.Thread.spawn(.{}, Producer.run, .{ tile, @as(u32, @intCast(p)) });
    // join on ANY exit (incl. a failed assertion) so producers never outlive the ring
    defer for (threads) |t| t.join();

    // single consumer drains concurrently; track (pid,i) keys for dup/loss/corruption
    var seen = std.AutoHashMap(u64, void).init(A);
    defer seen.deinit();
    var got: usize = 0;
    const total: usize = NP * PER;
    var msg: RingMsg = undefined;
    while (got < total) {
        if (tile.dequeue(&msg)) {
            try std.testing.expectEqual(MSG_DATA, msg.kind);
            try std.testing.expectEqual(@as(u32, 8), msg.len);
            const pid = std.mem.readInt(u32, msg.buf[0..4], .little);
            const i = std.mem.readInt(u32, msg.buf[4..8], .little);
            try std.testing.expect(pid < NP and i < PER); // not corrupted
            try std.testing.expectEqual(i, msg.index); // header index preserved (producer set index=i)
            try std.testing.expectEqual(@as(u64, pid), msg.slot); // header slot preserved (producer set slot=pid)
            const key = (@as(u64, pid) << 32) | i;
            try std.testing.expect(!seen.contains(key)); // no duplicate
            try seen.put(key, {});
            got += 1;
        } else {
            std.Thread.yield() catch {};
        }
    }
    try std.testing.expectEqual(total, seen.count()); // every msg arrived exactly once
    try std.testing.expectEqual(@as(u64, 0), tile.dropped.load(.monotonic)); // retry path => no drops
}

test "MPSC ring: drops cleanly when full, no block, survivors intact" {
    const A = std.testing.allocator;
    const cap: usize = 16;
    const tile = try testRing(A, cap);
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }

    // fill exactly to capacity
    var i: u32 = 0;
    while (i < cap) : (i += 1) {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], i, .little);
        try std.testing.expect(tile.tryEnqueue(MSG_DATA, i, i, &p));
    }
    // next K must DROP (never block), counted
    const K: u32 = 100;
    var k: u32 = 0;
    while (k < K) : (k += 1) {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, p[0..4], 9999, .little);
        tile.enqueueDrop(MSG_DATA, 9999, 9999, &p);
    }
    try std.testing.expectEqual(@as(u64, K), tile.dropped.load(.monotonic));
    try std.testing.expectEqual(cap, tile.count);

    // the cap survivors are the FIRST cap, in order, uncorrupted (no overwrite)
    var msg: RingMsg = undefined;
    var expect: u32 = 0;
    while (tile.dequeue(&msg)) : (expect += 1) {
        try std.testing.expectEqual(expect, msg.index);
        try std.testing.expectEqual(expect, std.mem.readInt(u32, msg.buf[0..4], .little));
    }
    try std.testing.expectEqual(@as(u32, cap), expect);
}

test "DEFAULT_CAPACITY ring allocates cleanly (memory sanity, Phase 2a)" {
    // Confirms the 65536-slot ring is a plain heap alloc (allocator.alloc, no
    // stack array) that succeeds and is exactly RingMsg-size * capacity — no
    // hidden fixed-size ceiling elsewhere silently truncates it.
    const A = std.testing.allocator;
    const tile = try testRing(A, DEFAULT_CAPACITY);
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }
    try std.testing.expectEqual(DEFAULT_CAPACITY, tile.ring.len);
    const bytes = @sizeOf(RingMsg) * DEFAULT_CAPACITY;
    std.debug.print("[LEDGER-TILE ring sizing] sizeOf(RingMsg)={d}B * DEFAULT_CAPACITY={d} = {d}B ({d} MiB)\n", .{ @sizeOf(RingMsg), DEFAULT_CAPACITY, bytes, bytes >> 20 });
}

test "burst that saturates the old 8192 cap does NOT saturate DEFAULT_CAPACITY (65536)" {
    // Regression KAT for Phase 2a (SCOPE-2-vexledger-repair-persist-2026-07-17.md
    // §1e): the live specimen's ring pegged 8192/8192 and dropped 5244 msgs in
    // the first catch-up burst. This proves a same-shaped burst (a touch over
    // the OLD 8192 cap) drops against the old cap but is fully absorbed at the
    // new DEFAULT_CAPACITY, without ever making tryEnqueue block.
    const A = std.testing.allocator;
    const old_cap: usize = 8192;
    const burst: usize = old_cap + 500; // mirrors "burst exceeds ring" in the field

    // Old cap: the burst must overflow and drop (reproduces the field symptom).
    {
        const tile = try testRing(A, old_cap);
        defer {
            A.free(tile.ring);
            A.destroy(tile);
        }
        var i: usize = 0;
        while (i < burst) : (i += 1) {
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, p[0..4], @intCast(i), .little);
            tile.enqueueDrop(MSG_DATA, @intCast(i), @intCast(i), &p); // non-blocking either way
        }
        try std.testing.expectEqual(burst - old_cap, tile.dropped.load(.monotonic));
    }

    // New DEFAULT_CAPACITY: the identical-shaped burst is fully absorbed, zero drops.
    {
        const tile = try testRing(A, DEFAULT_CAPACITY);
        defer {
            A.free(tile.ring);
            A.destroy(tile);
        }
        var i: usize = 0;
        while (i < burst) : (i += 1) {
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, p[0..4], @intCast(i), .little);
            tile.enqueueDrop(MSG_DATA, @intCast(i), @intCast(i), &p);
        }
        try std.testing.expectEqual(@as(u64, 0), tile.dropped.load(.monotonic));
        try std.testing.expectEqual(burst, tile.count);
    }
}

test "tile path: gap telemetry (Phase 2b) fires through the real production path" {
    // The other KATs prove the ring (tryEnqueue/enqueueDrop) and prove
    // VexLedger.finishSlot's reconciliation math in isolation (kat_vex_ledger's
    // direct finishSlot calls). Neither proves the thing Phase 2b actually
    // depends on in production: that `received` survives enqueueFinish's
    // FinishBlob.encode -> ring -> apply's FinishBlob.decode -> finishSlot
    // round-trip on the REAL tile path (persistCompletedSlotViaTile's shape:
    // enqueueShred × N then enqueueFinish, drained by apply). This uses a real
    // VexLedger + real LedgerTile (not the `vl=undefined` testRing helper) to
    // close that gap.
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathbuf);
    const ledger_path = try std.fs.path.join(A, &.{ base, "ledger" });
    defer A.free(ledger_path);

    var ledger = try VexLedger.init(A, ledger_path);
    defer ledger.deinit();

    const tile = try LedgerTile.init(A, ledger, 64);
    defer tile.deinit();

    // drain helper: dequeue+apply everything currently queued.
    const drain = struct {
        fn run(t: *LedgerTile) void {
            var msg: RingMsg = undefined;
            while (t.dequeue(&msg)) t.apply(&msg);
        }
    }.run;

    // Case 1: complete slot — all N shreds enqueued before FINISH(received=N).
    // No gap should be recorded.
    {
        const slot: u64 = 500;
        const n: u32 = 10;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            var wire = [_]u8{0xAB} ** 32;
            tile.enqueueShred(slot, i, &wire);
        }
        const meta = SlotMeta{ .received = n, .consumed = n, .last_index = n - 1 };
        tile.enqueueFinish(slot, meta);
        drain(tile);
        try std.testing.expectEqual(@as(u64, 0), ledger.gap_slots_total);
        try std.testing.expectEqual(@as(u64, 0), ledger.gap_shreds_total);
    }

    // Case 2: partial slot — k of the N expected shreds never got enqueued
    // (models a ring-full drop mid-burst), FINISH still claims received=N (the
    // producer derived N before the tile started dropping). This must surface
    // as exactly one gap slot with gap==k, through the FULL encode/ring/decode/
    // finishSlot path — not a direct finishSlot call.
    {
        const slot: u64 = 501;
        const n: u32 = 10;
        const k: u32 = 3;
        var i: u32 = 0;
        while (i < n - k) : (i += 1) {
            var wire = [_]u8{0xCD} ** 32;
            tile.enqueueShred(slot, i, &wire);
        }
        const meta = SlotMeta{ .received = n, .consumed = n - k, .last_index = n - 1 };
        tile.enqueueFinish(slot, meta);
        drain(tile);
        try std.testing.expectEqual(@as(u64, 1), ledger.gap_slots_total);
        try std.testing.expectEqual(@as(u64, k), ledger.gap_shreds_total);
    }
}

test "FINISH oversize meta is dropped, not truncated" {
    const A = std.testing.allocator;
    const tile = try testRing(A, 8);
    defer {
        A.free(tile.ring);
        A.destroy(tile);
    }
    // a meta whose completed_data_indexes overflow MAX_MSG must drop, not enqueue
    const huge = try A.alloc(u32, MAX_MSG); // 4·MAX_MSG bytes >> MAX_MSG
    defer A.free(huge);
    const meta = SlotMeta{ .completed_data_indexes = huge };
    tile.enqueueFinish(1234, meta);
    try std.testing.expectEqual(@as(usize, 0), tile.count); // nothing enqueued
    try std.testing.expectEqual(@as(u64, 1), tile.dropped.load(.monotonic));
}

// ----------------------------------------------------------------------------
// KATs — Track 2c reconciliation backfill (VEXLEDGER-HYBRID-FD-SPEED-AGAVE-
// COMPLETE-DESIGN-2026-07-17.md). Prove: (a) a dropped shred is recorded in
// the suspect-set, (b) the backfill re-reads from the assembler and
// re-persists so the slot becomes complete, (c) idempotency (double putShred
// is safe), (d) the suspect-set bound is respected (FIFO eviction + overflow
// telemetry).
// ----------------------------------------------------------------------------

// Like testRing, but also allocates a suspect ring — for KATs that exercise
// recordSuspectSlot/popSuspectSlot directly without needing a real VexLedger.
fn testRingWithSuspect(allocator: std.mem.Allocator, capacity: usize, suspect_cap: usize) !*LedgerTile {
    const self = try allocator.create(LedgerTile);
    self.* = .{
        .ring = try allocator.alloc(RingMsg, capacity),
        .vl = undefined,
        .allocator = allocator,
        .suspect_slots = try allocator.alloc(u64, suspect_cap),
    };
    return self;
}

fn freeTestRingWithSuspect(allocator: std.mem.Allocator, tile: *LedgerTile) void {
    allocator.free(tile.ring);
    allocator.free(tile.suspect_slots);
    allocator.destroy(tile);
}

test "suspect-set: a dropped DATA shred records its slot; a dropped CODE shred does not" {
    const A = std.testing.allocator;
    const tile = try testRingWithSuspect(A, 2, 8); // tiny ring: 2 slots, easy to saturate
    defer freeTestRingWithSuspect(A, tile);

    // Fill the ring with unrelated slot-1 traffic.
    var p = [_]u8{0} ** 8;
    try std.testing.expect(tile.tryEnqueue(MSG_DATA, 1, 0, &p));
    try std.testing.expect(tile.tryEnqueue(MSG_DATA, 1, 1, &p));

    // Slot 777's DATA shred drops (ring full) -> must become suspect.
    tile.enqueueShred(777, 0, &p);
    try std.testing.expectEqual(@as(u64, 1), tile.dropped.load(.monotonic));
    try std.testing.expectEqual(@as(?u64, 777), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot());

    // Slot 888's CODE shred drops -> must NOT become suspect (coding shreds
    // have no completion-path feeder; backfill only covers data shreds).
    tile.enqueueCodingShred(888, 0, &p);
    try std.testing.expectEqual(@as(u64, 2), tile.dropped.load(.monotonic));
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot());

    // A dropped FINISH also records its slot.
    tile.enqueueFinish(999, SlotMeta{ .received = 1, .consumed = 1, .last_index = 0 });
    try std.testing.expectEqual(@as(?u64, 999), tile.popSuspectSlot());
}

test "suspect-set: same-burst dedup collapses a run of drops for one slot" {
    // The observed field pattern (SCOPE-2 §1e): a burst pegs the ring and one
    // slot sheds MANY consecutive shreds. Without dedup, that alone would
    // fill the whole suspect ring with copies of ONE slot and evict every
    // other suspect. The cheap "skip if same as last-pushed" check must
    // collapse this to a single entry.
    const A = std.testing.allocator;
    const tile = try testRingWithSuspect(A, 1, 8);
    defer freeTestRingWithSuspect(A, tile);

    var p = [_]u8{0} ** 8;
    try std.testing.expect(tile.tryEnqueue(MSG_DATA, 1, 0, &p)); // fill the 1-slot ring

    var i: u32 = 0;
    while (i < 500) : (i += 1) tile.enqueueShred(5000, i, &p); // 500 consecutive drops, same slot
    try std.testing.expectEqual(@as(u64, 500), tile.dropped.load(.monotonic));

    try std.testing.expectEqual(@as(?u64, 5000), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot()); // collapsed to ONE entry
    try std.testing.expectEqual(@as(u64, 0), tile.suspect_overflow_total.load(.monotonic));
}

test "suspect-set: bounded — FIFO eviction + overflow telemetry when distinct suspects exceed capacity" {
    const A = std.testing.allocator;
    const cap: usize = 4;
    const tile = try testRingWithSuspect(A, 1, cap);
    defer freeTestRingWithSuspect(A, tile);

    var p = [_]u8{0} ** 8;
    try std.testing.expect(tile.tryEnqueue(MSG_DATA, 1, 0, &p)); // fill the 1-slot ring

    // 6 DISTINCT slots drop (never consecutive-same, so dedup never collapses
    // them) against a suspect cap of 4 -> the OLDEST 2 must be evicted FIFO.
    var slot: u64 = 100;
    while (slot < 106) : (slot += 1) tile.enqueueShred(slot, 0, &p);

    try std.testing.expectEqual(@as(u64, 2), tile.suspect_overflow_total.load(.monotonic));
    // Survivors are the newest `cap` entries, oldest-to-newest order preserved.
    try std.testing.expectEqual(@as(?u64, 102), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, 103), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, 104), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, 105), tile.popSuspectSlot());
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot());
}

test "backfill: cold-consumer re-persists a dropped slot from the assembler's authoritative copy (Phase 2c)" {
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathbuf);
    const ledger_path = try std.fs.path.join(A, &.{ base, "ledger" });
    defer A.free(ledger_path);

    var ledger = try VexLedger.init(A, ledger_path);
    defer ledger.deinit();

    // Tiny ring: this is what actually drops the shreds below (mirrors the
    // real production drop path — not a synthetic recordSuspectSlot call).
    const tile = try LedgerTile.init(A, ledger, 4);
    defer tile.deinit();

    const assembler = try ShredAssembler.init(A);
    defer assembler.deinit();
    tile.setAssembler(assembler);

    // Build one FULL FEC set (32 data shreds, on-boundary LAST at index 31)
    // straight into the assembler's map — the clearRootedSlots KAT's pattern
    // (shred_assembler.zig) — so the slot is genuinely `is_complete`.
    const slot: u64 = 909;
    const entry = try assembler.slots.getOrPut(slot);
    entry.value_ptr.* = try A.create(ShredAssembler.SlotAssembly);
    entry.value_ptr.*.* = ShredAssembler.SlotAssembly.init(A, slot);
    const sa = entry.value_ptr.*;

    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        var payload = [_]u8{0} ** 88; // SHRED_HEADER_SIZE
        payload[64] = 0x80; // Merkle DATA variant (parseVariantByte.is_data)
        if (i == 31) payload[85] = 0x40; // DATA_COMPLETE flag on the true last
        _ = try sa.insert(i, &payload, i == 31); // on-boundary LAST -> completes
    }
    try std.testing.expect(sa.is_complete);

    // Drive every one of the 32 shreds through the REAL producer path with a
    // ring that can only hold 4 — the tail drops and must land in the
    // suspect-set via enqueueDrop -> recordSuspectSlot.
    i = 0;
    while (i < 32) : (i += 1) {
        var payload = [_]u8{0} ** 88;
        payload[64] = 0x80;
        if (i == 31) payload[85] = 0x40;
        tile.enqueueShred(slot, i, &payload);
    }
    try std.testing.expect(tile.dropped.load(.monotonic) > 0); // the 4-slot ring truly overflowed

    // Drain whatever DID make it through the ring (mirrors apply() draining
    // in run()), then run the reconciliation pass to close the rest.
    var msg: RingMsg = undefined;
    while (tile.dequeue(&msg)) tile.apply(&msg);

    const before = try ledger.getSlotShredIndices(A, slot);
    defer A.free(before);
    // Only the ring-capacity's worth made it through the drop; the rest are
    // genuinely missing from the ledger at this point (proves the drop was
    // real, not a no-op test) — this is exactly the gap the backfill exists
    // to close.
    try std.testing.expectEqual(@as(usize, 4), before.len);
    try std.testing.expectEqual(@as(u64, 28), tile.dropped.load(.monotonic));

    tile.backfillOneSuspect();

    const idx = try ledger.getSlotShredIndices(A, slot);
    defer A.free(idx);
    try std.testing.expectEqual(@as(usize, 32), idx.len); // FULLY re-persisted from the assembler
    for (idx, 0..) |v, n| try std.testing.expectEqual(@as(u32, @intCast(n)), v);

    const m = (try ledger.meta(A, slot)).?;
    defer A.free(m.completed_data_indexes);
    try std.testing.expectEqual(@as(u32, 32), m.received);
    try std.testing.expectEqual(@as(?u32, 31), m.last_index);
    try std.testing.expectEqual(@as(u32, 31), m.completed_data_indexes[0]);

    try std.testing.expectEqual(@as(u64, 1), tile.backfilled_total);
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot()); // suspect entry consumed
}

test "backfill: multi-chunk slot (>BACKFILL_CHUNK shreds) reassembles correctly across chunk boundaries" {
    // The single most important KAT for the C5/C6 caveat: every other backfill
    // KAT uses a <=32-shred slot, which BACKFILL_CHUNK=64 always satisfies in
    // ONE getRawDataShredsForSlotChunk call — so `next_idx` feedback, the
    // intermediate `done=false` branch, and the per-chunk `free(chunk.shreds)`-
    // but-keep-`.wire` ownership handoff in backfillOneSuspect's loop NEVER
    // ran more than once anywhere else. Real slots are hundreds-to-thousands
    // of shreds, so production always multi-chunks. This uses a 96-shred slot
    // (on-boundary LAST at index 95: (95+1)%32==0) spanning exactly THREE
    // chunk calls at BACKFILL_CHUNK=64 (0..63, 64..95 done=false since 96%64
    // != 0 lands exactly on scanned==32<64 -> done via received-set end, plus
    // the loop's own idx>=MAX_SHREDS_PER_SLOT is never hit here) — the point
    // is >64 so at least one resume via next_idx is forced.
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathbuf);
    const ledger_path = try std.fs.path.join(A, &.{ base, "ledger" });
    defer A.free(ledger_path);

    var ledger = try VexLedger.init(A, ledger_path);
    defer ledger.deinit();

    const tile = try LedgerTile.init(A, ledger, 64);
    defer tile.deinit();

    const assembler = try ShredAssembler.init(A);
    defer assembler.deinit();
    tile.setAssembler(assembler);

    const slot: u64 = 7777;
    const n: u32 = 96; // > BACKFILL_CHUNK (64) -> forces a second getRawDataShredsForSlotChunk call
    try std.testing.expect(n > LedgerTile.BACKFILL_CHUNK);
    const entry = try assembler.slots.getOrPut(slot);
    entry.value_ptr.* = try A.create(ShredAssembler.SlotAssembly);
    entry.value_ptr.*.* = ShredAssembler.SlotAssembly.init(A, slot);
    const sa = entry.value_ptr.*;

    var i: u32 = 0;
    while (i < n) : (i += 1) {
        var payload = [_]u8{0} ** 88;
        payload[64] = 0x80;
        if (i == n - 1) payload[85] = 0x40; // DATA_COMPLETE on the true last
        _ = try sa.insert(i, &payload, i == n - 1); // (96)%32==0 -> on-boundary LAST -> completes
    }
    try std.testing.expect(sa.is_complete);

    tile.recordSuspectSlot(slot);
    tile.backfillOneSuspect();

    const idx = try ledger.getSlotShredIndices(A, slot);
    defer A.free(idx);
    try std.testing.expectEqual(@as(usize, n), idx.len); // every shred survived the chunk boundary
    for (idx, 0..) |v, k| try std.testing.expectEqual(@as(u32, @intCast(k)), v); // contiguous 0..n-1, no dup/gap from the pagination

    const m = (try ledger.meta(A, slot)).?;
    defer A.free(m.completed_data_indexes);
    try std.testing.expectEqual(n, m.received);
    try std.testing.expectEqual(@as(?u32, n - 1), m.last_index);

    try std.testing.expectEqual(@as(u64, 1), tile.backfilled_total);
    try std.testing.expectEqual(@as(?u64, null), tile.popSuspectSlot());
}

test "backfill: idempotent — re-running the reconciliation pass on an already-complete slot is a safe no-op" {
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathbuf);
    const ledger_path = try std.fs.path.join(A, &.{ base, "ledger" });
    defer A.free(ledger_path);

    var ledger = try VexLedger.init(A, ledger_path);
    defer ledger.deinit();

    const tile = try LedgerTile.init(A, ledger, 64);
    defer tile.deinit();

    const assembler = try ShredAssembler.init(A);
    defer assembler.deinit();
    tile.setAssembler(assembler);

    const slot: u64 = 42;
    const entry = try assembler.slots.getOrPut(slot);
    entry.value_ptr.* = try A.create(ShredAssembler.SlotAssembly);
    entry.value_ptr.*.* = ShredAssembler.SlotAssembly.init(A, slot);
    const sa = entry.value_ptr.*;
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        var payload = [_]u8{0} ** 88;
        payload[64] = 0x80;
        if (i == 31) payload[85] = 0x40;
        _ = try sa.insert(i, &payload, i == 31);
    }
    try std.testing.expect(sa.is_complete);

    // Run the SAME backfill twice against the SAME already-complete slot
    // (double putShred/finishSlot — no ring drop needed to trigger this,
    // recordSuspectSlot directly models "this slot got marked suspect again").
    tile.recordSuspectSlot(slot);
    tile.backfillOneSuspect();
    const first = try ledger.getSlotShredIndices(A, slot);
    defer A.free(first);
    try std.testing.expectEqual(@as(usize, 32), first.len);

    tile.recordSuspectSlot(slot);
    tile.backfillOneSuspect();
    const second = try ledger.getSlotShredIndices(A, slot);
    defer A.free(second);
    try std.testing.expectEqual(@as(usize, 32), second.len); // unchanged, not doubled
    try std.testing.expectEqualSlices(u32, first, second);

    try std.testing.expectEqual(@as(u64, 2), tile.backfilled_total); // ran twice, both harmless
    try std.testing.expectEqual(@as(u64, 0), ledger.gap_slots_total); // both finishSlot calls saw a full match
}

test "backfill: a still-incomplete slot is re-queued, not prematurely finished" {
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pathbuf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &pathbuf);
    const ledger_path = try std.fs.path.join(A, &.{ base, "ledger" });
    defer A.free(ledger_path);

    var ledger = try VexLedger.init(A, ledger_path);
    defer ledger.deinit();

    const tile = try LedgerTile.init(A, ledger, 64);
    defer tile.deinit();

    const assembler = try ShredAssembler.init(A);
    defer assembler.deinit();
    tile.setAssembler(assembler);

    const slot: u64 = 55;
    const entry = try assembler.slots.getOrPut(slot);
    entry.value_ptr.* = try A.create(ShredAssembler.SlotAssembly);
    entry.value_ptr.*.* = ShredAssembler.SlotAssembly.init(A, slot);
    const sa = entry.value_ptr.*;
    // Only 10 of a would-be-32-shred FEC set — no LAST flag -> NOT complete.
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        var payload = [_]u8{0} ** 88;
        payload[64] = 0x80;
        _ = try sa.insert(i, &payload, false);
    }
    try std.testing.expect(!sa.is_complete);

    tile.recordSuspectSlot(slot);
    tile.backfillOneSuspect();

    // Nothing persisted yet (the design gates strict re-persist on
    // is_complete) — but the slot must NOT be lost: it goes to the back of
    // the suspect queue instead of being dropped on the floor.
    const idx = try ledger.getSlotShredIndices(A, slot);
    defer A.free(idx);
    try std.testing.expectEqual(@as(usize, 0), idx.len);
    try std.testing.expectEqual(@as(u64, 0), tile.backfilled_total);
    try std.testing.expectEqual(@as(?u64, slot), tile.popSuspectSlot()); // re-queued, still findable
}
