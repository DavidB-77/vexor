//! SlotChainTracker — SIMD-0340 chained-merkle-root validation.
//!
//! Tracks per-slot FEC-set merkle-root chain state and flags violations when a
//! newly observed FEC set's `chained_merkle_root` does not match the previously
//! accepted root (intra-slot) or the parent slot's last accepted root
//! (inter-slot).
//!
//! This module is pure logic — it does NOT touch the blockstore or decide
//! whether to mark slots dead. Callers (typically replay or shred-insertion
//! code) decide based on the feature-gate state from
//! `features.validateChainedBlockIdActive(slot)`:
//!   - Gate ACTIVE → on violation, call blockstore.markSlotDead(slot, ...).
//!   - Gate INACTIVE → log the violation via `[CHAIN-VIOLATION]` but continue.

const std = @import("std");
const core = @import("core");

/// SIMD-0340 Phase 2 ENFORCEMENT GATE.
///
/// Promotion history:
/// - Phase 1 (SHADOW): emit warnings only. Verified low FP rate.
///   Original blocker: Vexor's `bmtree.reconstructRoot` returned `[20]u8`
///   while Agave 4.0 (`ledger/src/shred/merkle_tree.rs:6-9`) defines
///   `SIZE_OF_MERKLE_ROOT = size_of::<Hash>() = 32`. Tracker comparisons
///   against leader-written 32-byte chained roots would never match.
/// - Phase 2 (ENFORCE, 2026-05-13): bmtree parity landed — `reconstructRootFull`
///   at bmtree.zig:141 returns `[32]u8`, shred.zig:276 calls it,
///   slot_chain_tracker uses `[32]u8` end-to-end. Verified empirically:
///   13k slots of SHADOW emissions yielded 6 violations, all genuine
///   fork-orphan / equivocation patterns (no false positives). Promoting
///   to ENFORCE so Vexor marks the offending slot dead and skips replay
///   downstream — matching Agave's `check_chained_block_id` behavior
///   under the active `validate_chained_block_id` feature gate
///   (vcmrbYbiMVKaq1snKP6eCacNDcr6qZvpCNUjmk6gxvZ, activated cluster slot
///   406604256).
///
/// SIMD-0340 = `validate_chained_block_id_2` (vcmrw431aNM8ngQ46derkZXipoTGQdbHkEygBDh12dA,
///   activated cluster slot 416540256, epoch-effective from epoch 978 per the
///   epoch-delayed shred filter) is a SECOND, incremental feature — NOT a re-key
///   of the above (rc.1 feature-set/src/lib.rs:1512-1517 declares BOTH; both are
///   live on testnet). For the CONSENSUS-relevant replay path it changes nothing
///   for us: rc.1 `check_chained_block_id` (blockstore_processor.rs:2629) gates on
///   `(validate_chained_block_id || validate_chained_block_id_2)`, and since v1 is
///   permanently active and activated EARLIER, our v1-only gate is byte-equivalent
///   to (v1||v2) for every real slot — Vexor already enforces the mismatch→dead
///   check canonically. The ONLY behavior v2 adds is in the duplicate-shred
///   detection path (window_service.rs:149-152): a `FixedFECChainedMerkleRootConflict`
///   → set_dead_slot, a cross-client courtesy ("mark dead for other client teams",
///   NOT needed for Agave's own duplicate resolution) for an adversarial fixed-FEC
///   equivocation. That belongs to the separate, still-unwired DuplicateShred
///   detection layer (network-citizenship gap), is not a divergence-now, and does
///   not require a change to this module.
///
/// What ENFORCE catches: leader equivocation (two slots N from same leader,
/// different chained_root), intra-slot chain breaks (FEC k's chained_merkle_root
/// ≠ FEC k-1's root), and the SIMD-0340 dead-slot pattern.
///
/// What ENFORCE does NOT catch: leader-skips-ahead orphans (slot N with
/// parent=K, K < N-1, where the chain itself is valid but the cluster will
/// extend a competing fork). Those need Tower BFT + fork-isolated accounts_db
/// (separate work — see project_iter6_carrier_CONFIRMED memo).
// 2026-06-09: a stopgap had flipped this to false, but the dead-slot regression
// was actually a STALE-TREE artifact (the May-29 vex-fd-dev tree was deployed by
// mistake). The canonical fix105 tree (this one) has the June seam fixes, and the
// original c32329e8 binary ran the catch-up→tip seam with ENFORCE ON and never
// dead-slotted. Restored to ENFORCE (proven config). If false-positive dead-slots
// recur on the CORRECT tree, that's a real seam-linkage bug to fix canonically
// (Agave/FD research pending) — not to mask. See BUG-DEADSLOT-CHAINBLOCK-2026-06-09.md.
pub const SIMD_0340_ENFORCE_MARK_DEAD: bool = true;

/// VEX_CHAIN_TRACE diagnostic gate (cached). When set, observe() logs every call
/// so the per-slot FEC accept sequence is visible (ordering-bug diagnosis).
var chain_trace_cached: ?bool = null;
fn chainTraceEnabled() bool {
    if (chain_trace_cached) |v| return v;
    const v = std.posix.getenv("VEX_CHAIN_TRACE") != null;
    chain_trace_cached = v;
    return v;
}

pub const ViolationKind = enum { intra_slot, inter_slot };

pub const Violation = struct {
    slot: core.Slot,
    fec_set_index: u32,
    expected_root: [32]u8,
    observed_root: [32]u8,
    kind: ViolationKind,
};

/// Per-FEC-set record. SIMD-0340 chains erasure sets by VALUE
/// (next.chained_merkle_root == prev.merkle_root) and adjacency by INDEX
/// (next.fec_set_index == prev.fec_set_index + prev.num_data). We store both so
/// the check is keyed by fec_set_index against the EXACT arithmetic predecessor —
/// never a streaming "last accepted" (the 2026-06-14 false-dead bug).
pub const SetInfo = struct {
    merkle_root: [32]u8,
    chained_root: ?[32]u8,
    /// Data-shred count of THIS set, from the FEC erasure config (coding-shred
    /// header / completed set). 0 = not yet known → adjacency can't be confirmed
    /// in the forward direction, so the forward check defers.
    num_data: u32,
};

pub const SlotState = struct {
    /// fec_set_index → SetInfo. Index-keyed; replaces the streaming last_accepted
    /// model. Allocated lazily on first observe() of the slot; freed on pruneBelow
    /// / deinit.
    sets: std.AutoHashMap(u32, SetInfo),
    /// Sticky flag: once invalidated (gate-active violation), further observe()
    /// calls on this slot return null (do not re-emit). Callers mark dead once.
    invalidated: bool = false,
    /// Most recent Violation observed by observe() that the caller recorded
    /// via `recordObservation()`. Read by replay-side to decide whether to
    /// mark the slot dead when the feature gate is active for this bank.
    recorded_violation: ?Violation = null,
};

pub const SlotChainTracker = struct {
    allocator: std.mem.Allocator,
    slots: std.AutoHashMap(core.Slot, SlotState),
    /// THREAD SAFETY (2026-06-14, net-tile Stage 2): chain observation moved off
    /// the recv-thread-exclusive site (tvu.zig observeChainForShred) onto the 8
    /// verify-worker threads (they now do FEC + chain inside the fused
    /// ShredAssembler.insertFrameWithFec). `observe()` mutates `self.slots`
    /// (getOrPut) and the nested `state.sets` (put) → concurrent workers would
    /// race the AutoHashMap rehash/insert (the same class as the getRepairPeers
    /// race and the fec_mutex UAF). The replay thread also reads concurrently via
    /// `observedViolation` (replay_stage.zig:2970). So ALL FIVE entry points lock
    /// this leaf mutex internally. observe+recordObservation are fused into one
    /// critical section via `observeAndRecord` (recordObservation re-looks-up by
    /// slot, so it must not race a prune/insert between the two). This is a LEAF
    /// lock: getNumData (fec_resolver) takes+releases fec_mutex BEFORE chain_mutex
    /// is taken, and chain_tracker touches no assembler state, so the only nesting
    /// is assembler.mutex (worker insert) sequentially wrapping fec_mutex then
    /// chain_mutex — no inversion, no co-hold. Tests below are single-threaded so
    /// the lock is always uncontended (and proves it didn't alter the logic).
    chain_mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .slots = std.AutoHashMap(core.Slot, SlotState).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.slots.valueIterator();
        while (it.next()) |st| st.sets.deinit();
        self.slots.deinit();
    }

    /// Find the EXACT arithmetic predecessor of `idx`: the stored set P with
    /// P.num_data > 0 and P.fec_set_index + P.num_data == idx (Agave
    /// previous_erasure_set adjacency filter, blockstore.rs:619-621). Returns null
    /// when no such set is recorded yet → caller DEFERS (no violation). Never uses
    /// "nearest lower index" — a missing middle set must defer, not mis-pair.
    fn findPrevAdjacent(state: *const SlotState, idx: u32) ?SetInfo {
        var it = state.sets.iterator();
        while (it.next()) |e| {
            const p = e.value_ptr.*;
            if (p.num_data > 0 and e.key_ptr.* + p.num_data == idx) return p;
        }
        return null;
    }

    /// Observe the completion of a FEC set identified by `slot` and
    /// `fec_set_index`. `this_merkle_root` is the merkle root of this FEC set.
    /// `chained_merkle_root` is the 32-byte value embedded in this FEC set's
    /// shreds (null if the shred is not chained / feature inactive upstream).
    ///
    /// Returns a Violation when the chain does not match expectations. Returns
    /// null on first-observation or when the chain matches. Does NOT mutate the
    /// slot's accepted state when returning a violation — callers decide
    /// whether to invalidate + mark dead based on feature-gate.
    pub fn observe(
        self: *Self,
        slot: core.Slot,
        fec_set_index: u32,
        num_data: u32,
        this_merkle_root: [32]u8,
        chained_merkle_root: ?[32]u8,
    ) !?Violation {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        return self.observeLocked(slot, fec_set_index, num_data, this_merkle_root, chained_merkle_root);
    }

    /// Caller MUST hold `chain_mutex`. The lock-free body of observe(); also
    /// invoked by `observeAndRecord` so the observe+record pair runs in ONE
    /// critical section (recordObservation re-looks-up by slot — a prune/insert
    /// must not interleave between observe returning a Violation and the record).
    fn observeLocked(
        self: *Self,
        slot: core.Slot,
        fec_set_index: u32,
        num_data: u32,
        this_merkle_root: [32]u8,
        chained_merkle_root: ?[32]u8,
    ) !?Violation {
        const gop = try self.slots.getOrPut(slot);
        if (!gop.found_existing) gop.value_ptr.* = .{ .sets = std.AutoHashMap(u32, SetInfo).init(self.allocator) };
        const state = gop.value_ptr;

        if (state.invalidated) return null;

        // IDEMPOTENCY (Agave: the merkle_root_meta is created once per erasure set
        // from the FIRST shred; should_write/Dirty-once means the consistency check
        // runs once per set, blockstore.rs:1155/1841). observe() here is called once
        // PER SHRED on FEC-complete, so re-observations of an already-recorded set
        // MUST be no-ops — re-checking after the map advanced was the self-violation
        // half of the 2026-06-14 false-dead bug.
        if (state.sets.get(fec_set_index)) |existing| {
            // EQUIVOCATION / DUP-ROOT DETECTOR (2026-06-15): a 2nd shred claiming the
            // SAME fec_set_index but a DIFFERENT merkle root than the first-recorded
            // one => Vexor ingested a non-canonical shred; idempotency keeps whichever
            // arrived FIRST, which may be the chain-breaking (wrong-fork/duplicate) one.
            // This is the smoking gun for the AF_XDP false intra_slot violation.
            if (!std.mem.eql(u8, &existing.merkle_root, &this_merkle_root)) {
                const r1 = std.fmt.bytesToHex(existing.merkle_root[0..8].*, .lower);
                const r2 = std.fmt.bytesToHex(this_merkle_root[0..8].*, .lower);
                std.log.warn("[CHAIN-EQUIV] slot={d} fec={d} recorded_root={s} second_root={s} (two shreds, SAME fec, DIFFERENT roots)", .{ slot, fec_set_index, &r1, &r2 });
            } else if (chainTraceEnabled()) {
                std.log.warn("[CHAIN-TRACE] slot={d} fec={d} DUP-skip (already recorded)", .{ slot, fec_set_index });
            }
            return null;
        }
        try state.sets.put(fec_set_index, .{ .merkle_root = this_merkle_root, .chained_root = chained_merkle_root, .num_data = num_data });

        if (chainTraceEnabled()) {
            const tr = std.fmt.bytesToHex(this_merkle_root[0..8].*, .lower);
            const ch = if (chained_merkle_root) |c| std.fmt.bytesToHex(c[0..8].*, .lower) else std.fmt.bytesToHex([_]u8{0} ** 8, .lower);
            std.log.warn("[CHAIN-TRACE] slot={d} fec={d} num_data={d} this_root={s} chained={s} sets={d}", .{
                slot, fec_set_index, num_data, &tr, &ch, state.sets.count(),
            });
        }

        // BACKWARD check (Agave check_backwards_chained_merkle_root_consistency):
        // this set's chained_merkle_root must equal the EXACT arithmetic
        // predecessor's merkle root. fec_set_index 0 has no predecessor (cross-slot
        // is replay's check_chained_block_id, NOT done here). Predecessor absent →
        // DEFER (the forward check fires when it arrives).
        if (fec_set_index != 0) {
            if (chained_merkle_root) |chained| {
                if (findPrevAdjacent(state, fec_set_index)) |prev| {
                    if (!std.mem.eql(u8, &prev.merkle_root, &chained)) {
                        // DIAGNOSTIC (2026-06-15): dump the FULL recorded set map for
                        // this slot at violation time, so the complete chain (every
                        // fec_idx -> root/chained/num_data) is visible to confirm the
                        // true predecessor relationship and spot a poisoned entry.
                        var dit = state.sets.iterator();
                        while (dit.next()) |de| {
                            const mr = std.fmt.bytesToHex(de.value_ptr.merkle_root[0..8].*, .lower);
                            const cr = if (de.value_ptr.chained_root) |c| std.fmt.bytesToHex(c[0..8].*, .lower) else std.fmt.bytesToHex([_]u8{0} ** 8, .lower);
                            std.log.warn("[CHAIN-DUMP] slot={d} fec={d} num_data={d} root={s} chained={s}", .{ slot, de.key_ptr.*, de.value_ptr.num_data, &mr, &cr });
                        }
                        return Violation{
                            .slot = slot,
                            .fec_set_index = fec_set_index,
                            .expected_root = prev.merkle_root,
                            .observed_root = chained,
                            .kind = .intra_slot,
                        };
                    }
                }
            }
        }

        // FORWARD check (Agave check_forward_chained_merkle_root_consistency):
        // if the immediate successor (at fec_set_index + num_data) already arrived,
        // its chained_merkle_root must equal THIS set's merkle root. Catches a bad
        // chain when the successor arrived first and deferred. num_data unknown
        // (0) → can't locate the successor → skip (defer).
        if (num_data > 0) {
            if (state.sets.get(fec_set_index + num_data)) |next| {
                if (next.chained_root) |next_chained| {
                    if (!std.mem.eql(u8, &this_merkle_root, &next_chained)) {
                        return Violation{
                            .slot = slot,
                            .fec_set_index = fec_set_index + num_data,
                            .expected_root = this_merkle_root,
                            .observed_root = next_chained,
                            .kind = .intra_slot,
                        };
                    }
                }
            }
        }

        return null;
    }

    /// Observe + (on violation) record, as ONE critical section. This is the
    /// entry point the verify-worker fold uses: it replaces the recv-thread
    /// `observe()`-then-`recordObservation()` pair (tvu.zig:1460/1473) so the two
    /// can never interleave with a concurrent worker's observe or a prune. Returns
    /// the Violation (already recorded) or null. Same trigger semantics as the
    /// old observeChainForShred: caller decides ONLY whether to call this (data on
    /// FEC-complete; coding on FEC-complete && chained) — the gating stays out
    /// here, identical to before.
    pub fn observeAndRecord(
        self: *Self,
        slot: core.Slot,
        fec_set_index: u32,
        num_data: u32,
        this_merkle_root: [32]u8,
        chained_merkle_root: ?[32]u8,
    ) !?Violation {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        const maybe_v = try self.observeLocked(slot, fec_set_index, num_data, this_merkle_root, chained_merkle_root);
        if (maybe_v) |v| {
            if (self.slots.getPtr(slot)) |state| state.recorded_violation = v;
        }
        return maybe_v;
    }

    /// Mark `slot` as invalidated. Subsequent observe() calls return null for
    /// this slot. Used when the feature gate is active and the caller has
    /// already propagated markSlotDead.
    pub fn invalidate(self: *Self, slot: core.Slot) void {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        if (self.slots.getPtr(slot)) |state| state.invalidated = true;
    }

    /// Record that this slot had an observed chained-merkle-root violation.
    /// Used by the ingestion-side wireup after observe() returns a non-null
    /// Violation — caller persists the fact so that replay-side can later
    /// decide (based on bank feature-gate state) whether to mark the slot dead.
    pub fn recordObservation(self: *Self, slot: core.Slot, v: Violation) void {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        if (self.slots.getPtr(slot)) |state| {
            state.recorded_violation = v;
        }
    }

    /// Query whether this slot has a recorded violation. Returns the Violation
    /// if any was recorded via `recordObservation()`. Takes the mutex (a worker
    /// thread may be mutating `self.slots`/`state` concurrently via observe).
    /// `*Self` (not `*const`) is required to take the mutex.
    pub fn observedViolation(self: *Self, slot: core.Slot) ?Violation {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        if (self.slots.get(slot)) |state| return state.recorded_violation;
        return null;
    }

    /// Drop state for slots strictly below `root`. Called from replay after
    /// committing a new root to bound memory.
    pub fn pruneBelow(self: *Self, root: core.Slot) void {
        self.chain_mutex.lock();
        defer self.chain_mutex.unlock();
        var to_remove: std.ArrayListUnmanaged(core.Slot) = .empty;
        defer to_remove.deinit(self.allocator);
        var iter = self.slots.keyIterator();
        while (iter.next()) |k| {
            if (k.* < root) to_remove.append(self.allocator, k.*) catch continue;
        }
        for (to_remove.items) |s| {
            if (self.slots.getPtr(s)) |st| st.sets.deinit();
            _ = self.slots.remove(s);
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

const R0: [32]u8 = .{0x01} ** 32;
const R1: [32]u8 = .{0x02} ** 32;
const R2: [32]u8 = .{0x03} ** 32;
const R_WRONG: [32]u8 = .{0xFF} ** 32;
// observe(slot, fec_set_index, num_data, this_merkle_root, chained_merkle_root)
// num_data=32 ⇒ adjacency 0→32→64; cross-slot/parent is NOT checked here.

test "in-order OK: 0,32,64 correctly chained — no violation" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 0, 32, R0, null));
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 32, 32, R1, R0));
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 64, 32, R2, R1));
}

test "out-of-order 0,64,32: middle missing must DEFER not violate (the false-dead bug)" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 0, 32, R0, null));
    // set 64 arrives BEFORE set 32. Predecessor (32) absent → DEFER. The old
    // streaming code compared R64.chained(R1) vs last_accepted(R0) → FALSE violation.
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 64, 32, R2, R1));
    // set 32 now arrives, chains to R0 (correct). Backward(0) ok; forward sees 64
    // already present, R64.chained(R1)==R32 root(R1) ok.
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 32, 32, R1, R0));
}

test "re-observe an already-recorded set is idempotent (no self-violation)" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    _ = try t.observe(100, 0, 32, R0, null);
    _ = try t.observe(100, 32, 32, R1, R0);
    // Re-deliver set 32 (per-shred call). Must return null — NOT re-check against
    // an advanced map (the self-violation half of the 2026-06-14 false-dead bug).
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 32, 32, R1, R0));
}

test "genuine intra-slot break IS caught (backward, true positive)" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    _ = try t.observe(100, 0, 32, R0, null);
    const v = (try t.observe(100, 32, 32, R1, R_WRONG)) orelse return error.ExpectedViolation;
    try std.testing.expectEqual(ViolationKind.intra_slot, v.kind);
    try std.testing.expectEqualSlices(u8, &R0, &v.expected_root);
    try std.testing.expectEqualSlices(u8, &R_WRONG, &v.observed_root);
}

test "forward detection: successor arrives first with bad chain, caught when predecessor lands" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    // set 32 arrives first, chains to R_WRONG (should be set 0's root R0).
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 32, 32, R1, R_WRONG)); // defer: pred absent
    // set 0 arrives. Forward: 0+32==32 present; set 32.chained(R_WRONG) != R0 → violation reported on 32.
    const v = (try t.observe(100, 0, 32, R0, null)) orelse return error.ExpectedViolation;
    try std.testing.expectEqual(ViolationKind.intra_slot, v.kind);
    try std.testing.expectEqual(@as(u32, 32), v.fec_set_index);
    try std.testing.expectEqualSlices(u8, &R0, &v.expected_root);
    try std.testing.expectEqualSlices(u8, &R_WRONG, &v.observed_root);
}

test "fec_set_index 0 does NOT do an inter-slot/parent check at insert" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    // Even with a chained_root present, the first set must never violate here
    // (cross-slot validation is replay's check_chained_block_id, not insert-time).
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 0, 32, R0, R_WRONG));
}

test "variable num_data adjacency: last set is smaller (must not mis-pair)" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    // set 0 has 32 data shreds → successor at 32. set 32 has 20 → successor at 52.
    _ = try t.observe(100, 0, 32, R0, null);
    _ = try t.observe(100, 32, 20, R1, R0);
    // set 52 chains to set 32's root (R1). Adjacency 32+20==52 must be found.
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 52, 20, R2, R1));
    // A set at 52 whose chained != R1 must violate against the arithmetic predecessor (32).
    var t2 = SlotChainTracker.init(std.testing.allocator);
    defer t2.deinit();
    _ = try t2.observe(100, 0, 32, R0, null);
    _ = try t2.observe(100, 32, 20, R1, R0);
    const v = (try t2.observe(100, 52, 20, R2, R_WRONG)) orelse return error.ExpectedViolation;
    try std.testing.expectEqualSlices(u8, &R1, &v.expected_root);
}

test "sticky-invalid: after invalidate(), subsequent observe() returns null" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    _ = try t.observe(100, 0, 32, R0, null);
    t.invalidate(100);
    try std.testing.expectEqual(@as(?Violation, null), try t.observe(100, 32, 32, R1, R_WRONG));
    const state = t.slots.get(100).?;
    try std.testing.expect(state.invalidated);
}

test "pruneBelow drops old slot state (and frees nested sets)" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    _ = try t.observe(100, 0, 32, R0, null);
    _ = try t.observe(200, 0, 32, R1, null);
    t.pruneBelow(150);
    try std.testing.expect(t.slots.get(100) == null);
    try std.testing.expect(t.slots.get(200) != null);
}

test "recordObservation + observedViolation roundtrip" {
    var t = SlotChainTracker.init(std.testing.allocator);
    defer t.deinit();
    _ = try t.observe(100, 0, 32, R0, null);
    const v = (try t.observe(100, 32, 32, R1, R_WRONG)) orelse return error.ExpectedViolation;
    try std.testing.expect(t.observedViolation(100) == null);
    t.recordObservation(100, v);
    const got = t.observedViolation(100) orelse return error.ExpectedViolation;
    try std.testing.expectEqual(ViolationKind.intra_slot, got.kind);
    try std.testing.expectEqualSlices(u8, &R_WRONG, &got.observed_root);
}
