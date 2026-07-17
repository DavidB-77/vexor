//! Canonical block tick-validity (`verify_ticks`), pure Zig-native.
//!
//! Port of Firedancer `src/discof/replay/fd_sched.c` verify_ticks_eager /
//! verify_ticks_final (lines 1976-2020) and the per-tick hash accounting at
//! fd_sched.c:2166-2180, cross-checked against Agave rc.1
//! `entry/src/entry.rs:675-698` (verify_tick_hash_count, incl. the rc.1
//! zero-hash delta) and `ledger/src/blockstore_processor.rs:1085-1101`.
//!
//! This module is the SINGLE SOURCE OF TRUTH for the check algorithm. The
//! replay loop (replay_stage.zig replayEntriesInternal) drives a `Verifier`
//! incrementally as it parses entries — so the KAT (verify_ticks_kat.zig) and
//! the live consensus path exercise the exact same code, not two copies.
//!
//! IMPORTANT: this module is PURE — no Bank, no AccountsDb, no ReplayStage,
//! no allocation. It only consumes (num_hashes, is_tick) per entry plus the
//! PoH cadence params, and returns a verdict. That keeps it trivially testable
//! and side-effect-free; the caller does the actual markSlotDead/abort.

const std = @import("std");

/// The canonical tick window for a slot, mirroring FD fd_runtime.c:45 +
/// fd_bank.c:584:
///   tick_height     = (parent_slot+1) * ticks_per_slot   (== parent.max_tick_height)
///   max_tick_height = (slot+1)        * ticks_per_slot
/// => a valid block contains exactly (slot - parent_slot) * ticks_per_slot
///    ticks (consecutive parent => ticks_per_slot; post-skip blocks > that).
pub fn tickHeight(parent_slot: u64, ticks_per_slot: u64) u64 {
    return (parent_slot +% 1) *% ticks_per_slot;
}
pub fn maxTickHeight(slot: u64, ticks_per_slot: u64) u64 {
    return (slot +% 1) *% ticks_per_slot;
}

/// Graduated enforcement level, matching build_options.verify_ticks.
/// Kept as an independent enum so this module has no build_options dependency
/// (the caller passes the active level; the KAT exercises all levels).
pub const Level = enum { off, zerohash, full };

/// Why a block was rejected. `ok` = no violation (so far). Each non-ok variant
/// maps to the FD/Agave BlockError it mirrors.
pub const Verdict = enum {
    ok,
    /// FD verify_ticks_eager TOO_MANY_TICKS (fd_sched.c:1979).
    too_many_ticks,
    /// FD verify_ticks_final TOO_FEW_TICKS (fd_sched.c:2014).
    too_few_ticks,
    /// Agave entry.rs:684 zero-hash tick (rc.1 delta) — a tick with num_hashes==0
    /// while hashing is enabled. The `zerohash` level checks ONLY this.
    invalid_tick_hash_count_zero,
    /// FD fd_sched.c:1987 cumulative DoS bound: curr_tick_hashcnt > hashes_per_tick.
    invalid_tick_hash_count_cumulative,
    /// FD fd_sched.c:2170 per-tick watermark inconsistency: a tick's hashcnt
    /// differs from the FIRST tick's (inter-tick consistency).
    invalid_tick_hash_count_inconsistent,
    /// FD fd_sched.c:1983 / Agave entry.rs:687 EXACT per-tick equality: a tick's
    /// hashcnt != hashes_per_tick. Catches a UNIFORMLY-wrong block (every tick
    /// HPT-1) that the inter-tick-consistency check alone would miss. This is the
    /// canonical primary check; the inconsistent variant above is kept as a finer
    /// diagnostic but is subsumed by this one.
    invalid_tick_hash_count_exact,

    pub fn isDead(self: Verdict) bool {
        return self != .ok;
    }
};

/// Incremental verifier. Construct with the slot's params, call `onEntry` for
/// each parsed entry in order (eager checks), then `onSlotEnd` once the slot is
/// fully ingested (final TOO_FEW check). Any non-ok return = mark the slot dead.
///
/// `hashes_per_tick` is Agave `bank.hashes_per_tick().unwrap_or(0)`: 0 disables
/// the hash-count checks (FD gates them on `>1`). `level` selects which checks
/// run (full subsumes zerohash).
pub const Verifier = struct {
    level: Level,
    hashes_per_tick: u64,
    tick_height: u64,
    max_tick_height: u64,

    // accounting (FD fd_sched.c fields)
    tick_count: u64 = 0, // mblk_tick_cnt — ticks seen so far (this slot)
    curr_tick_hashcnt: u64 = 0, // hashes since the last tick (Agave tick_hash_count)
    tick_hashcnt_wmk: u64 = 0, // first tick's per-tick hashcnt (watermark)

    pub fn init(level: Level, hashes_per_tick: u64, parent_slot: u64, slot: u64, ticks_per_slot: u64) Verifier {
        return .{
            .level = level,
            .hashes_per_tick = hashes_per_tick,
            .tick_height = tickHeight(parent_slot, ticks_per_slot),
            .max_tick_height = maxTickHeight(slot, ticks_per_slot),
        };
    }

    /// Process one entry (in block order). `num_hashes` = entry.num_hashes,
    /// `is_tick` = (entry.num_txs == 0) (Agave Entry::is_tick). Returns the
    /// verdict; `.ok` means continue, anything else means reject the block.
    pub fn onEntry(self: *Verifier, num_hashes: u64, is_tick: bool) Verdict {
        if (self.level == .off) return .ok;

        if (is_tick) self.tick_count +%= 1;

        // ── zerohash level (rc.1 zero-hash delta, entry.rs:684-686) ──
        // A tick with num_hashes==0 while hashing is enabled is invalid. CANNOT
        // false-reject a valid block (every honest tick has hashes_per_tick
        // hashes). This is the only check the `zerohash` level performs.
        if (self.hashes_per_tick > 1 and is_tick and num_hashes == 0) {
            return .invalid_tick_hash_count_zero;
        }

        if (self.level != .full) return .ok;

        // ── full: FD verify_ticks_eager ──
        // TOO_MANY_TICKS (fd_sched.c:1979): checked on each tick. tick_count
        // already includes this tick.
        if (is_tick and (self.tick_count +% self.tick_height > self.max_tick_height)) {
            return .too_many_ticks;
        }

        // Accumulate hashes across ALL entries (tick + non-tick), Agave
        // entry.rs:682 / FD fd_sched.c:2166.
        self.curr_tick_hashcnt +%= num_hashes;

        // Cumulative DoS bound (fd_sched.c:1987): running per-tick hashcnt must
        // never exceed hashes_per_tick. Bounds individual microblock hashcnt
        // transitively. Note: checked BEFORE the tick reset so it also catches a
        // non-tick microblock with a huge hashcnt.
        if (self.hashes_per_tick > 1 and self.curr_tick_hashcnt > self.hashes_per_tick) {
            return .invalid_tick_hash_count_cumulative;
        }

        if (is_tick) {
            // EXACT per-tick equality (Agave entry.rs:687 `*tick_hash_count !=
            // hashes_per_tick`; FD fd_sched.c:1983 `hashes_per_tick != wmk`):
            // every tick must carry EXACTLY hashes_per_tick hashes. This is the
            // primary canonical check — it catches a UNIFORMLY-wrong block (every
            // tick HPT-1) that the inter-tick consistency check alone misses
            // (the watermark would latch to HPT-1 and every tick would "agree").
            // Folds in the zero-hash case too (0 != HPT). Checked on EVERY tick
            // (Agave checks each; FD checks the watermark at verify time, which is
            // equivalent once all ticks are consistent — and the per-tick form is
            // stricter / fails earlier, never accepting what Agave rejects).
            if (self.hashes_per_tick > 1 and self.curr_tick_hashcnt != self.hashes_per_tick) {
                return .invalid_tick_hash_count_exact;
            }
            // Inter-tick consistency (fd_sched.c:2170), kept as a finer diagnostic
            // — subsumed by the exact check above for hashes_per_tick>1, but still
            // meaningful as a defense-in-depth signal. tick_count>1 == FD
            // `mblk_tick_cnt` nonzero (>=1 prior tick already counted).
            if (self.hashes_per_tick > 1 and self.tick_count > 1 and
                self.tick_hashcnt_wmk != self.curr_tick_hashcnt)
            {
                return .invalid_tick_hash_count_inconsistent;
            }
            // Watermark = max(curr, wmk); with 0 init this latches the first
            // tick's hashcnt (FD fd_ulong_max). Reset for the next tick.
            if (self.curr_tick_hashcnt > self.tick_hashcnt_wmk) self.tick_hashcnt_wmk = self.curr_tick_hashcnt;
            self.curr_tick_hashcnt = 0;
        }

        return .ok;
    }

    /// Call once after the last entry, when the slot is fully ingested (fec_eos).
    /// FD verify_ticks_final TOO_FEW_TICKS (fd_sched.c:2014). Only the `full`
    /// level performs this; `zerohash`/`off` return `.ok` (the live replay path
    /// keeps its own flat deferred TooFewTicks gate for those levels).
    pub fn onSlotEnd(self: *Verifier) Verdict {
        if (self.level != .full) return .ok;
        // FD verify_ticks_final TOO_FEW_TICKS (fd_sched.c:2014).
        if (self.tick_count +% self.tick_height < self.max_tick_height) {
            return .too_few_ticks;
        }
        // Agave entry.rs:697 final residual check: after the last entry the
        // running (post-last-tick) hashcnt must be < hashes_per_tick. A block
        // ending on a non-tick microblock whose leftover hashcnt >= hashes_per_tick
        // (no closing tick to reset it) is invalid. If the block ended on a tick,
        // curr_tick_hashcnt was reset to 0 (always < hashes_per_tick) so this is a
        // no-op for the well-formed end-with-tick case. Gated on hashes_per_tick>1.
        if (self.hashes_per_tick > 1 and self.curr_tick_hashcnt >= self.hashes_per_tick) {
            return .invalid_tick_hash_count_cumulative;
        }
        return .ok;
    }
};
