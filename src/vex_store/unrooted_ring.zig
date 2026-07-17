//! `UnrootedRing` — fork-aware per-slot account cache.
//!
//! Replaces (additively, for now) the fork-blind `unflushed_cache` HashMap
//! shape that caused the iter-6 carrier: a write at sibling slot K+1 could
//! overwrite the canonical-fork value for the same pubkey, and every
//! attempted read-time ancestor filter (Phase 1C/1D/1E/1F-v1/1F-v2/1G)
//! regressed parity catastrophically because the filter was bolted onto a
//! structure that had already lost the canonical value.
//!
//! Design (2026-05-18): a fixed-capacity ring of per-slot buckets. Each
//! bucket owns its own lock and pubkey→account map. Writes route by
//! `slot % capacity`; reads scan all buckets and pick the highest one whose
//! `slot` is in the caller's ancestor set. The ring cannot return a
//! wrong-fork value because the bucket key (slot) is checked against the
//! reader's ancestor chain on every probe.
//!
//! @prov:unrooted-ring.core
//! Renamed and re-typed for Vexor's `core.Pubkey` / `core.Slot` /
//! `accounts.Account` shape and Vexor's `[]const core.Slot` ancestors
//! representation (Vexor doesn't carry an `Ancestors` struct; replay paths
//! already build a stack slice for `sig_overlay.get`).
//!
//! Ownership: account data is owned by the ring — caller passes data
//! already duplicated with the same allocator the ring was init'd with.
//! Freed when the slot is dropped via `dropSlot`, when the bucket is
//! recycled for a new slot, or when the ring is `deinit`'d.

const std = @import("std");
const core = @import("core");
const Atomic = std.atomic.Value;

const Pubkey = core.Pubkey;
const Slot = core.Slot;

const accounts_mod = @import("accounts.zig");
const Account = accounts_mod.Account;
const AccountView = accounts_mod.AccountView;

const build_options = @import("build_options");
/// Shadow-verify gate (default OFF). When ON, EVERY indexed read is
/// cross-checked against the original full-ring scan via `std.debug.assert`
/// (see `getWithModifiedSlot` / `getWithModifiedSlotPlusSelf`). This is the
/// safety backstop that empirically proves index==scan. Default false makes
/// the whole shadow path comptime-dead — production ReleaseSafe is byte-for-
/// byte unaffected. Armed by `-Dverify_ring_index`. `@hasDecl`-guarded so the
/// file still compiles under any `build_options` module lacking the flag.
const verify_ring_index: bool = if (@hasDecl(build_options, "verify_ring_index"))
    build_options.verify_ring_index
else
    false;

/// Ring capacity — same constant Sig uses and same as Vexor's existing
/// `sig_overlay` capacity. Assumes consensus roots a slot within this
/// many slots of execution; on collision the older bucket's data is
/// freed and reused (Sig panics here; Vexor relaxes since catchup can
/// burst through more unrooted slots than this).
pub const RING_CAPACITY: usize = 4096;

// ── per-pubkey read index (eliminates the O(RING_CAPACITY) full-ring scan) ──
//
// The reads (`getWithModifiedSlot` / `getWithModifiedSlotPlusSelf`) previously
// scanned all RING_CAPACITY buckets on every call — 17.2% CPU, the #1 hot spot.
// The index maps `pubkey -> {bucket indices that hold a write for it}` so a read
// visits only the handful of candidate buckets instead of all 4096.
//
// CORRECTNESS: the indexed read is a FILTERED SCAN — the per-bucket loop body
// is byte-identical to the old full scan, only the iteration source changes
// from `self.buckets` to the candidate buckets the index reports. Extra/stale
// candidates SELF-FILTER: every candidate is re-checked under its bucket lock
// (is_empty / slot-predicate / entries.get), so a stale index entry can only
// cost a wasted probe, never a wrong result. The ONLY unsafe direction is a
// MISSING candidate; the replay model prevents it (ancestors are frozen before
// a slot executes; same-slot writes are read-your-writes on the same thread,
// and each `put` records the index entry BEFORE the bucket entry — see `put`).
//
// SHARDING: pubkeys are hashed into NUM_SHARDS shards, each with its own
// RwLock, so index traffic doesn't serialize on one global lock.
//
// LOCK ORDER is strictly `bucket ≻ shard`:
//   * writers hold the BUCKET lock and, while holding it, take ONE shard lock
//     at a time to mutate the index (never two shards at once, never a bucket
//     while holding a shard);
//   * readers take the pubkey's shard lock (shared), COPY the candidate bucket
//     indices to a stack buffer, RELEASE the shard lock, then take bucket
//     shared-locks one at a time (≤1 lock held at any instant).
// A reader never holds shard+bucket simultaneously, so no lock cycle exists.
const NUM_SHARDS: usize = 256;

/// A ring bucket index (0..RING_CAPACITY-1). u16 covers RING_CAPACITY=4096.
const BucketIdx = u16;

comptime {
    // shardOf masks with (NUM_SHARDS-1); require a power of two.
    std.debug.assert(std.math.isPowerOfTwo(NUM_SHARDS));
    // BucketIdx must index every ring bucket.
    std.debug.assert(RING_CAPACITY <= std.math.maxInt(BucketIdx) + 1);
}

/// Small inline-2 set of bucket indices for one pubkey. Allocation-free while
/// a pubkey occupies ≤2 unrooted buckets (the common case); spills to a heap
/// list beyond that. `len` is the TOTAL count and is u16 (NOT u8): a hot
/// account written every slot during deep catch-up can occupy far more than
/// 255 buckets (up to RING_CAPACITY), so a u8 count would overflow and drop
/// candidates — exactly the unsafe direction. Semantics: when `len<=2` all
/// elements live in `inline_buf[0..len]` and `spill` is empty; when `len>2`
/// the first two live in `inline_buf` and the remaining `len-2` live in `spill`.
const IdxSet = struct {
    inline_buf: [2]BucketIdx = undefined,
    len: u16 = 0,
    spill: std.ArrayListUnmanaged(BucketIdx) = .{},

    fn contains(self: *const IdxSet, idx: BucketIdx) bool {
        const inl: usize = @min(self.len, 2);
        for (self.inline_buf[0..inl]) |x| if (x == idx) return true;
        if (self.len > 2) for (self.spill.items) |x| if (x == idx) return true;
        return false;
    }

    /// Add `idx` if not already present (idempotent). Only allocates when the
    /// set spills past 2 elements.
    fn add(self: *IdxSet, allocator: std.mem.Allocator, idx: BucketIdx) !void {
        if (self.contains(idx)) return;
        if (self.len < 2) {
            self.inline_buf[self.len] = idx;
            self.len += 1;
            return;
        }
        try self.spill.append(allocator, idx);
        self.len += 1;
    }

    /// Remove `idx` if present (swap-remove; order not preserved). No-op if
    /// absent. Never allocates or frees the spill backing (shrinks in place).
    fn remove(self: *IdxSet, idx: BucketIdx) void {
        const inl: usize = @min(self.len, 2);
        var i: usize = 0;
        while (i < inl) : (i += 1) {
            if (self.inline_buf[i] == idx) {
                if (self.len > 2) {
                    // Backfill the hole with the last spill element.
                    self.inline_buf[i] = self.spill.pop().?;
                } else {
                    self.inline_buf[i] = self.inline_buf[inl - 1];
                }
                self.len -= 1;
                return;
            }
        }
        if (self.len > 2) {
            for (self.spill.items, 0..) |x, j| {
                if (x == idx) {
                    _ = self.spill.swapRemove(j);
                    self.len -= 1;
                    return;
                }
            }
        }
    }

    /// Copy every bucket index into `buf` (which MUST hold at least `len`
    /// entries — callers size it `[RING_CAPACITY]`, the hard upper bound on
    /// distinct bucket indices). Returns the count written.
    fn copyTo(self: *const IdxSet, buf: []BucketIdx) usize {
        const inl: usize = @min(self.len, 2);
        var n: usize = 0;
        for (self.inline_buf[0..inl]) |x| {
            buf[n] = x;
            n += 1;
        }
        if (self.len > 2) for (self.spill.items) |x| {
            buf[n] = x;
            n += 1;
        };
        return n;
    }
};

/// One index shard: an RwLock + a `pubkey -> IdxSet` map.
const Shard = struct {
    lock: std.Thread.RwLock = .{},
    map: std.AutoHashMapUnmanaged(Pubkey, IdxSet) = .empty,
};

const UnrootedRing = @This();

allocator: std.mem.Allocator,
buckets: []SlotBucket,
/// Per-pubkey read index (see the block comment above). Sharded by pubkey hash.
shards: [NUM_SHARDS]Shard,

pub const SlotBucket = struct {
    lock: std.Thread.RwLock,
    slot: Slot,
    is_empty: Atomic(bool),
    entries: std.AutoHashMapUnmanaged(Pubkey, Account),

    fn init() SlotBucket {
        return .{
            .lock = .{},
            .slot = 0,
            .is_empty = Atomic(bool).init(true),
            .entries = .empty,
        };
    }

    /// Free every (account.data) we own for this bucket plus the map's
    /// internal storage. Uses the ring's allocator for both (caller passes
    /// it because the bucket itself doesn't store a back-reference).
    fn freeAll(self: *SlotBucket, allocator: std.mem.Allocator) void {
        var it = self.entries.valueIterator();
        while (it.next()) |acct| {
            if (acct.data.len > 0) {
                allocator.free(@constCast(acct.data));
            }
        }
        self.entries.deinit(allocator);
        self.entries = .empty;
    }

    /// Clear entries (free their data + clear map) without releasing the
    /// underlying hashmap allocation. Used on slot recycle.
    fn clearKeepCapacity(self: *SlotBucket, allocator: std.mem.Allocator) void {
        var it = self.entries.valueIterator();
        while (it.next()) |acct| {
            if (acct.data.len > 0) {
                allocator.free(@constCast(acct.data));
            }
        }
        self.entries.clearRetainingCapacity();
    }
};

pub fn init(allocator: std.mem.Allocator) !UnrootedRing {
    const buckets = try allocator.alloc(SlotBucket, RING_CAPACITY);
    errdefer allocator.free(buckets);
    for (buckets) |*b| b.* = SlotBucket.init();
    // Shards default-init (RwLock=.{}, map=.empty); the array is duplicated at
    // comptime from a zero-state Shard, which is safe because no lock is held
    // during the single init→store move.
    return .{ .allocator = allocator, .buckets = buckets, .shards = [_]Shard{.{}} ** NUM_SHARDS };
}

pub fn deinit(self: *UnrootedRing) void {
    for (self.buckets) |*b| b.freeAll(self.allocator);
    self.allocator.free(self.buckets);
    // Free each shard's map plus any IdxSet spill backing.
    for (&self.shards) |*shard| {
        var it = shard.map.valueIterator();
        while (it.next()) |set| set.spill.deinit(self.allocator);
        shard.map.deinit(self.allocator);
    }
    self.* = undefined;
}

/// Shard owning `pubkey`'s index entry. Hashes the 32 pubkey bytes and masks
/// to NUM_SHARDS (a power of two). The distribution only needs to be stable;
/// it deliberately does NOT need to match the AutoHashMap internal hash.
fn shardOf(self: *UnrootedRing, pubkey: Pubkey) *Shard {
    const h = std.hash.Wyhash.hash(0, &pubkey.data);
    return &self.shards[@as(usize, @intCast(h & (NUM_SHARDS - 1)))];
}

/// Record `(pubkey -> idx)` in the index. MUST be called with `idx`'s bucket
/// lock held (preserves the bucket ≻ shard order — this takes exactly one
/// shard lock). Idempotent. May allocate (shard map / IdxSet spill); on OOM it
/// returns the error and records NOTHING, so `put` can roll back cleanly.
fn indexAdd(self: *UnrootedRing, pubkey: Pubkey, idx: BucketIdx) !void {
    const shard = self.shardOf(pubkey);
    shard.lock.lock();
    defer shard.lock.unlock();
    const gop = try shard.map.getOrPut(self.allocator, pubkey);
    if (!gop.found_existing) gop.value_ptr.* = .{};
    try gop.value_ptr.add(self.allocator, idx);
}

/// Remove `(pubkey -> idx)` from the index. MUST be called with `idx`'s bucket
/// lock held. Never allocates. No-op if absent. Drops the pubkey's map entry
/// (and frees its spill) once its last bucket index is removed.
fn indexRemove(self: *UnrootedRing, pubkey: Pubkey, idx: BucketIdx) void {
    const shard = self.shardOf(pubkey);
    shard.lock.lock();
    defer shard.lock.unlock();
    const set = shard.map.getPtr(pubkey) orelse return;
    set.remove(idx);
    if (set.len == 0) {
        set.spill.deinit(self.allocator);
        _ = shard.map.remove(pubkey);
    }
}

/// Remove EVERY index entry for the pubkeys currently living in `bucket`
/// (whose ring index is `idx`). MUST be called with `bucket`'s lock held; it
/// takes one shard lock at a time, so the bucket ≻ shard order holds. Used on
/// slot recycle and `dropSlot` — the alias fix, so a recycled bucket no longer
/// advertises the OLD slot's pubkeys.
fn indexRemoveBucket(self: *UnrootedRing, bucket: *SlotBucket, idx: BucketIdx) void {
    var it = bucket.entries.keyIterator();
    while (it.next()) |key_ptr| self.indexRemove(key_ptr.*, idx);
}

/// Put `account` at (slot, pubkey). The ring TAKES OWNERSHIP of
/// `account.data` — caller must `dupe` the data with the same allocator
/// the ring was init'd with (or pass `&.{}` for empty data) before calling.
///
/// Concurrent put on the same (slot, pubkey) is impossible during normal
/// replay: each slot is executed by a single thread and pending_writes
/// flush is single-call.
///
/// Concurrent puts on the same pubkey from DIFFERENT slots ARE possible
/// during forked execution. Different slot → different bucket (mod
/// RING_CAPACITY) so they don't contend on the same lock except at
/// bucket-recycle time.
///
/// On bucket recycle (the indexed bucket was last used by another slot),
/// the OLD entries are freed and the bucket is reused for the new slot.
/// This deviates from Sig (which asserts is_empty); Vexor's catchup mode
/// regularly executes more unrooted slots than RING_CAPACITY in a burst,
/// so panic would be hostile. The trade-off: an unrooted bucket that has
/// not been rooted yet but was indexed long ago will lose its data. In
/// practice consensus roots within ~64 slots, far below RING_CAPACITY.
pub fn put(self: *UnrootedRing, slot: Slot, pubkey: Pubkey, account: Account) !void {
    const index = slot % RING_CAPACITY;
    const bidx: BucketIdx = @intCast(index);
    const bucket = &self.buckets[index];

    bucket.lock.lock();
    defer bucket.lock.unlock();

    if (bucket.slot != slot) {
        // Bucket recycle — free prior contents if any.
        if (!bucket.is_empty.load(.acquire)) {
            // Alias fix: drop the OLD slot's pubkeys from the index BEFORE
            // clearing, so the index never advertises a recycled identity.
            self.indexRemoveBucket(bucket, bidx);
            bucket.clearKeepCapacity(self.allocator);
        }
        bucket.slot = slot;
    }

    // Index the write BEFORE inserting the bucket entry. This ordering is what
    // makes OOM safe: if anything below fails, `put` returns an error leaving
    // AT WORST a stale/extra index candidate (which self-filters on read),
    // never a MISSING one. The `errdefer` rolls the index add back so a failed
    // bucket insert leaves the index consistent too. `indexAdd` is idempotent,
    // so a same-(slot,pubkey) re-put is a no-op here.
    try self.indexAdd(pubkey, bidx);
    errdefer self.indexRemove(pubkey, bidx);

    const gop = try bucket.entries.getOrPut(self.allocator, pubkey);
    if (gop.found_existing) {
        // Same (slot, pubkey) re-put within the slot's execution window.
        // Free the previous data — ring owns it.
        if (gop.value_ptr.data.len > 0) {
            self.allocator.free(@constCast(gop.value_ptr.data));
        }
    }
    gop.value_ptr.* = account;
    bucket.is_empty.store(false, .release);
}

pub const Hit = struct {
    view: AccountView,
    modified_slot: Slot,
};

/// Read the latest version of `pubkey` whose writer-slot is in `ancestors`.
/// Returns `null` if no ancestor slot has a write for this pubkey.
///
/// `ancestors` is the reader's slot ∪ ancestor chain (the same slice
/// `getAccountInSlot` already builds for `sig_overlay.get`).
///
/// Optimization (2026-05-18 post-first-deploy A/B test): the prior
/// implementation called `sliceContains(ancestors, bucket.slot)` on
/// every non-empty bucket, which is O(ancestors_len) ≈ 65 per bucket.
/// At 4096 buckets × 65 ancestors × 1000 reads/slot during catchup
/// that's ~266k ops/read = ~25M ops/slot for ring scan alone — the
/// reason the first ring deploy stalled 3700 slots behind cluster tip
/// (see `project_ring_port_first_run_2026_05_18.md`).
///
/// Fix: pre-compute a bitmap of `slot % RING_CAPACITY` for each
/// ancestor at the top of the function, then the per-bucket filter is
/// a single O(1) bit test. Reduces per-read cost from O(buckets ×
/// ancestors) to O(buckets + ancestors). Matches Firedancer's
/// `fd_accdb_lineage` pre-cached lineage pattern.
///
/// Aliasing handling: two slots that differ by exactly `RING_CAPACITY`
/// map to the same bitmap index. The bucket stores its raw slot, so
/// after the bitmap pre-filter we ALSO call `sliceContains` to verify
/// exact membership. False-positive rate is ~ancestors_len /
/// RING_CAPACITY ≈ 1.6% of non-empty buckets pass the pre-filter
/// falsely; the exact-check fast-path catches them. Net: the per-call
/// bitmap build (~65 ops) + per-bucket bit test (~4096 ops) +
/// fallback exact-check for the false positives (~65 buckets × 65
/// scans ≈ 4225 ops) ≈ ~8000 ops total, vs. the prior ~266k ops.
/// 30× reduction in the hot path.
///
/// Returned `AccountView.data` is BORROWED from the ring's owned storage.
/// Valid until the bucket is recycled or dropped. For long-lived reads
/// (RPC responses, snapshot serialization) the caller must copy the data.
pub fn getWithModifiedSlot(
    self: *UnrootedRing,
    pubkey: Pubkey,
    ancestors: []const Slot,
) ?Hit {
    const result = self.indexedRead(pubkey, ancestors);
    if (verify_ring_index) {
        // SHADOW BACKSTOP: prove the index-driven read equals the full scan.
        const ref = self.scanModifiedSlot(pubkey, ancestors);
        std.debug.assert(hitEql(result, ref));
    }
    return result;
}

/// Index-driven read: identical per-bucket loop body to `scanModifiedSlot`
/// below, but visits ONLY the candidate buckets the per-pubkey index reports.
/// The candidate list is snapshotted under the shard lock and the shard lock
/// is released BEFORE any bucket lock is taken (≤1 lock held at any instant).
fn indexedRead(self: *UnrootedRing, pubkey: Pubkey, ancestors: []const Slot) ?Hit {
    // Snapshot the candidate bucket indices under the shard's shared lock,
    // then release it before touching any bucket lock. RING_CAPACITY is the
    // hard upper bound on distinct bucket indices for one pubkey.
    var cand_buf: [RING_CAPACITY]BucketIdx = undefined;
    const n = blk: {
        const shard = self.shardOf(pubkey);
        shard.lock.lockShared();
        defer shard.lock.unlockShared();
        const set = shard.map.getPtr(pubkey) orelse break :blk 0;
        break :blk set.copyTo(&cand_buf);
    };
    if (n == 0) return null;

    var bitmap: std.bit_set.IntegerBitSet(RING_CAPACITY) = .initEmpty();
    for (ancestors) |s| bitmap.set(s % RING_CAPACITY);

    var best_slot: Slot = 0;
    var result: ?Hit = null;

    for (cand_buf[0..n]) |bidx| {
        const bucket = &self.buckets[bidx];
        if (bucket.is_empty.load(.acquire)) continue;

        bucket.lock.lockShared();
        defer bucket.lock.unlockShared();

        if (bucket.slot < best_slot) continue;
        if (!bitmap.isSet(bucket.slot % RING_CAPACITY)) continue;
        // Exact verification — handles both the bitmap aliasing case and any
        // stale index candidate. Bounded by ancestors.len.
        if (!sliceContains(ancestors, bucket.slot)) continue;

        const acct = bucket.entries.get(pubkey) orelse continue;
        result = .{
            .view = .{
                .lamports = acct.lamports,
                .owner = acct.owner,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
            },
            .modified_slot = bucket.slot,
        };
        best_slot = bucket.slot;
    }

    return result;
}

/// SHADOW REFERENCE — the original full-ring scan, kept VERBATIM as the
/// correctness oracle for `indexedRead` (only reachable under
/// `-Dverify_ring_index` or from the equivalence KAT). Do NOT optimize.
fn scanModifiedSlot(
    self: *UnrootedRing,
    pubkey: Pubkey,
    ancestors: []const Slot,
) ?Hit {
    // Pre-build ancestor bitmap (512 bytes, single allocation on stack).
    var bitmap: std.bit_set.IntegerBitSet(RING_CAPACITY) = .initEmpty();
    for (ancestors) |s| bitmap.set(s % RING_CAPACITY);

    var best_slot: Slot = 0;
    var result: ?Hit = null;

    for (self.buckets) |*bucket| {
        if (bucket.is_empty.load(.acquire)) continue;

        bucket.lock.lockShared();
        defer bucket.lock.unlockShared();

        if (bucket.slot < best_slot) continue;
        // Pre-filter: O(1) bit test. False positives only when a
        // non-ancestor bucket-slot aliases an ancestor slot mod
        // RING_CAPACITY (rare with 4096-slot ring + ~65-slot ancestor
        // depth: ~1.6% false-positive rate).
        if (!bitmap.isSet(bucket.slot % RING_CAPACITY)) continue;
        // Exact verification — handles the aliasing case. Bounded by
        // ancestors.len and only runs for buckets that passed the
        // bitmap, so near-zero amortized cost.
        if (!sliceContains(ancestors, bucket.slot)) continue;

        const acct = bucket.entries.get(pubkey) orelse continue;
        result = .{
            .view = .{
                .lamports = acct.lamports,
                .owner = acct.owner,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
            },
            .modified_slot = bucket.slot,
        };
        best_slot = bucket.slot;
    }

    return result;
}

/// Convenience: just the view, dropping the modified_slot tag.
pub fn get(self: *UnrootedRing, pubkey: Pubkey, ancestors: []const Slot) ?AccountView {
    const hit = self.getWithModifiedSlot(pubkey, ancestors) orelse return null;
    return hit.view;
}

/// Two-tier read entry point (STEP 1, dormant until STEP 2 wires it).
///
/// Like `getWithModifiedSlot`, but ALSO treats `self_slot` (the reading
/// bank's own slot) as a matching slot — equivalent to the old
/// `getAccountInSlot` building `extended = ancestors ++ [slot]`, WITHOUT the
/// per-read 65-element stack copy. `ancestors` is the bank's FULL unrooted
/// ancestor chain (`bank.ancestors()`, which STEP 3 widens from 64 to the
/// full root-lag window). Self-slot is included so within-slot
/// read-your-writes works (the commit path writes the ring keyed by bank.slot).
///
/// Perf: with the window widened to the full root-lag, `ancestors.len` can be
/// up to RING_CAPACITY. The bitmap pre-filter keeps this near O(buckets) in the
/// common case (few false positives at small root-lag); the exact
/// `sliceContains` verification runs ONLY for the rare aliasing false positive,
/// so it stays cheap for the carrier case (root-lag ~138). It is kept
/// UNCONDITIONALLY for correctness — ring recycle can push root-lag past
/// RING_CAPACITY in pathological deep catch-up (residual risk #2), and a
/// span-based skip would then return aliased (wrong-fork) data. Correctness
/// over the micro-optimization; a proven-safe fast path is a follow-up.
pub fn getWithModifiedSlotPlusSelf(
    self: *UnrootedRing,
    pubkey: Pubkey,
    ancestors: []const Slot,
    self_slot: Slot,
) ?Hit {
    const result = self.indexedReadPlusSelf(pubkey, ancestors, self_slot);
    if (verify_ring_index) {
        // SHADOW BACKSTOP: prove the index-driven read equals the full scan.
        const ref = self.scanPlusSelf(pubkey, ancestors, self_slot);
        std.debug.assert(hitEql(result, ref));
    }
    return result;
}

/// Index-driven twin of `scanPlusSelf`: identical per-bucket loop body,
/// candidate buckets snapshotted from the index (shard lock released before
/// any bucket lock — ≤1 lock held at any instant). Read-your-writes for
/// `self_slot` holds because `put(self_slot, pubkey, ..)` recorded the index
/// entry on this same thread before this read.
fn indexedReadPlusSelf(
    self: *UnrootedRing,
    pubkey: Pubkey,
    ancestors: []const Slot,
    self_slot: Slot,
) ?Hit {
    var cand_buf: [RING_CAPACITY]BucketIdx = undefined;
    const n = blk: {
        const shard = self.shardOf(pubkey);
        shard.lock.lockShared();
        defer shard.lock.unlockShared();
        const set = shard.map.getPtr(pubkey) orelse break :blk 0;
        break :blk set.copyTo(&cand_buf);
    };
    if (n == 0) return null;

    var bitmap: std.bit_set.IntegerBitSet(RING_CAPACITY) = .initEmpty();
    bitmap.set(self_slot % RING_CAPACITY);
    for (ancestors) |s| bitmap.set(s % RING_CAPACITY);

    var best_slot: Slot = 0;
    var result: ?Hit = null;

    for (cand_buf[0..n]) |bidx| {
        const bucket = &self.buckets[bidx];
        if (bucket.is_empty.load(.acquire)) continue;

        bucket.lock.lockShared();
        defer bucket.lock.unlockShared();

        if (bucket.slot < best_slot) continue;
        if (!bitmap.isSet(bucket.slot % RING_CAPACITY)) continue;
        // Exact membership: bucket.slot must be the self-slot or an ancestor.
        if (bucket.slot != self_slot and !sliceContains(ancestors, bucket.slot)) continue;

        const acct = bucket.entries.get(pubkey) orelse continue;
        result = .{
            .view = .{
                .lamports = acct.lamports,
                .owner = acct.owner,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
            },
            .modified_slot = bucket.slot,
        };
        best_slot = bucket.slot;
    }

    return result;
}

/// SHADOW REFERENCE — the original full-ring scan (self-slot variant), kept
/// VERBATIM as the correctness oracle for `indexedReadPlusSelf`. Only reachable
/// under `-Dverify_ring_index` or from the equivalence KAT. Do NOT optimize.
fn scanPlusSelf(
    self: *UnrootedRing,
    pubkey: Pubkey,
    ancestors: []const Slot,
    self_slot: Slot,
) ?Hit {
    var bitmap: std.bit_set.IntegerBitSet(RING_CAPACITY) = .initEmpty();
    bitmap.set(self_slot % RING_CAPACITY);
    for (ancestors) |s| bitmap.set(s % RING_CAPACITY);

    var best_slot: Slot = 0;
    var result: ?Hit = null;

    for (self.buckets) |*bucket| {
        if (bucket.is_empty.load(.acquire)) continue;

        bucket.lock.lockShared();
        defer bucket.lock.unlockShared();

        if (bucket.slot < best_slot) continue;
        if (!bitmap.isSet(bucket.slot % RING_CAPACITY)) continue;
        // Exact membership: bucket.slot must be the self-slot or an ancestor.
        if (bucket.slot != self_slot and !sliceContains(ancestors, bucket.slot)) continue;

        const acct = bucket.entries.get(pubkey) orelse continue;
        result = .{
            .view = .{
                .lamports = acct.lamports,
                .owner = acct.owner,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = acct.data,
            },
            .modified_slot = bucket.slot,
        };
        best_slot = bucket.slot;
    }

    return result;
}

/// Structural equality for the shadow-verify: compares `modified_slot` and
/// every `AccountView` field including the data bytes.
fn hitEql(a: ?Hit, b: ?Hit) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    const x = a.?;
    const y = b.?;
    if (x.modified_slot != y.modified_slot) return false;
    if (x.view.lamports != y.view.lamports) return false;
    if (!std.mem.eql(u8, &x.view.owner.data, &y.view.owner.data)) return false;
    if (x.view.executable != y.view.executable) return false;
    if (x.view.rent_epoch != y.view.rent_epoch) return false;
    if (!std.mem.eql(u8, x.view.data, y.view.data)) return false;
    return true;
}

/// Drop the bucket for `slot` if it still owns that slot. Called from
/// `purgeUnrootedSlot` (slot marked dead via Phase H/I/J) or after a slot
/// is rooted+flushed to permanent storage. Frees all owned account data.
pub fn dropSlot(self: *UnrootedRing, slot: Slot) void {
    const index = slot % RING_CAPACITY;
    const bucket = &self.buckets[index];

    bucket.lock.lock();
    defer bucket.lock.unlock();

    if (bucket.slot != slot) return; // already recycled by a later slot
    if (bucket.is_empty.load(.acquire)) return;

    // Drop this bucket's pubkeys from the index BEFORE clearing / flagging
    // empty, so no reader snapshots a candidate for a bucket we just emptied.
    self.indexRemoveBucket(bucket, @intCast(index));
    bucket.clearKeepCapacity(self.allocator);
    bucket.is_empty.store(true, .release);
}

/// Iterate every (pubkey, account) in `slot`'s bucket under the bucket's
/// shared lock, invoking `func(ctx, pubkey, account)`. Used by `updateRoot`
/// to promote a rooted slot's writes into the Rooted store before `dropSlot`.
/// No-op if the bucket no longer owns `slot` (recycled) or is empty. The
/// callback MUST NOT write back into this ring (it writes the Rooted store) —
/// doing so would deadlock on the bucket lock. (STEP 1, dormant until STEP 5.)
pub fn forEachInSlot(
    self: *UnrootedRing,
    slot: Slot,
    ctx: anytype,
    comptime func: fn (@TypeOf(ctx), Slot, Pubkey, Account) void,
) void {
    const index = slot % RING_CAPACITY;
    const bucket = &self.buckets[index];

    bucket.lock.lockShared();
    defer bucket.lock.unlockShared();

    if (bucket.slot != slot) return; // recycled by a later slot
    if (bucket.is_empty.load(.acquire)) return;

    // Pass the bucket's true write-slot so the promotion can file the rooted
    // entry under `last_modified_slot` (canonical Sig semantics), not the root slot.
    var it = bucket.entries.iterator();
    while (it.next()) |kv| {
        func(ctx, bucket.slot, kv.key_ptr.*, kv.value_ptr.*);
    }
}

/// Append every pubkey written at `slot` into `out` (caller owns `out` and its
/// allocator). Snapshot semantics: keys are COPIED while the bucket's shared
/// lock is held, then the lock is released — so the caller can safely call back
/// into the ring (e.g. via getAccountInSlot) without re-entrant locking. Used by
/// the [LTHASH-VERIFY] full-recompute and [LT-WRITE-LOCALIZER] paths
/// (accounts.zig:recomputeAndVerifyLtHash / verifyLtHashWrites) to enumerate
/// accounts written this slot that have no rooted index entry yet.
pub fn collectSlotKeys(
    self: *UnrootedRing,
    slot: Slot,
    out: *std.ArrayListUnmanaged(Pubkey),
    allocator: std.mem.Allocator,
) void {
    const index = slot % RING_CAPACITY;
    const bucket = &self.buckets[index];

    bucket.lock.lockShared();
    defer bucket.lock.unlockShared();

    if (bucket.slot != slot) return; // recycled by a later slot
    if (bucket.is_empty.load(.acquire)) return;

    var it = bucket.entries.keyIterator();
    while (it.next()) |key_ptr| {
        out.append(allocator, key_ptr.*) catch {};
    }
}

/// Task #71 [MEM-BREAKDOWN]: racy unlocked sum of per-bucket entry counts.
/// Diagnostic-only — torn counts are acceptable; takes NO locks so it can
/// never contend with the replay hot path.
pub fn approxEntries(self: *UnrootedRing) usize {
    var n: usize = 0;
    for (self.buckets) |*b| {
        if (b.is_empty.load(.monotonic)) continue;
        n += b.entries.count();
    }
    return n;
}

fn sliceContains(haystack: []const Slot, needle: Slot) bool {
    for (haystack) |s| if (s == needle) return true;
    return false;
}

/// TEST-ONLY: number of candidate bucket indices the index currently records
/// for `pubkey` (0 if absent). Used by the alias/recycle KAT to prove stale
/// entries are dropped. Takes the shard shared-lock.
fn indexCandidateCount(self: *UnrootedRing, pubkey: Pubkey) usize {
    const shard = self.shardOf(pubkey);
    shard.lock.lockShared();
    defer shard.lock.unlockShared();
    const set = shard.map.getPtr(pubkey) orelse return 0;
    return set.len;
}

// ── tests ────────────────────────────────────────────────────────────────

test "sanity: get returns highest-ancestor write" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk_a = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0xBB} ** 32 };

    for ([_]Slot{ 1, 2, 3 }) |s| {
        try ring.put(s, pk_a, .{
            .lamports = @as(u64, s) * 100_000,
            .owner = owner,
            .executable = false,
            .rent_epoch = 0,
            .data = &.{},
        });
    }

    // Ancestor set [1, 3] — should pick slot 3
    const hit = ring.getWithModifiedSlot(pk_a, &[_]Slot{ 1, 3 }).?;
    try std.testing.expectEqual(@as(u64, 300_000), hit.view.lamports);
    try std.testing.expectEqual(@as(Slot, 3), hit.modified_slot);

    // Ancestor set [1, 2] — should pick slot 2
    const hit2 = ring.getWithModifiedSlot(pk_a, &[_]Slot{ 1, 2 }).?;
    try std.testing.expectEqual(@as(u64, 200_000), hit2.view.lamports);
}

// THE carrier regression lock (413408129 stale-read). Models a high-frequency
// fee-payer whose last write is 138 slots back, with no write since, read at the
// tip during a long root-lag seam. The FULL-window read (getWithModifiedSlotPlusSelf
// with the complete unrooted ancestor chain) MUST surface that far-back write; the
// legacy 64-deep window MISSES it and would fall through to the stale rooted store
// — which is exactly the bug. This test fails under the old 64-cap, passes uncapped.
test "carrier: full-window read surfaces a 138-slot-back write (64-cap misses it)" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk = Pubkey{ .data = [_]u8{0xAB} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0xCD} ** 32 };

    const root: Slot = 413_408_000;
    const write_slot: Slot = root + 1; // last write, 138 slots before the tip
    const tip: Slot = root + 138;

    // The fee-payer's only unrooted write — its correct on-fork value.
    try ring.put(write_slot, pk, .{
        .lamports = 22_822_087_621_452,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    });

    // Build the FULL unrooted ancestor chain [root+1 .. tip-1] (the tip itself is
    // `self_slot`). 137 ancestors — deeper than the legacy 64-cap.
    var full_anc: [137]Slot = undefined;
    for (0..137) |i| full_anc[i] = write_slot + @as(Slot, @intCast(i));

    // FULL-WINDOW read (the fix): must find the far-back write.
    const hit = ring.getWithModifiedSlotPlusSelf(pk, full_anc[0..], tip).?;
    try std.testing.expectEqual(@as(u64, 22_822_087_621_452), hit.view.lamports);
    try std.testing.expectEqual(write_slot, hit.modified_slot);

    // LEGACY 64-cap window (the bug): only the most-recent 64 ancestors are
    // visible, so the 138-back write is UNREACHABLE → miss → (in production) a
    // fall-through to the stale rooted store. This asserts the cap was the carrier.
    const capped = full_anc[(137 - 64)..]; // last 64 ancestors only
    try std.testing.expectEqual(@as(?Hit, null), ring.getWithModifiedSlot(pk, capped));
}

test "fork isolation: sibling-fork slot is invisible" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk_a = Pubkey{ .data = [_]u8{0xCC} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0xDD} ** 32 };

    try ring.put(5, pk_a, .{
        .lamports = 999_999,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    });

    // Reader's ancestors don't include slot 5 — must miss.
    try std.testing.expectEqual(@as(?Hit, null), ring.getWithModifiedSlot(pk_a, &[_]Slot{ 1, 2, 3 }));
}

test "dropSlot frees the bucket" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk_a = Pubkey{ .data = [_]u8{0xEE} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0xFF} ** 32 };

    try ring.put(42, pk_a, .{
        .lamports = 500_000,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    });

    try std.testing.expect(ring.getWithModifiedSlot(pk_a, &[_]Slot{42}) != null);
    ring.dropSlot(42);
    try std.testing.expectEqual(@as(?Hit, null), ring.getWithModifiedSlot(pk_a, &[_]Slot{42}));
}

test "bucket recycle when capacity wraps" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk_a = Pubkey{ .data = [_]u8{0x11} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0x22} ** 32 };

    // Put at slot 5
    try ring.put(5, pk_a, .{
        .lamports = 111_111,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    });

    // Put at slot (5 + RING_CAPACITY) — same bucket index, different slot.
    // Should evict slot-5 data without panicking.
    try ring.put(5 + RING_CAPACITY, pk_a, .{
        .lamports = 222_222,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    });

    // Slot 5 should be gone
    try std.testing.expectEqual(@as(?Hit, null), ring.getWithModifiedSlot(pk_a, &[_]Slot{5}));
    // Slot 5 + RING_CAPACITY should be there
    const hit = ring.getWithModifiedSlot(pk_a, &[_]Slot{5 + RING_CAPACITY}).?;
    try std.testing.expectEqual(@as(u64, 222_222), hit.view.lamports);
}

// ── per-pubkey read-index KATs (2026-07-08) ────────────────────────────────

// THE centerpiece: exhaustive equivalence fuzz. Random puts (incl. deliberate
// slot / slot+RING_CAPACITY aliasing collisions), dropSlots and re-puts, then
// many random (pubkey, ancestors, self_slot) reads asserting the index-driven
// public reads equal the verbatim full-scan references. Single-threaded, so any
// difference is a pure index bug (never a race). This is the empirical proof of
// the correctness lemma (index == scan) — the same check the -Dverify_ring_index
// shadow backstop runs in production, exercised here unconditionally.
test "index equivalence fuzz: indexed reads == full scan under puts/drops/recycles" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const owner = Pubkey{ .data = [_]u8{0x90} ** 32 };
    var pks: [8]Pubkey = undefined;
    for (&pks, 0..) |*p, i| p.* = Pubkey{ .data = [_]u8{@intCast(i + 1)} ** 32 };
    // {5,6,7} and {4101,4102,4103} alias buckets {5,6,7} (diff by RING_CAPACITY).
    const slots = [_]Slot{ 5, 6, 7, 5 + RING_CAPACITY, 6 + RING_CAPACITY, 7 + RING_CAPACITY };

    var prng = std.Random.DefaultPrng.init(0xC0FFEEBABE);
    const rand = prng.random();

    var op: usize = 0;
    while (op < 4000) : (op += 1) {
        const pk = pks[rand.intRangeLessThan(usize, 0, pks.len)];
        const slot = slots[rand.intRangeLessThan(usize, 0, slots.len)];
        if (rand.intRangeLessThan(usize, 0, 10) < 7) {
            const dlen = rand.intRangeAtMost(usize, 1, 3); // ≥1 so the ring always frees it
            const data = try allocator.alloc(u8, dlen);
            rand.bytes(data);
            ring.put(slot, pk, .{
                .lamports = rand.int(u64),
                .owner = owner,
                .executable = rand.boolean(),
                .rent_epoch = rand.int(u64),
                .data = data,
            }) catch allocator.free(data);
        } else {
            ring.dropSlot(slot);
        }

        // Random read, compared against the verbatim scan references.
        const rpk = pks[rand.intRangeLessThan(usize, 0, pks.len)];
        var anc_buf: [slots.len]Slot = undefined;
        var anc_n: usize = 0;
        for (slots) |s| if (rand.boolean()) {
            anc_buf[anc_n] = s;
            anc_n += 1;
        };
        const anc = anc_buf[0..anc_n];
        const self_slot = slots[rand.intRangeLessThan(usize, 0, slots.len)];

        try std.testing.expect(hitEql(
            ring.getWithModifiedSlot(rpk, anc),
            ring.scanModifiedSlot(rpk, anc),
        ));
        try std.testing.expect(hitEql(
            ring.getWithModifiedSlotPlusSelf(rpk, anc, self_slot),
            ring.scanPlusSelf(rpk, anc, self_slot),
        ));
    }
}

// Recycle/alias fix: a bucket reused by a slot exactly RING_CAPACITY apart must
// DROP the previous slot's pubkey from the index (else the read would alias to a
// wrong-fork identity). Uses DIFFERENT pubkeys so the removal is observable.
test "index recycle drops the old identity's candidate" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const owner = Pubkey{ .data = [_]u8{0x33} ** 32 };
    const pk_old = Pubkey{ .data = [_]u8{0x44} ** 32 };
    const pk_new = Pubkey{ .data = [_]u8{0x55} ** 32 };

    try ring.put(5, pk_old, .{ .lamports = 1, .owner = owner, .executable = false, .rent_epoch = 0, .data = &.{} });
    try std.testing.expectEqual(@as(usize, 1), ring.indexCandidateCount(pk_old));

    // Recycle bucket 5 with a different pubkey at slot 5 + RING_CAPACITY.
    try ring.put(5 + RING_CAPACITY, pk_new, .{ .lamports = 2, .owner = owner, .executable = false, .rent_epoch = 0, .data = &.{} });

    // Old identity: no read hit for slot 5 AND no lingering index candidate.
    try std.testing.expectEqual(@as(?Hit, null), ring.getWithModifiedSlot(pk_old, &[_]Slot{5}));
    try std.testing.expectEqual(@as(usize, 0), ring.indexCandidateCount(pk_old));
    // New identity: present, single candidate (bucket 5).
    try std.testing.expectEqual(@as(usize, 1), ring.indexCandidateCount(pk_new));
    const hit = ring.getWithModifiedSlot(pk_new, &[_]Slot{5 + RING_CAPACITY}).?;
    try std.testing.expectEqual(@as(u64, 2), hit.view.lamports);

    // dropSlot must also clear the index candidate.
    ring.dropSlot(5 + RING_CAPACITY);
    try std.testing.expectEqual(@as(usize, 0), ring.indexCandidateCount(pk_new));
}

// Read-your-writes: a same-thread put keyed by the reading bank's own slot is
// immediately visible via the self_slot exemption (no ancestor entry needed).
test "index read-your-writes: same-thread put visible via self_slot" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk = Pubkey{ .data = [_]u8{0x66} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0x67} ** 32 };
    const self_slot: Slot = 123_456;

    try ring.put(self_slot, pk, .{ .lamports = 7_777, .owner = owner, .executable = false, .rent_epoch = 0, .data = &.{} });

    const hit = ring.getWithModifiedSlotPlusSelf(pk, &[_]Slot{}, self_slot).?;
    try std.testing.expectEqual(@as(u64, 7_777), hit.view.lamports);
    try std.testing.expectEqual(self_slot, hit.modified_slot);
}

// Concurrent put+read: one writer churns SIBLING slots (never in the reader's
// ancestor set, never bucket-colliding with the winner) while a reader loops on
// a fixed pubkey/ancestor whose winning bucket is stable. Stresses the strict
// bucket ≻ shard lock order (writer holds bucket then shard; reader holds shard
// alone, releases, then bucket alone) for deadlock/torn-read freedom. Because
// every sibling write self-filters out of the read, the result is invariant —
// so this is also the intended target for `-Dverify_ring_index` (the shadow
// assert can never race). Run: `zig build test-accounts -Dverify_ring_index`.
test "index concurrent put+read: stable winner survives writer churn" {
    const allocator = std.testing.allocator;
    var ring: UnrootedRing = try .init(allocator);
    defer ring.deinit();

    const pk_hot = Pubkey{ .data = [_]u8{0x77} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0x88} ** 32 };
    const HOT_LAMPORTS: u64 = 424_242;
    const WIN_SLOT: Slot = 100;

    try ring.put(WIN_SLOT, pk_hot, .{ .lamports = HOT_LAMPORTS, .owner = owner, .executable = false, .rent_epoch = 0, .data = &.{} });

    var stop = Atomic(bool).init(false);
    var reader_ok = Atomic(bool).init(true);

    const Writer = struct {
        fn run(r: *UnrootedRing, ow: Pubkey, phot: Pubkey, stopf: *Atomic(bool)) void {
            var i: usize = 0;
            while (i < 6000) : (i += 1) {
                // Sibling slots 200..599 — buckets 200..599, never bucket 100,
                // never in the reader's {WIN_SLOT} ancestor set.
                const slot: Slot = 200 + @as(Slot, @intCast((i * 7) % 400));
                r.put(slot, phot, .{ .lamports = 1, .owner = ow, .executable = false, .rent_epoch = 0, .data = &.{} }) catch {};
                if (i % 2 == 1) r.dropSlot(slot);
            }
            stopf.store(true, .release);
        }
    };
    const Reader = struct {
        fn run(r: *UnrootedRing, phot: Pubkey, want: u64, wslot: Slot, stopf: *Atomic(bool), okf: *Atomic(bool)) void {
            while (!stopf.load(.acquire)) {
                const hit = r.getWithModifiedSlot(phot, &[_]Slot{wslot});
                if (hit == null or hit.?.view.lamports != want or hit.?.modified_slot != wslot) {
                    okf.store(false, .release);
                }
            }
        }
    };

    const wt = try std.Thread.spawn(.{}, Writer.run, .{ &ring, owner, pk_hot, &stop });
    const rt = try std.Thread.spawn(.{}, Reader.run, .{ &ring, pk_hot, HOT_LAMPORTS, WIN_SLOT, &stop, &reader_ok });
    wt.join();
    rt.join();

    try std.testing.expect(reader_ok.load(.acquire));
    const final = ring.getWithModifiedSlot(pk_hot, &[_]Slot{WIN_SLOT}).?;
    try std.testing.expectEqual(HOT_LAMPORTS, final.view.lamports);
}
