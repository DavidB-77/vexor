//! Vexor Accounts Database — core AccountsDb (rooted index + AppendVec/overlay
//! read/write/root paths), AccountIndex, AccountCache, BulkLoadBuffer, TopVote,
//! and the unit-test / carrier-reproducer suite.
//! SPLIT from accounts.zig (rebuild module 25): AppendVec -> appendvec.zig,
//! AccountStorage -> account_storage.zig (imported below).
const std = @import("std");
const core = @import("core");
const mem_alloc = @import("core").allocator;
const build_options = @import("build_options");
const crypto = @import("vex_crypto");
const sig_overlay_mod = @import("sig_overlay.zig");
const recorder = @import("recorder.zig");
const root_partition = @import("root_partition.zig"); // FIX #105: pure root-advance partition (moved from vex_svm so db owns the durable parent map + computeRootPartition)
const appendvec = @import("appendvec.zig");
const account_storage = @import("account_storage.zig");
const Account = appendvec.Account;
const AccountView = appendvec.AccountView;
const AccountLocation = appendvec.AccountLocation;
const SlotOverlay = appendvec.SlotOverlay;
const AppendVec = appendvec.AppendVec;
const AccountStorage = account_storage.AccountStorage;


/// RULE#0 / canonical-storage-collapse (2026-06-07): count rooted-write losses that
/// were previously SILENT. A dropped rooted promotion leaves the rooted index with a
/// stale value → stale old-state read → wrong accounts_lt_hash → bank_hash divergence →
/// vote-freeze. This was the PROVEN AppendVec store-rotation carrier (the retry returned
/// the SAME full store). The room-aware `getOrCreateStore` below prevents it; this counter
/// + the loud `[LOST-ROOTED-WRITE]` logs make any residual loss impossible to miss on a
/// live soak (the honest production signal that replaces the diagnostic-replay loop).
/// MUST stay 0 in a healthy run. NOTE: with the room-aware getOrCreateStore fix this
/// counter stays 0 BY CONSTRUCTION (the loss is prevented upstream, the catch is never
/// reached) — so it is a future-REGRESSION TRIPWIRE, not a carrier-confirmation signal.
pub var lost_rooted_writes: u64 = 0;

/// DETECTOR (advisor 2026-06-08, behavior-preserving): count of ring writes at OFF-FORK
/// (non-ancestor-of-`new_root`) slots that `advanceRoot` STEP-5 promotes into the rooted
/// index. This is the suspected lt `op0` stale-read carrier (Class-1 "sibling-promote"):
/// a sibling/orphan slot frozen into the ring but not purged before the root crosses its
/// slot number gets promoted under its TRUE write-slot and, via higher-slot-wins, can mask
/// the canonical version → every later ring-miss read returns the sibling bytes as op0.
/// The probe instruments the CAUSE directly (logging only, no behavior change) so a CURRENT
/// validator confirms or REFUTES the hypothesis without the recorder. NONZERO + correlated
/// with an lthash-vs-cluster divergence = Class-1 confirmed (→ write the minimal promote-side
/// ancestor filter). Stays 0 while divergence keeps happening = the storage-stale-read family
/// is refuted (→ stop re-fixing this file; pivot to compute/sysvar/vote-state path).
pub var sibling_promotes_observed: u64 = 0;
var sibling_promote_detail_logged: u64 = 0;

/// FIX#95 regress-detector (2026-06-01): latest committed write per pubkey
/// (slot + lamports). At the rooted-read fall-through, if a write at a slot
/// <= rooted_slot (canonical truth) recorded a different value than the read
/// returned, the rooted store is STALE = the 412372439 carrier. Gated by
/// VEX_REGRESS_DETECT=1. Module-level fire counter rate-limits the log.
const DbgRegressEntry = struct { slot: u64, lamports: u64, data_sha8: u64, dlen: u32 };
var dbg_regress_fires = std.atomic.Value(u64).init(0);
/// FIX#95 regress-detector: 8-byte SHA-256 prefix over the FULL account data
/// (NOT first-64 — the Task#100 trap that masked past-byte-64 divergence).
/// Lets a stale rooted read be caught when data differs even if lamports match.
fn dbgDataSha8(data: []const u8) u64 {
    if (data.len == 0) return 0;
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return std.mem.readInt(u64, h[0..8], .big);
}

fn accountViewFromOwned(account: *const Account) AccountView {
    return .{
        .lamports = account.lamports,
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
        .data = account.data,
    };
}

fn serializeAccount(allocator: std.mem.Allocator, account: *const Account) ![]u8 {
    const header_len: usize = 8 + 32 + 1 + 8 + 4;
    const total = header_len + account.data.len;
    var buf = try allocator.alloc(u8, total);
    var offset: usize = 0;

    std.mem.writeInt(u64, buf[offset..][0..8], account.lamports, .little);
    offset += 8;
    @memcpy(buf[offset..][0..32], &account.owner.data);
    offset += 32;
    buf[offset] = if (account.executable) 1 else 0;
    offset += 1;
    std.mem.writeInt(u64, buf[offset..][0..8], account.rent_epoch, .little);
    offset += 8;
    std.mem.writeInt(u32, buf[offset..][0..4], @intCast(account.data.len), .little);
    offset += 4;
    @memcpy(buf[offset..][0..account.data.len], account.data);

    return buf;
}

fn serializeAccountView(allocator: std.mem.Allocator, account: *const AccountView) ![]u8 {
    const header_len: usize = 8 + 32 + 1 + 8 + 4;
    const total = header_len + account.data.len;
    var buf = try allocator.alloc(u8, total);
    var offset: usize = 0;

    std.mem.writeInt(u64, buf[offset..][0..8], account.lamports, .little);
    offset += 8;
    @memcpy(buf[offset..][0..32], &account.owner.data);
    offset += 32;
    buf[offset] = if (account.executable) 1 else 0;
    offset += 1;
    std.mem.writeInt(u64, buf[offset..][0..8], account.rent_epoch, .little);
    offset += 8;
    std.mem.writeInt(u32, buf[offset..][0..4], @intCast(account.data.len), .little);
    offset += 4;
    @memcpy(buf[offset..][0..account.data.len], account.data);

    return buf;
}

/// Bulk load buffer for snapshot loading
/// Uses heap allocation instead of mmap to avoid thousands of 64MB mmap regions
pub const BulkLoadBuffer = struct {
    allocator: std.mem.Allocator,
    lock: std.Thread.RwLock,
    /// Account data stored as pubkey -> (lamports, owner, executable, rent_epoch, data)
    accounts: std.AutoHashMap(core.Pubkey, StoredAccount),
    /// Total accounts stored
    count: u64,

    const StoredAccount = struct {
        lamports: u64,
        owner: core.Pubkey,
        executable: bool,
        rent_epoch: u64,
        data: []u8, // Heap allocated copy
    };

    pub fn init(allocator: std.mem.Allocator) !*BulkLoadBuffer {
        const self = try allocator.create(BulkLoadBuffer);
        self.* = .{
            .allocator = allocator,
            .lock = .{},
            .accounts = std.AutoHashMap(core.Pubkey, StoredAccount).init(allocator),
            .count = 0,
        };
        return self;
    }

    pub fn deinit(self: *BulkLoadBuffer) void {
        // Free all stored account data
        var iter = self.accounts.valueIterator();
        while (iter.next()) |stored| {
            if (stored.data.len > 0) {
                self.allocator.free(stored.data);
            }
        }
        self.accounts.deinit();
        self.allocator.destroy(self);
    }

    pub fn store(self: *BulkLoadBuffer, pubkey: *const core.Pubkey, account: *const Account) !void {
        self.lock.lock();
        defer self.lock.unlock();
        // Copy account data to heap
        const data_copy = if (account.data.len > 0)
            try self.allocator.dupe(u8, account.data)
        else
            &[_]u8{};

        // Remove old data if exists
        if (self.accounts.get(pubkey.*)) |old| {
            if (old.data.len > 0) {
                self.allocator.free(old.data);
            }
        }

        try self.accounts.put(pubkey.*, .{
            .lamports = account.lamports,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
            .data = data_copy,
        });
        self.count += 1;
    }

    pub fn get(self: *BulkLoadBuffer, pubkey: *const core.Pubkey) ?AccountView {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        if (self.accounts.get(pubkey.*)) |stored| {
            return AccountView{
                .lamports = stored.lamports,
                .owner = stored.owner,
                .executable = stored.executable,
                .rent_epoch = stored.rent_epoch,
                .data = stored.data,
            };
        }
        return null;
    }
};

/// Main accounts database
/// One fork-attributed version of a voter's `last_timestamp`. `write_slot` is
/// the bank slot whose flush produced this vote-state write — the fork-lineage
/// key (mirrors how sig_overlay / unrooted_ring key writes by slot for PR-5ac
/// fork isolation). The SIMD-0001 Clock harvest selects the version whose
/// `write_slot` is on the reading bank's ancestor chain (or already rooted), so
/// a sibling-fork vote write can never contaminate a canonical child's estimate.
pub const TopVoteVersion = struct {
    write_slot: u64,
    last_vote_slot: u64,
    last_vote_timestamp: i64,
    /// Tower-top last-voted slot for the fork-choice vote-weight feed
    /// (`fork_choice_feed.buildVoteAccountBatch`). DISTINCT from `last_vote_slot`,
    /// which is `vote_state.last_timestamp.slot` — the SIMD-0001 Clock sample slot.
    /// A vote tx may omit a timestamp, so the timestamp slot can lag the tower top;
    /// fork choice must weight by the *actual* last vote (`VoteState.lastVotedSlot()`
    /// == `lockouts[count-1].slot`, the same value the legacy feed parsed via
    /// `getLastVotedSlot`). 0 = no usable vote (empty/corrupt tower) → feed skips it.
    /// Defaulted so existing 3-field initializers + tests keep compiling; the three
    /// production upsert sites set it explicitly. Agave parity: the
    /// `bank.vote_accounts()` view fork choice walks carries the real tower.
    tower_last_voted_slot: u64 = 0,
};

/// Fork-aware multi-version vote-timestamp summary for one vote account, stored
/// in AccountsDb.top_votes and consumed by updateClockSysvar()'s stake-weighted
/// median (SIMD-0001) without deserialising vote accounts on every slot.
///
/// Replaces the pre-2026-05-31 single fork-blind value — the Clock
/// unix_timestamp −1s carrier: a sibling-fork vote write (e.g. testnet skipped
/// slot 412149074) overwrote the canonical value in one global slot, so a
/// canonical child harvested an off-fork timestamp. This applies the same
/// multi-version-keyed-by-slot fork-isolation pattern already proven for general
/// accounts in sig_overlay / unrooted_ring, sized for the harvest's all-pubkeys
/// access pattern. Pure value type (no owned heap) — crash-safe, never mmap.
/// Agave parity: per-bank stakes_cache vote_accounts(); Firedancer:
/// fd_vote_stakes_fork_iter. Both maintain a per-fork view; neither re-reads.
pub const TopVote = struct {
    /// Concurrent unrooted forks for one voter are few (typically 1, rarely 2-3
    /// during brief equivocation). 32 covers the rooted baseline + the latest
    /// write on each active fork with wide margin. Overflow evicts the lowest
    /// UNROOTED write_slot (never the rooted baseline, never the active-fork
    /// latest the harvest needs).
    pub const MAX_VERSIONS = 32;

    versions: [MAX_VERSIONS]TopVoteVersion = undefined,
    len: u8 = 0,

    fn containsSlot(haystack: []const u64, needle: u64) bool {
        for (haystack) |s| if (s == needle) return true;
        return false;
    }

    /// Insert or replace the version for `v.write_slot` (always-write — preserves
    /// d16-v3: never leaves a stale value behind). On overflow, evict the lowest
    /// write_slot strictly greater than `rooted_slot` (oldest unrooted, already
    /// superseded on its lineage); if somehow all are rooted, evict the lowest.
    pub fn upsert(self: *TopVote, v: TopVoteVersion, rooted_slot: u64) void {
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            if (self.versions[i].write_slot == v.write_slot) {
                self.versions[i] = v;
                return;
            }
        }
        if (self.len < MAX_VERSIONS) {
            self.versions[self.len] = v;
            self.len += 1;
            return;
        }
        // Full: evict the version carrying the LOWEST `tower_last_voted_slot` among
        // the UNROOTED versions (already superseded on its lineage), tie-broken by
        // lowest write_slot. This preserves the freshest tower the feed needs
        // (`latestVotedSlot` = max tower) AND the rooted baseline (`ws <= rooted_slot`
        // is excluded from the victim pool). When towers are equal — the steady-state
        // case where write_slot and tower advance together — this reduces to the prior
        // lowest-unrooted-write_slot policy, so fork-isolation eviction is unchanged.
        var victim: u8 = 0;
        var victim_tower: u64 = std.math.maxInt(u64);
        var victim_slot: u64 = std.math.maxInt(u64);
        var have_unrooted = false;
        i = 0;
        while (i < self.len) : (i += 1) {
            const ws = self.versions[i].write_slot;
            if (ws > rooted_slot) {
                const tw = self.versions[i].tower_last_voted_slot;
                if (!have_unrooted or tw < victim_tower or (tw == victim_tower and ws < victim_slot)) {
                    victim = i;
                    victim_tower = tw;
                    victim_slot = ws;
                    have_unrooted = true;
                }
            }
        }
        if (!have_unrooted) {
            // Degenerate: all versions rooted. Evict the lowest tower (tie: lowest ws).
            victim = 0;
            victim_tower = self.versions[0].tower_last_voted_slot;
            victim_slot = self.versions[0].write_slot;
            i = 1;
            while (i < self.len) : (i += 1) {
                const tw = self.versions[i].tower_last_voted_slot;
                const ws = self.versions[i].write_slot;
                if (tw < victim_tower or (tw == victim_tower and ws < victim_slot)) {
                    victim = i;
                    victim_tower = tw;
                    victim_slot = ws;
                }
            }
        }
        // Recovery path: never silently drop a write that carries a fresher (or
        // equal) tower than the victim — that is exactly the fresh vote the feed
        // must surface. Only discard the incoming when it is staler than every
        // retained version (keeping the victim then preserves strictly more signal).
        if (v.tower_last_voted_slot >= victim_tower) self.versions[victim] = v;
    }

    /// Fork-aware selection (advisor rule): the version with the highest
    /// `write_slot` that is in `ancestors` OR ≤ `rooted_slot` (rooted history is
    /// linear/canonical). null if the voter has no version on this fork lineage.
    pub fn selectForFork(self: *const TopVote, ancestors: []const u64, rooted_slot: u64) ?TopVoteVersion {
        var best: ?TopVoteVersion = null;
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            const v = self.versions[i];
            const on_lineage = v.write_slot <= rooted_slot or containsSlot(ancestors, v.write_slot);
            if (!on_lineage) continue;
            if (best == null or v.write_slot > best.?.write_slot) best = v;
        }
        return best;
    }

    /// Collapse rooted history on root advance: keep at most one version ≤
    /// `new_root` (the highest = rooted baseline) plus all versions > new_root.
    /// Mirrors unrooted_ring's dropSlot-on-root. Returns true if now empty.
    pub fn pruneBelowRoot(self: *TopVote, new_root: u64) bool {
        var baseline_idx: ?u8 = null;
        var baseline_slot: u64 = 0;
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            const ws = self.versions[i].write_slot;
            if (ws <= new_root and (baseline_idx == null or ws > baseline_slot)) {
                baseline_idx = i;
                baseline_slot = ws;
            }
        }
        var out: u8 = 0;
        i = 0;
        while (i < self.len) : (i += 1) {
            const keep = self.versions[i].write_slot > new_root or
                (baseline_idx != null and i == baseline_idx.?);
            if (keep) {
                self.versions[out] = self.versions[i];
                out += 1;
            }
        }
        self.len = out;
        return self.len == 0;
    }

    /// Fork-choice vote-weight feed (v1, fork-blind): the `tower_last_voted_slot`
    /// of the version with the highest `write_slot` (the voter's most recently
    /// observed vote). null when the voter has no version, or its newest tower is
    /// empty (tower_last_voted_slot == 0 → never a real vote target).
    ///
    /// The legacy `unflushed_cache` feed this replaces was already fork-blind
    /// (it scanned whatever vote writes happened to be un-flushed).
    /// `selectForFork(ancestors, rooted_slot)` is the strictly-better fork-aware
    /// follow-up — not a prerequisite for fixing the drain.
    ///
    /// SELECTION (2026-07-09): return the MAXIMUM `tower_last_voted_slot` across all
    /// stored versions — NOT the tower of the highest-`write_slot` version. A voter's
    /// tower is monotonic (a validator never un-votes), so the freshest vote target is
    /// always the highest tower value the cache has observed, regardless of which
    /// write-path (tip flush at bank.slot vs promoteRootedChain at the rooted slot)
    /// recorded it. The prior max-`write_slot` pick masked a fresher tower whenever it
    /// arrived on a LOWER write_slot landing (the routine `readback_stale` signal) —
    /// benign while the tip-flush input keeps flowing, but it left the feed unable to
    /// surface a fresh vote that only reaches the cache via a non-tip path. Off-fork
    /// equivocating targets can't leak: the feed resolves each voted_slot through
    /// `bank_hash_ctx.lookup`, which returns null for slots outside our frozen banks.
    pub fn latestVotedSlot(self: *const TopVote) ?u64 {
        var best: u64 = 0;
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            const t = self.versions[i].tower_last_voted_slot;
            if (t > best) best = t;
        }
        return if (best == 0) null else best;
    }

};

test "top_vote: upsert appends then replaces same write_slot in place" {
    var tv = TopVote{};
    tv.upsert(.{ .write_slot = 10, .last_vote_slot = 9, .last_vote_timestamp = 100 }, 0);
    tv.upsert(.{ .write_slot = 11, .last_vote_slot = 10, .last_vote_timestamp = 101 }, 0);
    try std.testing.expectEqual(@as(u8, 2), tv.len);
    // Same write_slot 11 → replace in place, no growth.
    tv.upsert(.{ .write_slot = 11, .last_vote_slot = 10, .last_vote_timestamp = 999 }, 0);
    try std.testing.expectEqual(@as(u8, 2), tv.len);
    const sel = tv.selectForFork(&[_]u64{ 10, 11 }, 0).?;
    try std.testing.expectEqual(@as(i64, 999), sel.last_vote_timestamp);
}

test "top_vote: selectForFork excludes sibling, returns canonical (the 412149075 carrier)" {
    // Voter voted canonical 149073 (ts=...142) AND sibling 149074 (ts=...141).
    // Canonical child 149075 harvests: ancestors include 149073, NOT 149074.
    // The fix MUST return the canonical 142, not the sibling 141.
    var tv = TopVote{};
    const root: u64 = 412149036;
    tv.upsert(.{ .write_slot = 412149073, .last_vote_slot = 412149073, .last_vote_timestamp = 1780229142 }, root);
    tv.upsert(.{ .write_slot = 412149074, .last_vote_slot = 412149074, .last_vote_timestamp = 1780229141 }, root);
    const anc = [_]u64{ 412149073, 412149072, 412149071, 412149070 }; // canonical chain; NO sibling 149074
    const sel = tv.selectForFork(&anc, root).?;
    try std.testing.expectEqual(@as(i64, 1780229142), sel.last_vote_timestamp);
    try std.testing.expectEqual(@as(u64, 412149073), sel.write_slot);
}

test "top_vote: selectForFork falls back to rooted baseline for an inactive voter" {
    var tv = TopVote{};
    const root: u64 = 100;
    tv.upsert(.{ .write_slot = 50, .last_vote_slot = 49, .last_vote_timestamp = 5000 }, root); // rooted (<= root)
    const sel = tv.selectForFork(&[_]u64{ 101, 102, 103 }, root).?;
    try std.testing.expectEqual(@as(i64, 5000), sel.last_vote_timestamp);
}

test "top_vote: selectForFork returns null when only a sibling version exists" {
    var tv = TopVote{};
    const root: u64 = 100;
    tv.upsert(.{ .write_slot = 150, .last_vote_slot = 150, .last_vote_timestamp = 7000 }, root); // > root, off-lineage
    try std.testing.expectEqual(@as(?TopVoteVersion, null), tv.selectForFork(&[_]u64{ 101, 102, 103 }, root));
}

test "top_vote: pruneBelowRoot collapses rooted history to one baseline, keeps unrooted" {
    var tv = TopVote{};
    tv.upsert(.{ .write_slot = 10, .last_vote_slot = 10, .last_vote_timestamp = 1 }, 0);
    tv.upsert(.{ .write_slot = 20, .last_vote_slot = 20, .last_vote_timestamp = 2 }, 0);
    tv.upsert(.{ .write_slot = 30, .last_vote_slot = 30, .last_vote_timestamp = 3 }, 0);
    tv.upsert(.{ .write_slot = 40, .last_vote_slot = 40, .last_vote_timestamp = 4 }, 0);
    tv.upsert(.{ .write_slot = 50, .last_vote_slot = 50, .last_vote_timestamp = 5 }, 0);
    try std.testing.expect(!tv.pruneBelowRoot(35));
    try std.testing.expectEqual(@as(u8, 3), tv.len); // baseline(30) + unrooted 40,50
    const base = tv.selectForFork(&[_]u64{}, 35).?; // no ancestors → baseline only
    try std.testing.expectEqual(@as(u64, 30), base.write_slot);
}

test "top_vote: overflow evicts lowest unrooted, preserves baseline and active-fork latest" {
    var tv = TopVote{};
    const root: u64 = 1000;
    tv.upsert(.{ .write_slot = 900, .last_vote_slot = 900, .last_vote_timestamp = 900 }, root); // rooted baseline
    var s: u64 = 1001;
    const top: u64 = 1001 + TopVote.MAX_VERSIONS + 5 - 1;
    while (s <= top) : (s += 1) {
        tv.upsert(.{ .write_slot = s, .last_vote_slot = s, .last_vote_timestamp = @intCast(s) }, root);
    }
    try std.testing.expectEqual(@as(u8, TopVote.MAX_VERSIONS), tv.len);
    // Baseline (<= root) survives.
    try std.testing.expectEqual(@as(u64, 900), tv.selectForFork(&[_]u64{}, root).?.write_slot);
    // Highest unrooted (active-fork latest) survives.
    try std.testing.expectEqual(@as(u64, top), tv.selectForFork(&[_]u64{top}, root).?.write_slot);
}

test "top_vote: feed surfaces the freshest tower even when it lands on a LOWER write_slot" {
    // Reproduces the version-selection masking that the fork-choice feed hit: a stale
    // tip version at a HIGH write_slot (old tower) coexists with a FRESH vote delivered
    // via a LOWER write_slot landing (e.g. promoteRootedChain / out-of-order replay).
    // Pre-fix latestVotedSlot() returned the max-write_slot version's tower (1500,
    // stale-masked); post-fix it returns the max tower observed (1600).
    var tv = TopVote{};
    const root: u64 = 1000;
    tv.upsert(.{ .write_slot = 5000, .last_vote_slot = 0, .last_vote_timestamp = 0, .tower_last_voted_slot = 1500 }, root);
    tv.upsert(.{ .write_slot = 1010, .last_vote_slot = 0, .last_vote_timestamp = 0, .tower_last_voted_slot = 1600 }, root);
    try std.testing.expectEqual(@as(?u64, 1600), tv.latestVotedSlot());
}

test "top_vote: overflow never evicts the freshest tower (recovery path)" {
    // Fill PAST MAX_VERSIONS with stale (lower-tower) unrooted versions and assert the
    // single fresh-tower version SURVIVES eviction — the feed must never lose the
    // freshest vote target, so a fresh vote reaching the cache via any path is always
    // surfaced (readback returns fresh, never stuck on a stale high-write_slot version).
    var tv = TopVote{};
    const root: u64 = 1000;
    // The fresh vote (highest tower) sits on a LOW write_slot — the worst case for the
    // old write_slot-based eviction, which would have evicted it first.
    tv.upsert(.{ .write_slot = 1001, .last_vote_slot = 0, .last_vote_timestamp = 0, .tower_last_voted_slot = 1600 }, root);
    var s: u64 = 5000;
    var k: u32 = 0;
    while (k < TopVote.MAX_VERSIONS + 8) : (k += 1) {
        tv.upsert(.{ .write_slot = s, .last_vote_slot = 0, .last_vote_timestamp = 0, .tower_last_voted_slot = 1400 }, root);
        s += 1;
    }
    try std.testing.expectEqual(@as(u8, TopVote.MAX_VERSIONS), tv.len);
    // Freshest tower (1600) preserved despite MAX_VERSIONS+ churn of staler versions.
    try std.testing.expectEqual(@as(?u64, 1600), tv.latestVotedSlot());
}

/// First-slot-of-epoch (slot, unix_ts) anchor used by SIMD-0001 Clock estimator.
/// Kept at module scope (not inside AccountsDb) so it can sit alongside
/// AccountsDb fields without triggering Zig's "decls can't be interleaved with
/// fields" rule.
pub const ClockEpochAnchor = struct { slot: u64, unix_ts: i64 };

pub const AccountsDb = struct {
    allocator: std.mem.Allocator,
    metadata_lock: std.Thread.Mutex, // Protects slot, stats, and metadata
    accounts_path: []const u8,
    /// Account index: pubkey -> location
    index: AccountIndex,
    /// Storage for account data
    storage: AccountStorage,
    /// fork-BGSAVE (task #26, 2026-07-01): TRUE while a CoW snapshot child is
    /// alive. Parent-side purge/clean/shrink check it and DEFER their work a few
    /// minutes (they already run opportunistically). NOT a child-correctness
    /// requirement — CoW freezes the child's view regardless; this is (a)
    /// CoW-amplification control (shrink REWRITES whole 64 MB stores, dirtying
    /// pages the child still shares) and (b) the truncate invariant for
    /// file-backed Agave-boot mmaps (truncate ⇒ child SIGBUS; unlink is fine).
    /// Design: vexor-designs/FORK-BGSAVE-SNAPSHOT-DESIGN-2026-07-01.md §3.
    gc_quiesce: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    accounts_shrink_enabled: bool,
    accounts_shrink_ratio_percent: u32,
    accounts_shrink_min_bytes: u64,
    accounts_shrink_hysteresis_percent: u32,
    accounts_shrink_last_slot: core.Slot,
    accounts_stats_enabled: bool,
    accounts_stats_interval_ms: u64,
    accounts_stats_last_ms: u64,
    accounts_purge_enabled: bool,
    accounts_purge_age_slots: u64,
    accounts_clean_enabled: bool,
    accounts_clean_age_slots: u64,
    accounts_clean_last_slot: core.Slot,
    accounts_stats_top_n: usize,
    accounts_completed_max_slot: core.Slot,
    accounts_safe_lag_slots: u64,
    accounts_gc_slots: std.ArrayListUnmanaged(core.Slot),
    accounts_gc_cursor: usize,
    accounts_gc_batch: usize,
    accounts_gc_scan_interval_ms: u64,
    accounts_gc_last_scan_ms: u64,
    accounts_store_capacity_bytes: u64,
    /// Task #71: slots the root must advance past a store's retirement before
    /// reapRetired frees it. Covers reader TOCTOU + borrowed-AccountView
    /// lifetimes (~1 slot in practice; 512 is overkill-safe ≈ 3.5 min).
    accounts_store_quarantine_slots: u64,
    /// Cache of recently accessed accounts
    cache: AccountCache,
    /// Current slot being processed
    slot: std.atomic.Value(u64),
    /// Bulk loading mode - skips AppendVec storage, stores only in index
    /// Used during snapshot loading to avoid creating thousands of mmap'd files
    bulk_loading_mode: bool,
    /// Bulk loading buffer - heap allocated storage for accounts during bulk load
    bulk_buffer: ?*BulkLoadBuffer,
    /// L1 RAM cache — accounts promoted from Bank.pending_writes during freeze().
    /// Protected by RwLock: getAccount() takes shared, promoteToUnflushedCache() takes exclusive.
    unflushed_cache: std.AutoHashMap(core.Pubkey, Account),
    unflushed_cache_lock: std.Thread.Mutex,
    /// Slot when each cache entry was last written (for rooting eviction).
    cache_slot_map: std.AutoHashMap(core.Pubkey, u64),
    /// FIX#95 regress-detector state (VEX_REGRESS_DETECT=1).
    dbg_regress_map: std.AutoHashMap(core.Pubkey, DbgRegressEntry),
    dbg_regress_gate: bool,
    dbg_regress_mutex: std.Thread.Mutex,
    /// Per-slot overlay of writes from unrooted slots, enabling ancestor-filtered
    /// reads (iter-6 fork-isolation defense). Each slot maps to a Pubkey→Account.
    /// Slots leave this map via `advanceRoot` (≤ root) or `purgeUnrootedSlot`
    /// (dead/orphan). Enabled by `fork_isolation_enabled`; when disabled, all
    /// hooks are no-ops and behavior is identical to Phase A baseline.
    unrooted_overlay: std.AutoHashMap(u64, *SlotOverlay),
    unrooted_overlay_lock: std.Thread.Mutex,
    /// Runtime gate for the fork-isolation overlay. Set at init() from env var
    /// `VEX_FORK_ISOLATION=1`. Default false (Phase A behavior).
    fork_isolation_enabled: bool,
    /// PR-S2 (2026-05-15) — Sig-pattern per-slot account overlay. This is the
    /// successor to `unrooted_overlay`: ancestor-required reads enforce fork
    /// isolation at the API level (no caller can bypass by forgetting ancestors).
    /// Unconditionally active. Phase 1 — additive: the legacy `unrooted_overlay`
    /// remains live until Phase 4 rip; this field carries no traffic yet.
    sig_overlay: sig_overlay_mod,
    /// 2026-05-18 (post-Phase-1G failures): fork-aware per-slot account
    /// cache. Replaces the role that `unflushed_cache` + `cache_slot_map`
    /// previously played as the L1 cache for unrooted writes, but in a
    /// slot-keyed shape that makes the iter-6 carrier structurally
    /// impossible. Six read-time-filter attempts on the flat unflushed_cache
    /// (Phase 1C/1D/1E/1F-v1/1F-v2/1G) regressed parity catastrophically;
    /// the fix is to change the storage shape, not bolt filters on top.
    /// Consulted FIRST by getAccountInSlot after sig_overlay miss. Writes
    /// happen in parallel with unflushed_cache writes (additive — the legacy
    /// path stays live until the ring is empirically validated). See
    /// `src/vex_store/unrooted_ring.zig` for the data structure and
    /// `project_sig_unrooted_port_the_answer_2026_05_18.md` for the
    /// derivation.
    unrooted_ring: @import("unrooted_ring.zig"),
    /// Dedicated arena for L1 cache allocations — backed by page_allocator,
    /// completely isolated from the potentially corrupted AccountsDb allocator.
    cache_arena: std.heap.ArenaAllocator,
    /// Current root slot — accounts written before this can be evicted from cache.
    rooted_slot: u64,

    /// FIX #105 (Option A): durable slot→parent map for root-advance ancestry.
    /// Unlike the live bank tree (ReplayStage.banks, which is PRUNED during
    /// heavy catch-up), this RETAINS every unrooted slot's parent link so
    /// `partitionRootAdvance`'s walk never breaks on a missing bank — the root
    /// cause of the slot-564 incomplete-promote-chain carrier (a multi-slot
    /// root JUMP whose ancestor chain excluded the carrier's rooted writes,
    /// which were then raw-range-purged → read fell through to a stale value).
    /// Populated by `recordSlotParent` (from replay_stage bank-insert), snapshot
    /// by `computeRootPartition`, pruned ≤ root by `advanceRoot`. Keyed by slot.
    slot_parents: std.AutoHashMap(u64, u64),
    slot_parents_lock: std.Thread.RwLock,

    /// Top-votes cache: vote_pubkey → (last_vote_slot, last_vote_timestamp)
    ///
    /// Mirrors Firedancer's fd_top_votes_t. Updated in promoteToUnflushedCache()
    /// whenever a vote account is committed, so updateClockSysvar() can read
    /// validator timestamps in O(1) without deserialising every vote account.
    top_votes: std.AutoHashMap([32]u8, TopVote),
    top_votes_lock: std.Thread.Mutex,

    /// TOPVOTES-DIAG (2026-06-04 consolidation): cumulative counters bumped by the
    /// single canonical chokepoint refreshTopVoteForWrite(). replay_stage's
    /// TopVotesDiag.roll() snapshots these per-slot to confirm upsert_ok stays
    /// ~1050 at the tip after the consolidation. Replay worker is the sole writer
    /// (every db landing runs on it), so plain counters are race-free.
    tv_upsert_ok: u64 = 0,
    tv_remove_ok: u64 = 0,
    tv_deser_fail: u64 = 0,
    tv_readback_stale: u64 = 0,

    /// Snapshot-epoch vote_account → stake lookup. Populated from the
    /// snapshot manifest by bootstrap; consumed per-slot by Bank's
    /// stake-weighted Clock estimator (SIMD-0001). Slice is owned by this
    /// struct and freed in deinit. Empty default = fallback to wall-clock.
    vote_account_stakes: []const @import("snapshot_manifest.zig").VoteAccountStake = &[_]@import("snapshot_manifest.zig").VoteAccountStake{},
    /// carrier #16: parallel FROZEN vote account data from the serialized stakes
    /// cache (same indexing as vote_account_stakes). Canonical source for epoch-
    /// boundary points vote windows. Per-entry slices + outer slice are owned;
    /// freed in deinit.
    vote_frozen_data: []const []const u8 = &.{},

    /// d16 (2026-05-10): per-epoch frozen vote-account stake tables (Agave's
    /// `epoch_stakes` blob). Indexed by epoch in `computeStakeWeightedClockEstimate`
    /// to mirror Agave's `Bank::epoch_vote_accounts(epoch)` source. Each entry
    /// is owned by this struct; both the outer slice and each entry's
    /// `vote_account_stakes` slice are freed in deinit.
    epoch_stakes: []const @import("snapshot_manifest.zig").EpochStakesEntry = &[_]@import("snapshot_manifest.zig").EpochStakesEntry{},

    /// F1 (HARD-FORK-FAMILY-DESIGN-2026-06-17): the snapshot bank's `hard_forks`
    /// list (Agave `solana_hard_forks::HardForks`), loaded once at bootstrap and
    /// NEVER mutated during replay. Rides on AccountsDb — the same "cluster-wide
    /// immutable snapshot state" idiom as `epoch_stakes`/`vote_account_stakes`
    /// (Bank reads it via `self.accounts_db.?.hard_forks`) — rather than a
    /// per-Bank field cloned parent→child, because Vexor's Bank.init/reset take
    /// no parent-Bank ref and a single shared immutable list is byte-identical
    /// to Agave's per-bank `parent.hard_forks.clone()`. (A future
    /// `register_hard_fork` for block production would write here.) Drives F2
    /// (bank-hash mixin) + F3 (LastRestartSlot). Owned by this struct; freed in
    /// deinit. DORMANT on post-restart testnet (no fork in (parent, slot]).
    hard_forks: []const @import("snapshot_manifest.zig").HardFork = &[_]@import("snapshot_manifest.zig").HardFork{},

    /// First-slot-of-epoch (slot, unix_ts) anchor used by stake-weighted
    /// clock estimation to bound drift vs PoH projection. Null = skip
    /// drift-bound clamp (bootstrap, pre-first-epoch-boundary).
    clock_epoch_anchor: ?ClockEpochAnchor = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, path: []const u8, async_io_manager: ?*anyopaque) !*Self {
        _ = async_io_manager;
        const db = try allocator.create(Self);
        // Task #71 (2026-06-10): shrink defaults ON. Canonical: Agave runs
        // clean/shrink unconditionally in AccountsBackgroundService; the
        // dormant-by-default gate is what let rooted 64MB AppendVec stores
        // accumulate at 28-30 GB/h. VEXOR_ACCOUNTS_SHRINK_ENABLE=0 remains an
        // emergency off-switch. Purge-by-age stays OFF (unsafe with shared
        // stores: it frees whole stores other slots still reference).
        var accounts_shrink_enabled = true;
        var accounts_shrink_ratio_percent: u32 = 50;
        var accounts_shrink_min_bytes: u64 = 8 * 1024 * 1024;
        var accounts_shrink_hysteresis_percent: u32 = 5;
        var accounts_stats_enabled = false;
        var accounts_stats_interval_ms: u64 = 10_000;
        var accounts_purge_enabled = false;
        var accounts_purge_age_slots: u64 = 1024;
        var accounts_clean_enabled = false;
        var accounts_clean_age_slots: u64 = 64;
        var accounts_stats_top_n: usize = 3;
        var accounts_index_bin_capacity: usize = 0;
        var accounts_safe_lag_slots: u64 = 32;
        var accounts_gc_batch: usize = 2;
        var accounts_gc_scan_interval_ms: u64 = 30_000;
        var accounts_store_capacity_bytes: u64 = 64 * 1024 * 1024;
        var accounts_store_quarantine_slots: u64 = 512;
        // VexStore shadow backend ripped 2026-05-15 — AccountsDb is the
        // single storage source of truth now.
        {
            const shrink_enabled = std.process.getEnvVarOwned(allocator, "VEXOR_ACCOUNTS_SHRINK_ENABLE") catch null;
            if (shrink_enabled) |value| {
                defer allocator.free(value);
                accounts_shrink_enabled = std.mem.eql(u8, value, "1");
            }
            accounts_shrink_ratio_percent = @intCast(parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_SHRINK_RATIO",
                accounts_shrink_ratio_percent,
            ) catch accounts_shrink_ratio_percent);
            accounts_shrink_min_bytes = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_SHRINK_MIN_BYTES",
                accounts_shrink_min_bytes,
            ) catch accounts_shrink_min_bytes;
            accounts_shrink_hysteresis_percent = @intCast(parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_SHRINK_HYSTERESIS",
                accounts_shrink_hysteresis_percent,
            ) catch accounts_shrink_hysteresis_percent);
            accounts_store_quarantine_slots = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_STORE_QUARANTINE",
                accounts_store_quarantine_slots,
            ) catch accounts_store_quarantine_slots;
        }
        {
            const stats_enabled = std.process.getEnvVarOwned(allocator, "VEXOR_ACCOUNTS_STATS_ENABLE") catch null;
            if (stats_enabled) |value| {
                defer allocator.free(value);
                accounts_stats_enabled = std.mem.eql(u8, value, "1");
            }
            accounts_stats_interval_ms = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_STATS_INTERVAL_MS",
                accounts_stats_interval_ms,
            ) catch accounts_stats_interval_ms;
            accounts_stats_top_n = @intCast(parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_STATS_TOP_N",
                accounts_stats_top_n,
            ) catch accounts_stats_top_n);
        }
        {
            const purge_enabled = std.process.getEnvVarOwned(allocator, "VEXOR_ACCOUNTS_PURGE_ENABLE") catch null;
            if (purge_enabled) |value| {
                defer allocator.free(value);
                accounts_purge_enabled = std.mem.eql(u8, value, "1");
            }
            accounts_purge_age_slots = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_PURGE_AGE_SLOTS",
                accounts_purge_age_slots,
            ) catch accounts_purge_age_slots;
        }
        {
            const clean_enabled = std.process.getEnvVarOwned(allocator, "VEXOR_ACCOUNTS_CLEAN_ENABLE") catch null;
            if (clean_enabled) |value| {
                defer allocator.free(value);
                accounts_clean_enabled = std.mem.eql(u8, value, "1");
            }
            accounts_clean_age_slots = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_CLEAN_AGE_SLOTS",
                accounts_clean_age_slots,
            ) catch accounts_clean_age_slots;
        }
        accounts_index_bin_capacity = @intCast(parseEnvU64(
            allocator,
            "VEXOR_ACCOUNTS_INDEX_BIN_CAPACITY",
            accounts_index_bin_capacity,
        ) catch accounts_index_bin_capacity);
        accounts_safe_lag_slots = parseEnvU64(
            allocator,
            "VEXOR_ACCOUNTS_SAFE_LAG_SLOTS",
            accounts_safe_lag_slots,
        ) catch accounts_safe_lag_slots;
        accounts_gc_batch = @intCast(parseEnvU64(
            allocator,
            "VEXOR_ACCOUNTS_GC_BATCH",
            accounts_gc_batch,
        ) catch accounts_gc_batch);
        accounts_gc_scan_interval_ms = parseEnvU64(
            allocator,
            "VEXOR_ACCOUNTS_GC_SCAN_INTERVAL_MS",
            accounts_gc_scan_interval_ms,
        ) catch accounts_gc_scan_interval_ms;
        {
            const mb = parseEnvU64(
                allocator,
                "VEXOR_ACCOUNTS_STORE_CAPACITY_MB",
                accounts_store_capacity_bytes / (1024 * 1024),
            ) catch accounts_store_capacity_bytes / (1024 * 1024);
            accounts_store_capacity_bytes = @max(@as(u64, 1), mb) * 1024 * 1024;
        }
        const accounts_path_copy = try allocator.dupe(u8, path);
        db.* = .{
            .allocator = allocator,
            .metadata_lock = .{},
            .accounts_path = accounts_path_copy,
            .index = AccountIndex.initWithCapacity(allocator, accounts_index_bin_capacity),
            .storage = try AccountStorage.init(allocator, path, accounts_store_capacity_bytes),
            .cache = AccountCache.init(allocator),
            .slot = std.atomic.Value(u64).init(0),
            .accounts_shrink_enabled = accounts_shrink_enabled,
            .accounts_shrink_ratio_percent = accounts_shrink_ratio_percent,
            .accounts_shrink_min_bytes = accounts_shrink_min_bytes,
            .accounts_shrink_hysteresis_percent = accounts_shrink_hysteresis_percent,
            .accounts_shrink_last_slot = 0,
            .accounts_stats_enabled = accounts_stats_enabled,
            .accounts_stats_interval_ms = accounts_stats_interval_ms,
            .accounts_stats_last_ms = 0,
            .accounts_purge_enabled = accounts_purge_enabled,
            .accounts_purge_age_slots = accounts_purge_age_slots,
            .accounts_clean_enabled = accounts_clean_enabled,
            .accounts_clean_age_slots = accounts_clean_age_slots,
            .accounts_clean_last_slot = 0,
            .accounts_stats_top_n = accounts_stats_top_n,
            .accounts_completed_max_slot = 0,
            .accounts_safe_lag_slots = accounts_safe_lag_slots,
            .accounts_gc_slots = std.ArrayListUnmanaged(core.Slot){},
            .accounts_gc_cursor = 0,
            .accounts_gc_batch = accounts_gc_batch,
            .accounts_gc_scan_interval_ms = accounts_gc_scan_interval_ms,
            .accounts_gc_last_scan_ms = 0,
            .accounts_store_capacity_bytes = accounts_store_capacity_bytes,
            .accounts_store_quarantine_slots = accounts_store_quarantine_slots,
            .bulk_loading_mode = false,
            .bulk_buffer = null,
            .cache_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
            .unflushed_cache = undefined, // initialized below
            .unflushed_cache_lock = .{},
            .cache_slot_map = std.AutoHashMap(core.Pubkey, u64).init(std.heap.page_allocator),
            .dbg_regress_map = std.AutoHashMap(core.Pubkey, DbgRegressEntry).init(std.heap.page_allocator),
            .dbg_regress_gate = (std.posix.getenv("VEX_REGRESS_DETECT") != null),
            .dbg_regress_mutex = .{},
            .unrooted_overlay = std.AutoHashMap(u64, *SlotOverlay).init(std.heap.page_allocator),
            .unrooted_overlay_lock = .{},
            .fork_isolation_enabled = blk: {
                const env = std.posix.getenv("VEX_FORK_ISOLATION") orelse break :blk false;
                break :blk std.mem.eql(u8, env, "1");
            },
            .rooted_slot = 0,
            // FIX #105: page_allocator-backed (matches cache_slot_map) so it
            // is independent of the db arena lifecycle.
            .slot_parents = std.AutoHashMap(u64, u64).init(std.heap.page_allocator),
            .slot_parents_lock = .{},
            .top_votes = std.AutoHashMap([32]u8, TopVote).init(allocator),
            .top_votes_lock = .{},
            .sig_overlay = try sig_overlay_mod.init(allocator),
            // 2026-05-18: fork-aware ring (4096 buckets, ~256B each) consulted
            // before `_getRooted` fall-through. Same allocator as the
            // `unflushed_cache` so both layers' data is freed by the same
            // page_allocator lifecycle.
            .unrooted_ring = try @import("unrooted_ring.zig").init(std.heap.page_allocator),
        };
        // Initialize unflushed_cache with page_allocator (NOT arena — arena leaks on resize).
        // Account data within the cache is also page_allocator-managed with explicit free on overwrite.
        db.unflushed_cache = std.AutoHashMap(core.Pubkey, Account).init(std.heap.page_allocator);

        return db;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.accounts_path);
        self.cache.deinit();
        self.accounts_gc_slots.deinit(self.allocator);
        self.top_votes.deinit();
        if (self.vote_frozen_data.len > 0) {
            for (self.vote_frozen_data) |fd| if (fd.len > 0) self.allocator.free(fd);
            self.allocator.free(self.vote_frozen_data);
            self.vote_frozen_data = &.{};
        }
        if (self.vote_account_stakes.len > 0) {
            self.allocator.free(self.vote_account_stakes);
            self.vote_account_stakes = &[_]@import("snapshot_manifest.zig").VoteAccountStake{};
        }
        if (self.epoch_stakes.len > 0) {
            for (self.epoch_stakes) |entry| {
                if (entry.vote_account_stakes.len > 0) {
                    self.allocator.free(entry.vote_account_stakes);
                }
            }
            self.allocator.free(self.epoch_stakes);
            self.epoch_stakes = &[_]@import("snapshot_manifest.zig").EpochStakesEntry{};
        }
        // F1: free the hard-fork list (allocator-owned, transferred from loader).
        if (self.hard_forks.len > 0) {
            self.allocator.free(@constCast(self.hard_forks));
            self.hard_forks = &[_]@import("snapshot_manifest.zig").HardFork{};
        }
        self.sig_overlay.deinit(self.allocator);
        self.slot_parents.deinit(); // FIX #105
        self.unrooted_ring.deinit();
        self.storage.deinit();
        self.index.deinit();
        self.allocator.destroy(self);
    }

    /// PR-S4 (2026-05-15 Phase 2c-A): the ancestorless facade. Every call
    /// site is a potential fork-isolation leak (orphan-slot writes can flow
    /// through this path to a canonical reader). Production tx-replay MUST
    /// use `getAccountInSlot(pubkey, slot, ancestors)` instead. Bootstrap /
    /// snapshot / RPC paths that legitimately have no ancestor context
    /// should call `_getRooted(pubkey)` directly to make the intent explicit.
    ///
    /// In `VEX_STRICT_FORK_ISO=1` mode this panics so any remaining caller
    /// is forced to the surface. Otherwise it logs a warn (rate-limited)
    /// and delegates to `_getRooted`. Default is warn-only in ReleaseSafe
    /// so a missed site doesn't crash production.
    pub fn getAccount(self: *Self, pubkey: *const core.Pubkey) ?AccountView {
        const StrictGate = struct {
            var checked: bool = false;
            var strict: bool = false;
            var warn_count: u32 = 0;
        };
        if (!StrictGate.checked) {
            StrictGate.checked = true;
            const v = std.process.getEnvVarOwned(std.heap.page_allocator, "VEX_STRICT_FORK_ISO") catch null;
            if (v) |s| {
                StrictGate.strict = std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "true");
                std.heap.page_allocator.free(s);
            }
        }
        if (StrictGate.strict) {
            @panic("[PR-S4] AccountsDb.getAccount(pubkey) called with VEX_STRICT_FORK_ISO=1 — use getAccountInSlot");
        }
        if (StrictGate.warn_count < 32) {
            StrictGate.warn_count += 1;
            std.log.warn("[PR-S4] unfiltered AccountsDb.getAccount(pubkey) call — use getAccountInSlot (count={d})", .{StrictGate.warn_count});
        }
        return self._getRooted(pubkey);
    }

    /// Scan all accounts owned by a specific program.
    /// Used at epoch boundaries to find all vote/stake accounts for reward calculation.
    /// Returns allocated array of (pubkey, account) pairs — caller owns the slice.
    ///
    /// Performance: O(N) over unflushed_cache + index. On 86M accounts this takes
    /// ~1-2 seconds, which is acceptable at epoch boundaries (every ~2 days on mainnet).
    /// Future optimization: maintain a per-owner cache updated incrementally.
    /// Enumerate all accounts owned by `owner`, as visible to the bank at
    /// `self_slot` with unrooted ancestor chain `ancestors`. Used by
    /// `processEpochBoundary` to build the vote/stake set for inflation rewards.
    ///
    /// two_tier (canonical): read fork-aware over the ring (unrooted) + index
    /// (rooted) ONLY — no fork-blind unflushed_cache/sig_overlay. The boundary
    /// slot is typically NOT yet rooted (rooting lags ~tower depth), so its
    /// stake/vote writes live in the ring; reading rooted-index-only would
    /// return stale boundary state. Enumerate candidate pubkeys with the target
    /// owner from BOTH tiers along THIS fork, then re-read each fork-aware
    /// AS-OF self_slot so the value (and current owner — owner can change) is
    /// the newest ancestor-visible version. Auto-degrades to index-only when the
    /// boundary is already rooted (ring ancestor buckets empty). Called once per
    /// epoch boundary; the O(index) scan matches the legacy Phase-2 cost.
    pub fn scanByOwner(
        self: *Self,
        owner: *const core.Pubkey,
        ancestors: []const u64,
        self_slot: u64,
        alloc: std.mem.Allocator,
    ) ![]OwnerScanResult {
        var results = std.ArrayListUnmanaged(OwnerScanResult){};
        errdefer results.deinit(alloc);

        if (!build_options.two_tier) {
            // ── Legacy A/B fallback: fork-blind unflushed_cache + index ──
            var seen = std.AutoHashMap(core.Pubkey, void).init(alloc);
            defer seen.deinit();
            {
                self.unflushed_cache_lock.lock();
                defer self.unflushed_cache_lock.unlock();
                var cache_iter = self.unflushed_cache.iterator();
                while (cache_iter.next()) |entry| {
                    if (std.mem.eql(u8, &entry.value_ptr.owner.data, &owner.data)) {
                        try results.append(alloc, .{
                            .pubkey = entry.key_ptr.*,
                            .lamports = entry.value_ptr.lamports,
                            .data = entry.value_ptr.data,
                            .executable = entry.value_ptr.executable,
                            .rent_epoch = entry.value_ptr.rent_epoch,
                        });
                        try seen.put(entry.key_ptr.*, {});
                    }
                }
            }
            for (self.index.bins) |*bin| {
                bin.lock.lockShared();
                defer bin.lock.unlockShared();
                var bin_iter = bin.entries.iterator();
                while (bin_iter.next()) |entry| {
                    if (seen.contains(entry.key_ptr.*)) continue;
                    if (self.storage.readAccount(entry.value_ptr.*)) |acct| {
                        if (std.mem.eql(u8, &acct.owner.data, &owner.data)) {
                            try results.append(alloc, .{
                                .pubkey = entry.key_ptr.*,
                                .lamports = acct.lamports,
                                .data = acct.data,
                                .executable = acct.executable,
                                .rent_epoch = acct.rent_epoch,
                            });
                        }
                    }
                }
            }
            return results.toOwnedSlice(alloc);
        }

        // ── two_tier: fork-aware over ring (unrooted) + index (rooted) ──
        var candidates = std.AutoHashMap(core.Pubkey, void).init(alloc);
        defer candidates.deinit();

        // Phase A: unrooted candidates from this fork's self + ancestor slots.
        const CollectCtx = struct {
            owner: [32]u8,
            set: *std.AutoHashMap(core.Pubkey, void),
            fn visit(ctx: *@This(), slot: u64, pk: core.Pubkey, acct: Account) void {
                _ = slot; // owner-scan is slot-agnostic; ancestor membership already gated by caller
                if (std.mem.eql(u8, &acct.owner.data, &ctx.owner))
                    ctx.set.put(pk, {}) catch {};
            }
        };
        var cctx = CollectCtx{ .owner = owner.data, .set = &candidates };
        self.unrooted_ring.forEachInSlot(self_slot, &cctx, CollectCtx.visit);
        for (ancestors) |s| self.unrooted_ring.forEachInSlot(s, &cctx, CollectCtx.visit);

        // Phase B: rooted candidates from the index (owner via storage read).
        for (self.index.bins) |*bin| {
            bin.lock.lockShared();
            defer bin.lock.unlockShared();
            var bin_iter = bin.entries.iterator();
            while (bin_iter.next()) |entry| {
                if (candidates.contains(entry.key_ptr.*)) continue;
                // Perf (#4a): owner-only read — skips lamports/data slicing and
                // the heap-store pubkey copy vs building a full AccountView.
                if (self.storage.readOwner(entry.value_ptr.*)) |owner_ptr| {
                    if (std.mem.eql(u8, owner_ptr, &owner.data))
                        candidates.put(entry.key_ptr.*, {}) catch {};
                }
            }
        }

        // Phase C: fork-aware read each candidate AS-OF self_slot; include only
        // if its newest ancestor-visible value still has the target owner.
        var cit = candidates.keyIterator();
        while (cit.next()) |pk| {
            const maybe_view: ?AccountView =
                if (self.unrooted_ring.getWithModifiedSlotPlusSelf(pk.*, ancestors, self_slot)) |hit|
                    hit.view
                else
                    self.getRooted(pk);
            const view = maybe_view orelse continue;
            if (!std.mem.eql(u8, &view.owner.data, &owner.data)) continue;
            try results.append(alloc, .{
                .pubkey = pk.*,
                .lamports = view.lamports,
                .data = view.data,
                .executable = view.executable,
                .rent_epoch = view.rent_epoch,
            });
        }

        return results.toOwnedSlice(alloc);
    }

    pub const OwnerScanResult = struct {
        pubkey: core.Pubkey,
        lamports: u64,
        data: []const u8,
        executable: bool,
        rent_epoch: u64,
    };

    /// Promote pending_writes from a frozen Bank into the shared L1 RAM cache.
    /// Deep-copies account data so the cache owns the memory independently of the Bank.
    /// Thread-safe: acquires exclusive write lock on unflushed_cache.
    /// Also updates top_votes cache for any vote accounts — mirrors Firedancer's
    /// fd_top_votes_update() which is called from fd_runtime_save_account().
    pub fn promoteToUnflushedCache(self: *Self, pending_writes: []const AccountWrite, slot: u64) !void {
        // Fork-isolation: mirror writes into per-slot overlay BEFORE the flat-cache
        // write loop. This way orphan slots' writes live in their own bucket and
        // get purged by `purgeUnrootedSlot` when the slot is marked dead, rather
        // than permanently polluting the flat cache for the canonical fork.
        // Gated by VEX_FORK_ISOLATION=1 — when disabled, behavior is Phase A.
        if (self.fork_isolation_enabled) {
            self.unrooted_overlay_lock.lock();
            defer self.unrooted_overlay_lock.unlock();

            const gop = try self.unrooted_overlay.getOrPut(slot);
            if (!gop.found_existing) {
                const overlay_ptr = try std.heap.page_allocator.create(SlotOverlay);
                overlay_ptr.* = SlotOverlay.init(std.heap.page_allocator);
                gop.value_ptr.* = overlay_ptr;
            }
            const overlay = gop.value_ptr.*;

            for (pending_writes) |*write| {
                const owned_data = if (write.account.data.len > 0) blk: {
                    const copy = std.heap.page_allocator.alloc(u8, write.account.data.len) catch break :blk &[_]u8{};
                    @memcpy(copy, write.account.data);
                    break :blk copy;
                } else &[_]u8{};

                // Free prior overlay entry's data for the same (slot, pubkey) — same
                // slot can produce multiple writes for the same payer across multi-tx.
                if (overlay.get(write.pubkey)) |old| {
                    if (old.data.len > 0) std.heap.page_allocator.free(@constCast(old.data));
                }

                overlay.put(write.pubkey, .{
                    .lamports = write.account.lamports,
                    .owner = write.account.owner,
                    .executable = write.account.executable,
                    .rent_epoch = write.account.rent_epoch,
                    .data = owned_data,
                }) catch {};

                // PR-S2 Phase 2b (2026-05-15): also mirror into sig_overlay so
                // post-PR-S2-Phase-2a readers (which now use getAccountInSlot)
                // see the same per-slot overlay data as the legacy
                // getAccountInAncestors path. Without this, Phase 2a regresses
                // PR-A.1's ancestor-isolation benefit. sig_overlay.put clones
                // data internally with self.allocator.
                self.sig_overlay.put(self.allocator, slot, write.pubkey, .{
                    .lamports = write.account.lamports,
                    .owner = write.account.owner,
                    .executable = write.account.executable,
                    .rent_epoch = write.account.rent_epoch,
                    .data = if (write.account.data.len > 0) blk: {
                        const copy = self.allocator.alloc(u8, write.account.data.len) catch break :blk &[_]u8{};
                        @memcpy(copy, write.account.data);
                        break :blk copy;
                    } else &[_]u8{},
                }) catch {};

                // 2026-05-18: mirror into the fork-aware UnrootedRing too.
                // The ring is the post-Phase-1G-failure read-side fork-iso
                // primitive: storage keyed by slot makes wrong-fork reads
                // structurally impossible without a per-read filter. Dupe
                // data with page_allocator so it matches the ring's deinit
                // free path. Failure to put is logged-silent — the legacy
                // unflushed_cache path below still captures the write, so
                // the ring is best-effort additive for this iteration.
                const ring_data: []const u8 = if (write.account.data.len > 0) blk: {
                    const copy = std.heap.page_allocator.alloc(u8, write.account.data.len) catch break :blk &[_]u8{};
                    @memcpy(copy, write.account.data);
                    break :blk copy;
                } else &[_]u8{};
                self.unrooted_ring.put(slot, write.pubkey, .{
                    .lamports = write.account.lamports,
                    .owner = write.account.owner,
                    .executable = write.account.executable,
                    .rent_epoch = write.account.rent_epoch,
                    .data = ring_data,
                }) catch {
                    // ring took ownership only on success — free the dup on failure
                    if (ring_data.len > 0) std.heap.page_allocator.free(@constCast(ring_data));
                };
            }
        }

        // Phase B recorder pre-state capture: snapshot cache_slot_map BEFORE
        // we mutate it, so the emitted prev_csm represents the slot that owned
        // this pk in unflushed_cache PRIOR to this write. Cheap when recorder off.
        const rec_writes_on = recorder.isWriteEnabled();

        self.unflushed_cache_lock.lock();
        defer self.unflushed_cache_lock.unlock();

        for (pending_writes) |*write| {
            // Phase B recorder: capture pre-state BEFORE the put-and-free below
            // overwrites unflushed_cache[pk] and cache_slot_map[pk].
            const prev_csm: ?u64 = if (rec_writes_on) self.cache_slot_map.get(write.pubkey) else null;
            const prev_unflushed = if (rec_writes_on) self.unflushed_cache.get(write.pubkey) else null;
            const prev_lam: ?u64 = if (prev_unflushed) |a| a.lamports else null;
            const prev_data: ?[]const u8 = if (prev_unflushed) |a| a.data else null;

            // Deep copy account data using page_allocator (supports individual frees)
            const owned_data = if (write.account.data.len > 0) blk: {
                const copy = try std.heap.page_allocator.alloc(u8, write.account.data.len);
                @memcpy(copy, write.account.data);
                break :blk copy;
            } else &[_]u8{};

            // Emit BEFORE the free so prev_data slice is still valid for sha8.
            if (rec_writes_on) {
                recorder.emitWrite(
                    &write.pubkey.data,
                    &write.account.owner.data,
                    write.account.lamports,
                    write.account.data,
                    prev_csm,
                    prev_lam,
                    prev_data,
                );
            }

            // Free old data on overwrite to prevent unbounded memory growth.
            // Vote accounts update every slot (~600/slot), so this is critical.
            // Only free if the data was heap-allocated by us (not mmap'd from snapshot).
            // Detect heap allocation: data pointer is NOT within any mmap'd AppendVec range.
            // Simple heuristic: data.len > 0 means it was previously deep-copied by us
            // (mmap'd data is returned directly by getAccount, but promoteToUnflushedCache
            //  always deep-copies — so any existing cache entry was previously heap-allocated).
            if (self.unflushed_cache.get(write.pubkey)) |old_acct| {
                if (old_acct.data.len > 0) {
                    std.heap.page_allocator.free(@constCast(old_acct.data));
                }
            }

            try self.unflushed_cache.put(write.pubkey, .{
                .lamports = write.account.lamports,
                .owner = write.account.owner,
                .executable = write.account.executable,
                .rent_epoch = write.account.rent_epoch,
                .data = owned_data,
            });
            self.cache_slot_map.put(write.pubkey, slot) catch {};

            // FIX#95 regress-detector: record the latest committed write
            // (monotonic by slot) so a later rooted read can be checked for
            // staleness. Own mutex (read-check runs outside unflushed_cache_lock).
            if (self.dbg_regress_gate) {
                const w_sha8 = dbgDataSha8(write.account.data);
                const w_dlen: u32 = @intCast(write.account.data.len);
                self.dbg_regress_mutex.lock();
                if (self.dbg_regress_map.getOrPut(write.pubkey)) |gg| {
                    if (!gg.found_existing or slot >= gg.value_ptr.slot)
                        gg.value_ptr.* = .{ .slot = slot, .lamports = write.account.lamports, .data_sha8 = w_sha8, .dlen = w_dlen };
                } else |_| {}
                self.dbg_regress_mutex.unlock();
            }

            // Update top_votes cache if this is a vote account.
            // VoteState binary layout (v2/Current, discriminant=2):
            //   After variable-length fields, last_timestamp is the final 16 bytes:
            //   [u64 slot][i64 timestamp]
            // We use vote_state_serde to parse it properly.
            // Firedancer reference: fd_top_votes_update() in fd_runtime_save_account()
            // d16 v3 (2026-05-10): mirror Agave's `Stakes::vote_accounts` —
            // ALWAYS write current state, never leave stale entries. Three
            // cases:
            //   - Vote-account write with valid last_timestamp → put
            //   - Vote-account write with timestamp=0 → put (runtime filter
            //     drops it; matches Agave reading 0 from live state)
            //   - Vote-account zero-lamports (closed) → remove (matches
            //     Agave's StakesCache::check_and_store removal path)
            //   - Vote-account write that fails deserialize → remove (corrupted)
            if (std.mem.eql(u8, &write.account.owner.data, &@import("vex_svm").native.program_ids.vote)) {
                if (write.account.lamports == 0) {
                    self.top_votes_lock.lock();
                    defer self.top_votes_lock.unlock();
                    _ = self.top_votes.remove(write.pubkey.data);
                } else if (write.account.data.len >= 16) {
                    const serde = @import("vex_svm").native.vote;
                    if (serde.deserializeVoteState(write.account.data)) |vs| {
                        // d16 v3: removed `if (timestamp != 0)` filter — always
                        // write so cache mirrors live state.
                        {
                            self.top_votes_lock.lock();
                            defer self.top_votes_lock.unlock();
                            // Fork-aware multi-version upsert (write_slot = the
                            // bank slot producing this write). Preserves d16-v3
                            // always-write; the SIMD-0001 harvest selects the
                            // in-lineage version so siblings can't pollute it.
                            if (self.top_votes.getOrPut(write.pubkey.data)) |gop| {
                                if (!gop.found_existing) gop.value_ptr.* = .{};
                                gop.value_ptr.upsert(.{
                                    .write_slot = slot,
                                    .last_vote_slot = vs.last_timestamp.slot,
                                    .last_vote_timestamp = vs.last_timestamp.timestamp,
                                    // Fork-choice feed source (tower top, not the
                                    // timestamp slot). See TopVoteVersion field doc.
                                    .tower_last_voted_slot = vs.lastVotedSlot() orelse 0,
                                }, self.rooted_slot);
                            } else |_| {}
                        }
                    }
                }
            }
        }
    }

    /// CANONICAL SINGLE CHOKEPOINT for the fork-choice vote-weight feed
    /// (`top_votes`, the Firedancer `fd_top_votes_t` / Agave `StakesCache` analog).
    ///
    /// CONSOLIDATION (2026-06-04): the top_votes refresh used to be bolted onto 3
    /// scattered replay/flush sites in replay_stage (refreshTopVotes site1/2/3).
    /// At the catch-up→tip boundary the tip's actual vote-commit db landing
    /// (promoteRootedChain, root-advance re-promotion) was NONE of those sites →
    /// feed went stale → no self-vote → delinquent. This method is the SINGLE
    /// update point, called once at EVERY real db landing (flushPendingWritesToDb,
    /// flushPendingWritesFromIndex, promoteRootedChain) so no commit path can skip
    /// the refresh — the shape Agave gets from `StakesCache::check_and_store`.
    ///
    /// Encodes the full check_and_store contract (lifted byte-for-byte from the
    /// previously-dead promoteToUnflushedCache:1076-1107, which the scattered
    /// refreshTopVotes helper did NOT fully implement — it had no zero-lamports
    /// remove branch, leaving stale entries for closed/withdrawn vote accounts):
    ///   - owner != vote program          → no-op
    ///   - owner == vote & lamports == 0  → REMOVE (account closed/withdrawn)
    ///   - owner == vote & deser OK       → upsert (fork-aware, keyed by write_slot)
    ///   - owner == vote & deser fail     → fall through (no upsert; mirrors 1076-1107)
    ///
    /// Caller MUST already hold `unflushed_cache_lock` (all 3 db landings do);
    /// this acquires only `top_votes_lock` nested inside it — same lock order as
    /// every other nesting (unflushed_cache_lock → top_votes_lock), no inversion.
    pub fn refreshTopVoteForWrite(
        self: *Self,
        pubkey: [32]u8,
        owner: [32]u8,
        data: []const u8,
        lamports: u64,
        write_slot: u64,
    ) void {
        const native = @import("vex_svm").native;
        if (!std.mem.eql(u8, &owner, &native.vote_program.VOTE_PROGRAM_ID)) return;

        // Contract case 2: zero-lamport (closed) vote account → REMOVE.
        if (lamports == 0) {
            self.top_votes_lock.lock();
            defer self.top_votes_lock.unlock();
            if (self.top_votes.remove(pubkey)) self.tv_remove_ok += 1;
            return;
        }
        if (data.len < 16) return;

        // Contract case 4: vote account with deserializable state → upsert.
        // Fall through (no upsert) on deser failure — mirrors promoteToUnflushedCache.
        const vs = native.vote_state_serde.deserializeVoteState(data) orelse {
            self.tv_deser_fail += 1;
            return;
        };
        const tower = vs.lastVotedSlot() orelse 0;

        self.top_votes_lock.lock();
        defer self.top_votes_lock.unlock();
        if (self.top_votes.getOrPut(pubkey)) |gop| {
            if (!gop.found_existing) gop.value_ptr.* = .{};
            gop.value_ptr.upsert(.{
                .write_slot = write_slot,
                .last_vote_slot = vs.last_timestamp.slot,
                .last_vote_timestamp = vs.last_timestamp.timestamp,
                // Fork-choice feed source (tower top, not the timestamp slot).
                .tower_last_voted_slot = tower,
            }, self.rooted_slot);
            self.tv_upsert_ok += 1;
            // Read-back diagnostic: does THIS write become the value the feed serves?
            // With freshest-tower selection (latestVotedSlot = max tower), a mismatch
            // means the cache already holds a version with a HIGHER tower than the one
            // we just wrote — i.e. this landing was not the freshest vote for the voter.
            // BENIGN by itself (routinely ~half of upserts, e.g. the promoteRootedChain
            // re-promotions at the rooted slot, while the feed stays healthy): the feed
            // still serves the freshest tower. It is NOT a "wrote fresh, feed sees stale"
            // masking bug — the fork-choice wedge is INPUT STARVATION (the tip-flush
            // vote-write stream stalling), not this per-write ordering signal.
            const seen = gop.value_ptr.latestVotedSlot() orelse 0;
            if (seen != tower) self.tv_readback_stale += 1;
        } else |_| {}
    }

    /// Advance the root slot and evict stale cache entries.
    /// Called when the tower root advances. Accounts last written before
    /// the new root are safe in the mmap'd AppendVecs and can be freed.
    /// STEP 5 helper: promote ONE fork-aware ring entry into the rooted index.
    /// Filed under the account's TRUE write-slot `slot` (the ring bucket slot),
    /// canonical Sig `last_modified_slot` semantics — the index's higher-slot-wins
    /// guard (`AccountIndex.insert`, slot < existing → reject) then records reality.
    /// SOLE rooted-index writer under two_tier; a drop here = stale rooted value =
    /// lt divergence, so BOTH failure paths are loud + counted (RULE#0), never silent.
    fn promoteRingEntry(self: *Self, slot: u64, pubkey: core.Pubkey, account: Account) void {
        const dd: ?[]u8 = if (account.data.len > 0)
            (std.heap.page_allocator.dupe(u8, account.data) catch {
                lost_rooted_writes += 1;
                std.log.err("[LOST-ROOTED-WRITE] promoteRingEntry dupe OOM slot={d} pk={x}{x}{x}{x} lam={d} total_lost={d}", .{ slot, pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], account.lamports, lost_rooted_writes });
                return;
            })
        else
            null;
        const loc = self.storage.writeAccount(&pubkey, &Account{
            .lamports = account.lamports,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
            .data = if (dd) |d| d else &[_]u8{},
        }, slot) catch |err| {
            lost_rooted_writes += 1;
            std.log.err("[LOST-ROOTED-WRITE] promoteRingEntry writeAccount err={s} slot={d} pk={x}{x}{x}{x} lam={d} total_lost={d}", .{ @errorName(err), slot, pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], account.lamports, lost_rooted_writes });
            if (dd) |d| std.heap.page_allocator.free(d);
            return;
        };
        _ = self.index.insert(&pubkey, loc) catch |err| {
            lost_rooted_writes += 1;
            std.log.err("[LOST-ROOTED-WRITE] promoteRingEntry index.insert err={s} slot={d} pk={x}{x}{x}{x} lam={d} total_lost={d}", .{ @errorName(err), slot, pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], account.lamports, lost_rooted_writes });
        };
        if (dd) |d| std.heap.page_allocator.free(d);
    }

    pub fn advanceRoot(self: *Self, new_root: u64) void {
        if (new_root <= self.rooted_slot) return;
        const prev_root = self.rooted_slot; // capture before the bump below (STEP 5)
        // PROMOTE-DIAG (2026-05-28): record every root advance + its jump size.
        // A large jump after a catchup stall is the suspected trigger for the
        // slot-564 write-loss carrier (ROLLOVER). Logging-only.
        if (recorder.promoteDiagTick()) {
            std.log.warn("[PROMOTE-DIAG][ADVANCE] prev_root={d} new_root={d} jump={d}", .{ self.rooted_slot, new_root, new_root - self.rooted_slot });
        }
        self.rooted_slot = new_root;

        // Task #71 (2026-06-10): drive the GC safe-slot watermark from root
        // advance. Without this, accounts_completed_max_slot stays 0 →
        // safeSlot()==0 → every reclamation tick is a no-op (one of the three
        // dormancy causes of the 28-30 GB/h AppendVec store leak).
        self.onSlotCompleted(new_root);

        // Fork-aware top_votes: collapse rooted vote-version history on root
        // advance (mirror unrooted_ring's dropSlot-on-root). Keeps one baseline
        // version <= new_root plus any still-unrooted versions; bounds per-voter
        // version growth so the array never overflows in steady state.
        {
            self.top_votes_lock.lock();
            defer self.top_votes_lock.unlock();
            var tv_it = self.top_votes.iterator();
            while (tv_it.next()) |tv_e| {
                _ = tv_e.value_ptr.pruneBelowRoot(new_root);
            }
        }

        self.unflushed_cache_lock.lock();
        defer self.unflushed_cache_lock.unlock();

        var to_evict = std.ArrayListUnmanaged(core.Pubkey){};
        defer to_evict.deinit(std.heap.page_allocator);

        // Find accounts last written before root
        var slot_iter = self.cache_slot_map.iterator();
        while (slot_iter.next()) |entry| {
            if (entry.value_ptr.* < new_root) {
                to_evict.append(std.heap.page_allocator, entry.key_ptr.*) catch continue;
            }
        }

        // r74-vex-132-REAPPLY-WITH-DUPE (2026-05-06) — re-applies the
        // persist-before-evict logic from r71-fix-9 (4a352c7), this time
        // with `allocator.dupe(acct.data)` before passing to writeAccount.
        //
        // PRIOR REVERT (r72-carrier-hunt-2026-05-05): the original block
        // corrupted Vote111 index entries because `acct.data` was a slice
        // into snapshot mmap memory (READ-ONLY). writeAccount's re-encoding
        // mutated through that slice, silently producing corrupted appendvec
        // records. Subsequent getAccount(vote_pk) → readAccount(corrupted_loc)
        // → null → 0 Vote111 writes/slot → 100% bank_hash divergence.
        //
        // FIX: deep-copy `acct.data` via `std.heap.page_allocator.dupe(u8, acct.data)`
        // BEFORE passing to writeAccount. The dupe lives until writeAccount
        // returns; we free it inline after the index.insert. This guarantees
        // no mmap mutation regardless of `acct.data`'s provenance.
        //
        // PROBLEM ADDRESSED (per LOCKED memory `feedback_jito_anti_regression_LOCKED_2026_04_28.md`):
        // pre-fix this loop freed + removed cache entries WITHOUT flushing
        // them to AppendVec storage. Leader-class System wallets (data_len=0,
        // the slot leader's identity) frequently get cache-evicted between
        // fee-credit slots; the next slot's settleFees() then calls
        // db.getAccount(leader_id) and gets either null or stale-from-snapshot
        // state. Vexor writes pending_writes[L] = (stale + fees) instead of
        // (correct_pre + fees), diverging lthash every leader slot.
        // Diagnosed in vault/research/2026-04-28-r71-leader-class-carrier-discovery.md
        // (slot 404,669,369 fingerprint: Δ=-1 write/slot, data_len=0, ~1700 SOL gap).
        //
        // Persist failure logs but does not abort the eviction — a stale
        // persisted entry is recoverable; a leaked cache entry is unbounded
        // growth. Errors here are best-effort, NOT bank-corrupting.
        for (to_evict.items) |pubkey| {
            // STEP 5 (two_tier): the FORK-AWARE ring promotion below is the SOLE
            // index writer. Do NOT promote from the fork-blind unflushed_cache:
            // this loop fires when an account's last-write slot < new_root, so it
            // files the cache value under `new_root` — HIGHER than the true write
            // slot the ring promotion files under — and the index's higher-slot-wins
            // guard then lets the (possibly stale/sibling) cache value clobber the
            // correct ring value. Just DRAIN the cache (bound RSS) and skip.
            if (build_options.two_tier) {
                if (self.unflushed_cache.get(pubkey)) |acct| {
                    if (acct.data.len > 0) std.heap.page_allocator.free(@constCast(acct.data));
                }
                _ = self.unflushed_cache.remove(pubkey);
                _ = self.cache_slot_map.remove(pubkey);
                self.cache.invalidate(&pubkey);
                continue;
            }
            if (self.unflushed_cache.get(pubkey)) |acct| {
                // Deep-copy data BEFORE writeAccount so mmap-backed slices
                // are NEVER mutated through. The dupe lives just long enough
                // to encode + index, then is freed inline.
                const data_dup = if (acct.data.len > 0)
                    std.heap.page_allocator.dupe(u8, acct.data) catch null
                else
                    null;

                if (data_dup) |dd| {
                    const location = self.storage.writeAccount(&pubkey, &Account{
                        .lamports = acct.lamports,
                        .owner = acct.owner,
                        .executable = acct.executable,
                        .rent_epoch = acct.rent_epoch,
                        .data = dd,
                    }, self.rooted_slot) catch |err| blk: {
                        std.log.warn(
                            "[vex-132-r74] writeAccount failed pk={x}{x}{x}{x} err={s}",
                            .{ pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], @errorName(err) },
                        );
                        break :blk null;
                    };
                    if (location) |loc| {
                        self.index.insert(&pubkey, loc) catch |err| {
                            std.log.warn(
                                "[vex-132-r74] index.insert failed pk={x}{x}{x}{x} err={s}",
                                .{ pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], @errorName(err) },
                            );
                        };
                    }
                    std.heap.page_allocator.free(dd);
                } else if (acct.data.len == 0) {
                    // 0-byte data path (e.g., System fee-payers, leader identity):
                    // no dupe needed; pass empty slice.
                    const location = self.storage.writeAccount(&pubkey, &Account{
                        .lamports = acct.lamports,
                        .owner = acct.owner,
                        .executable = acct.executable,
                        .rent_epoch = acct.rent_epoch,
                        .data = @constCast(acct.data),
                    }, self.rooted_slot) catch null;
                    if (location) |loc| {
                        _ = self.index.insert(&pubkey, loc) catch {};
                    }
                }

                if (acct.data.len > 0) {
                    std.heap.page_allocator.free(@constCast(acct.data));
                }

                // DURABLE-CAM (FIX #95, 2026-05-31): record this durable filing —
                // content lamports, the value's TRUE write-slot (cache_slot_map),
                // and the LABEL it is filed under (rooted_slot). hit=1 = the
                // unflushed_cache had the value (normal path). Log-only, gated +
                // line-capped; cache_slot_map still holds pubkey here (removed below).
                if (recorder.durableCamOn()) {
                    const cam_ws: u64 = self.cache_slot_map.get(pubkey) orelse 0;
                    if ((self.rooted_slot -| cam_ws) >= recorder.durableCamGap() and recorder.durableCamTick()) {
                        std.log.warn("[DURABLE-CAM][EVICT] pk={x}{x}{x}{x} lam={d} write_slot={d} label={d} hit=1", .{ pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], acct.lamports, cam_ws, self.rooted_slot });
                    }
                }
            } else if (recorder.durableCamOn() and recorder.durableCamTick()) {
                // DURABLE-CAM Mode-2 signature: pubkey was in to_evict (its
                // cache_slot_map slot was < new_root) but unflushed_cache holds NO
                // value → the durable write is SKIPPED and a stale older AppendVec
                // value is RETAINED. This is exactly "correct value never reached
                // durable." Log-only.
                const cam_ws: u64 = self.cache_slot_map.get(pubkey) orelse 0;
                std.log.warn("[DURABLE-CAM][EVICT-SKIP] pk={x}{x}{x}{x} write_slot={d} label={d} hit=0 STALE-RETAINED", .{ pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3], cam_ws, self.rooted_slot });
            }
            _ = self.unflushed_cache.remove(pubkey);
            _ = self.cache_slot_map.remove(pubkey);
            // r75-bug-class-b-cache-invalidate: companion to flushCacheToDisk.
            // advanceRoot also persists to AppendVec via writeAccount, must
            // invalidate the read cache or stale snapshot bytes will surface.
            self.cache.invalidate(&pubkey);
        }

        if (to_evict.items.len > 0) {
            const RootDbg = struct { var count: u64 = 0; };
            RootDbg.count += 1;
            if (RootDbg.count <= 3 or RootDbg.count % 100 == 0) {
                std.log.debug("[ACCOUNTS] Root advanced to {d}: evicted {d} stale entries, cache size={d}\n", .{
                    new_root, to_evict.items.len, self.unflushed_cache.count(),
                });
            }
        }

        // Fork-isolation: drop overlay entries for slots ≤ new_root. Their state
        // is already in `unflushed_cache` (or being flushed to AppendVec above).
        // Orphan slots ≤ root would already have been purged by `purgeUnrootedSlot`.
        if (self.fork_isolation_enabled) {
            self.unrooted_overlay_lock.lock();
            defer self.unrooted_overlay_lock.unlock();

            var drop_slots = std.ArrayListUnmanaged(u64){};
            defer drop_slots.deinit(std.heap.page_allocator);
            var ov_iter = self.unrooted_overlay.iterator();
            while (ov_iter.next()) |entry| {
                if (entry.key_ptr.* <= new_root) {
                    drop_slots.append(std.heap.page_allocator, entry.key_ptr.*) catch continue;
                }
            }
            for (drop_slots.items) |slot| {
                if (self.unrooted_overlay.fetchRemove(slot)) |kv| {
                    var inner = kv.value;
                    var inner_iter = inner.iterator();
                    while (inner_iter.next()) |e| {
                        if (e.value_ptr.data.len > 0) {
                            std.heap.page_allocator.free(@constCast(e.value_ptr.data));
                        }
                    }
                    inner.deinit();
                    std.heap.page_allocator.destroy(inner);
                }
            }
        }

        // STEP 5 (two_tier): keep the rooted INDEX current with the FORK-AWARE ring
        // value. The index MUST be current because when rooting is tight the unrooted
        // window is empty and every read hits the index. Promote the ring's canonical
        // newest-on-fork value for every slot in (prev_root, new_root] into the rooted
        // index, then drop the bucket (its state is now durable). Bounded by
        // RING_CAPACITY (older buckets recycled past root-lag>4096). Ascending so the
        // newest write wins; each entry is filed under its TRUE write-slot
        // (canonical Sig `last_modified_slot`), and the index's higher-slot-wins guard
        // (AccountIndex.insert: slot < existing → reject) records reality. promoteRingEntry
        // is the SOLE rooted-index writer under two_tier and now NEVER drops silently
        // (loud [LOST-ROOTED-WRITE] + lost_rooted_writes counter; room-aware
        // getOrCreateStore prevents the store-rotation drop that was the carrier).
        if (build_options.two_tier) {
            const lo: u64 = if (new_root > 4096 and prev_root + 1 < new_root - 4095)
                (new_root - 4095)
            else
                (prev_root + 1);

            // DETECTOR (behavior-preserving, advisor 2026-06-08): build new_root's
            // on-fork ancestor set within [lo, new_root) by walking the durable
            // slot_parents chain, so the promote loop can FLAG (not skip) any ring
            // bucket at a NON-ancestor (off-fork sibling) slot it is about to promote.
            // `self.rooted_slot` was already bumped to `new_root` above, so we cannot
            // use `unrootedAncestorChain` here (it stops at rooted_slot). Logging only.
            var anc_buf: [4097]u64 = undefined;
            var anc_n: usize = 0;
            {
                self.slot_parents_lock.lockShared();
                defer self.slot_parents_lock.unlockShared();
                var p: u64 = new_root;
                while (anc_n < anc_buf.len) {
                    const par = self.slot_parents.get(p) orelse break;
                    if (par < lo) break;
                    anc_buf[anc_n] = par;
                    anc_n += 1;
                    if (par >= p) break; // malformed-cycle guard
                    p = par;
                }
            }
            const new_root_anc = anc_buf[0..anc_n];

            const SiblingProbe = struct {
                slot: u64,
                new_root: u64,
                count: u64 = 0,
                fn visit(self_p: *@This(), bslot: u64, pubkey: core.Pubkey, account: Account) void {
                    _ = bslot;
                    self_p.count += 1;
                    if (sibling_promote_detail_logged < 64) {
                        sibling_promote_detail_logged += 1;
                        const pk_hex = std.fmt.bytesToHex(pubkey.data, .lower);
                        std.log.warn("[SIBLING-PROMOTE-PK] off_fork_slot={d} new_root={d} pk={s} lam={d} dlen={d}", .{
                            self_p.slot, self_p.new_root, &pk_hex, account.lamports, account.data.len,
                        });
                    }
                }
            };

            var s: u64 = lo;
            while (s <= new_root) : (s += 1) {
                // Probe only OFF-FORK slots actually carrying ring writes about to be
                // promoted (s != new_root and s not an ancestor of new_root).
                if (s != new_root) {
                    var is_anc = false;
                    for (new_root_anc) |a| {
                        if (a == s) {
                            is_anc = true;
                            break;
                        }
                    }
                    if (!is_anc) {
                        var probe = SiblingProbe{ .slot = s, .new_root = new_root };
                        self.unrooted_ring.forEachInSlot(s, &probe, SiblingProbe.visit);
                        if (probe.count > 0) {
                            sibling_promotes_observed += probe.count;
                            std.log.warn("[SIBLING-PROMOTE] off_fork_slot={d} new_root={d} n_writes={d} total_observed={d}", .{
                                s, new_root, probe.count, sibling_promotes_observed,
                            });
                        }
                    }
                }
                self.unrooted_ring.forEachInSlot(s, self, Self.promoteRingEntry);
                self.unrooted_ring.dropSlot(s);
            }
        }

        // FIX #105: bound the durable parent map — links ≤ root are now dead
        // (a rooted slot's ancestry is permanent; no future walk descends below it).
        self.pruneSlotParentsBelow(new_root);
    }

    /// Fork-isolation: return the most-recent write for `pubkey` from a slot in
    /// `ancestor_slots` (caller-supplied ancestor chain of the reading bank).
    /// Falls through to `getAccount(pubkey)` (rooted view) if no overlay match.
    /// When `fork_isolation_enabled` is false, this is equivalent to `getAccount`.
    ///
    /// Defense against iter-6 fork-isolation carrier: orphan slots' writes live
    /// in their own overlay bucket; this method skips non-ancestor slots, so the
    /// canonical fork never reads sibling-orphan pre-state.
    pub fn getAccountInAncestors(
        self: *Self,
        pubkey: *const core.Pubkey,
        ancestor_slots: []const u64,
    ) ?AccountView {
        if (self.fork_isolation_enabled and ancestor_slots.len > 0) {
            self.unrooted_overlay_lock.lock();
            defer self.unrooted_overlay_lock.unlock();

            var best_slot: u64 = 0;
            var best: ?Account = null;
            for (ancestor_slots) |slot| {
                const overlay_ptr = self.unrooted_overlay.get(slot) orelse continue;
                if (overlay_ptr.get(pubkey.*)) |acct| {
                    if (slot >= best_slot) {
                        best_slot = slot;
                        best = acct;
                    }
                }
            }
            if (best) |acct| return accountViewFromOwned(&acct);
        }
        // PR-S4: bootstrap/legacy path — overlay miss falls back to rooted state.
        return self._getRooted(pubkey);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PR-S2 (2026-05-15) — Sig-pattern ancestor-required API surface.
    //
    // Phase 1: ADDITIVE — these functions exist alongside the legacy overlay.
    // Phase 2 will migrate callers; Phase 4 will rip the legacy code.
    //
    // The structural invariant: readers MUST supply an ancestor slice;
    // writers compute their own old_lt by reading via the ancestor-aware
    // path. This makes the PR-A.2 Vote regression class (caller-computed
    // old_lt from stale flat read) impossible at the API level.
    // ─────────────────────────────────────────────────────────────────────────

    pub const LtHashDelta = struct {
        old: crypto.lthash.LtHashValue,
        new: crypto.lthash.LtHashValue,
    };

    /// Audit hatch — flat rooted read, no ancestors. Only callable from
    /// bootstrap, snapshot load, and the rooted-fallthrough inside
    /// `getAccountInSlot`. NEVER call from tx-exec; reads via this path
    /// bypass per-slot fork isolation.
    /// PR-5o (2026-05-19): result of a fall-through-only read (bulk_buffer /
    /// cache / index→storage, NO unflushed_cache). Used by `_getRooted` for the
    /// post-L1 lookup AND by PR-5o instrumentation in `getAccountInSlot` to
    /// compute the counterfactual ("what would the future fork-iso filter
    /// return if it bypassed L1?"). Future Option A filter will use the same
    /// helper.
    pub const FallthroughResult = struct {
        view: AccountView,
        layer: recorder.Layer,
    };

    /// Read pk from the rooted-state layers ONLY: bulk_buffer → cache → index
    /// → storage. Does NOT consult unflushed_cache. Caller decides whether to
    /// populate the LRU cache on index hit (the production read path does;
    /// PR-5o instrumentation does not, to keep the probe side-effect-free).
    fn _readFromStorage(
        self: *Self,
        pubkey: *const core.Pubkey,
        populate_cache: bool,
    ) ?FallthroughResult {
        if (self.bulk_buffer) |buf| {
            if (buf.get(pubkey)) |account| {
                return .{ .view = account, .layer = .bulk_buffer };
            }
        }
        if (self.cache.get(pubkey)) |cached| {
            return .{ .view = cached, .layer = .cache };
        }
        if (self.index.get(pubkey)) |location| {
            const account = self.storage.readAccount(location) orelse return null;
            if (populate_cache) {
                _ = self.cache.insert(pubkey, account) catch {};
            }
            return .{ .view = account, .layer = .index_storage };
        }
        return null;
    }

    pub fn _getRooted(self: *Self, pubkey: *const core.Pubkey) ?AccountView {
        // Two-tier: the rooted read is the clean index→AppendVec path (no
        // fork-blind unflushed_cache/cache). All 15 callers route here. This is
        // what fixes the carrier-#2 "_getRooted returns orphan" reproducer: the
        // orphan lived in unflushed_cache, which `getRooted` never consults.
        if (build_options.two_tier) return self.getRooted(pubkey);

        // Phase A recorder: fetch cache_slot_map value once up-front so each
        // return-site can attribute the layer-vs-csm relationship without
        // re-locking. Cheap; skipped when recorder disabled.
        const rec_on = recorder.isEnabled();
        const csm_opt: ?u64 = if (rec_on) blk: {
            // cache_slot_map has no dedicated lock — diagnostic-only read,
            // racing a concurrent insert is acceptable (best-effort attribution).
            break :blk self.cache_slot_map.get(pubkey.*);
        } else null;

        // L1: Check unflushed RAM cache first (accounts from recent freeze() calls)
        {
            self.unflushed_cache_lock.lock();
            defer self.unflushed_cache_lock.unlock();
            if (self.unflushed_cache.get(pubkey.*)) |account| {
                const av = accountViewFromOwned(&account);
                if (rec_on) {
                    // Phase E-2 (2026-05-17): bump sigov_buf from 16→256 so the
                    // recorder shows the FULL list of slots sig_overlay has for
                    // this pubkey, not just the first 16 in for-loop order. The
                    // 16-cap was masking whether sig_overlay had the canonical
                    // csm_slot — earlier we saw "sigov: [705..720]" and assumed
                    // sig_overlay was missing slot 735, but slotsContaining is
                    // bounded by out.len so we can't actually tell from a 16-cap.
                    var sigov_buf: [256]u64 = undefined;
                    const sigov_n: usize = if (csm_opt != null) self.sig_overlay.slotsContaining(pubkey.*, &sigov_buf) else 0;
                    const sigov_slice: ?[]const u64 = if (csm_opt != null) sigov_buf[0..sigov_n] else null;
                    recorder.emitRead(&pubkey.data, .unflushed_cache, av.lamports, av.data, av.data.len, csm_opt, null, null, sigov_slice);
                }
                if (self.dbg_regress_gate) self.dbgRegressCheck(pubkey, av);
                return av;
            }
        }

        // Fall-through: bulk_buffer / cache / index→storage via the shared
        // helper. `populate_cache=true` preserves the legacy behavior of
        // hoisting an index hit into the LRU cache for the next read.
        if (self._readFromStorage(pubkey, true)) |r| {
            if (rec_on) recorder.emitRead(&pubkey.data, r.layer, r.view.lamports, r.view.data, r.view.data.len, csm_opt, null, null, null);
            if (self.dbg_regress_gate) self.dbgRegressCheck(pubkey, r.view);
            return r.view;
        }

        if (rec_on) recorder.emitRead(&pubkey.data, .miss, null, null, null, csm_opt, null, null, null);
        return null;
    }

    /// Two-tier ROOTED read (STEP 1, dormant until STEP 2 wires it into
    /// getAccountInSlot). The clean rooted-only path: bulk_buffer (snapshot mmap)
    /// → index → AppendVec storage. NO unflushed_cache, NO L3 `cache`/`shadow`.
    /// Everything reachable here is the newest ROOTED version (the live
    /// AccountIndex already guards newest-slot-wins at upsert). Fork-awareness is
    /// unnecessary: rooted state is the single finalized version visible on every
    /// fork. Returns a BORROWED view (data points into bulk_buffer/mmap); callers
    /// that outlive a re-entrant write must use `getAccountInSlotOwned`.
    pub fn getRooted(self: *Self, pubkey: *const core.Pubkey) ?AccountView {
        if (self.bulk_buffer) |buf| {
            if (buf.get(pubkey)) |account| return account;
        }
        if (self.index.get(pubkey)) |location| {
            return self.storage.readAccount(location);
        }
        return null;
    }

    /// Walk the DURABLE `slot_parents` chain (FIX #105) from `start_parent` down
    /// to (but excluding) `rooted_slot`, filling `out` newest-first. Unlike the
    /// legacy `self.banks.get` walk (which prunes in catch-up and truncates the
    /// chain to ~64), `slot_parents` persists every parent link, so this yields
    /// the FULL unrooted ancestor window up to `out.len` (sized RING_CAPACITY by
    /// the caller). Widening the fork-aware read window from 64 → 4096 via this
    /// chain is what kills the stale-read carrier (read at the tip during a
    /// >64-slot root-lag seam could not reach a 138-slot-back on-fork write).
    /// (STEP 1, dormant until STEP 3.)
    pub fn unrootedAncestorChain(self: *Self, start_parent: core.Slot, out: []core.Slot) []const core.Slot {
        var n: usize = 0;
        var p = start_parent;
        const root = self.rooted_slot;
        self.slot_parents_lock.lockShared();
        defer self.slot_parents_lock.unlockShared();
        while (n < out.len and p > root) {
            out[n] = p;
            n += 1;
            p = self.slot_parents.get(p) orelse break;
        }
        return out[0..n];
    }

    /// Primary read API during replay. Consults (in order):
    ///   1. sig_overlay.get(pubkey, ancestors) — fork-isolated per-slot writes
    ///   2. unflushed_cache / cache / shadow / index — rooted state (via `_getRooted`)
    ///
    /// `slot` is the reading bank's slot. Phase 2c-B: sig_overlay is consulted
    /// AT `slot` first (within-slot read-your-writes), then at each ancestor.
    /// This is required because `bank.ancestors()` collects the PARENT chain
    /// and does NOT include the bank's own slot — but the flush-to-overlay path
    /// (replay_stage.flushPendingWritesToDb) writes keyed by `bank.slot`.
    /// Canonical account load for EXECUTION and general reads.
    ///
    /// carrier #11 (2026-06-11 @414670256): applies Agave's
    /// `LoadZeroLamports::None` semantics — a zero-lamport account does NOT
    /// exist. The cluster deletes accounts the moment lamports hit 0 (loader
    /// `Close`, withdrawals, …); any later load must see NOTHING, not the
    /// dead version's stale bytes and NOT an older alive version underneath.
    /// Without this, the create→write×450→close→REcreate cycle (loader buffer
    /// EtS4njg…, closed @414670169, re-created @414670256) read the dead
    /// buffer's stale 525,957-byte data → System createAccount returned
    /// ERR_ACCT_ALREADY_IN_USE (allocate(): data.len != 0) → Vexor failed a
    /// tx the cluster executed → accounts_lt_hash divergence (equal sigs).
    /// CRITICAL: the dead version MASKS older alive versions — we return null
    /// from the WINNING version's lamports check; we never fall through to a
    /// lower tier (FD's "always leave tombstones in funk", 784310871).
    /// Diagnostic/forensic callers that need the raw dead version can call
    /// getAccountInSlotRaw.
    pub fn getAccountInSlot(
        self: *Self,
        pubkey: *const core.Pubkey,
        slot: core.Slot,
        ancestors: []const core.Slot,
    ) ?AccountView {
        const v = self.getAccountInSlotRaw(pubkey, slot, ancestors) orelse return null;
        if (v.lamports == 0) return null;
        return v;
    }

    pub fn getAccountInSlotRaw(
        self: *Self,
        pubkey: *const core.Pubkey,
        slot: core.Slot,
        ancestors: []const core.Slot,
    ) ?AccountView {
        // ── Canonical TWO-TIER read (default; -Dtwo_tier) ──────────────────────
        // Fork-aware unrooted ring (FULL window: `ancestors` is the complete
        // unrooted ancestor chain after STEP 3 widens bank.ancestors_buf) → clean
        // rooted (index→AppendVec). NO sig_overlay, NO fork-blind unflushed_cache,
        // NO L3 cache/shadow, NO non-fork-aware `_getRooted` fall-through — i.e.
        // none of the tiers between which the stale-read / orphan-leak carriers
        // lived. The ring is ancestors-gated so a sibling-fork write is invisible;
        // a miss means the account is rooted, whose single finalized version is
        // visible on every fork. `self_slot` = `slot` gives within-slot
        // read-your-writes without the per-read 65-element copy.
        if (build_options.two_tier) {
            if (self.unrooted_ring.getWithModifiedSlotPlusSelf(pubkey.*, ancestors, slot)) |hit| {
                if (recorder.isEnabled())
                    recorder.emitRead(&pubkey.data, .unflushed_cache, hit.view.lamports, hit.view.data, hit.view.data.len, null, null, hit.modified_slot, null);
                return hit.view;
            }
            const rv = self.getRooted(pubkey);
            if (recorder.isEnabled()) {
                if (rv) |v|
                    recorder.emitRead(&pubkey.data, .index_storage, v.lamports, v.data, v.data.len, null, null, null, null)
                else
                    recorder.emitRead(&pubkey.data, .miss, null, null, null, null, null, null, null);
            }
            return rv;
        }

        // ── Legacy 5-tier read (only under -Dtwo_tier=false; emergency A/B) ─────
        // Phase 2c-B (2026-05-15): include `slot` in the ancestor scan so writes
        // mirrored into sig_overlay at bank.slot are visible to within-slot reads.
        // Build a stack-resident extended slice. Cap at 65 (64 ancestors + self).
        var extended: [65]core.Slot = undefined;
        const n_anc = @min(ancestors.len, 64);
        @memcpy(extended[0..n_anc], ancestors[0..n_anc]);
        extended[n_anc] = slot;
        const lookup: []const core.Slot = extended[0 .. n_anc + 1];

        if (lookup.len > 0) {
            if (self.sig_overlay.get(pubkey.*, lookup)) |acct| {
                if (recorder.isEnabled()) {
                    const csm_opt: ?u64 = self.cache_slot_map.get(pubkey.*);
                    recorder.emitRead(
                        &pubkey.data,
                        .sig_overlay,
                        acct.lamports,
                        acct.data,
                        acct.data.len,
                        csm_opt,
                        if (lookup.len > 0) lookup[0] else null,
                        if (lookup.len > 0) lookup[lookup.len - 1] else null,
                        null,
                    );
                }
                return .{
                    .lamports = acct.lamports,
                    .owner = acct.owner,
                    .executable = acct.executable,
                    .rent_epoch = acct.rent_epoch,
                    .data = acct.data,
                };
            }

            // 2026-05-18: UnrootedRing — fork-aware per-slot cache. Consulted
            // after sig_overlay miss and BEFORE the legacy `_getRooted`
            // fall-through. The ring stores writes from every
            // promoteToUnflushedCache / flushPendingWritesToDb /
            // flushPendingWritesFromIndex (the same paths that populate
            // sig_overlay), but its scan filters by `lookup` slot membership,
            // so a sibling-fork write at K+1 is invisible to a slot-K reader.
            // This is the structural answer to the iter-6 carrier that 6
            // attempted read-time filters on the fork-blind unflushed_cache
            // could not provide (all 6 regressed parity catastrophically —
            // see project_iter6_4_attempts_failed_2026_05_18.md).
            if (self.unrooted_ring.getWithModifiedSlot(pubkey.*, lookup)) |hit| {
                if (recorder.isEnabled()) {
                    const csm_opt: ?u64 = self.cache_slot_map.get(pubkey.*);
                    recorder.emitRead(
                        &pubkey.data,
                        .unflushed_cache, // reuse the existing layer enum; ring hit attributed to L1
                        hit.view.lamports,
                        hit.view.data,
                        hit.view.data.len,
                        csm_opt,
                        if (lookup.len > 0) lookup[0] else null,
                        hit.modified_slot,
                        null,
                    );
                }
                return hit.view;
            }
        }

        // PR-5o instrumentation (2026-05-19): when both sig_overlay and
        // unrooted_ring missed, the next layer (`_getRooted` → unflushed_cache
        // at line 1043) is the carrier #2 bug surface. If pr5o is enabled AND
        // cache_slot_map[pk] indicates the orphan-leak condition (csm ∉ lookup),
        // log what unflushed_cache (the buggy result) AND fall-through (the
        // counterfactual a future Option A filter would return) WOULD return.
        // Does NOT mutate behavior — `_getRooted` is still called and returns
        // the buggy value. Bounded by VEX_PR5O_MAX_RECORDS.
        if (recorder.isPr5oEnabled()) {
            const csm_opt: ?u64 = self.cache_slot_map.get(pubkey.*);
            if (csm_opt) |csm_slot| {
                var csm_in_anc = false;
                for (lookup) |s| {
                    if (s == csm_slot) {
                        csm_in_anc = true;
                        break;
                    }
                }
                if (!csm_in_anc) {
                    // Capture what unflushed_cache WOULD return (the bug path).
                    // Hold the lock long enough to copy primitives + grab the
                    // data slice pointer; the underlying allocation outlives
                    // this lock window because unflushed_cache never frees
                    // entries until purgeUnrootedSlot / advanceRoot runs.
                    var u_lam: ?u64 = null;
                    var u_data: ?[]const u8 = null;
                    {
                        self.unflushed_cache_lock.lock();
                        defer self.unflushed_cache_lock.unlock();
                        if (self.unflushed_cache.get(pubkey.*)) |a| {
                            u_lam = a.lamports;
                            u_data = a.data;
                        }
                    }

                    // Capture what fall-through WOULD return. `populate_cache=
                    // false` keeps this probe side-effect-free so it does not
                    // alter the LRU cache state observed by the immediately
                    // following `_getRooted` call.
                    const ft = self._readFromStorage(pubkey, false);
                    const ft_lam: ?u64 = if (ft) |r| r.view.lamports else null;
                    const ft_data: ?[]const u8 = if (ft) |r| r.view.data else null;
                    const ft_layer: ?recorder.Layer = if (ft) |r| r.layer else null;

                    recorder.emitPr5oInstrument(
                        &pubkey.data,
                        csm_slot,
                        lookup,
                        u_lam,
                        u_data,
                        ft_lam,
                        ft_data,
                        ft_layer,
                    );
                }
            }
        }

        // PROMOTE-DIAG (2026-05-28): sig_overlay + unrooted_ring both missed, so
        // this read is about to fall through to the fork-blind `_getRooted`
        // (unflushed_cache → cache → index_storage). When `slot` is more than
        // 64 ahead of `rooted_slot`, the unrooted window exceeds the 64-slot
        // `bank.ancestors_buf` cap → a sig_overlay entry for this pubkey in
        // (rooted_slot, slot-64] is RETAINED (MAX_SLOTS=4096) but UNREACHABLE by
        // `lookup`. If `slotsContaining` finds such an entry, that is the H1
        // catchup-root-lag stale-read carrier proven at the read site. Bounded
        // scan only when the gap exceeds the cap (rare; deep catchup only).
        if (recorder.promoteDiagOn() and slot > self.rooted_slot + 64) {
            var lk_min: core.Slot = slot;
            for (lookup) |s| {
                if (s < lk_min) lk_min = s;
            }
            var ov_slots: [16]core.Slot = undefined;
            const ov_n = self.sig_overlay.slotsContaining(pubkey.*, &ov_slots);
            // unreachable = sig_overlay holds it at a slot strictly below the
            // lookup window floor but above the root (i.e., unrooted yet
            // out-of-window). That is the carrier condition.
            var unreachable_slot: ?core.Slot = null;
            for (ov_slots[0..ov_n]) |s| {
                if (s < lk_min and s > self.rooted_slot) {
                    unreachable_slot = s;
                    break;
                }
            }
            if (unreachable_slot != null and recorder.promoteDiagTick()) {
                std.log.warn("[PROMOTE-DIAG][STALE-READ] pk={x}{x}{x}{x} read_slot={d} rooted_slot={d} gap={d} window_floor={d} sig_overlay_has_at_slot={d} (entry RETAINED but UNREACHABLE → falling to stale _getRooted = H1 confirmed)", .{
                    pubkey.data[0], pubkey.data[1], pubkey.data[2], pubkey.data[3],
                    slot,                  self.rooted_slot, slot - self.rooted_slot,
                    lk_min,                unreachable_slot.?,
                });
            }
        }

        // FIX#95 regress-detector now runs INSIDE _getRooted (covers every
        // rooted-read caller, not just this replay path), so no explicit
        // call here — _getRooted self-checks at both its return sites.
        return self._getRooted(pubkey);
    }

    /// FIX#95 regress-detector: at the rooted-read fall-through (sig_overlay +
    /// unrooted_ring both missed), if a ROOTED write (slot <= rooted_slot =
    /// canonical truth, fork-unambiguous) recorded a different value than this
    /// read returned, the rooted store is STALE — the exact carrier of the
    /// 412372439 divergence (CRnkKQTx read the slot-268 value after writes
    /// 269-287 were rooted). Rate-limited; logs full store context.
    fn dbgRegressCheck(self: *Self, pubkey: *const core.Pubkey, got: AccountView) void {
        self.dbg_regress_mutex.lock();
        const entry = self.dbg_regress_map.get(pubkey.*);
        self.dbg_regress_mutex.unlock();
        const e = entry orelse return;
        if (e.slot > self.rooted_slot) return; // only rooted writes are canonical truth (no fork ambiguity)
        // Broadened (advisor 2026-06-01): compare lamports AND a FULL-data hash
        // AND data length. The lamports-only v1 missed a wedge whose divergence
        // was in DATA (same lamports, e.g. vote-state). data_sha8 covers the
        // FULL data (not first-64 — Task#100 trap).
        const got_sha8 = dbgDataSha8(got.data);
        const got_dlen: u32 = @intCast(got.data.len);
        const lam_bad = (e.lamports != got.lamports);
        const data_bad = (e.data_sha8 != got_sha8);
        const dlen_bad = (e.dlen != got_dlen);
        if (!lam_bad and !data_bad and !dlen_bad) return; // read matches latest rooted write — OK
        if (dbg_regress_fires.fetchAdd(1, .monotonic) >= 200) return;

        const csm: ?u64 = self.cache_slot_map.get(pubkey.*);
        var ov_slots: [16]core.Slot = undefined;
        const ov_n = self.sig_overlay.slotsContaining(pubkey.*, &ov_slots);
        const idx_present = self.index.get(pubkey) != null;
        const pk_hex = std.fmt.bytesToHex(pubkey.data, .lower);
        std.log.warn("[REGRESS-DETECT] pk={s} reason={s}{s}{s}rooted_slot={d} READ_lam={d} READ_sha8={x} READ_dlen={d} | WRITE_slot={d} WRITE_lam={d} WRITE_sha8={x} WRITE_dlen={d} | lam_delta={d} csm={?d} sigov_n={d} idx_present={} (rooted write value LOST -> stale rooted read = FIX#95 carrier)", .{
            &pk_hex,
            if (lam_bad) "LAM " else "",
            if (data_bad) "DATA " else "",
            if (dlen_bad) "DLEN " else "",
            self.rooted_slot, got.lamports, got_sha8, got_dlen,
            e.slot, e.lamports, e.data_sha8, e.dlen,
            @as(i64, @intCast(got.lamports)) - @as(i64, @intCast(e.lamports)),
            csm, ov_n, idx_present,
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // [LTHASH-VERIFY] Full accounts_lt_hash RECOMPUTE-and-verify
    // ─────────────────────────────────────────────────────────────────────────
    //
    // Decisive byte-vs-accumulation test (gated by env VEX_VERIFY_LTHASH_SLOT).
    //
    // The bank maintains `accounts_lthash` INCREMENTALLY in freeze():
    //   accounts_lthash = parent_lthash − Σ(first_old_lt per pk) + Σ(last_new_lt per pk)
    // This method re-derives the SAME quantity ABSOLUTELY by re-summing the
    // accountLtHash of every account's COMMITTED state visible at `bank.slot`,
    // reading via the EXACT same fork-aware path freeze's accumulator targets
    // (`getAccountInSlot(pk, bank.slot, bank.ancestors())`). It then compares.
    //
    //   MATCH    ⇒ the incremental accumulator is correct for Vexor's own states
    //              ⇒ any cluster divergence is BYTE-class (the underlying account
    //                bytes themselves differ from canonical).
    //   MISMATCH ⇒ ACCUMULATION-class carrier (a per-account incremental update
    //              was dropped / doubled / mis-based, or the parent_lthash seed
    //              is poisoned, or a collected write value disagrees with what
    //              actually committed — the exact DM-lamport-write-drop class).
    //
    // CRITICAL invariants (why this is sound):
    //  - Reads COMMITTED storage via getAccountInSlot — NOT the accumulator's
    //    own delta inputs (pending_writes[].new_lt). Re-using those would make
    //    written-account contributions tautologically MATCH and blind the test
    //    to the very commit-vs-accumulator class we hunt.
    //  - Calls Bank.accountLtHash (the SAME function the accumulator uses) so a
    //    function-level byte diff can't masquerade as a carrier.
    //  - MUST be invoked AFTER this slot's writes are flushed into the read path
    //    (unrooted_ring) — i.e. after flushPendingWritesFromIndex in
    //    replay_stage — otherwise getAccountInSlot returns PARENT state and a
    //    read-timing artifact MISMATCH appears. See the call site comment.
    //
    // Iteration set = union of (a) every rooted pubkey in `self.index` (the
    // snapshot/disk base) and (b) every unrooted write in `unrooted_ring` for
    // `bank.slot` and each ancestor (accounts created this slot have NO index
    // entry yet and live only in the ring). Dedup is done lazily: ring keys
    // already present in the index were already counted in the index pass
    // (getAccountInSlot returned their ring version there).
    //
    // Concurrency: collect keys under each lock, RELEASE the lock, THEN call
    // getAccountInSlot — never call it while holding the bin or ring-bucket
    // shared lock (getAccountInSlot re-locks the same structures → re-entrant
    // shared-lock deadlock under a queued writer). This is a diagnostic-only,
    // single-slot, env-gated path; production deploys pay zero cost.
    pub fn recomputeAndVerifyLtHash(
        self: *Self,
        bank: anytype, // *Bank — `anytype` avoids an import cycle (accounts ← bank ← accounts)
    ) void {
        const Bank = @import("vex_svm").bank.Bank;
        const LtHash = crypto.LtHash;

        var timer = std.time.Timer.start() catch return;
        const slot = bank.slot;
        const ancestors = bank.ancestors();

        var recompute = LtHash.init();
        var n: usize = 0;
        var zero_lam: usize = 0;

        // Local "seen" set so a ring key already counted in the index pass is
        // not double-summed. Holds only the ring-extra pubkeys; bounded by the
        // per-slot write set (tiny vs the 86.7M index), so a heap set is cheap.
        var seen = std.AutoHashMap(core.Pubkey, void).init(self.allocator);
        defer seen.deinit();

        // ── Pass 1: rooted/snapshot base — iterate every index bin ───────────
        // Snapshot the bin's keys under its lock, release, then read each via
        // getAccountInSlot (which re-locks the bin) to avoid re-entrant locking.
        var bin_keys = std.ArrayListUnmanaged(core.Pubkey){};
        defer bin_keys.deinit(self.allocator);
        for (self.index.bins) |*bin| {
            bin_keys.clearRetainingCapacity();
            bin.lock.lockShared();
            {
                var it = bin.entries.iterator();
                while (it.next()) |kv| {
                    bin_keys.append(self.allocator, kv.key_ptr.*) catch {};
                }
            }
            bin.lock.unlockShared();

            for (bin_keys.items) |pk| {
                seen.put(pk, {}) catch {};
                const view = self.getAccountInSlot(&pk, slot, ancestors) orelse continue;
                if (view.lamports == 0) {
                    zero_lam += 1;
                    continue;
                }
                const lt = Bank.accountLtHash(&pk.data, &view.owner.data, view.lamports, view.executable, view.data);
                recompute.wrappingAdd(&lt);
                n += 1;
            }
        }

        // ── Pass 2: unrooted writes (this slot + ancestors) not in the index ──
        // collectSlotKeys snapshots each bucket's pubkeys under its shared lock,
        // releases the lock, and appends them to ring_keys — so the subsequent
        // getAccountInSlot calls (which re-lock the same ring buckets) cannot
        // re-enter a held shared lock. Covers bank.slot + every ancestor slot.
        var ring_keys = std.ArrayListUnmanaged(core.Pubkey){};
        defer ring_keys.deinit(self.allocator);

        self.unrooted_ring.collectSlotKeys(slot, &ring_keys, self.allocator);
        for (ancestors) |anc| {
            self.unrooted_ring.collectSlotKeys(anc, &ring_keys, self.allocator);
        }

        for (ring_keys.items) |pk| {
            if (seen.contains(pk)) continue; // already counted in index pass
            seen.put(pk, {}) catch {};
            const view = self.getAccountInSlot(&pk, slot, ancestors) orelse continue;
            if (view.lamports == 0) {
                zero_lam += 1;
                continue;
            }
            const lt = Bank.accountLtHash(&pk.data, &view.owner.data, view.lamports, view.executable, view.data);
            recompute.wrappingAdd(&lt);
            n += 1;
        }

        const elapsed_ms = timer.read() / std.time.ns_per_ms;

        // BLAKE3 checksum of each 2048-byte lattice for a compact compare field
        // (matches the [BANK-FROZEN] lthash_full convention).
        var inc_full: [32]u8 = undefined;
        var rec_full: [32]u8 = undefined;
        // stdlib BLAKE3 (matches bank.zig's [BANK-FROZEN] lthash_full idiom);
        // diagnostic-only digest, no ballet backend needed.
        std.crypto.hash.Blake3.hash(bank.accounts_lthash.asBytes(), &inc_full, .{});
        std.crypto.hash.Blake3.hash(recompute.asBytes(), &rec_full, .{});
        const inc_hex = std.fmt.bytesToHex(inc_full, .lower);
        const rec_hex = std.fmt.bytesToHex(rec_full, .lower);

        const matched = std.mem.eql(u8, bank.accounts_lthash.asBytes(), recompute.asBytes());
        const total = self.index.totalCount();
        std.log.warn(
            "[LTHASH-VERIFY] slot={d} n={d} index_total={d} zero_lam={d} ms={d} incremental={s} recompute={s} {s}",
            .{ slot, n, total, zero_lam, elapsed_ms, &inc_hex, &rec_hex, if (matched) "MATCH" else "MISMATCH" },
        );

        // On MISMATCH, surface the first 16 differing u16 component indices so a
        // follow-up per-account oracle can localize the diverging contribution.
        if (!matched) {
            const inc_el = &bank.accounts_lthash.elements;
            const rec_el = &recompute.elements;
            var printed: usize = 0;
            var i: usize = 0;
            while (i < 1024 and printed < 16) : (i += 1) {
                if (inc_el[i] != rec_el[i]) {
                    std.log.warn(
                        "[LTHASH-VERIFY-DIFF] slot={d} comp[{d}] incremental={d} recompute={d}",
                        .{ slot, i, inc_el[i], rec_el[i] },
                    );
                    printed += 1;
                }
            }
        }
    }

    // [LT-WRITE-LOCALIZER] (env VEX_VERIFY_LTHASH_WRITES, optional lower-bound
    // VEX_VERIFY_LTHASH_SLOT) — writeset-sized accumulation-carrier localizer.
    //
    // The full recompute above re-sums ALL ~86.7M accounts (~24min) and tells us
    // a MISMATCH exists but not WHICH account. This runs at replay speed: it
    // touches only THIS slot's writeset. For each changed pubkey, freeze() stashed
    // (in bank.lt_write_capture, during Pass C) the EXACT LtHash contribution it
    // added to the accumulator. Here we read the COMMITTED final state via the same
    // fork-aware getAccountInSlot the recompute uses, recompute its accountLtHash,
    // and compare. If they DIFFER, the applied delta was computed from different
    // bytes than what committed to storage — that pubkey IS the carrier.
    //
    // MUST be invoked AFTER this slot's writes are flushed into the read path
    // (same call-site discipline as recomputeAndVerifyLtHash) so getAccountInSlot
    // returns committed final state, not parent state.
    //
    // THREE checks, all under VEX_VERIFY_LTHASH_WRITES (zero production cost):
    //  1. NEW-side ([LT-WRITE-MISMATCH]): applied_new_lt == accountLtHash(committed
    //     readback @ bank.slot). Already CLEAN on every slot this session.
    //  2. OLD-side ([LT-OLD-MISMATCH]): the captured first_old_lt (what freeze
    //     SUBTRACTED) == accountLtHash(TRUE parent-state readback). A DIFFER means
    //     the subtracted pre-state was stale/wrong — the OLD-side accumulation
    //     carrier. The parent read is fork-correct under two-tier: the unrooted
    //     ring is slot-keyed, so reading @ parent_slot with the parent's ancestor
    //     set EXCLUDES bank.slot's just-flushed write and yields a clean pre-state
    //     even post-flush (the earlier "OLD-side not available post-flush" caveat
    //     was wrong for two-tier).
    //  3. DROPPED / PHANTOM ([LT-DROPPED-WRITE]/[LT-PHANTOM-WRITE]): set-diff of
    //     pubkeys ACTUALLY committed at bank.slot (unrooted_ring.collectSlotKeys)
    //     vs pubkeys in the capture. Ring-key not captured = committed with NO
    //     accumulator contribution (dropped). Capture-key not in ring = contribution
    //     applied but not committed to the ring writeset (phantom).
    //
    // CAVEATS:
    //  - OLD-side fork-correctness holds only under two-tier (default-ON). Under
    //    -Dtwo_tier=false the parent read falls through to the fork-blind
    //    unflushed_cache, which bank.slot's just-flushed write can pollute → the
    //    OLD check is unreliable in that (emergency A/B) mode. NEW + DROPPED/PHANTOM
    //    are unaffected.
    //  - DROPPED/PHANTOM scope is bank.slot's ring bucket ONLY (NOT ancestors) —
    //    the capture is bank.slot-scoped, so mixing ancestor ring keys would
    //    fabricate diffs.
    //  - applied data digest is NOT logged: the applied account-data slice is freed
    //    once last_new_lt is cached in freeze (rev1 UAF), so it can't be hashed
    //    safely. We log applied_lamports/applied_owner (inline, safe) instead, which
    //    pins the DM-lamport/owner-drop carrier DIRECTLY (lam_applied != lam_committed)
    //    rather than by inference. committed_dsha8 is computed from the safe readback
    //    so a pure data-only diff is still visible.
    pub fn verifyLtHashWrites(
        self: *Self,
        bank: anytype, // *Bank — anytype avoids the accounts←bank←accounts import cycle
    ) void {
        const Bank = @import("vex_svm").bank.Bank;
        const Sha256 = std.crypto.hash.sha2.Sha256;

        const slot = bank.slot;
        const ancestors = bank.ancestors();
        const writes = bank.lt_write_capture.items;

        // [LT-OLD-LOCALIZER] Parent read setup (load-bearing for the OLD check).
        // `bank.ancestors()` is the PARENT chain and EXCLUDES bank.slot. The
        // fork-aware read helper is "PlusSelf": it reads {self_slot} ∪ {ancestors}.
        // So reading the parent's pre-state =
        //   getAccountInSlot(pk, parent_slot, bank.ancestors())
        // → set {parent} ∪ {parent, grandparent, …, root} = {parent..root}, which
        // EXCLUDES bank.slot. `parent_slot` is bank.parent_slot (the authoritative
        // field; equal to ancestors()[0] when non-empty). When parent_slot is null
        // (genesis/sentinel) the OLD check is skipped for the slot. When ancestors
        // is empty (parent ≤ rooted_slot, or fork-iso off) we still read @
        // parent_slot with empty ancestors — getRooted returns the right rooted
        // pre-state; do NOT skip (that would lose coverage on rooted-parent slots).
        const parent_slot_opt: ?core.Slot = bank.parent_slot;

        var mismatches: usize = 0;
        var old_mismatch: usize = 0;
        for (writes) |cap| {
            var pk = core.Pubkey{ .data = cap.pubkey };
            const committed = self.getAccountInSlot(&pk, slot, ancestors);

            // Committed contribution: zero-lamport (or missing) → LtHash.init(),
            // matching Bank.accountLtHash's own zero-lamport branch.
            var committed_lt = crypto.LtHash.init();
            var lam_committed: u64 = 0;
            var dlen_committed: usize = 0;
            var owner_committed: [32]u8 = [_]u8{0} ** 32;
            var committed_dsha: [32]u8 = undefined;
            Sha256.hash(&[_]u8{}, &committed_dsha, .{}); // sha256("") for missing/zero
            if (committed) |v| {
                lam_committed = v.lamports;
                dlen_committed = v.data.len;
                owner_committed = v.owner.data;
                Sha256.hash(v.data, &committed_dsha, .{});
                committed_lt = Bank.accountLtHash(&pk.data, &v.owner.data, v.lamports, v.executable, v.data);
            }

            if (!std.mem.eql(u8, cap.applied_lt.asBytes(), committed_lt.asBytes())) {
                mismatches += 1;
                const applied_u64 = std.mem.readInt(u64, cap.applied_lt.asBytes()[0..8], .big);
                const committed_u64 = std.mem.readInt(u64, committed_lt.asBytes()[0..8], .big);
                const pk_hex = std.fmt.bytesToHex(&cap.pubkey, .lower);
                const owner_hex = std.fmt.bytesToHex(&owner_committed, .lower);
                const cd_hex = std.fmt.bytesToHex(committed_dsha[0..4], .lower); // first 8 hex
                std.log.warn(
                    "[LT-WRITE-MISMATCH] slot={d} pk={s} owner={s} lam_applied={d} lam_committed={d} dlen_committed={d} applied_new_lt={x:0>16} committed_lt={x:0>16} applied_dsha8={s} committed_dsha8={s}",
                    .{ slot, &pk_hex, &owner_hex, cap.applied_lamports, lam_committed, dlen_committed, applied_u64, committed_u64, "skip(UAF)", &cd_hex },
                );
            }

            // ── OLD-side check: captured first_old_lt vs TRUE parent pre-state ──
            // Read the account AS OF the parent (excludes bank.slot's write). The
            // TRUE pre-state contribution = accountLtHash(parent readback), or
            // LtHash.init() for a zero-lamport/missing parent (genuinely new acct).
            if (parent_slot_opt) |parent_slot| {
                const parent_view = self.getAccountInSlot(&pk, parent_slot, ancestors);
                var true_old_lt = crypto.LtHash.init();
                var lam_parent: u64 = 0;
                var owner_parent: [32]u8 = [_]u8{0} ** 32;
                if (parent_view) |pv| {
                    if (pv.lamports != 0) {
                        true_old_lt = Bank.accountLtHash(&pk.data, &pv.owner.data, pv.lamports, pv.executable, pv.data);
                    }
                    lam_parent = pv.lamports;
                    owner_parent = pv.owner.data;
                }

                if (!std.mem.eql(u8, cap.first_old_lt.asBytes(), true_old_lt.asBytes())) {
                    old_mismatch += 1;
                    const captured_old_u64 = std.mem.readInt(u64, cap.first_old_lt.asBytes()[0..8], .big);
                    const true_old_u64 = std.mem.readInt(u64, true_old_lt.asBytes()[0..8], .big);
                    const pk_hex = std.fmt.bytesToHex(&cap.pubkey, .lower);
                    const owner_hex = std.fmt.bytesToHex(&owner_parent, .lower);
                    std.log.warn(
                        "[LT-OLD-MISMATCH] slot={d} pk={s} owner={s} parent_slot={d} lam_parent={d} had_old={} captured_old_lt={x:0>16} true_old_lt={x:0>16}",
                        .{ slot, &pk_hex, &owner_hex, parent_slot, lam_parent, cap.had_old, captured_old_u64, true_old_u64 },
                    );
                }
            }
        }

        // ── DROPPED / PHANTOM set-diff (bank.slot ring bucket vs capture) ──────
        // Ring-key NOT captured → committed but no accumulator contribution
        // (DROPPED). Capture-key NOT in ring → contribution applied but not in the
        // committed ring writeset (PHANTOM). Scope = bank.slot ONLY (capture is
        // bank.slot-scoped; ancestor keys would fabricate diffs). Both sides are
        // normalized to core.Pubkey to avoid the [32]u8-vs-Pubkey key mismatch.
        var ring_keys = std.ArrayListUnmanaged(core.Pubkey){};
        defer ring_keys.deinit(self.allocator);
        self.unrooted_ring.collectSlotKeys(slot, &ring_keys, self.allocator);

        // Capture set as a hash set of core.Pubkey for O(1) membership.
        var cap_set = std.AutoHashMap(core.Pubkey, void).init(self.allocator);
        defer cap_set.deinit();
        for (writes) |cap| {
            cap_set.put(core.Pubkey{ .data = cap.pubkey }, {}) catch {};
        }
        // Ring set for the reverse direction (capture-key not in ring).
        var ring_set = std.AutoHashMap(core.Pubkey, void).init(self.allocator);
        defer ring_set.deinit();
        for (ring_keys.items) |rk| ring_set.put(rk, {}) catch {};

        var dropped: usize = 0;
        for (ring_keys.items) |rk| {
            if (cap_set.contains(rk)) continue;
            dropped += 1;
            // committed lamports for context (fork-aware readback @ bank.slot).
            var pk = rk;
            const committed = self.getAccountInSlot(&pk, slot, ancestors);
            var lam_committed: u64 = 0;
            var owner_committed: [32]u8 = [_]u8{0} ** 32;
            if (committed) |v| {
                lam_committed = v.lamports;
                owner_committed = v.owner.data;
            }
            const pk_hex = std.fmt.bytesToHex(&rk.data, .lower);
            const owner_hex = std.fmt.bytesToHex(&owner_committed, .lower);
            std.log.warn(
                "[LT-DROPPED-WRITE] slot={d} pk={s} owner={s} lam_committed={d}",
                .{ slot, &pk_hex, &owner_hex, lam_committed },
            );
        }

        var phantom: usize = 0;
        for (writes) |cap| {
            const cpk = core.Pubkey{ .data = cap.pubkey };
            if (ring_set.contains(cpk)) continue;
            phantom += 1;
            const pk_hex = std.fmt.bytesToHex(&cap.pubkey, .lower);
            std.log.warn(
                "[LT-PHANTOM-WRITE] slot={d} pk={s}",
                .{ slot, &pk_hex },
            );
        }

        std.log.warn(
            "[LT-WRITE-SUMMARY] slot={d} writes={d} mismatches={d}",
            .{ slot, writes.len, mismatches },
        );
        std.log.warn(
            "[LT-OLD-SUMMARY] slot={d} writes={d} ring_keys={d} old_mismatch={d} dropped={d} phantom={d}",
            .{ slot, writes.len, ring_keys.items.len, old_mismatch, dropped, phantom },
        );
    }

    /// Write `account` at `(slot, pubkey)` into the sig overlay. Returns the
    /// LtHash delta (old/new) the caller applies to `bank.accounts_lthash`.
    ///
    /// `old_lt` is computed INTERNALLY by reading via the ancestor-aware
    /// path, so callers cannot get the pre-state wrong. This is the
    /// structural fix for the PR-A.2 Vote regression.
    ///
    /// `account.data` ownership: the overlay clones the slice internally
    /// (allocates via `self.allocator`). Callers retain ownership of their
    /// input slice and can free it after `writeAccountAtSlot` returns.
    pub fn writeAccountAtSlot(
        self: *Self,
        slot: core.Slot,
        ancestors: []const core.Slot,
        pubkey: *const core.Pubkey,
        account: sig_overlay_mod.Account,
    ) !LtHashDelta {
        // Compute old_lt from pre-write state via ancestor-aware read.
        const Bank = @import("vex_svm").bank.Bank;
        const pre = self.getAccountInSlot(pubkey, slot, ancestors);
        const old_lt = if (pre) |p|
            Bank.accountLtHash(&pubkey.data, &p.owner.data, p.lamports, p.executable, p.data)
        else
            crypto.lthash.LtHashValue.init();

        // Compute new_lt from post-write state.
        const new_lt = Bank.accountLtHash(&pubkey.data, &account.owner.data, account.lamports, account.executable, account.data);

        // Clone data into overlay-owned allocation (overlay takes ownership).
        const owned_data = if (account.data.len > 0) blk: {
            const copy = try self.allocator.alloc(u8, account.data.len);
            @memcpy(copy, account.data);
            break :blk @as([]const u8, copy);
        } else @as([]const u8, &[_]u8{});

        try self.sig_overlay.put(self.allocator, slot, pubkey.*, .{
            .lamports = account.lamports,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
            .data = owned_data,
        });

        return .{ .old = old_lt, .new = new_lt };
    }

    /// Promote a rooted slot's sig_overlay entries into the AppendVec rooted
    /// layer, then purge that slot's overlay bucket AND all sibling buckets
    /// for the same root advancement (slots in (prev_root..root_slot] that
    /// were never promoted because they were orphaned).
    ///
    /// Phase 1: defined but not wired. Phase 4 rip routes the existing
    /// `advanceRoot` flush through this entrypoint.
    pub fn updateRoot(self: *Self, root_slot: core.Slot, prev_root: core.Slot) !void {
        const Ctx = struct {
            db: *Self,
            slot: core.Slot,
            failed: bool = false,
        };
        var ctx = Ctx{ .db = self, .slot = root_slot };

        const Visitor = struct {
            fn visit(c: *Ctx, pk: core.Pubkey, acct: sig_overlay_mod.Account) void {
                const account_for_write = Account{
                    .lamports = acct.lamports,
                    .owner = acct.owner,
                    .executable = acct.executable,
                    .rent_epoch = acct.rent_epoch,
                    .data = acct.data,
                };
                const location = c.db.storage.writeAccount(&pk, &account_for_write, c.slot) catch {
                    c.failed = true;
                    return;
                };
                c.db.index.insert(&pk, location) catch {
                    c.failed = true;
                };
            }
        };

        self.sig_overlay.forEachInSlot(root_slot, &ctx, Visitor.visit);
        self.sig_overlay.purgeSlot(self.allocator, root_slot);

        // Purge sibling/skipped slots in (prev_root..root_slot]. Their state
        // is dead (orphan or never promoted) and must not pollute future reads.
        var s: core.Slot = prev_root + 1;
        while (s < root_slot) : (s += 1) {
            self.sig_overlay.purgeSlot(self.allocator, s);
        }
    }

    /// FIX #105 (Option A, Step 1): promote a newly-rooted ANCESTOR chain's
    /// fork-aware `sig_overlay` entries into the fork-blind `unflushed_cache` +
    /// `cache_slot_map`. This is the write-side fork-isolation fix — the
    /// structural analog of Firedancer funk's publish (promote winner's records
    /// into root) and Agave's defer-durable-write-until-root.
    ///
    /// WHY: during replay, a sibling fork (e.g. slot 514, parent 510) and the
    /// main chain (slot 513) both write the same pubkey. `sig_overlay` keeps
    /// them apart (keyed by slot), but the prior fork-blind replay-flush writes
    /// `unflushed_cache[pk]` last-write-wins — so the sibling's value can
    /// pollute the flat cache and surface for a later main-chain reader (the
    /// slot-733 / CRnk carrier). Promoting the ANCESTOR slot's sig_overlay
    /// value overwrites that pollution with the per-fork-correct value.
    ///
    /// CONTRACT:
    ///   - `rooted_chain` MUST be the slots in (prev_root, new_root] that are
    ///     genuine ancestors of `new_root`, in ASCENDING slot order. Ascending
    ///     order makes the highest ancestor slot win per-pubkey (mirrors Agave
    ///     `AccountsIndex::latest_slot`). Callers prove ancestry via a parent-
    ///     pointer walk; on any uncertainty they MUST omit the slot (never pass
    ///     a non-ancestor here — that would promote a sibling's value).
    ///   - Call BEFORE `advanceRoot` so the promoted (correct) values are what
    ///     advanceRoot evicts to AppendVec, AND BEFORE purging sibling slots so
    ///     the reset `cache_slot_map[pk] = ancestor_slot` makes the sibling
    ///     purge's `csm == sibling_slot` guard skip shared pubkeys.
    ///   - Entries are promoted VERBATIM, including zero-lamport accounts: a
    ///     zero-lamport entry in `unflushed_cache` correctly tombstone-shadows a
    ///     stale older AppendVec value rather than letting it resurface.
    ///
    /// Lock discipline mirrors `purgeUnrootedSlot`: two passes, never holding
    /// the sig_overlay per-slot RwLock and `unflushed_cache_lock` at once
    /// (flushPendingWritesToDb takes them unflushed→sig_overlay; we must not
    /// nest them sig_overlay→unflushed in the opposite order).
    pub fn promoteRootedChain(self: *Self, rooted_chain: []const u64) void {
        const data_alloc = std.heap.page_allocator;

        const Collected = struct { pk: core.Pubkey, acct: Account };
        const CollectCtx = struct {
            list: *std.ArrayListUnmanaged(Collected),
            alloc: std.mem.Allocator,
            fn visit(ctx: *@This(), pk: core.Pubkey, acct: sig_overlay_mod.Account) void {
                const data_copy = if (acct.data.len > 0) blk: {
                    const cp = ctx.alloc.alloc(u8, acct.data.len) catch return;
                    @memcpy(cp, acct.data);
                    break :blk @as([]const u8, cp);
                } else @as([]const u8, &[_]u8{});
                ctx.list.append(ctx.alloc, .{ .pk = pk, .acct = .{
                    .lamports = acct.lamports,
                    .owner = acct.owner,
                    .executable = acct.executable,
                    .rent_epoch = acct.rent_epoch,
                    .data = data_copy,
                } }) catch {
                    if (data_copy.len > 0) ctx.alloc.free(@constCast(data_copy));
                };
            }
        };

        for (rooted_chain) |s| {
            // Pass 1: collect this rooted slot's writes (owned copies) under the
            // sig_overlay per-slot RwLock (held inside forEachInSlot).
            var collected = std.ArrayListUnmanaged(Collected){};
            defer {
                for (collected.items) |c| {
                    if (c.acct.data.len > 0) data_alloc.free(@constCast(c.acct.data));
                }
                collected.deinit(data_alloc);
            }
            var cctx = CollectCtx{ .list = &collected, .alloc = data_alloc };
            self.sig_overlay.forEachInSlot(s, &cctx, CollectCtx.visit);
            if (collected.items.len == 0) continue;

            // Pass 2: write into the fork-blind unflushed_cache + cache_slot_map
            // under unflushed_cache_lock. Mirrors flushPendingWritesToDb's write
            // pattern (free-old-on-overwrite, page_allocator-owned copy, cache
            // invalidation) so the AppendVec eviction in advanceRoot persists the
            // correct value.
            self.unflushed_cache_lock.lock();
            defer self.unflushed_cache_lock.unlock();
            for (collected.items) |c| {
                // PROMOTE-DIAG (2026-05-28): detect REGRESSION — promoting slot
                // `s`'s value over a cache entry whose cache_slot_map slot is
                // NEWER (> s) AND whose lamports differ. This overwrites a more-
                // recent flushed value with an older rooted value = the suspected
                // slot-564 carrier (hazard #2). Logging-only; the put still runs.
                if (recorder.promoteDiagOn()) {
                    if (self.cache_slot_map.get(c.pk)) |prev_csm| {
                        if (prev_csm > s) {
                            const old_lam: ?u64 = if (self.unflushed_cache.get(c.pk)) |a| a.lamports else null;
                            if (old_lam != null and old_lam.? != c.acct.lamports and recorder.promoteDiagTick()) {
                                // chain-membership split (advisor 2026-05-29): if
                                // prev_csm ∈ rooted_chain it is re-promoted later in
                                // THIS ascending call → INCHAIN (benign-transient,
                                // self-corrects). Else AHEAD = a replay-ahead value
                                // NOT rooted in this advance → the regress persists
                                // until a future advance reaches prev_csm; a slot that
                                // freezes in that window locks a wrong bank_hash =
                                // capable-of-harm. This split is what tells us whether
                                // the heavy-catch-up REGRESS volume is the carrier.
                                var inchain = false;
                                for (rooted_chain) |cc| {
                                    if (cc == prev_csm) {
                                        inchain = true;
                                        break;
                                    }
                                }
                                std.log.warn("[PROMOTE-DIAG][REGRESS][{s}] pk={x}{x}{x}{x} promote_slot={d} cached_slot={d} cached_lam={?d} promoted_lam={d}", .{ if (inchain) "INCHAIN" else "AHEAD", c.pk.data[0], c.pk.data[1], c.pk.data[2], c.pk.data[3], s, prev_csm, old_lam, c.acct.lamports });
                            }
                        }
                    }
                }
                const owned = if (c.acct.data.len > 0) blk: {
                    const cp = data_alloc.alloc(u8, c.acct.data.len) catch continue;
                    @memcpy(cp, c.acct.data);
                    break :blk @as([]const u8, cp);
                } else @as([]const u8, &[_]u8{});
                if (self.unflushed_cache.get(c.pk)) |old| {
                    if (old.data.len > 0) data_alloc.free(@constCast(old.data));
                }
                self.unflushed_cache.put(c.pk, .{
                    .lamports = c.acct.lamports,
                    .owner = c.acct.owner,
                    .executable = c.acct.executable,
                    .rent_epoch = c.acct.rent_epoch,
                    .data = owned,
                }) catch {
                    if (owned.len > 0) data_alloc.free(@constCast(owned));
                    continue;
                };
                self.cache_slot_map.put(c.pk, s) catch {};
                self.cache.invalidate(&c.pk);

                // CANONICAL CHOKEPOINT (2026-06-04): refresh top_votes at THIS db
                // landing. This is the tip-active / catch-up-dormant root-advance
                // re-promotion that the old scattered refreshTopVotes sites missed
                // → the feed-staleness-at-tip carrier. write_slot = `s` (rooted
                // slot); it survives the subsequent advanceRoot pruneBelowRoot as
                // the kept baseline (ws<=new_root). Use the promoted value `c.acct`
                // (the canonical sig_overlay value committed to the flat cache).
                self.refreshTopVoteForWrite(c.pk.data, c.acct.owner.data, c.acct.data, c.acct.lamports, s);
            }
        }
    }

    /// FIX #105: record a slot's parent link durably (survives bank pruning).
    /// Called from replay_stage when a bank is inserted into the live tree.
    /// Idempotent; cheap (single hashmap put under a brief write lock).
    pub fn recordSlotParent(self: *Self, slot: u64, parent: u64) void {
        self.slot_parents_lock.lock();
        defer self.slot_parents_lock.unlock();
        self.slot_parents.put(slot, parent) catch {};
    }

    /// CARRIER #7 LAYER 2 (2026-06-10): TRUE iff `candidate_root` lies on the
    /// parent-chain ancestry of `voted_slot` per the DURABLE slot_parents map
    /// (the same source computeRootPartition trusts), or is already at/below
    /// the current rooted_slot (the rooted prefix is linear). Used by
    /// replay_stage's root-advance guard: a tower root NOT on the just-voted
    /// bank's ancestry is an abandoned-fork slot — advancing to it would
    /// promote the fork's writes into the rooted store and PURGE the canonical
    /// siblings (the 414406146 poison). Conservative: broken/over-long chains
    /// return false → caller refuses the advance (retried on the next vote).
    pub fn isRootOnVotedAncestry(self: *Self, candidate_root: u64, voted_slot: u64) bool {
        if (candidate_root <= self.rooted_slot) return true; // rooted prefix
        self.slot_parents_lock.lockShared();
        defer self.slot_parents_lock.unlockShared();
        const Ctx = struct {
            m: *const std.AutoHashMap(u64, u64),
            pub fn getParent(c: @This(), s: u64) ?u64 {
                return c.m.get(s);
            }
        };
        return root_partition.rootOnVotedAncestry(
            Ctx{ .m = &self.slot_parents },
            candidate_root,
            voted_slot,
        );
    }

    /// FIX #105: build the root-advance partition (rooted-ancestor chain +
    /// proven abandoned siblings) from the DURABLE slot→parent map — NOT the
    /// live bank tree, which prunes unrooted banks during catch-up and severs
    /// the ancestry walk (the slot-564 incomplete-chain carrier). Caller owns
    /// the returned RootPartition and MUST `deinit(alloc)` it. Returns null on
    /// allocation failure → caller then promotes/purges NOTHING (conservative:
    /// never destroy rooted data on uncertainty).
    pub fn computeRootPartition(self: *Self, alloc: std.mem.Allocator, prev_root: u64, root: u64) ?root_partition.RootPartition {
        // Snapshot the durable parent links for slots in (prev_root, root].
        var snap = std.ArrayListUnmanaged(root_partition.SlotParent){};
        defer snap.deinit(alloc);
        {
            self.slot_parents_lock.lockShared();
            defer self.slot_parents_lock.unlockShared();
            var it = self.slot_parents.iterator();
            while (it.next()) |e| {
                if (e.key_ptr.* > prev_root and e.key_ptr.* <= root) {
                    snap.append(alloc, .{ .slot = e.key_ptr.*, .parent = e.value_ptr.* }) catch return null;
                }
            }
        }
        return root_partition.partitionRootAdvance(alloc, prev_root, root, snap.items) catch null;
    }

    /// FIX #105: drop durable parent links at/below `rooted` — once a slot is
    /// rooted its ancestry is permanent and no future (root, next_root] walk
    /// descends below it, so the link is dead weight. Bounds the map. Called
    /// at the end of advanceRoot.
    fn pruneSlotParentsBelow(self: *Self, rooted: u64) void {
        self.slot_parents_lock.lock();
        defer self.slot_parents_lock.unlock();
        var to_drop = std.ArrayListUnmanaged(u64){};
        defer to_drop.deinit(std.heap.page_allocator);
        var it = self.slot_parents.iterator();
        while (it.next()) |e| {
            if (e.key_ptr.* <= rooted) to_drop.append(std.heap.page_allocator, e.key_ptr.*) catch {};
        }
        for (to_drop.items) |s| _ = self.slot_parents.remove(s);
    }

    /// Phase 2c-B conservative root-advance hook. Used ALONGSIDE the existing
    /// `advanceRoot` (which evicts unflushed_cache → AppendVec). This purges
    /// the per-slot sig_overlay for the newly-rooted slot AND any sibling
    /// slots in (prev_root..root_slot) that were never promoted (orphans).
    ///
    /// Does NOT call storage.writeAccount — that path is already handled by
    /// `advanceRoot` (legacy unflushed_cache → AppendVec eviction). This
    /// avoids the double-AppendVec-write hazard when sig_overlay mirrors
    /// the unflushed_cache writes (Phase 2c-B conservative mode).
    pub fn purgeRootedSlot(self: *Self, root_slot: core.Slot, prev_root: core.Slot, chain_complete: bool) void {
        // Purge the newly-rooted slot's overlay bucket — its writes are now
        // permanent in AppendVec via advanceRoot's eviction path.
        self.sig_overlay.purgeSlot(self.allocator, root_slot);

        // FIX #105 (#3, purge-only-when-proven gate): only raw-range-purge the
        // intervening (prev_root..root_slot) slots when the ancestor walk was
        // PROVEN complete. If it was incomplete (a durable-map gap left the
        // chain partial), an un-promoted rooted ANCESTOR could still be sitting
        // in that range; purging it would destroy data that promote never
        // recovered — exactly the slot-564 carrier. On uncertainty, retain
        // those buckets (accept residual pollution; a later complete advance
        // can still promote them). With the durable slot_parents map the chain
        // is complete in the common case, so this only changes the rare gap path.
        if (chain_complete and prev_root < root_slot) {
            var s: core.Slot = prev_root + 1;
            while (s < root_slot) : (s += 1) {
                self.sig_overlay.purgeSlot(self.allocator, s);
            }
        }
    }

    /// Fork-isolation: drop all writes for `slot` from the overlay. Called by
    /// replay_stage `markSlotDead` so an orphan slot's pre-state debits never
    /// pollute canonical-fork reads. No-op when fork-isolation is disabled.
    pub fn purgeUnrootedSlot(self: *Self, slot: u64) void {
        // 2026-05-18: drop the UnrootedRing bucket for this slot. Clean
        // single-call free; the ring's per-slot keying makes this O(1) for
        // the bucket lookup + the bucket's entries free. Idempotent: if the
        // bucket was already recycled by a later slot, dropSlot is a no-op.
        self.unrooted_ring.dropSlot(slot);

        // Phase 2c-B: sig_overlay purge runs UNCONDITIONALLY (sig_overlay is
        // unconditionally active per the field doc at L271). Legacy
        // unrooted_overlay purge stays gated by fork_isolation_enabled.
        if (self.fork_isolation_enabled) {
            self.unrooted_overlay_lock.lock();
            defer self.unrooted_overlay_lock.unlock();

            if (self.unrooted_overlay.fetchRemove(slot)) |kv| {
                var inner = kv.value;
                var inner_iter = inner.iterator();
                while (inner_iter.next()) |e| {
                    if (e.value_ptr.data.len > 0) {
                        std.heap.page_allocator.free(@constCast(e.value_ptr.data));
                    }
                }
                inner.deinit();
                std.heap.page_allocator.destroy(inner);
                std.log.warn("[FORK-ISO] purged unrooted overlay for slot={d}", .{slot});
            }
        }

        // Phase H (2026-05-17): also purge unflushed_cache + cache_slot_map for
        // pubkeys this orphan slot wrote. Phase D recorder oracle (slot 408970284
        // analysis) proved this is the residual post-Phase-E iter-6 carrier:
        // pubkey 5920b04aead08f97 was first-touched by orphan slot 408970288;
        // sig_overlay correctly returned null (no canonical ancestor wrote it)
        // but unflushed_cache fall-through returned the orphan-polluted value
        // (+77,600 lamports off from cluster). Phase E populated sig_overlay
        // for orphan writes; that helped MOST iter-6 cases (98.7% reduction)
        // but for accounts ONLY-touched-by-orphan, removing sig_overlay alone
        // leaves unflushed_cache as the polluting source.
        //
        // Two-pass under separate locks: collect orphan pubkeys via
        // sig_overlay.forEachInSlot (per-slot RwLock), then take
        // unflushed_cache_lock and remove. Avoids lock-order issues. Only
        // remove from unflushed_cache when cache_slot_map[pk] == slot — if a
        // later canonical write set csm[pk] = newer_slot, the orphan doesn't
        // own the entry anymore, leave it alone.
        {
            var orphan_pks = std.ArrayListUnmanaged(core.Pubkey){};
            defer orphan_pks.deinit(std.heap.page_allocator);

            const CollectCtx = struct { list: *std.ArrayListUnmanaged(core.Pubkey) };
            var collect_ctx = CollectCtx{ .list = &orphan_pks };
            self.sig_overlay.forEachInSlot(slot, &collect_ctx, struct {
                fn visit(ctx: *CollectCtx, pk: core.Pubkey, _: sig_overlay_mod.Account) void {
                    ctx.list.append(std.heap.page_allocator, pk) catch {};
                }
            }.visit);

            if (orphan_pks.items.len > 0) {
                self.unflushed_cache_lock.lock();
                defer self.unflushed_cache_lock.unlock();
                var removed: u32 = 0;
                for (orphan_pks.items) |pk| {
                    const csm = self.cache_slot_map.get(pk) orelse continue;
                    if (csm != slot) continue;
                    if (self.unflushed_cache.get(pk)) |acct| {
                        if (acct.data.len > 0) {
                            std.heap.page_allocator.free(@constCast(acct.data));
                        }
                    }
                    _ = self.unflushed_cache.remove(pk);
                    _ = self.cache_slot_map.remove(pk);
                    self.cache.invalidate(&pk);
                    removed += 1;
                }
                if (removed > 0) {
                    std.log.warn("[FORK-ISO] purged unflushed_cache for slot={d}: {d}/{d} pubkeys (where csm still matched orphan slot)", .{ slot, removed, orphan_pks.items.len });
                }
            }
        }

        // PR-S2 Phase 2b: mirror purge to sig_overlay so dead-slot writes don't
        // leak into canonical-fork reads via the new API. Phase 2c-B: always
        // active regardless of fork_isolation_enabled flag.
        self.sig_overlay.purgeSlot(self.allocator, slot);
    }

    /// Flush a portion of the unflushed cache to disk (AppendVec storage).
    /// Called periodically to prevent unbounded RAM growth on long runs.
    /// Writes up to `max_entries` from the cache, updates the index, and frees the cache entries.
    pub fn flushCacheToDisk(self: *Self, slot: core.Slot, max_entries: usize) !u64 {
        self.unflushed_cache_lock.lock();
        defer self.unflushed_cache_lock.unlock();

        var flushed: u64 = 0;
        var to_remove = std.ArrayListUnmanaged(core.Pubkey){};
        defer to_remove.deinit(std.heap.page_allocator);

        var iter = self.unflushed_cache.iterator();
        while (iter.next()) |entry| {
            if (flushed >= max_entries) break;
            const pk = entry.key_ptr.*;
            const acct = entry.value_ptr.*;
            const acct_for_write = Account{
                .lamports = acct.lamports,
                .owner = acct.owner,
                .executable = acct.executable,
                .rent_epoch = acct.rent_epoch,
                .data = @constCast(acct.data),
            };
            const location = self.storage.writeAccount(&pk, &acct_for_write, slot) catch continue;
            self.index.insert(&pk, location) catch continue;
            // DURABLE-CAM (FIX #95, 2026-05-31): flushCacheToDisk is the OTHER
            // durable-filing path; same fields as the advanceRoot EVICT cam so a
            // carrier reached via either path is captured. Log-only, gated + capped.
            if (recorder.durableCamOn()) {
                const cam_ws: u64 = self.cache_slot_map.get(pk) orelse slot;
                if ((slot -| cam_ws) >= recorder.durableCamGap() and recorder.durableCamTick()) {
                    std.log.warn("[DURABLE-CAM][FLUSH] pk={x}{x}{x}{x} lam={d} write_slot={d} label={d} hit=1", .{ pk.data[0], pk.data[1], pk.data[2], pk.data[3], acct.lamports, cam_ws, slot });
                }
            }
            to_remove.append(std.heap.page_allocator, pk) catch continue;
            flushed += 1;
        }

        for (to_remove.items) |pk| {
            if (self.unflushed_cache.get(pk)) |acct| {
                if (acct.data.len > 0) {
                    std.heap.page_allocator.free(@constCast(acct.data));
                }
            }
            _ = self.unflushed_cache.remove(pk);
            _ = self.cache_slot_map.remove(pk);
            // r75-bug-class-b-cache-invalidate (2026-05-06): see AccountCache.invalidate
            // doc-comment. Without this, slot-200 Config mutations get persisted to
            // AppendVec via writeAccount + index.insert above, but the LRU read
            // cache still holds snapshot bytes — every subsequent getAccount call
            // returns stale state, ConstraintRaw 2003 fires for every GJHt
            // ChangeTipReceiver from slot ~220 onwards, 9 PDA writes/slot missing
            // → bank_hash diverges. Carrier of all post-slot-200 parity failures.
            self.cache.invalidate(&pk);
        }

        if (flushed > 0) {
            const FlushDbg = struct { var count: u64 = 0; };
            FlushDbg.count += 1;
            if (FlushDbg.count <= 3 or FlushDbg.count % 10 == 0) {
                std.log.debug("[ACCOUNTS] Flushed {d} entries to disk, cache={d}\n", .{
                    flushed, self.unflushed_cache.count(),
                });
            }
        }
        return flushed;
    }

    /// Store an account
    pub fn storeAccount(self: *Self, pubkey: *const core.Pubkey, account: *const Account, slot: core.Slot) !void {
        // Write to storage
        const location = try self.storage.writeAccount(pubkey, account, slot);

        // Update index
        try self.index.insert(pubkey, location);

        // Update cache
        if (self.storage.readAccount(location)) |stored| {
            try self.cache.insert(pubkey, stored);
        }
    }

    pub const AccountWrite = struct {
        pubkey: core.Pubkey,
        account: Account,
        old_lt: ?crypto.lthash.LtHashValue = null,
        new_lt: ?crypto.lthash.LtHashValue = null,
    };

    /// Store multiple accounts atomically (at index level)
    pub fn storeAccounts(self: *Self, accounts: []const AccountWrite, slot: core.Slot) !void {
        var batch_entries = try std.ArrayListUnmanaged(AccountIndex.BatchEntry).initCapacity(self.allocator, accounts.len);
        defer batch_entries.deinit(self.allocator);

        for (accounts) |*write| {
            // Write to storage
            const location = try self.storage.writeAccount(&write.pubkey, &write.account, slot);

            // Add to batch
            try batch_entries.append(self.allocator, .{
                .pubkey = write.pubkey,
                .location = location,
            });

            // Update cache
            if (self.storage.readAccount(location)) |stored| {
                try self.cache.insert(&write.pubkey, stored);
            }
        }

        // Atomic index update
        try self.index.upsertBatch(batch_entries.items);
    }

    /// Fast bulk store for snapshot loading - skips cache and shadow
    /// This is optimized for initial loading when we don't need caching
    /// Pre-serializes account data outside the lock for better throughput
    pub fn storeAccountBulk(self: *Self, pubkey: *const core.Pubkey, account: *const Account, slot: core.Slot) !void {
        // Serialize outside the lock (this is the expensive part)
        const data = try self.storage.serializeAccountToBytes(pubkey, account);
        defer self.allocator.free(data);

        // Write with minimal lock time
        const location = try self.storage.writeAccountBytes(data, slot);

        // Update index only - skip cache during bulk load
        try self.index.insert(pubkey, location);
    }

    /// Bulk store with a REUSABLE buffer — zero-allocation hot path.
    /// The caller provides a persistent ArrayList(u8) that is cleared and reused
    /// for each account, eliminating heap thrashing during snapshot loading.
    pub fn storeAccountBulkReuse(self: *Self, pubkey: *const core.Pubkey, account: *const Account, slot: core.Slot, reuse_buf: *std.ArrayListUnmanaged(u8)) !void {
        // Serialize into the reusable buffer (no allocation unless it grows)
        reuse_buf.clearRetainingCapacity();
        try reuse_buf.appendSlice(self.allocator, &pubkey.data);
        try reuse_buf.writer(self.allocator).writeInt(u64, account.lamports, .little);
        try reuse_buf.appendSlice(self.allocator, &account.owner.data);
        try reuse_buf.append(self.allocator, @intFromBool(account.executable));
        try reuse_buf.writer(self.allocator).writeInt(u64, account.rent_epoch, .little);
        try reuse_buf.writer(self.allocator).writeInt(u32, @intCast(account.data.len), .little);
        try reuse_buf.appendSlice(self.allocator, account.data);

        // Write with retry — under 31-thread contention, AppendVecFull can
        // slip through even after writeAccountBytes' internal rotation.
        // A brief yield lets the storage layer create a new store.
        var location: AccountLocation = undefined;
        var retries: u32 = 0;
        while (retries < 3) : (retries += 1) {
            location = self.storage.writeAccountBytes(reuse_buf.items, slot) catch |err| {
                if (retries < 2) {
                    std.Thread.yield() catch {};
                    continue;
                }
                return err;
            };
            break;
        }

        // Update index only - skip cache during bulk load
        try self.index.insert(pubkey, location);
    }

    /// Enable bulk loading mode - uses faster code paths for initial snapshot loading
    pub fn enableBulkLoading(self: *Self) void {
        self.bulk_loading_mode = true;
        self.storage.bulk_mode = true;
    }

    /// Disable bulk loading mode and switch to normal operation
    pub fn disableBulkLoading(self: *Self) void {
        self.bulk_loading_mode = false;
        self.storage.bulk_mode = false;
    }

    /// Register mmap'd Agave-format AppendVec data and return the store_id.
    /// The AppendVec will be read-only and use Agave record layout for getAccount().
    pub fn registerAgaveMmap(self: *Self, data: []u8, file_size: u64) !u32 {
        return self.storage.registerAgaveMmap(data, file_size);
    }

    fn parseEnvU64(allocator: std.mem.Allocator, name: []const u8, default_value: u64) !u64 {
        const raw = std.process.getEnvVarOwned(allocator, name) catch return default_value;
        defer allocator.free(raw);
        return std.fmt.parseInt(u64, raw, 10);
    }

    /// Get multiple accounts (batch). PR-S4: bootstrap-only, no ancestors required.
    /// No production tx-replay caller — preserved for snapshot/RPC convenience.
    pub fn getAccounts(self: *Self, pubkeys: []const core.Pubkey, results: []?AccountView) usize {
        var found: usize = 0;
        for (pubkeys, 0..) |*pubkey, i| {
            if (self._getRooted(pubkey)) |account| {
                results[i] = account;
                found += 1;
            } else {
                results[i] = null;
            }
        }
        return found;
    }

    /// Clean zero-lamport accounts for a slot
    pub fn cleanZeroLamports(self: *Self, slot: core.Slot) void {
        self.storage.lock.lockShared();
        defer self.storage.lock.unlockShared();
        self.index.removeIf(slot, &self.storage);
    }

    /// Purge a slot's storage and index entries
    pub fn purgeSlot(self: *Self, slot: core.Slot) void {
        self.index.removeSlot(slot);
        self.storage.purgeSlot(slot);
    }

    pub fn tickAccountsGc(self: *Self, current_slot: core.Slot, now_ms: u64) void {
        // BGSAVE CoW quiesce: while a forked snapshot child is alive, defer ALL
        // gc (clean/purge/reap; shrink is additionally gated inside shrinkSlot).
        // This is the LIVE gc entry point (replay_stage + rpc); the checks in
        // tickAccountsPurge/tickAccountsClean guard uncalled code paths.
        if (self.gc_quiesce.load(.acquire)) return;
        self.refreshGcSlots(now_ms) catch {};
        if (self.accounts_gc_slots.items.len == 0) return;
        const safe_slot = self.safeSlot(current_slot);
        const batch = @min(self.accounts_gc_batch, self.accounts_gc_slots.items.len);
        var i: usize = 0;
        while (i < batch) : (i += 1) {
            if (self.accounts_gc_cursor >= self.accounts_gc_slots.items.len) {
                self.accounts_gc_cursor = 0;
            }
            const slot = self.accounts_gc_slots.items[self.accounts_gc_cursor];
            self.accounts_gc_cursor += 1;
            if (slot > safe_slot) continue;
            if (self.accounts_clean_enabled and slot > 0 and slot != self.accounts_clean_last_slot) {
                if (safe_slot > self.accounts_clean_age_slots and slot <= safe_slot - self.accounts_clean_age_slots) {
                    self.cleanZeroLamports(slot);
                    self.accounts_clean_last_slot = slot;
                }
            }
            if (self.accounts_shrink_enabled and slot > 0 and slot != self.accounts_shrink_last_slot) {
                const did = self.shrinkSlot(
                    slot,
                    self.accounts_shrink_ratio_percent,
                    self.accounts_shrink_min_bytes,
                    self.accounts_shrink_hysteresis_percent,
                ) catch false;
                if (did) {
                    std.log.info("[AccountsDb] shrink completed slot={d}", .{slot});
                    self.accounts_shrink_last_slot = slot;
                }
            }
            if (self.accounts_purge_enabled and slot > 0) {
                if (safe_slot > self.accounts_purge_age_slots and slot <= safe_slot - self.accounts_purge_age_slots) {
                    self.purgeSlot(slot);
                }
            }
        }
        // Task #71: free retired stores whose quarantine window has expired.
        self.storage.reapRetired(self.rooted_slot, self.accounts_store_quarantine_slots);
    }

    pub fn flushAccountsMetadata(self: *Self) void {
        self.storage.flushMetadata();
    }

    fn refreshGcSlots(self: *Self, now_ms: u64) !void {
        if (self.accounts_gc_scan_interval_ms == 0) return;
        if (self.accounts_gc_last_scan_ms != 0 and now_ms - self.accounts_gc_last_scan_ms < self.accounts_gc_scan_interval_ms) {
            return;
        }
        self.accounts_gc_last_scan_ms = now_ms;
        self.accounts_gc_slots.clearRetainingCapacity();
        self.storage.lock.lock();
        var iter = self.storage.slot_to_store.iterator();
        while (iter.next()) |entry| {
            try self.accounts_gc_slots.append(self.allocator, entry.key_ptr.*);
        }
        self.storage.lock.unlock();
        std.sort.heap(core.Slot, self.accounts_gc_slots.items, {}, sortSlotAsc);
        self.accounts_gc_cursor = 0;
    }

    pub fn onSlotCompleted(self: *Self, slot: core.Slot) void {
        if (slot > self.accounts_completed_max_slot) {
            self.accounts_completed_max_slot = slot;
        }
    }

    fn safeSlot(self: *Self, current_slot: core.Slot) core.Slot {
        const max_completed = self.accounts_completed_max_slot;
        const lag = self.accounts_safe_lag_slots;
        const capped = if (max_completed > lag) max_completed - lag else 0;
        return if (capped < current_slot) capped else current_slot;
    }

    fn sortSlotAsc(_: void, a: core.Slot, b: core.Slot) bool {
        return a < b;
    }

    pub const AccountsStoreStats = struct {
        slot: core.Slot,
        store_id: u32,
        total_bytes: u64,
        live_bytes: u64,
        dead_bytes: u64,
        dead_ratio_percent: u32,
        records: u64,
        live_records: u64,
    };

    pub const AccountsStatsSummary = struct {
        total_bytes: u64,
        live_bytes: u64,
        dead_bytes: u64,
        dead_ratio_percent: u32,
        records: u64,
        live_records: u64,
    };

    pub fn collectStoreStats(self: *Self, allocator: std.mem.Allocator) !std.ArrayListUnmanaged(AccountsStoreStats) {
        const SlotStore = struct { slot: core.Slot, store_id: u32 };
        var pairs = std.ArrayListUnmanaged(SlotStore){};
        defer pairs.deinit(allocator);

        self.storage.lock.lock();
        var iter = self.storage.slot_to_store.iterator();
        while (iter.next()) |entry| {
            try pairs.append(allocator, .{
                .slot = entry.key_ptr.*,
                .store_id = entry.value_ptr.*,
            });
        }
        self.storage.lock.unlock();

        var stats = std.ArrayListUnmanaged(AccountsStoreStats){};
        for (pairs.items) |pair| {
            const store_stats = try self.computeStoreStats(pair.slot, pair.store_id);
            try stats.append(allocator, store_stats);
        }
        return stats;
    }

    pub fn computeSummary(self: *Self, stores: []const AccountsStoreStats) AccountsStatsSummary {
        _ = self;
        var total_bytes: u64 = 0;
        var live_bytes: u64 = 0;
        var dead_bytes: u64 = 0;
        var records: u64 = 0;
        var live_records: u64 = 0;
        for (stores) |s| {
            total_bytes += s.total_bytes;
            live_bytes += s.live_bytes;
            dead_bytes += s.dead_bytes;
            records += s.records;
            live_records += s.live_records;
        }
        const ratio = if (total_bytes == 0) 0 else @as(u32, @intCast(@as(u128, dead_bytes) * 100 / @as(u128, total_bytes)));
        return .{
            .total_bytes = total_bytes,
            .live_bytes = live_bytes,
            .dead_bytes = dead_bytes,
            .dead_ratio_percent = ratio,
            .records = records,
            .live_records = live_records,
        };
    }

    fn computeStoreStats(self: *Self, slot: core.Slot, store_id: u32) !AccountsStoreStats {
        self.storage.lock.lock();
        const av = self.storage.stores.get(store_id) orelse {
            self.storage.lock.unlock();
            return error.StoreNotFound;
        };
        var total_bytes: u64 = 0;
        var live_bytes: u64 = 0;
        var records: u64 = 0;
        var live_records: u64 = 0;
        var offset: u64 = av.firstRecordOffset();

        while (av.readRecord(offset)) |record| {
            total_bytes += record.total_len;
            records += 1;
            if (self.index.get(&record.pubkey)) |location| {
                if (location.store_id == store_id and location.offset == offset) {
                    live_bytes += record.total_len;
                    live_records += 1;
                }
            }
            offset += record.total_len;
        }
        self.storage.lock.unlock();

        const dead_bytes = total_bytes - live_bytes;
        const dead_ratio = if (total_bytes == 0) 0 else @as(u32, @intCast(@as(u128, dead_bytes) * 100 / @as(u128, total_bytes)));
        return .{
            .slot = slot,
            .store_id = store_id,
            .total_bytes = total_bytes,
            .live_bytes = live_bytes,
            .dead_bytes = dead_bytes,
            .dead_ratio_percent = dead_ratio,
            .records = records,
            .live_records = live_records,
        };
    }

    fn sortByDeadRatio(_: void, a: AccountsStoreStats, b: AccountsStoreStats) bool {
        return a.dead_ratio_percent > b.dead_ratio_percent;
    }

    /// Shrink an appendvec for a slot if dead ratio exceeds threshold.
    ///
    /// Task #71 (2026-06-10) REWRITE — this function had a latent
    /// index-corruption bug and an unsafe immediate-free; both fixed here:
    ///
    /// 1. SLOT-PRESERVING RE-INSERT: stores are SHARED across slots
    ///    (getOrCreateStore reuses current_bulk_store_id), so a record's true
    ///    index slot can be HIGHER than the mapping slot being shrunk. The old
    ///    code re-inserted with `.slot = slot`, which the index's
    ///    higher-slot-wins guard silently REJECTED — then the old store was
    ///    freed, leaving a dangling index entry (account vanishes). We now
    ///    carry the existing index entry's slot through unchanged.
    /// 2. QUARANTINE, not free: the old store is retired (stays readable via
    ///    stale locations / borrowed views) and only freed by reapRetired
    ///    after the root advances past the quarantine window.
    /// 3. APPEND-ACTIVE GUARD: never shrink the store still receiving appends
    ///    (current_bulk_store_id) — a record appended after our walk would be
    ///    lost when the store retires.
    /// 4. CO-MAPPED REMAP: every slot_to_store entry pointing at the old store
    ///    is remapped to the new store (or removed), so later GC passes can
    ///    never re-walk or double-shrink a retired store.
    /// 5. FULLY-DEAD FAST PATH: live_bytes == 0 retires the store without
    ///    creating a replacement.
    pub fn shrinkSlot(
        self: *Self,
        slot: core.Slot,
        dead_ratio_percent: u32,
        min_dead_bytes: u64,
        hysteresis_percent: u32,
    ) !bool {
        // fork-BGSAVE child alive: shrink rewrites whole stores (worst CoW
        // amplifier) — defer until the child exits (design §3 gc_quiesce).
        if (self.gc_quiesce.load(.acquire)) return false;
        self.storage.lock.lock();
        defer self.storage.lock.unlock(); // CRITICAL: defer guarantees unlock on ALL exit paths
        // RE-CHECK after acquiring the lock: a shrink that passed the entry
        // check and then BLOCKED on storage.lock while the bgsave fork window
        // ran would otherwise proceed the instant the parent unlocks — i.e.
        // exactly while the child is walking (check-then-block race). CoW
        // still keeps the child CORRECT (shrink never touches file-backed
        // agave_format stores — see guard below — so no truncate-SIGBUS), but
        // the store rewrite is the worst CoW amplifier; this one load closes
        // the window.
        if (self.gc_quiesce.load(.acquire)) return false;
        const store_id = self.storage.slot_to_store.get(slot) orelse {
            return false;
        };
        // Task #71 guard 3: the shared store still receiving appends must
        // never be shrunk (its walk would race its own growth).
        if (self.storage.current_bulk_store_id) |bulk_id| {
            if (store_id == bulk_id) return false;
        }
        const av = self.storage.stores.get(store_id) orelse {
            return false;
        };
        // Snapshot-mmap stores are file-backed, read-only and bounded — not
        // the leak class, and their record layout differs. Never shrink.
        if (!av.owns_data or av.agave_format) return false;

        var live_bytes: u64 = 0;
        var total_bytes: u64 = 0;
        var offset: u64 = av.firstRecordOffset();

        while (av.readRecord(offset)) |record| {
            total_bytes += record.total_len;
            const location = self.index.get(&record.pubkey);
            // ALIVE TEST = index-pointer identity (this store_id+offset is the version the
            // index resolves). Structurally == Agave is_alive (accounts_db.rs:2424-2451) and is
            // LAMPORTS-INDEPENDENT: a zero-lamport tombstone that is the index-current version is
            // ALIVE and kept. ⚠ FOOTGUN: Agave (:2441) treats an index MISS as ALIVE ("normal
            // on-disk account"); Vexor treats null as DEAD (record dropped). CORRECT here ONLY
            // because Vexor's index is fully in-memory & complete — null means the account was
            // legitimately removed (removeSlot/removeIf, the ONLY removers). DO NOT "match Agave"
            // by flipping null->alive: that RESURRECTS removed accounts and diverges bank_hash.
            // shrink is hash-neutral because computeHash reads through this SAME pointer.
            // Ref: agave-behavior-extractor 2026-06-13 shrink/zero-lamport + carrier #11 (69e1a98).
            if (location != null and location.?.store_id == store_id and location.?.offset == offset) {
                live_bytes += record.total_len;
            }
            offset += record.total_len;
        }

        const dead_bytes = total_bytes - live_bytes;
        if (total_bytes > 0) {
            const dead_ratio = @as(u128, dead_bytes) * 100 / @as(u128, total_bytes);
            const trigger_ratio = @as(u128, dead_ratio_percent) + @as(u128, hysteresis_percent);
            if (dead_ratio < trigger_ratio) return false;
            if (dead_bytes < min_dead_bytes) return false;
        }
        // total_bytes == 0 (created-but-empty store): fully dead by
        // definition — fall through to the retire-without-replacement path.

        // Task #71 guard 4: collect ALL slots mapped to this store (shared
        // stores are many-slots-to-one) so every mapping gets remapped.
        var co_slots = std.ArrayListUnmanaged(core.Slot){};
        defer co_slots.deinit(self.allocator);
        {
            var it = self.storage.slot_to_store.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.* == store_id) {
                    try co_slots.append(self.allocator, e.key_ptr.*);
                }
            }
        }

        if (live_bytes == 0) {
            // Task #71 path 5: nothing live — retire without a replacement
            // store; drop every mapping that pointed here.
            for (co_slots.items) |s| {
                _ = self.storage.slot_to_store.remove(s);
            }
            try self.storage.retireStoreUnlocked(store_id, self.rooted_slot);
            return true;
        }

        const min_capacity: u64 = @intCast(std.heap.page_size_min);
        // Task #71: capacity must also hold the 32-byte AppendVec header the
        // copy loop appends AFTER (current_len starts at header_size).
        const target_capacity = std.mem.alignForward(u64, @max(live_bytes + AppendVec.header_size, min_capacity), std.heap.page_size_min);
        const new_store = try self.storage.createStoreForSlotUnlocked(slot, target_capacity);

        offset = av.firstRecordOffset();
        while (av.readRecord(offset)) |record| {
            const location = self.index.get(&record.pubkey);
            // Same index-pointer alive test as the measure loop above (zero-lamport-independent;
            // null->drop is correct for Vexor's complete in-memory index). See that footgun block.
            if (location != null and location.?.store_id == store_id and location.?.offset == offset) {
                var buf = std.ArrayListUnmanaged(u8){};
                defer buf.deinit(self.allocator);
                try buf.appendSlice(self.allocator, &record.pubkey.data);
                try buf.writer(self.allocator).writeInt(u64, record.account.lamports, .little);
                try buf.appendSlice(self.allocator, &record.account.owner.data);
                try buf.append(self.allocator, @intFromBool(record.account.executable));
                try buf.writer(self.allocator).writeInt(u64, record.account.rent_epoch, .little);
                try buf.writer(self.allocator).writeInt(u32, @intCast(record.account.data.len), .little);
                try buf.appendSlice(self.allocator, record.account.data);

                const new_offset = try new_store.av.append(buf.items);
                const new_location = AccountLocation{
                    .store_id = new_store.store_id,
                    .offset = new_offset,
                    // Task #71 fix 1: carry the TRUE write slot through. Using
                    // the mapping slot here made the index higher-slot-wins
                    // guard reject the re-insert → dangling entry after free.
                    .slot = location.?.slot,
                };
                try self.index.insert(&record.pubkey, new_location);
            }
            offset += record.total_len;
        }

        // Task #71 fix 4: drop EVERY mapping that pointed at the old store.
        // The replacement store intentionally gets NO slot_to_store mapping:
        // its records are accounts NOT rewritten since this window (cold by
        // construction — hot accounts are already dead in an aged store), so
        // re-compaction would reclaim ~nothing, and keeping shrunk stores out
        // of the GC scan list keeps the cursor cycle bounded by the ACTIVE
        // window instead of growing forever (death-spiral guard).
        for (co_slots.items) |s| {
            _ = self.storage.slot_to_store.remove(s);
        }
        // Task #71 fix 2: retire (quarantine) instead of free. Stale
        // locations keep reading identical bytes until reapRetired.
        try self.storage.retireStoreUnlocked(store_id, self.rooted_slot);

        return true;
    }

    /// Compute accounts hash for snapshot
    pub fn computeHash(self: *Self) !core.Hash {
        var leaves = std.ArrayListUnmanaged(core.Hash){};
        defer leaves.deinit(self.allocator);

        // Lock storage shared to ensure no appendvecs are deleted/shrunk while hashing
        self.storage.lock.lockShared();
        defer self.storage.lock.unlockShared();

        for (self.index.bins) |*bin| {
            bin.lock.lockShared();
            // We must collect both pubkey and account data while holding the bin lock
            // to ensure a consistent point-in-time view of this bin.
            var it = bin.entries.iterator();
            while (it.next()) |entry| {
                const pubkey = entry.key_ptr.*;
                const location = entry.value_ptr.*;
                if (self.storage.readAccountUnlocked(location)) |account| {
                    try leaves.append(self.allocator, hashAccount(&pubkey, account));
                }
            }
            bin.lock.unlockShared();
        }

        if (leaves.items.len == 0) {
            return core.Hash.ZERO;
        }

        // Sort leaves for deterministic Merkle root
        std.sort.heap(core.Hash, leaves.items, {}, hashLessThan);

        return merkleize(self.allocator, leaves.items);
    }

    /// Callback invoked once per LIVE account by the canonical enumeration
    /// iterator. `pubkey` and `account` are valid ONLY for the duration of the
    /// call (the index bin lock + storage shared lock are held). `ctx` is the
    /// opaque per-consumer state pointer passed to `forEachLiveAccount*`.
    pub const ForEachAccountFn = *const fn (pubkey: *const core.Pubkey, account: AccountView, ctx: *anyopaque) anyerror!void;

    /// CANONICAL account-enumeration iterator (locked variant). Walks the index
    /// exactly as the proven snapshot/checkpoint READ path does — iterate
    /// `index.bins`, hold each bin's RwLock SHARED (short-held), resolve each
    /// entry via `storage.readAccountUnlocked`, and invoke `callback` for every
    /// NON-null (live) account. The CALLER must already hold `self.storage.lock`
    /// SHARED for the whole walk (do NOT re-acquire here — the RwLock is not
    /// recursion-safe against a waiting writer → would deadlock replay).
    ///
    /// Every enumerate-ALL-accounts WRITE consumer (snapshot AppendVec record +
    /// manifest tally, forensic checkpoint) routes through this single walk so
    /// the write paths physically cannot diverge from the read path. Enumeration
    /// order and the non-null filter are fixed HERE; per-account work lives in
    /// the consumer's callback. Byte-frozen: changing this changes snapshots.
    pub fn forEachLiveAccountLocked(self: *Self, ctx: *anyopaque, callback: ForEachAccountFn) anyerror!void {
        for (self.index.bins) |*bin| {
            bin.lock.lockShared();
            var it = bin.entries.iterator();
            while (it.next()) |entry| {
                const pubkey = entry.key_ptr.*;
                const location = entry.value_ptr.*;
                if (self.storage.readAccountUnlocked(location)) |account| {
                    try callback(&pubkey, account, ctx);
                }
            }
            bin.lock.unlockShared();
        }
    }

    /// CANONICAL account-enumeration iterator (lock-taking variant). Takes
    /// `self.storage.lock` SHARED for the whole walk, then delegates to
    /// `forEachLiveAccountLocked`. Use when the caller does NOT already hold the
    /// storage lock.
    pub fn forEachLiveAccount(self: *Self, ctx: *anyopaque, callback: ForEachAccountFn) anyerror!void {
        self.storage.lock.lockShared();
        defer self.storage.lock.unlockShared();
        try self.forEachLiveAccountLocked(ctx, callback);
    }

    /// fork-BGSAVE (task #26) CHILD-ONLY iterator: IDENTICAL enumeration to
    /// `forEachLiveAccountLocked` (same bin order, same `readAccountUnlocked`
    /// resolve, same non-null filter ⇒ byte-identical AppendVec over the same
    /// frozen state) but takes NO locks at all — neither `storage.lock` nor the
    /// per-bin RwLocks. The BGSAVE child MUST NOT touch any lock it inherited
    /// across fork(): a lock copied while another thread held it EXCLUSIVE is
    /// frozen forever in the child image (deadlock). Safety comes from the
    /// PARENT's fork protocol instead (design §1 row 5): `storage.lock` held
    /// SHARED + ALL 8192 bin locks held SHARED across fork() ⇒ the child's CoW
    /// image has no writer mid-mutation anywhere this walk reads.
    ///
    /// Returns `entries_seen` (every index entry iterated, INCLUDING the ones
    /// whose storage resolves null and are skipped — same filter as the legacy
    /// walk, see `snapshotWalkDiag`) so the parent can prove COMPLETE
    /// enumeration against its pre-fork under-lock bin-count sum (design §5.2).
    ///
    /// NEVER call this in the live (parent) process — parent walks stay on
    /// `forEachLiveAccountLocked`.
    pub fn forEachLiveAccountNoLock(self: *Self, ctx: *anyopaque, callback: ForEachAccountFn) anyerror!u64 {
        var entries_seen: u64 = 0;
        for (self.index.bins) |*bin| {
            var it = bin.entries.iterator();
            while (it.next()) |entry| {
                entries_seen += 1;
                const pubkey = entry.key_ptr.*;
                const location = entry.value_ptr.*;
                if (self.storage.readAccountUnlocked(location)) |account| {
                    try callback(&pubkey, account, ctx);
                }
            }
        }
        return entries_seen;
    }

    /// Shared return type for both snapshot AppendVec writers. MUST be a single
    /// NAMED type (not two inline `struct {...}`) — Zig gives each inline struct
    /// literal a distinct type, so `writeSnapshotAppendVec` delegating to
    /// `writeSnapshotAppendVecLocked` would fail to coerce the return values.
    pub const SnapshotWriteResult = struct { accounts_written: u64, lamports_total: u64 };

    /// Write accounts to a snapshot AppendVec file (Solana format).
    /// Takes `self.storage.lock` SHARED for the whole walk and delegates the
    /// account enumeration + record writing to `writeSnapshotAppendVecLocked`
    /// (the single canonical walk), so this legacy/RPC path and the forensic
    /// locked path emit byte-identical output.
    pub fn writeSnapshotAppendVec(self: *Self, writer: anytype) !SnapshotWriteResult {
        // Lock storage shared to ensure no appendvecs are deleted/shrunk while writing
        self.storage.lock.lockShared();
        defer self.storage.lock.unlockShared();
        return self.writeSnapshotAppendVecLocked(writer);
    }

    /// Same walk as `writeSnapshotAppendVec` but assumes the CALLER already holds
    /// `self.storage.lock` SHARED. This lets a forensic snapshotter capture the
    /// bank's metadata (bank_hash/lthash/slot from the rooted tip) and the account
    /// AppendVec under ONE lock acquisition, so no replay slot can commit between
    /// the metadata read and the account walk (the index-only walk otherwise races
    /// replay and would tag slot S's manifest over slot S+k's account state). Per-bin
    /// shared locks are still taken here. Byte-identical output to
    /// `writeSnapshotAppendVec`, which is left untouched so the RPC + legacy save
    /// paths are provably unchanged.
    pub fn writeSnapshotAppendVecLocked(self: *Self, writer: anytype) !SnapshotWriteResult {
        const W = @TypeOf(writer);
        // Per-account record writer + manifest tally. This is the ONE place the
        // Agave-format AppendVec record bytes are produced; both snapshot write
        // entry points reach it through `forEachLiveAccountLocked`, so they
        // cannot diverge from each other or from the canonical read walk.
        const Ctx = struct {
            writer: W,
            accounts_written: u64 = 0,
            lamports_total: u64 = 0,

            fn cb(pubkey: *const core.Pubkey, account: AccountView, ctxp: *anyopaque) anyerror!void {
                const c: *@This() = @ptrCast(@alignCast(ctxp));
                const STORED_META_SIZE: usize = 48;
                const ACCOUNT_META_SIZE: usize = 56;
                const write_version: u64 = 1;
                const pad_bytes = [_]u8{0} ** 8;
                var buf8: [8]u8 = undefined;

                std.mem.writeInt(u64, &buf8, write_version, .little);
                try c.writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, @intCast(account.data.len), .little);
                try c.writer.writeAll(&buf8);
                try c.writer.writeAll(&pubkey.data);

                std.mem.writeInt(u64, &buf8, account.lamports, .little);
                try c.writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, account.rent_epoch, .little);
                try c.writer.writeAll(&buf8);
                try c.writer.writeAll(&account.owner.data);
                try c.writer.writeByte(@intFromBool(account.executable));
                try c.writer.writeAll(pad_bytes[0..7]);

                const zero_hash = [_]u8{0} ** 32;
                try c.writer.writeAll(&zero_hash);

                try c.writer.writeAll(account.data);

                const HASH_SIZE: usize = 32;
                const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(account.data.len));
                const pad = (8 - (record_len % 8)) & 7;
                if (pad != 0) {
                    try c.writer.writeAll(pad_bytes[0..pad]);
                }

                c.accounts_written += 1;
                c.lamports_total = std.math.add(u64, c.lamports_total, account.lamports) catch c.lamports_total;
            }
        };

        // storage.lock is held SHARED by the caller — do NOT re-acquire (the RwLock
        // is not recursion-safe against a waiting writer → would deadlock replay).
        var ctx = Ctx{ .writer = writer };
        try self.forEachLiveAccountLocked(&ctx, Ctx.cb);

        return .{
            .accounts_written = ctx.accounts_written,
            .lamports_total = ctx.lamports_total,
        };
    }

    /// fork-BGSAVE result triple: legacy pair + `entries_seen` for the parent's
    /// complete-enumeration invariant (design §5.2).
    pub const SnapshotWriteResultNoLock = struct {
        accounts_written: u64,
        lamports_total: u64,
        entries_seen: u64,
    };

    /// fork-BGSAVE (task #26) CHILD-ONLY AppendVec writer. The per-account
    /// record emitter is a DELIBERATE byte-for-byte CLONE of
    /// `writeSnapshotAppendVecLocked`'s (NOT a refactor: the legacy walk/writer
    /// above stays byte-frozen — it is the VEX_FORENSIC_SNAPSHOT_FORK=0
    /// rollback path; the byte-equivalence KAT `test-bgsave-fork` pins the two
    /// emitters to each other). Runs over `forEachLiveAccountNoLock`.
    ///
    /// Fork-safe subset: alloc-free (stack `buf8` only) and lock-free; `writer`
    /// must be the pre-staged buffered writer (raw write(2) underneath).
    pub fn writeSnapshotAppendVecNoLock(self: *Self, writer: anytype) !SnapshotWriteResultNoLock {
        const W = @TypeOf(writer);
        const Ctx = struct {
            writer: W,
            accounts_written: u64 = 0,
            lamports_total: u64 = 0,

            fn cb(pubkey: *const core.Pubkey, account: AccountView, ctxp: *anyopaque) anyerror!void {
                const c: *@This() = @ptrCast(@alignCast(ctxp));
                const STORED_META_SIZE: usize = 48;
                const ACCOUNT_META_SIZE: usize = 56;
                const write_version: u64 = 1;
                const pad_bytes = [_]u8{0} ** 8;
                var buf8: [8]u8 = undefined;

                std.mem.writeInt(u64, &buf8, write_version, .little);
                try c.writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, @intCast(account.data.len), .little);
                try c.writer.writeAll(&buf8);
                try c.writer.writeAll(&pubkey.data);

                std.mem.writeInt(u64, &buf8, account.lamports, .little);
                try c.writer.writeAll(&buf8);
                std.mem.writeInt(u64, &buf8, account.rent_epoch, .little);
                try c.writer.writeAll(&buf8);
                try c.writer.writeAll(&account.owner.data);
                try c.writer.writeByte(@intFromBool(account.executable));
                try c.writer.writeAll(pad_bytes[0..7]);

                const zero_hash = [_]u8{0} ** 32;
                try c.writer.writeAll(&zero_hash);

                try c.writer.writeAll(account.data);

                const HASH_SIZE: usize = 32;
                const record_len = STORED_META_SIZE + ACCOUNT_META_SIZE + HASH_SIZE + @as(usize, @intCast(account.data.len));
                const pad = (8 - (record_len % 8)) & 7;
                if (pad != 0) {
                    try c.writer.writeAll(pad_bytes[0..pad]);
                }

                c.accounts_written += 1;
                c.lamports_total = std.math.add(u64, c.lamports_total, account.lamports) catch c.lamports_total;
            }
        };

        var ctx = Ctx{ .writer = writer };
        const entries_seen = try self.forEachLiveAccountNoLock(&ctx, Ctx.cb);

        return .{
            .accounts_written = ctx.accounts_written,
            .lamports_total = ctx.lamports_total,
            .entries_seen = entries_seen,
        };
    }

    pub const SnapshotWalkDiag = struct {
        entries: u64 = 0,
        storage_null: u64 = 0,
        store_id_missing: u64 = 0,
        getaccount_null: u64 = 0,
        null_resolved_by_bulk: u64 = 0,
        null_resolved_by_cache: u64 = 0,
    };

    /// DIAGNOSTIC (no file write): walk the index exactly as `writeSnapshotAppendVecLocked`
    /// does and tally how each entry resolves — proves whether the snapshot walk DROPS
    /// accounts (readAccountUnlocked returns null) and, if so, whether a higher read layer
    /// (bulk_buffer / cache) would have resolved them. Fast (no IO). Self-locking.
    pub fn snapshotWalkDiag(self: *Self) SnapshotWalkDiag {
        var d = SnapshotWalkDiag{};
        self.storage.lock.lockShared();
        defer self.storage.lock.unlockShared();
        for (self.index.bins) |*bin| {
            bin.lock.lockShared();
            var it = bin.entries.iterator();
            while (it.next()) |entry| {
                d.entries += 1;
                const pubkey = entry.key_ptr.*;
                const location = entry.value_ptr.*;
                if (self.storage.readAccountUnlocked(location) == null) {
                    d.storage_null += 1;
                    if (self.storage.stores.get(location.store_id) == null)
                        d.store_id_missing += 1
                    else
                        d.getaccount_null += 1;
                    if (self.bulk_buffer) |buf| {
                        if (buf.get(&pubkey) != null) d.null_resolved_by_bulk += 1;
                    }
                    if (self.cache.get(&pubkey) != null) d.null_resolved_by_cache += 1;
                }
            }
            bin.lock.unlockShared();
        }
        return d;
    }

};

fn pubkeyLessThan(_: void, a: core.Pubkey, b: core.Pubkey) bool {
    return std.mem.order(u8, &a.data, &b.data) == .lt;
}

fn pubkeyLessThanWrite(_: void, a: AccountsDb.AccountWrite, b: AccountsDb.AccountWrite) bool {
    return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .lt;
}

fn hashLessThan(_: void, a: core.Hash, b: core.Hash) bool {
    return std.mem.order(u8, &a.data, &b.data) == .lt;
}

fn hashAccount(pubkey: *const core.Pubkey, account: AccountView) core.Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    // Match Agave's hash_account_data() field order EXACTLY:
    //   SHA256(lamports || rent_epoch || data || executable || owner || pubkey)

    // 1. Lamports (u64 LE)
    var lamports_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, lamports_buf[0..8], account.lamports, .little);
    hasher.update(&lamports_buf);

    // 2. Rent epoch (u64 LE)
    var rent_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, rent_buf[0..8], account.rent_epoch, .little);
    hasher.update(&rent_buf);

    // 3. Account data (raw bytes, NOT double-hashed)
    hasher.update(account.data);

    // 4. Executable flag (1 byte)
    hasher.update(&[_]u8{@intFromBool(account.executable)});

    // 5. Owner pubkey (32 bytes)
    hasher.update(&account.owner.data);

    // 6. Pubkey (32 bytes) — LAST, not first
    hasher.update(&pubkey.data);

    return core.Hash{ .data = hasher.finalResult() };
}

fn merkleize(allocator: std.mem.Allocator, leaves: []const core.Hash) !core.Hash {
    var level = std.ArrayListUnmanaged(core.Hash){};
    defer level.deinit(allocator);
    try level.appendSlice(allocator, leaves);

    while (level.items.len > 1) {
        var next = std.ArrayListUnmanaged(core.Hash){};
        defer next.deinit(allocator);
        const pairs = (level.items.len + 1) / 2;
        try next.ensureTotalCapacity(allocator, pairs);

        var i: usize = 0;
        while (i < level.items.len) : (i += 2) {
            const left = level.items[i];
            const right = if (i + 1 < level.items.len) level.items[i + 1] else left;

            var hasher = std.crypto.hash.sha2.Sha256.init(.{});
            hasher.update(&left.data);
            hasher.update(&right.data);
            next.appendAssumeCapacity(core.Hash{ .data = hasher.finalResult() });
        }

        level.clearRetainingCapacity();
        try level.appendSlice(allocator, next.items);
    }

    return level.items[0];
}

// VexStore shadow-writes test removed 2026-05-15 along with the VexStore rip.

/// Account index mapping pubkeys to storage locations
pub const AccountIndex = struct {
    allocator: std.mem.Allocator,
    bins: []Bin,

    const Self = @This();

    const num_bins: usize = 8192;

    pub const BatchEntry = struct {
        pubkey: core.Pubkey,
        location: AccountLocation,
    };

    pub fn upsertBatch(self: *Self, entries: []const BatchEntry) !void {
        for (entries) |*entry| {
            const bin = self.binFor(&entry.pubkey);
            bin.lock.lock();
            defer bin.lock.unlock();
            // r52-fix: same higher-slot-wins guard as `insert`. See comment there.
            if (bin.entries.get(entry.pubkey)) |existing| {
                if (entry.location.slot < existing.slot) continue;
            }
            try bin.entries.put(entry.pubkey, entry.location);
        }
    }

    const Bin = struct {
        lock: std.Thread.RwLock,
        entries: std.AutoHashMap(core.Pubkey, AccountLocation),
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return initWithCapacity(allocator, 0);
    }

    pub fn initWithCapacity(allocator: std.mem.Allocator, per_bin_capacity: usize) Self {
        const bins = allocator.alloc(Bin, num_bins) catch unreachable;
        for (bins) |*bin| {
            bin.* = .{
                .lock = .{},
                .entries = std.AutoHashMap(core.Pubkey, AccountLocation).init(allocator),
            };
            if (per_bin_capacity > 0) {
                const cap: u32 = @intCast(@min(per_bin_capacity, std.math.maxInt(u32)));
                bin.entries.ensureTotalCapacity(cap) catch {};
            }
        }
        return .{
            .allocator = allocator,
            .bins = bins,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.bins) |*bin| {
            bin.entries.deinit();
        }
        self.allocator.free(self.bins);
    }

    pub fn get(self: *Self, pubkey: *const core.Pubkey) ?AccountLocation {
        const bin = self.binFor(pubkey);
        bin.lock.lockShared();
        defer bin.lock.unlockShared();
        return bin.entries.get(pubkey.*);
    }

    pub fn insert(self: *Self, pubkey: *const core.Pubkey, location: AccountLocation) !void {
        const bin = self.binFor(pubkey);
        bin.lock.lock();
        defer bin.lock.unlock();
        // r52-fix: snapshot load can call insert from multiple threads + multiple
        // appendvec files (full + incremental) carrying the same pubkey. The
        // canonical Solana rule is "highest slot wins" — without this guard, the
        // last write under filesystem-iteration order wins, which let the FULL
        // snapshot's SlotHistory overwrite the INCREMENTAL's, leaving the bitmap
        // ~96k slots stale at boot. Confirmed via direct binary parse of
        // .../accounts/404605189.322919 (incremental SH, bits=991717) vs
        // .../accounts/404508965.295543 (full SH, bits=991687) — Vexor's loaded
        // SH matched the FULL count exactly pre-r51, then r51-fix's clear-loop
        // wiped 92,570 legitimate bits. Higher-slot-wins makes the loader
        // order-independent and matches Agave's accounts_db merge semantics.
        if (bin.entries.get(pubkey.*)) |existing| {
            // Strictly-newer slot wins. Same-slot intra-tx writes are allowed
            // (last write of a slot must overwrite earlier writes of that slot).
            if (location.slot < existing.slot) return;
        }
        try bin.entries.put(pubkey.*, location);
    }

    /// fork-BGSAVE (task #26) PARENT-side fork barrier: acquire EVERY bin lock
    /// SHARED and hold them ACROSS fork(). This is the ONE active quiesce the
    /// design needs beyond the shared storage.lock hold (design §1 row 5):
    /// `insert`/`upsertBatch` take bin locks EXCLUSIVE *outside* storage.lock
    /// (storeAccount releases storage.lock before index.insert — accounts.zig
    /// storeAccount/writeAccount ordering), so holding storage.lock shared at
    /// the fork instant does NOT prove no hashmap-put is mid-flight. Sweeping
    /// all 8192 bins shared waits out any in-flight insert (µs each) and blocks
    /// new ones for the fork instant, so the child's CoW image contains no torn
    /// AutoHashMap. Lock-order-safe: no in-tree path holds a bin lock while
    /// WAITING on storage.lock, and `forEachLiveAccountLocked` already nests
    /// bin-shared INSIDE storage-shared in this same order.
    pub fn lockAllBinsShared(self: *Self) void {
        for (self.bins) |*bin| bin.lock.lockShared();
    }

    /// Release the fork barrier — call IMMEDIATELY after fork() returns in the
    /// parent, before releasing storage.lock.
    pub fn unlockAllBinsShared(self: *Self) void {
        for (self.bins) |*bin| bin.lock.unlockShared();
    }

    /// Σ bin.entries.count() — the frozen image's exact index-entry population.
    /// Caller MUST already hold every bin (shared), i.e. inside the
    /// lockAllBinsShared()..fork() window; pure counter reads, no allocation.
    pub fn countAssumeLocked(self: *Self) u64 {
        var total: u64 = 0;
        for (self.bins) |*bin| total += bin.entries.count();
        return total;
    }

    pub fn totalCount(self: *Self) usize {
        var total: usize = 0;
        for (self.bins) |*bin| {
            total += bin.entries.count();
        }
        return total;
    }

    /// Pre-allocate capacity across all bins for bulk loading
    pub fn ensureCapacity(self: *Self, total_capacity: usize) !void {
        const per_bin = (total_capacity + num_bins - 1) / num_bins;
        const cap: u32 = @intCast(@min(per_bin, std.math.maxInt(u32)));
        for (self.bins) |*bin| {
            bin.lock.lock();
            defer bin.lock.unlock();
            try bin.entries.ensureTotalCapacity(cap);
        }
    }

    pub fn removeSlot(self: *Self, slot: core.Slot) void {
        for (self.bins) |*bin| {
            bin.lock.lock();
            var iter = bin.entries.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.slot == slot) {
                    _ = bin.entries.remove(entry.key_ptr.*);
                }
            }
            bin.lock.unlock();
        }
    }

    // ⚠ FOOTGUN — CARRIER-#11-CLASS. This is Vexor's clean_accounts analogue: it evicts a
    // zero-lamport index entry whenever its slot matches, with NO ref_count==1 / single-ref check
    // and NO "is there an older version this would un-mask?" guard (cf. Agave's gated purge
    // accounts_db.rs:2407-2417 + can_purge_zero_lamport_single_ref_after_shrink:5095, and
    // clean_accounts' older-rooted-version logic). SAFE TODAY ONLY because accounts_clean is
    // DEFAULT-OFF (the clean-enabled flag / its callers are gated off). Before ever enabling clean,
    // port the full Agave clean predicate (single-ref + no-older-rooted-version + slot <=
    // latest_full_snapshot_slot) or this resurrects stale data → bank_hash/lt_hash divergence.
    // Ref: agave-behavior-extractor 2026-06-13 + carrier #11 (69e1a98).
    pub fn removeIf(self: *Self, slot: core.Slot, storage: *AccountStorage) void {
        for (self.bins) |*bin| {
            bin.lock.lock();
            var iter = bin.entries.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.slot != slot) continue;
                if (storage.readAccountUnlocked(entry.value_ptr.*)) |account| {
                    if (account.lamports == 0) {
                        _ = bin.entries.remove(entry.key_ptr.*);
                    }
                }
            }
            bin.lock.unlock();
        }
    }

    fn binFor(self: *Self, pubkey: *const core.Pubkey) *Bin {
        const hi: u16 = (@as(u16, pubkey.data[0]) << 8) | pubkey.data[1];
        const idx = @as(usize, hi >> 3) & (num_bins - 1);
        return &self.bins[idx];
    }
};


/// LRU cache for recently accessed accounts
///
/// OPTIMIZATION: Uses access counter instead of timestamp to avoid syscall overhead.
/// Eviction happens when cache exceeds max_size, removing ~25% of oldest entries.
pub const AccountCache = struct {
    allocator: std.mem.Allocator,
    lock: std.Thread.Mutex,
    entries: std.AutoHashMap(core.Pubkey, CacheEntry),
    max_size: usize,
    /// Global access counter (monotonically increasing)
    access_counter: u64,
    /// Cache statistics
    hits: u64,
    misses: u64,

    const Self = @This();

    const CacheEntry = struct {
        account: AccountView,
        /// Access order (higher = more recent)
        access_order: u64,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .lock = .{},
            .entries = std.AutoHashMap(core.Pubkey, CacheEntry).init(allocator),
            .max_size = 100_000, // Default cache size
            .access_counter = 0,
            .hits = 0,
            .misses = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.entries.deinit();
    }

    /// Get an account from cache
    /// NOTE: Returns a copy of the pointer - caller must not hold reference across slot boundaries
    pub fn get(self: *Self, pubkey: *const core.Pubkey) ?AccountView {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.entries.getPtr(pubkey.*)) |e| {
            self.access_counter += 1;
            e.access_order = self.access_counter;
            self.hits += 1;
            return e.account;
        }
        self.misses += 1;
        return null;
    }

    /// Remove an entry from the cache. Called when the underlying account
    /// has been persisted to AppendVec or the unflushed_cache so a stale
    /// pre-mutation snapshot view is no longer authoritative.
    /// r75-bug-class-b-cache-invalidate (2026-05-06): the AccountCache is an
    /// LRU read-cache that gets warmed via getAccount → index lookup. After
    /// flushCacheToDisk writes new post-mutation bytes to AppendVec and
    /// updates the index, the cached AccountView still points to PRE-mutation
    /// snapshot bytes. Subsequent getAccount calls hit cache (replay_stage
    /// reads via getAccount line 700 BEFORE index line 708) and return
    /// stale state — caused Bug Class B (GJHt ChangeTipReceiver constraint
    /// failures every slot post-200, 9 missing PDA writes per slot).
    pub fn invalidate(self: *Self, pubkey: *const core.Pubkey) void {
        self.lock.lock();
        defer self.lock.unlock();
        _ = self.entries.remove(pubkey.*);
    }

    /// Insert an account into cache, evicting old entries if needed
    pub fn insert(self: *Self, pubkey: *const core.Pubkey, account: AccountView) !void {
        self.lock.lock();
        defer self.lock.unlock();
        // Check if eviction is needed
        if (self.entries.count() >= self.max_size) {
            self.evictOldest();
        }

        self.access_counter += 1;
        try self.entries.put(pubkey.*, .{
            .account = account,
            .access_order = self.access_counter,
        });
    }

    /// Evict approximately 25% of oldest entries
    fn evictOldest(self: *Self) void {
        const target_count = self.max_size * 3 / 4;
        const current_count = self.entries.count();

        if (current_count <= target_count) return;

        const to_remove = current_count - target_count;

        // Find threshold access_order (entries below this will be removed)
        // Simple approach: collect all access_orders, sort, find threshold
        var min_order: u64 = std.math.maxInt(u64);
        var max_order: u64 = 0;

        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            if (entry.access_order < min_order) min_order = entry.access_order;
            if (entry.access_order > max_order) max_order = entry.access_order;
        }

        // Estimate threshold (simple linear interpolation)
        const range = max_order - min_order;
        if (range == 0) return;

        const threshold_fraction = @as(f64, @floatFromInt(to_remove)) / @as(f64, @floatFromInt(current_count));
        const threshold_offset = @as(u64, @intFromFloat(threshold_fraction * @as(f64, @floatFromInt(range))));
        const threshold = min_order + threshold_offset;

        // Collect keys to remove (avoid modifying during iteration)
        var keys_to_remove: [256]core.Pubkey = undefined;
        var remove_count: usize = 0;

        var key_iter = self.entries.iterator();
        while (key_iter.next()) |kv| {
            if (kv.value_ptr.access_order <= threshold and remove_count < 256) {
                keys_to_remove[remove_count] = kv.key_ptr.*;
                remove_count += 1;
            }
        }

        // Remove collected keys
        for (keys_to_remove[0..remove_count]) |key| {
            _ = self.entries.remove(key);
        }
    }

    /// Clear the cache
    pub fn clear(self: *Self) void {
        self.entries.clearRetainingCapacity();
        self.access_counter = 0;
        self.hits = 0;
        self.misses = 0;
    }
};

fn deserializeAccount(allocator: std.mem.Allocator, data: []const u8) !*Account {
    const header_len: usize = 8 + 32 + 1 + 8 + 4;
    if (data.len < header_len) return error.MalformedAccount;
    var offset: usize = 0;
    const lamports = std.mem.readInt(u64, data[offset..][0..8], .little);
    offset += 8;
    var owner = core.Pubkey{ .data = undefined };
    @memcpy(&owner.data, data[offset..][0..32]);
    offset += 32;
    const executable = data[offset] != 0;
    offset += 1;
    const rent_epoch = std.mem.readInt(u64, data[offset..][0..8], .little);
    offset += 8;
    const data_len = std.mem.readInt(u32, data[offset..][0..4], .little);
    offset += 4;
    if (offset + data_len > data.len) return error.MalformedAccount;

    const buf = try allocator.alloc(u8, data_len);
    @memcpy(buf, data[offset..][0..data_len]);

    const account = try allocator.create(Account);
    account.* = .{
        .lamports = lamports,
        .owner = owner,
        .executable = executable,
        .rent_epoch = rent_epoch,
        .data = buf,
    };
    return account;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "accounts db init" {
    var db = try AccountsDb.init(std.testing.allocator, "/tmp/test_accounts", null);
    defer db.deinit();

    const pubkey = core.Pubkey{ .data = [_]u8{1} ** 32 };
    try std.testing.expect(db.getAccount(&pubkey) == null);
}

test "account index" {
    var index = AccountIndex.init(std.testing.allocator);
    defer index.deinit();

    const pubkey = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const location = AccountLocation{
        .store_id = 1,
        .offset = 100,
        .slot = 50,
    };

    try index.insert(&pubkey, location);
    const found = index.get(&pubkey);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u32, 1), found.?.store_id);
}

test "account storage appendvec read" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var storage = try AccountStorage.init(std.testing.allocator, path, 64 * 1024 * 1024);
    defer storage.deinit();

    const pubkey = core.Pubkey{ .data = [_]u8{3} ** 32 };
    const owner = core.Pubkey{ .data = [_]u8{4} ** 32 };
    const account = Account{
        .lamports = 999,
        .owner = owner,
        .executable = true,
        .rent_epoch = 42,
        .data = "appendvec",
    };

    const location = try storage.writeAccount(&pubkey, &account, 7);
    const got = storage.readAccount(location) orelse return error.MissingAccount;

    try std.testing.expectEqual(account.lamports, got.lamports);
    try std.testing.expectEqualSlices(u8, &account.owner.data, &got.owner.data);
    try std.testing.expectEqual(account.executable, got.executable);
    try std.testing.expectEqual(account.rent_epoch, got.rent_epoch);
    try std.testing.expectEqualSlices(u8, account.data, got.data);
}

// REGRESSION LOCK — AppendVec store-rotation carrier (2026-06-07).
// PROVEN root of tip lt-divergence/vote-freeze: at steady tip the per-slot store
// fills; `writeAccount` hits `error.AppendVecFull`; pre-fix the retry re-called
// `getOrCreateStore(slot)` which returned the SAME full store via
// `slot_to_store.get(slot)`, the second `append` threw again, and `writeAccount`
// returned the error → `promoteRingEntry`'s silent catch DROPPED the rooted write →
// stale rooted value → wrong accounts_lt_hash → divergence.
// Capacity is tuned so exactly TWO zero-data records (header 32 + 2*85 = 202) fit;
// the THIRD must rotate to a new store. bulk_mode defaults false → this hits the
// buggy NORMAL-mode path. Every writeAccount uses `try`, so PRE-FIX the 3rd write
// throws and FAILS this test; POST-FIX (room-aware getOrCreateStore) all three land
// with no loss and the store rotates.
test "carrier: AppendVec store-rotation never silently drops a rooted write" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    // header_size(32) + 2 * record_header_len(85) = 202 → exactly two 0-data records.
    var storage = try AccountStorage.init(std.testing.allocator, path, 202);
    defer storage.deinit();

    const owner = core.Pubkey{ .data = [_]u8{7} ** 32 };
    const slot: core.Slot = 1;

    var locs: [3]AccountLocation = undefined;
    for (0..3) |i| {
        const pk = core.Pubkey{ .data = [_]u8{@intCast(i + 1)} ** 32 };
        const acct = Account{
            .lamports = (@as(u64, @intCast(i)) + 1) * 1000,
            .owner = owner,
            .executable = false,
            .rent_epoch = 0,
            .data = &.{}, // 0-byte = the System fee-payer / leader-identity carrier class
        };
        // PRE-FIX: i==2 throws error.AppendVecFull here → test fails. POST-FIX: succeeds.
        locs[i] = try storage.writeAccount(&pk, &acct, slot);
    }

    // No write lost — every account (incl. the rotation-triggering 3rd) reads back.
    for (0..3) |i| {
        const got = storage.readAccount(locs[i]) orelse return error.RootedWriteLost;
        try std.testing.expectEqual((@as(u64, @intCast(i)) + 1) * 1000, got.lamports);
    }

    // The full store rotated to a fresh one rather than re-throwing on the same store.
    try std.testing.expect(storage.stores.count() >= 2);
    // The 3rd record landed in a DIFFERENT store than the first two (proves rotation).
    try std.testing.expectEqual(locs[0].store_id, locs[1].store_id);
    try std.testing.expect(locs[2].store_id != locs[1].store_id);

    // A fresh write of pubkey[0] at a higher slot after the rotation lands in the
    // rotated store and reads back its NEW value (storage-level readback, not an
    // index-resolution check — the index higher-slot-wins guard is covered elsewhere).
    const pk0 = core.Pubkey{ .data = [_]u8{1} ** 32 };
    const reloc = try storage.writeAccount(&pk0, &Account{
        .lamports = 9_999_999,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &.{},
    }, slot + 1);
    const re = storage.readAccount(reloc) orelse return error.MissingAccount;
    try std.testing.expectEqual(@as(u64, 9_999_999), re.lamports);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CARRIER #2 REPRODUCER TESTS (2026-05-19, post-PR-5n)
//
// These tests document the carrier #2 bug shape at slot 409360896 (HANDOFF
// 2026-05-20 §5): orphan-slot writes leak into canonical-fork reads via the
// fork-blind `unflushed_cache` consulted by `_getRooted` at line 1043 (no
// ancestor filter). The bug fires when sig_overlay + unrooted_ring both miss
// (no slot in the read's ancestor lookup wrote the pubkey) and fall-through to
// `_getRooted` returns the orphan slot's value from unflushed_cache.
//
// Production scenario (slot 409360896):
//   slot 894 -> children: slot 895 (canonical) AND slot 898 (orphan)
//   Vexor freeze order: 893, 894, 895, 898, 896, 897, ... (898 BEFORE 896)
//   At slot 896 processing, 1119 of 1131 writes had prev_csm=898 - reads
//   returned slot 898's data because unflushed_cache is last-write-wins.
//
// These tests do NOT validate any fix; fix validation requires the
// 3-anchor empirical loop per HANDOFF section 7 step 4, and the hard rule
// section 10.4 against modifying Phase 1F-class read-time filters without
// that loop. Phase 1F-v1/v2 regressed parity 51.9% -> 0.04% twice; the
// regression mechanism is suspected to be compiler-artifact / inlining
// (per MEMORY iter-6 entries), not a logic gap these tests can probe.
// ═══════════════════════════════════════════════════════════════════════════════

// Helper for carrier #2 tests: simulate `promoteToUnflushedCache`'s effect on
// the fork-blind caches without constructing an AccountWrite literal. The
// AccountWrite type has lazily-resolved field-type annotations
// (`?crypto.lthash.LtHashValue`) that production never constructs directly;
// tests constructing it force eager resolution and hit a Zig type-name gap.
// All sig_overlay / unrooted_ring / top_votes side effects of the real path
// are irrelevant to the bug surface (which lives in `_getRooted` line 1043).
fn simulateOrphanPromote(
    db: *AccountsDb,
    pubkey: core.Pubkey,
    account: Account,
    slot: u64,
) !void {
    // Match `promoteToUnflushedCache`'s allocator for unflushed_cache entries.
    const data_copy = if (account.data.len > 0) blk: {
        const copy = try std.heap.page_allocator.alloc(u8, account.data.len);
        @memcpy(copy, account.data);
        break :blk @as([]const u8, copy);
    } else @as([]const u8, &[_]u8{});

    {
        db.unflushed_cache_lock.lock();
        defer db.unflushed_cache_lock.unlock();
        try db.unflushed_cache.put(pubkey, .{
            .lamports = account.lamports,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
            .data = data_copy,
        });
        try db.cache_slot_map.put(pubkey, slot);
    }

    // Two-tier: production's commit paths (flushPendingWritesToDb/FromIndex,
    // promoteToUnflushedCache) write the ring AND unflushed_cache together. The
    // legacy-only helper bypassed the ring, which made the two-tier read (ring →
    // rooted) miss the write. Mirror production: also put into the fork-aware
    // ring keyed by `slot`. Orphan slots remain correctly invisible because the
    // ring is ancestors-gated (a non-ancestor `slot` is filtered at read time),
    // so the orphan-leak reproducers still pass; the canonical-ancestor read now
    // resolves via the ring as it does in production. Ring owns its own copy.
    const ring_copy = if (account.data.len > 0) blk: {
        const c = try std.heap.page_allocator.alloc(u8, account.data.len);
        @memcpy(c, account.data);
        break :blk @as([]const u8, c);
    } else @as([]const u8, &[_]u8{});
    try db.unrooted_ring.put(slot, pubkey, .{
        .lamports = account.lamports,
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
        .data = ring_copy,
    });
}

test "carrier #11: zero-lamport (closed) account loads as NONEXISTENT and masks older alive versions" {
    // Real-world shape (@414670256): loader buffer EtS4njg… created → 450
    // Writes → Close (lamports→0 @414670169) → RE-created 87 slots later.
    // Cluster: dead account loads as nothing; createAccount succeeds.
    // Pre-fix Vexor: getAccountInSlot returned the dead version WITH its
    // stale data bytes → System allocate() saw data.len != 0 →
    // ERR_ACCT_ALREADY_IN_USE → tx failed that the cluster executed →
    // accounts_lt_hash divergence (equal sig counts). This KAT FAILS on
    // pre-fix code (got != null with lamports==0 + stale data).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();

    const pk = core.Pubkey{ .data = [_]u8{0xE7} ** 32 };
    const loader_owner = core.Pubkey{ .data = [_]u8{0x05} ** 32 };
    var stale_data: [64]u8 = undefined;
    @memset(&stale_data, 0xCC);

    // Slot 10: account ALIVE (the buffer's first life).
    try db.storeAccount(&pk, &.{
        .lamports = 4_873_204_080,
        .owner = loader_owner,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &stale_data,
    }, 10);
    // Slot 20: CLOSED — lamports drained to 0 (loader Close leaves the data
    // bytes in place; the runtime deletes the account because lamports==0).
    try db.storeAccount(&pk, &.{
        .lamports = 0,
        .owner = loader_owner,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &stale_data,
    }, 20);

    const ancestors = [_]u64{ 24, 23, 22, 21, 20 };

    // Canonical load: the dead account does NOT exist — and the dead version
    // MASKS the slot-10 alive version (no fall-through resurrection).
    const got = db.getAccountInSlot(&pk, 25, &ancestors);
    if (got) |acct| {
        std.debug.print(
            "[carrier #11 BUG REPRODUCED] dead account returned by load: lam={d} data_len={d}\n",
            .{ acct.lamports, acct.data.len },
        );
    }
    try std.testing.expect(got == null);

    // Forensic raw accessor still surfaces the dead version (lamports==0).
    const raw = db.getAccountInSlotRaw(&pk, 25, &ancestors);
    try std.testing.expect(raw != null);
    try std.testing.expectEqual(@as(u64, 0), raw.?.lamports);

    // A live account is unaffected by the normalization.
    const pk2 = core.Pubkey{ .data = [_]u8{0xE8} ** 32 };
    try db.storeAccount(&pk2, &.{
        .lamports = 1_000,
        .owner = loader_owner,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &stale_data,
    }, 10);
    const live = db.getAccountInSlot(&pk2, 25, &ancestors);
    try std.testing.expect(live != null);
    try std.testing.expectEqual(@as(u64, 1_000), live.?.lamports);
}

test "carrier #2 T1: orphan-slot leak when no canonical state exists" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const target_pk = core.Pubkey{ .data = [_]u8{0xAB} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xAA;
    const owner = core.Pubkey{ .data = owner_bytes };

    var orphan_data: [128]u8 = undefined;
    @memset(&orphan_data, 0xFF);

    const orphan_slot: u64 = 409360898;
    const canonical_reader_slot: u64 = 409360896;
    const ancestors_of_896 = [_]u64{
        409360895, 409360894, 409360893, 409360892, 409360891,
        409360890, 409360889, 409360888,
    };

    try simulateOrphanPromote(db, target_pk, .{
        .lamports = 999_999,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &orphan_data,
    }, orphan_slot);

    // sig_overlay/unrooted_ring are intentionally NOT populated for the orphan
    // slot — the bug surface is exactly: those caches miss, _getRooted's
    // line-1043 unflushed_cache.get returns the orphan-slot value despite
    // ancestors_of_896 NOT including 898.
    const got = db.getAccountInSlot(&target_pk, canonical_reader_slot, &ancestors_of_896);

    if (got) |acct| {
        std.debug.print(
            "[carrier #2 T1 BUG REPRODUCED] read at canonical slot {d} with ancestors NOT including orphan {d} returned orphan data: lam={d} data[0]=0x{x:0>2}\n",
            .{ canonical_reader_slot, orphan_slot, acct.lamports, acct.data[0] },
        );
    }
    try std.testing.expect(got == null);
}

test "carrier #2 T2: orphan-slot leak when rooted state X exists in storage" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const target_pk = core.Pubkey{ .data = [_]u8{0xCD} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xBB;
    const owner = core.Pubkey{ .data = owner_bytes };

    var rooted_data: [64]u8 = undefined;
    @memset(&rooted_data, 0x11);

    const rooted_account = Account{
        .lamports = 5_000_000,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &rooted_data,
    };

    // Rooted state X via index+storage path. storeAccount populates storage,
    // index, and cache - but NOT sig_overlay, unrooted_ring, or unflushed_cache.
    const rooted_slot: u64 = 409360500;
    try db.storeAccount(&target_pk, &rooted_account, rooted_slot);

    // Sanity: at this point _getRooted should return X via cache hit (or
    // index -> storage fall-through). This is the BASELINE for "rooted state
    // is recoverable when unflushed_cache is empty."
    const baseline = db._getRooted(&target_pk);
    try std.testing.expect(baseline != null);
    try std.testing.expectEqual(@as(u64, 5_000_000), baseline.?.lamports);

    // Orphan slot 898 writes Y into the fork-blind caches. cache_slot_map[pk]
    // = 898 (the slot that wrote this entry). unflushed_cache[pk] = Y bytes.
    var orphan_data: [64]u8 = undefined;
    @memset(&orphan_data, 0xFF);
    const orphan_slot: u64 = 409360898;
    try simulateOrphanPromote(db, target_pk, .{
        .lamports = 999_999,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &orphan_data,
    }, orphan_slot);

    // Canonical slot 896 read with ancestors NOT including 898.
    //   sig_overlay.get(P, [895..., 896]) -> miss (898 not in lookup)
    //   unrooted_ring -> miss (same)
    //   _getRooted(P) -> L1 unflushed_cache HIT on orphan 898's bytes -> BUG
    const canonical_reader_slot: u64 = 409360896;
    const ancestors_of_896 = [_]u64{
        409360895, 409360894, 409360893, 409360892, 409360891,
    };
    const got = db.getAccountInSlot(&target_pk, canonical_reader_slot, &ancestors_of_896);

    if (got) |acct| {
        std.debug.print(
            "[carrier #2 T2 BUG REPRODUCED] read at canonical {d}: lam={d} (rooted=5000000, orphan=999999) data[0]=0x{x:0>2}\n",
            .{ canonical_reader_slot, acct.lamports, acct.data[0] },
        );
    }
    try std.testing.expect(got != null);
    try std.testing.expectEqual(@as(u64, 5_000_000), got.?.lamports);
    try std.testing.expectEqualSlices(u8, &rooted_data, got.?.data);
}

test "keystone: scanByOwner fork-aware over ring (boundary unrooted write wins; sibling+reassign excluded)" {
    if (!build_options.two_tier) return; // two_tier read path only

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.rooted_slot = 1000;

    var stake_bytes = [_]u8{0} ** 32;
    stake_bytes[0] = 0x5A;
    const stake_owner = core.Pubkey{ .data = stake_bytes };
    const other_owner = core.Pubkey{ .data = [_]u8{0x99} ** 32 };

    const pk_a = core.Pubkey{ .data = [_]u8{0xA1} ** 32 }; // rooted-only stake
    const pk_b = core.Pubkey{ .data = [_]u8{0xB2} ** 32 }; // rooted stake + newer unrooted
    const pk_c = core.Pubkey{ .data = [_]u8{0xC3} ** 32 }; // unrooted-only stake
    const pk_d = core.Pubkey{ .data = [_]u8{0xD4} ** 32 }; // rooted stake, unrooted reassign
    const pk_e = core.Pubkey{ .data = [_]u8{0xE5} ** 32 }; // stake on a sibling slot (off-fork)

    // Rooted index (slot 1000): A=5M, B=1M (will be staled by an unrooted write), D=3M.
    var da = [_]u8{0xAA} ** 8;
    var db0 = [_]u8{0xB0} ** 8;
    var dd = [_]u8{0xDD} ** 8;
    try db.storeAccount(&pk_a, &Account{ .lamports = 5_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &da }, 1000);
    try db.storeAccount(&pk_b, &Account{ .lamports = 1_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &db0 }, 1000);
    try db.storeAccount(&pk_d, &Account{ .lamports = 3_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &dd }, 1000);

    // Unrooted ring writes along THIS fork's ancestor chain (slots 1001/1002):
    //   B gets a newer 7M; C is brand new; D is reassigned off the stake owner.
    //   E is written on a SIBLING slot 1500 NOT in the fork's ancestors.
    var db2 = [_]u8{0xB7} ** 8;
    var dc = [_]u8{0xCC} ** 8;
    var dd2 = [_]u8{0xD9} ** 8;
    var de = [_]u8{0xEE} ** 8;
    try simulateOrphanPromote(db, pk_b, .{ .lamports = 7_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &db2 }, 1002);
    try simulateOrphanPromote(db, pk_c, .{ .lamports = 9_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &dc }, 1001);
    try simulateOrphanPromote(db, pk_d, .{ .lamports = 3_000_000, .owner = other_owner, .executable = false, .rent_epoch = 0, .data = &dd2 }, 1002);
    try simulateOrphanPromote(db, pk_e, .{ .lamports = 2_000_000, .owner = stake_owner, .executable = false, .rent_epoch = 0, .data = &de }, 1500);

    const ancestors = [_]u64{ 1002, 1001, 1000 };
    const self_slot: u64 = 1003;

    const res = try db.scanByOwner(&stake_owner, &ancestors, self_slot, std.testing.allocator);
    defer std.testing.allocator.free(res);

    var seen = std.AutoHashMap([32]u8, u64).init(std.testing.allocator);
    defer seen.deinit();
    for (res) |r| try seen.put(r.pubkey.data, r.lamports);

    // A: rooted-only stake -> included with rooted value.
    try std.testing.expectEqual(@as(?u64, 5_000_000), seen.get(pk_a.data));
    // B: newer unrooted (7M) wins over the stale index (1M) -> the carrier-class fix.
    try std.testing.expectEqual(@as(?u64, 7_000_000), seen.get(pk_b.data));
    // C: unrooted-only stake account -> included.
    try std.testing.expectEqual(@as(?u64, 9_000_000), seen.get(pk_c.data));
    // D: reassigned to a non-stake owner on this fork -> EXCLUDED (owner re-checked
    //    on the newest ancestor-visible version, not the rooted candidate's owner).
    try std.testing.expectEqual(@as(?u64, null), seen.get(pk_d.data));
    // E: stake write on a SIBLING slot not in this fork -> EXCLUDED (fork isolation;
    //    legacy fork-blind unflushed_cache would have wrongly included it).
    try std.testing.expectEqual(@as(?u64, null), seen.get(pk_e.data));
}

test "carrier #2 FIX #105 Option A: promote rooted ancestor overwrites sibling-fork pollution (slot-733 CRnk)" {
    // Deterministic reproduction + fix of the slot 411,456,733 bank-hash carrier.
    // Carrier: CRnkKQTxctQ7LHVN... (system-owned, dlen=0). Slot 514 is a SIBLING
    // fork (parent=510, abandoned for slot 513's main chain). Slot 514's correct-
    // for-its-fork write polluted the fork-blind unflushed_cache; slot 733 (main
    // chain) then read the polluted value. promoteRootedChain(513) must overwrite
    // it with the ancestor-correct value before the sibling purge runs.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const crnk = core.Pubkey{ .data = [_]u8{0xC4} ** 32 };
    const sys_owner = core.Pubkey{ .data = [_]u8{0} ** 32 };
    const ancestor_lam: u64 = 4_551_848_578_400; // slot 513 value (main chain)
    const sibling_lam: u64 = 4_551_848_708_400; // slot 514 value (abandoned sibling)
    const main_slot: u64 = 411456513;
    const sibling_slot: u64 = 411456514;

    const empty: []const u8 = &[_]u8{};
    const sigov = struct {
        fn acct(l: u64, o: core.Pubkey, e: []const u8) sig_overlay_mod.Account {
            return .{ .lamports = l, .owner = o, .executable = false, .rent_epoch = 0, .data = e };
        }
    };
    const flat = struct {
        fn acct(l: u64, o: core.Pubkey, e: []const u8) Account {
            return .{ .lamports = l, .owner = o, .executable = false, .rent_epoch = 0, .data = e };
        }
    };

    // Replay-flush behavior (Step 1 KEEPS this): each fork writes BOTH the
    // fork-aware sig_overlay (keyed by slot → coexist) AND the fork-blind
    // unflushed_cache (last-write-wins → sibling 514 ends up polluting it).
    try db.sig_overlay.put(db.allocator, main_slot, crnk, sigov.acct(ancestor_lam, sys_owner, empty));
    try simulateOrphanPromote(db, crnk, flat.acct(ancestor_lam, sys_owner, empty), main_slot);
    try db.sig_overlay.put(db.allocator, sibling_slot, crnk, sigov.acct(sibling_lam, sys_owner, empty));
    try simulateOrphanPromote(db, crnk, flat.acct(sibling_lam, sys_owner, empty), sibling_slot);

    // RED: fork-blind cache is polluted with the abandoned sibling's value.
    {
        db.unflushed_cache_lock.lock();
        const polluted = db.unflushed_cache.get(crnk).?;
        db.unflushed_cache_lock.unlock();
        try std.testing.expectEqual(sibling_lam, polluted.lamports);
    }

    // FIX: promote the rooted ancestor chain (513 ∈ ancestors of root), then
    // purge the abandoned sibling (514, parent=510, NOT an ancestor).
    db.promoteRootedChain(&[_]u64{main_slot});
    db.purgeUnrootedSlot(sibling_slot);

    // GREEN #1: fork-blind cache now holds the ancestor-correct value. The
    // sibling purge's `csm == 514` guard left it intact because promote reset
    // cache_slot_map[CRnk] = 513.
    {
        db.unflushed_cache_lock.lock();
        const fixed = db.unflushed_cache.get(crnk).?;
        db.unflushed_cache_lock.unlock();
        try std.testing.expectEqual(ancestor_lam, fixed.lamports);
    }

    // GREEN #2: simulate the rooted state at slot 733 (513's sig_overlay bucket
    // long since purged at root), so the descendant read falls through to the
    // flat cache — exactly the slot-733 read path. It must see 513's value.
    db.sig_overlay.purgeSlot(db.allocator, main_slot);
    const ancestors_of_733 = [_]u64{ main_slot, 411456512, 411456511, 411456510 };
    const got733 = db.getAccountInSlot(&crnk, 411456733, &ancestors_of_733);
    try std.testing.expect(got733 != null);
    try std.testing.expectEqual(ancestor_lam, got733.?.lamports);
}

test "carrier #2 slot-564 REPRO: incomplete promote-chain root-jump persists stale slot-468 value" {
    // Deterministic reproduction of the slot 411,600,564 bank-hash carrier.
    // Recorder ground truth (carrier 06b4958c, a validator identity / fee payer):
    //   written each vote slot 468..491, value DECREASING 624664 -> 579664 (9
    //   vote-fee debits), CONTIGUOUS main chain (no sibling). By slot 564
    //   (rooted=532 → 468..491 all rootable), the persisted index_storage value
    //   REVERTED to 624664 (slot 468); the 469..491 debits LOST → read stale at
    //   564 → +45000 → divergence.
    // Advisor gate: this test must FIRST reproduce 624664; whichever drive
    // reproduces it IS the mechanism; the fix is whatever turns it into 579664.
    const A = std.testing.allocator;
    const carrier = core.Pubkey{ .data = [_]u8{0x6B} ** 32 };
    const sys = core.Pubkey{ .data = [_]u8{0} ** 32 };
    const W = struct { s: u64, l: u64 };
    const writes = [_]W{
        .{ .s = 411600468, .l = 8645952624664 }, // lowest slot, the LOST-to value
        .{ .s = 411600469, .l = 8645952619664 },
        .{ .s = 411600470, .l = 8645952614664 },
        .{ .s = 411600471, .l = 8645952609664 },
        .{ .s = 411600488, .l = 8645952594664 },
        .{ .s = 411600489, .l = 8645952589664 },
        .{ .s = 411600490, .l = 8645952584664 },
        .{ .s = 411600491, .l = 8645952579664 }, // highest rootable = CORRECT value
    };
    var ancestors_564: [64]u64 = undefined;
    {
        var i: usize = 0;
        while (i < 64) : (i += 1) ancestors_564[i] = 411600563 - i; // 563..500
    }

    // ── Pattern A (CONTROL): single-step contiguous advances 459→532. ──
    // Each slot's promote tracks forward; expect final index_storage = 579664.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(A, ".");
        defer A.free(path);
        var db = try AccountsDb.init(A, path, null);
        defer db.deinit();
        db.fork_isolation_enabled = true;
        db.rooted_slot = 411600459;
        for (writes) |w| {
            try db.sig_overlay.put(db.allocator, w.s, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} });
            try simulateOrphanPromote(db, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} }, w.s);
        }
        var prev: u64 = 411600459;
        var root: u64 = 411600460;
        while (root <= 411600532) : (root += 1) {
            db.promoteRootedChain(&[_]u64{root});
            db.advanceRoot(root);
            db.purgeRootedSlot(root, prev, true);
            prev = root;
        }
        const got = db.getAccountInSlot(&carrier, 411600564, &ancestors_564);
        std.debug.print("\n[REPRO A single-step]        index_storage lam = {?d}  (correct = 8645952579664 slot491)\n", .{if (got) |g| g.lamports else null});
        // CONTROL: contiguous single-step advance never loses the carrier.
        try std.testing.expect(got != null);
        try std.testing.expectEqual(@as(u64, 8645952579664), got.?.lamports);
    }

    // ── Pattern B (HYPOTHESIS): regress-at-468 then INCOMPLETE-chain root JUMP. ──
    // 459→468 complete (promote plants 468=624664 in the flat cache), then a JUMP
    // 468→532 whose walk broke above 491 (banks 469..491 pruned mid-catchup) so the
    // chain = [493..532] EXCLUDES the carrier's writes → not re-promoted → the stale
    // 624664 is evicted to AppendVec and 469..491 raw-range-purged from sig_overlay.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(A, ".");
        defer A.free(path);
        var db = try AccountsDb.init(A, path, null);
        defer db.deinit();
        db.fork_isolation_enabled = true;
        db.rooted_slot = 411600459;
        for (writes) |w| {
            try db.sig_overlay.put(db.allocator, w.s, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} });
            try simulateOrphanPromote(db, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} }, w.s);
        }
        // 459 → 468 (complete chain [460..468])
        var chain1: [9]u64 = undefined;
        {
            var i: usize = 0;
            while (i < 9) : (i += 1) chain1[i] = 411600460 + i;
        }
        db.promoteRootedChain(&chain1);
        db.advanceRoot(411600468);
        db.purgeRootedSlot(411600468, 411600459, true);
        // 468 → 532 INCOMPLETE: chain only [493..532], excludes carrier slots 469..491
        var chain2: [40]u64 = undefined;
        {
            var i: usize = 0;
            while (i < 40) : (i += 1) chain2[i] = 411600493 + i;
        }
        db.promoteRootedChain(&chain2);
        db.advanceRoot(411600532);
        db.purgeRootedSlot(411600532, 411600468, true);
        const got = db.getAccountInSlot(&carrier, 411600564, &ancestors_564);
        std.debug.print("[REPRO B regress+incomplete] index_storage lam = {?d}  (STEP-5 ring-promote → 8645952579664 slot491)\n", .{if (got) |g| g.lamports else null});
        try std.testing.expect(got != null);
        // STEP 5 (two_tier): even with an INCOMPLETE promote-chain jump, advanceRoot
        // now promotes the rooted slots' values from the FORK-AWARE ring (slots
        // 469..491 dual-written by simulateOrphanPromote), so slot 491's correct
        // value (579664) reaches the index regardless of the chain. The legacy
        // incomplete-chain carrier (stale 624664) no longer reproduces — the ring,
        // not the promote-chain, is the source of truth. Pattern C (durable-map
        // chain) remains as the belt-and-suspenders upstream guard.
        try std.testing.expectEqual(@as(u64, 8645952579664), got.?.lamports);
    }

    // ── Pattern C (THE FIX, #2 durable slot→parent map): same regress-then-JUMP
    // as B, but the ancestor chain comes from db.computeRootPartition over the
    // DURABLE slot_parents map. recordSlotParent retained 469..491's parent links
    // even though the live bank tree pruned those banks mid-catch-up, so the walk
    // reaches prev_root → COMPLETE chain [469..532] INCLUDES the carrier writes →
    // slot 491 (579664) is re-promoted → read at 564 is CORRECT. This is the flip
    // from B's 624664: the fix is upstream (complete chain), not in promote/purge.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(A, ".");
        defer A.free(path);
        var db = try AccountsDb.init(A, path, null);
        defer db.deinit();
        db.fork_isolation_enabled = true;
        db.rooted_slot = 411600459;
        // Durable parent map = contiguous main chain 460..532 (parent = slot-1).
        // Exactly what recordSlotParent builds live; SURVIVES the bank pruning
        // that severed Pattern B's chain.
        {
            var s: u64 = 411600460;
            while (s <= 411600532) : (s += 1) db.recordSlotParent(s, s - 1);
        }
        for (writes) |w| {
            try db.sig_overlay.put(db.allocator, w.s, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} });
            try simulateOrphanPromote(db, carrier, .{ .lamports = w.l, .owner = sys, .executable = false, .rent_epoch = 0, .data = &[_]u8{} }, w.s);
        }
        // advance 459 → 468 (durable chain complete)
        {
            var p1 = db.computeRootPartition(A, 411600459, 411600468) orelse return error.PartitionNull;
            defer p1.deinit(A);
            db.promoteRootedChain(p1.chain.items);
            db.advanceRoot(411600468);
            db.purgeRootedSlot(411600468, 411600459, p1.chain_complete);
        }
        // advance 468 → 532 — durable map STILL has 469..491 → COMPLETE chain
        var jump_complete = false;
        var jump_has_491 = false;
        {
            var p2 = db.computeRootPartition(A, 411600468, 411600532) orelse return error.PartitionNull;
            defer p2.deinit(A);
            jump_complete = p2.chain_complete;
            for (p2.chain.items) |cs| {
                if (cs == 411600491) jump_has_491 = true;
            }
            db.promoteRootedChain(p2.chain.items);
            db.advanceRoot(411600532);
            db.purgeRootedSlot(411600532, 411600468, p2.chain_complete);
        }
        const got = db.getAccountInSlot(&carrier, 411600564, &ancestors_564);
        std.debug.print("[FIX  C durable-map ]        index_storage lam = {?d}  (FIXED = 8645952579664 slot491) complete={} has491={}\n", .{ if (got) |g| g.lamports else null, jump_complete, jump_has_491 });
        // The durable map proves the chain is complete AND includes the carrier's
        // highest rooted write — the two properties that turn 624664 into 579664.
        try std.testing.expect(jump_complete);
        try std.testing.expect(jump_has_491);
        try std.testing.expect(got != null);
        try std.testing.expectEqual(@as(u64, 8645952579664), got.?.lamports);
    }
}

test "carrier #2 T2-probe: _getRooted directly returns orphan instead of rooted" {
    // Triangulates that the bug lives inside _getRooted (line 1043), not in
    // getAccountInSlot's sig_overlay/unrooted_ring layer. Should agree with T2.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const target_pk = core.Pubkey{ .data = [_]u8{0xEF} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xCC;
    const owner = core.Pubkey{ .data = owner_bytes };

    var rooted_data: [64]u8 = undefined;
    @memset(&rooted_data, 0x22);
    const rooted_account = Account{
        .lamports = 7_000_000,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &rooted_data,
    };
    try db.storeAccount(&target_pk, &rooted_account, 409360500);

    var orphan_data: [64]u8 = undefined;
    @memset(&orphan_data, 0x99);
    try simulateOrphanPromote(db, target_pk, .{
        .lamports = 333_333,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &orphan_data,
    }, 409360898);

    // _getRooted is the buggy function. On current main, line 1043's
    // unflushed_cache.get returns the orphan slot's bytes before any
    // ancestor-based filter runs.
    const got = db._getRooted(&target_pk);
    if (got) |acct| {
        std.debug.print(
            "[carrier #2 T2-probe] _getRooted returned: lam={d} (rooted=7000000, orphan=333333)\n",
            .{acct.lamports},
        );
    }
    try std.testing.expect(got != null);
    try std.testing.expectEqual(@as(u64, 7_000_000), got.?.lamports);
}

// ─── CARRIER #7 store-level KATs (414406146 promote/purge inversion) ─────────

test "carrier #7: root-advance ancestry guard refuses abandoned-fork root; canonical bytes survive (414406146 shape)" {
    if (!build_options.two_tier) return; // two_tier promote path under test
    const A = std.testing.allocator;

    const pk = core.Pubkey{ .data = [_]u8{0x77} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xAB;
    const owner = core.Pubkey{ .data = owner_bytes };
    var data_canon: [64]u8 = undefined;
    @memset(&data_canon, 0xCA); // bytes A — canonical write at 145
    var data_fork: [64]u8 = undefined;
    @memset(&data_fork, 0xF0); // bytes B — fork write at 146

    // Topology (live carrier, slots scaled): canonical 140→141→…→145→147;
    // fork 146 (parent 142, cluster-skipped). pk written at canonical 145
    // (bytes A) and fork 146 (bytes B).
    const Setup = struct {
        fn make(alloc: std.mem.Allocator, path: []const u8, a_canon: []const u8, a_fork: []const u8, p: core.Pubkey, own: core.Pubkey) !*AccountsDb {
            const db = try AccountsDb.init(alloc, path, null);
            db.fork_isolation_enabled = true;
            db.rooted_slot = 140;
            db.recordSlotParent(141, 140);
            db.recordSlotParent(142, 141);
            db.recordSlotParent(143, 142);
            db.recordSlotParent(144, 143);
            db.recordSlotParent(145, 144);
            db.recordSlotParent(146, 142); // the abandoned fork block
            db.recordSlotParent(147, 145);
            // canonical write FIRST, fork write SECOND (matches live order:
            // 145 froze after 146 in wall time is irrelevant — the ring is
            // keyed by slot, the fork-blind unflushed_cache by latest call).
            // sig_overlay takes OWNERSHIP of data (purgeSlot frees with
            // db.allocator) — dupe; the ring helper makes its own copies.
            try db.sig_overlay.put(db.allocator, 145, p, .{ .lamports = 1_000_145, .owner = own, .executable = false, .rent_epoch = 0, .data = try db.allocator.dupe(u8, a_canon) });
            try simulateOrphanPromote(db, p, .{ .lamports = 1_000_145, .owner = own, .executable = false, .rent_epoch = 0, .data = a_canon }, 145);
            try db.sig_overlay.put(db.allocator, 146, p, .{ .lamports = 1_000_146, .owner = own, .executable = false, .rent_epoch = 0, .data = try db.allocator.dupe(u8, a_fork) });
            try simulateOrphanPromote(db, p, .{ .lamports = 1_000_146, .owner = own, .executable = false, .rent_epoch = 0, .data = a_fork }, 146);
            return db;
        }
    };

    // ── BUG SHAPE (documentation lock): the OLD behavior — tower rooted the
    // fork slot 146 directly. Partition over slot_parents yields chain
    // {141,142,146} / siblings {143,144,145}: canonical 145 (bytes A) is
    // PURGED un-promoted, fork 146 (bytes B) is PROMOTED into the rooted
    // index. The post-advance read serves the FORK bytes — the exact poison
    // that fed our own vote account a fork-146 pre-state at 414406188.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(A, ".");
        defer A.free(path);
        const db = try Setup.make(A, path, &data_canon, &data_fork, pk, owner);
        defer db.deinit();

        var part = db.computeRootPartition(A, 140, 146) orelse return error.PartitionNull;
        defer part.deinit(A);
        try std.testing.expect(part.chain_complete);
        db.promoteRootedChain(part.chain.items);
        for (part.siblings.items) |s| db.purgeUnrootedSlot(s); // destroys canonical 143/144/145
        db.advanceRoot(146); // ring-promotes fork bucket 146 → rooted index
        db.purgeRootedSlot(146, 140, part.chain_complete);

        const got = db.getAccountInSlot(&pk, 148, &[_]u64{147});
        try std.testing.expect(got != null);
        // OLD behavior = POISON: rooted store serves the fork bytes.
        try std.testing.expectEqual(@as(u64, 1_000_146), got.?.lamports);
        try std.testing.expectEqualSlices(u8, &data_fork, got.?.data);
    }

    // ── NEW behavior: the guard predicate REFUSES 146 against voted bank 147
    // (replay_stage breaks out of the advance: NO promote, NO purge, NO
    // advanceRoot). The tower retries and later advances to a CANONICAL root;
    // the abandoned fork slot becomes a purged sibling and the rooted store
    // serves the canonical bytes.
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try tmp.dir.realpathAlloc(A, ".");
        defer A.free(path);
        const db = try Setup.make(A, path, &data_canon, &data_fork, pk, owner);
        defer db.deinit();

        // THE guard: fork-146 refused, canonical ancestors accepted, rooted
        // prefix accepted.
        try std.testing.expect(!db.isRootOnVotedAncestry(146, 147));
        try std.testing.expect(db.isRootOnVotedAncestry(145, 147));
        try std.testing.expect(db.isRootOnVotedAncestry(143, 147));
        try std.testing.expect(db.isRootOnVotedAncestry(140, 147)); // ≤ rooted_slot
        try std.testing.expect(db.isRootOnVotedAncestry(147, 147));

        // Guard refused → nothing advanced this vote. State intact:
        try std.testing.expectEqual(@as(u64, 140), db.rooted_slot);

        // Next canonical advance 140 → 145 (chain [141..145] complete; 146 is
        // NOT in (140,145) so its bucket merely ages out later).
        {
            var p1 = db.computeRootPartition(A, 140, 145) orelse return error.PartitionNull;
            defer p1.deinit(A);
            try std.testing.expect(p1.chain_complete);
            db.promoteRootedChain(p1.chain.items);
            for (p1.siblings.items) |s| db.purgeUnrootedSlot(s);
            db.advanceRoot(145); // ring-promotes canonical bucket 145 (bytes A)
            db.purgeRootedSlot(145, 140, p1.chain_complete);
        }
        // Then 145 → 147: fork 146 lands in (145,147) as a PROVEN sibling →
        // purged BEFORE advanceRoot can ring-promote its bucket.
        {
            var p2 = db.computeRootPartition(A, 145, 147) orelse return error.PartitionNull;
            defer p2.deinit(A);
            try std.testing.expect(p2.chain_complete);
            var has_146_sibling = false;
            for (p2.siblings.items) |s| {
                if (s == 146) has_146_sibling = true;
            }
            try std.testing.expect(has_146_sibling);
            db.promoteRootedChain(p2.chain.items);
            for (p2.siblings.items) |s| db.purgeUnrootedSlot(s);
            db.advanceRoot(147);
            db.purgeRootedSlot(147, 145, p2.chain_complete);
        }

        const got = db.getAccountInSlot(&pk, 148, &[_]u64{147});
        try std.testing.expect(got != null);
        // FIXED: rooted store serves the CANONICAL bytes (A), fork B destroyed.
        try std.testing.expectEqual(@as(u64, 1_000_145), got.?.lamports);
        try std.testing.expectEqualSlices(u8, &data_canon, got.?.data);
    }
}

test "carrier #7: fork write at HIGHER slot invisible to lower canonical-slot read, before and after root passes it" {
    if (!build_options.two_tier) return;
    const A = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(A, ".");
    defer A.free(path);

    const db = try AccountsDb.init(A, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const pk = core.Pubkey{ .data = [_]u8{0x78} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xAC;
    const owner = core.Pubkey{ .data = owner_bytes };

    var data_base: [64]u8 = undefined;
    @memset(&data_base, 0x11); // canonical rooted base at 100
    var data_fork: [64]u8 = undefined;
    @memset(&data_fork, 0xEE); // fork write at 104

    // Rooted canonical base at 100.
    try db.storeAccount(&pk, &Account{ .lamports = 5_000_100, .owner = owner, .executable = false, .rent_epoch = 0, .data = &data_base }, 100);
    db.rooted_slot = 100;

    // Topology: canonical 100→101→102→103→105; FORK 104 branches off 100
    // (the task's "write on fork at N+2 with parent N−1, read at canonical N"
    // with N=102 ⇒ fork slot 104 has parent 100 = N−2… parent BELOW the
    // reader, slot ABOVE it — the inversion that must stay invisible).
    db.recordSlotParent(101, 100);
    db.recordSlotParent(102, 101);
    db.recordSlotParent(103, 102);
    db.recordSlotParent(104, 100); // fork
    db.recordSlotParent(105, 103);

    // Fork write at the HIGHER slot 104.
    // sig_overlay takes OWNERSHIP of data — dupe with db.allocator.
    try db.sig_overlay.put(db.allocator, 104, pk, .{ .lamports = 9_000_104, .owner = owner, .executable = false, .rent_epoch = 0, .data = try db.allocator.dupe(u8, &data_fork) });
    try simulateOrphanPromote(db, pk, .{ .lamports = 9_000_104, .owner = owner, .executable = false, .rent_epoch = 0, .data = &data_fork }, 104);

    // (1) Read at LOWER canonical slot 102 (ancestors exclude 104): the ring
    // is ancestry-gated → fork bytes invisible → rooted canonical base.
    {
        const got = db.getAccountInSlot(&pk, 102, &[_]u64{101});
        try std.testing.expect(got != null);
        try std.testing.expectEqual(@as(u64, 5_000_100), got.?.lamports);
        try std.testing.expectEqualSlices(u8, &data_base, got.?.data);
    }

    // (2) Root jump 100 → 105 LANDS PAST the fork slot (the task's "promote
    // path under a root jump landing between the two"): 104 ∈ (100,105) is a
    // PROVEN sibling (complete chain) → purged before advanceRoot's ring
    // promotion can file its 104-keyed bytes into the rooted index.
    {
        var p = db.computeRootPartition(A, 100, 105) orelse return error.PartitionNull;
        defer p.deinit(A);
        try std.testing.expect(p.chain_complete);
        var has_104_sibling = false;
        for (p.siblings.items) |s| {
            if (s == 104) has_104_sibling = true;
        }
        try std.testing.expect(has_104_sibling);
        db.promoteRootedChain(p.chain.items);
        for (p.siblings.items) |s| db.purgeUnrootedSlot(s);
        db.advanceRoot(105);
        db.purgeRootedSlot(105, 100, p.chain_complete);
    }

    // (3) Post-advance read: rooted store STILL serves the canonical base —
    // the higher-slot fork write never reached the rooted index.
    {
        const got = db.getAccountInSlot(&pk, 106, &[_]u64{105});
        try std.testing.expect(got != null);
        try std.testing.expectEqual(@as(u64, 5_000_100), got.?.lamports);
        try std.testing.expectEqualSlices(u8, &data_base, got.?.data);
    }
}

// ─── Filter-safety preconditions (must pass on current main before any fix) ──
//
// A read-site filter at accounts.zig:1043 of the form
//   `if (cache_slot_map[pk] not in ancestors) skip unflushed_cache.get`
// would change behavior on TWO axes:
//   (a) canonical reads where csm IS in ancestors -> filter MUST NOT fire
//   (b) orphan reads where filter fires -> fall-through MUST be sane
// T-canonical guards (a). T-fallthrough guards (b). Both pass on current main
// (no filter exists yet), and they document the invariant any future filter
// must preserve. A filter that breaks either invariant is the Phase 1F shape.

test "carrier #2 T-canonical: canonical-ancestor read returns the L1 value" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const target_pk = core.Pubkey{ .data = [_]u8{0x12} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xDD;
    const owner = core.Pubkey{ .data = owner_bytes };

    var canonical_data: [64]u8 = undefined;
    @memset(&canonical_data, 0x55);

    // Canonical slot 895 (a child of slot 894 on the same fork as slot 896)
    // writes pk P. Mirrors a normal in-flight unflushed_cache entry whose
    // owning slot IS an ancestor of the reader at slot 896.
    const canonical_writer_slot: u64 = 409360895;
    try simulateOrphanPromote(db, target_pk, .{
        .lamports = 12_345_678,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &canonical_data,
    }, canonical_writer_slot);

    // Reader at slot 896 with ancestors INCLUDING 895.
    //   sig_overlay/unrooted_ring miss (helper doesn't populate them).
    //   _getRooted line 1043 unflushed_cache.get -> HIT canonical value.
    // Current main: returns canonical value. PASSES.
    // Future filter (csm=895 IS in ancestors -> don't filter): also returns
    // canonical value. PASSES.
    // Over-aggressive filter (e.g., "always skip" or "skip if csm != self"):
    // returns null. FAILS - regression caught.
    const ancestors = [_]u64{ 409360895, 409360894, 409360893, 409360892 };
    const got = db.getAccountInSlot(&target_pk, 409360896, &ancestors);

    try std.testing.expect(got != null);
    try std.testing.expectEqual(@as(u64, 12_345_678), got.?.lamports);
    try std.testing.expectEqualSlices(u8, &canonical_data, got.?.data);
}

test "carrier #2 T-fallthrough: fall-through recovers rooted X when L1 is bypassed" {
    // Phase 1F's regression hypothesis: when the filter skips unflushed_cache,
    // fall-through to bulk_buffer/cache/index returns wrong-bytes or null.
    // This test directly probes that pathway. It does NOT exercise the full
    // Phase 1F regression mechanism (canonical-value-overwritten-by-orphan),
    // which lives in unflushed_cache and disappears when filter fires - that
    // mechanism requires a real freeze/promote cycle and is out of scope for
    // a unit test. This test confirms the LOWER bound: in the configuration
    // where rooted state genuinely lives in storage/cache, fall-through finds
    // it. If this fails on current main, the filter design is impossible
    // until fall-through is fixed first.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    db.fork_isolation_enabled = true;

    const target_pk = core.Pubkey{ .data = [_]u8{0x34} ** 32 };
    var owner_bytes = [_]u8{0} ** 32;
    owner_bytes[0] = 0xEE;
    const owner = core.Pubkey{ .data = owner_bytes };

    var rooted_data: [64]u8 = undefined;
    @memset(&rooted_data, 0x77);
    const rooted_account = Account{
        .lamports = 4_500_000,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &rooted_data,
    };

    // Rooted state X in storage + index + cache (NOT in unflushed_cache).
    try db.storeAccount(&target_pk, &rooted_account, 409360400);

    // Orphan slot 898 writes Y into the fork-blind caches.
    var orphan_data: [64]u8 = undefined;
    @memset(&orphan_data, 0xAA);
    try simulateOrphanPromote(db, target_pk, .{
        .lamports = 11_111,
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &orphan_data,
    }, 409360898);

    // TWO-TIER invariant: the rooted read is index→AppendVec only — it NEVER
    // consults the fork-blind unflushed_cache where the orphan Y lives, so
    // _getRooted returns the ROOTED value X, not the orphan. Under the legacy
    // 5-tier path this returned the orphan 11_111 (the carrier-#2 bug); the
    // two-tier model fixes it by construction (no fork-blind tier in the read).
    const got_rooted = db._getRooted(&target_pk);
    try std.testing.expect(got_rooted != null);
    try std.testing.expectEqual(@as(u64, 4_500_000), got_rooted.?.lamports);

    // Removing the orphan from the (now-unread) unflushed_cache changes nothing:
    // the two-tier rooted read still resolves X via index → storage.
    {
        db.unflushed_cache_lock.lock();
        defer db.unflushed_cache_lock.unlock();
        _ = db.unflushed_cache.remove(target_pk);
    }
    const fall_through = db._getRooted(&target_pk);

    try std.testing.expect(fall_through != null);
    try std.testing.expectEqual(@as(u64, 4_500_000), fall_through.?.lamports);
    try std.testing.expectEqualSlices(u8, &rooted_data, fall_through.?.data);
}

// ── Task #71 (2026-06-10) REGRESSION LOCKS — AppendVec store reclamation ────
// The RSS leak (28-30 GB/h at-tip anon growth) was rooted 64MB AppendVec heap
// stores retained forever: the shrink/purge machinery was triple-dormant AND
// shrinkSlot had a latent index-corruption bug. These tests lock both fixes:
//
//   BUG (pre-fix): stores are SHARED across slots, so a record's true index
//   slot can exceed the mapping slot being shrunk. shrinkSlot re-inserted live
//   records with `.slot = <mapping slot>`; the index higher-slot-wins guard
//   silently REJECTED the re-insert, then the old store was freed immediately
//   → dangling index entry → live account VANISHES (bank_hash divergence).
//
//   FIX: slot-preserving re-insert + QUARANTINE (retired stores stay readable
//   until the root advances accounts_store_quarantine_slots past retirement)
//   + append-active-store guard + fully-dead retire-without-replacement.

test "task #71: shrinkSlot preserves true write slot in a shared store (dangling-index lock)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();

    const owner = core.Pubkey{ .data = [_]u8{0x11} ** 32 };
    const pk_a = core.Pubkey{ .data = [_]u8{0xA1} ** 32 };
    const pk_b = core.Pubkey{ .data = [_]u8{0xB2} ** 32 };

    // One SHARED store holding three records across two slots (the live-tip
    // shape: getOrCreateStore reuses current_bulk_store_id across slots):
    //   A@100 (superseded → dead), B@105 (live), A@110 (live, slot > mapping).
    const loc_a100 = try db.storage.writeAccount(&pk_a, &Account{ .lamports = 1000, .owner = owner, .executable = false, .rent_epoch = 0, .data = "old-A" }, 100);
    try db.index.insert(&pk_a, loc_a100);
    const loc_b105 = try db.storage.writeAccount(&pk_b, &Account{ .lamports = 2000, .owner = owner, .executable = false, .rent_epoch = 0, .data = "live-B" }, 105);
    try db.index.insert(&pk_b, loc_b105);
    const loc_a110 = try db.storage.writeAccount(&pk_a, &Account{ .lamports = 3000, .owner = owner, .executable = false, .rent_epoch = 0, .data = "new-A" }, 110);
    try db.index.insert(&pk_a, loc_a110);

    // All three landed in ONE shared store; both slots map to it.
    try std.testing.expectEqual(loc_a100.store_id, loc_b105.store_id);
    try std.testing.expectEqual(loc_b105.store_id, loc_a110.store_id);
    const old_store_id = loc_a100.store_id;

    // Guard 3 lock: while the store is still append-active, shrink REFUSES.
    db.rooted_slot = 200;
    db.onSlotCompleted(200);
    try std.testing.expect(!(try db.shrinkSlot(100, 0, 0, 0)));

    // Simulate rotation (store sealed) → shrink proceeds.
    db.storage.current_bulk_store_id = null;
    try std.testing.expect(try db.shrinkSlot(100, 0, 0, 0));

    // THE LOCK: both live accounts still resolve, with their TRUE slots.
    // Pre-fix, the re-insert of B@105 and A@110 under slot=100 was rejected by
    // the higher-slot-wins guard and the store was freed → both returned null.
    const got_a = db.getRooted(&pk_a) orelse return error.LiveAccountVanishedAfterShrink;
    try std.testing.expectEqual(@as(u64, 3000), got_a.lamports);
    try std.testing.expectEqualSlices(u8, "new-A", got_a.data);
    const got_b = db.getRooted(&pk_b) orelse return error.LiveAccountVanishedAfterShrink;
    try std.testing.expectEqual(@as(u64, 2000), got_b.lamports);
    try std.testing.expectEqualSlices(u8, "live-B", got_b.data);
    try std.testing.expectEqual(@as(core.Slot, 110), db.index.get(&pk_a).?.slot);
    try std.testing.expectEqual(@as(core.Slot, 105), db.index.get(&pk_b).?.slot);
    // Index now points into the NEW (compacted) store.
    try std.testing.expect(db.index.get(&pk_a).?.store_id != old_store_id);

    // QUARANTINE: the old store is retired, NOT freed — a stale location
    // (reader TOCTOU / borrowed view) still reads byte-identical content.
    try std.testing.expectEqual(@as(usize, 1), db.storage.retired_stores.items.len);
    const stale = db.storage.readAccount(loc_b105) orelse return error.QuarantineViolated;
    try std.testing.expectEqual(@as(u64, 2000), stale.lamports);

    // Mappings to the old store are gone (no re-walk / double-shrink).
    try std.testing.expect(db.storage.slot_to_store.get(100) == null);
    try std.testing.expect(db.storage.slot_to_store.get(105) == null);

    // REAP: before the quarantine window expires — still present.
    db.storage.reapRetired(200 + 511, 512);
    try std.testing.expect(db.storage.stores.get(old_store_id) != null);
    // After expiry — freed, gauges credited, stale reads now miss (allowed).
    db.storage.reapRetired(200 + 512, 512);
    try std.testing.expect(db.storage.stores.get(old_store_id) == null);
    try std.testing.expectEqual(@as(usize, 0), db.storage.retired_stores.items.len);
    // Live reads keep working after the reap.
    try std.testing.expectEqual(@as(u64, 3000), db.getRooted(&pk_a).?.lamports);
}

test "task #71: fully-dead store is retired without a replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();

    const owner = core.Pubkey{ .data = [_]u8{0x22} ** 32 };
    const pk_c = core.Pubkey{ .data = [_]u8{0xC3} ** 32 };

    // C@50 into store-1; force rotation; C@60 supersedes into store-2.
    const loc_c50 = try db.storage.writeAccount(&pk_c, &Account{ .lamports = 500, .owner = owner, .executable = false, .rent_epoch = 0, .data = "v1" }, 50);
    try db.index.insert(&pk_c, loc_c50);
    db.storage.current_bulk_store_id = null;
    const loc_c60 = try db.storage.writeAccount(&pk_c, &Account{ .lamports = 600, .owner = owner, .executable = false, .rent_epoch = 0, .data = "v2" }, 60);
    try db.index.insert(&pk_c, loc_c60);
    try std.testing.expect(loc_c50.store_id != loc_c60.store_id);

    db.rooted_slot = 100;
    db.onSlotCompleted(100);
    const stores_before = db.storage.stores.count();

    // Store-1 is 100% dead → retire WITHOUT creating a replacement store.
    try std.testing.expect(try db.shrinkSlot(50, 50, 1, 5));
    try std.testing.expectEqual(stores_before, db.storage.stores.count()); // retired, not yet freed; no new store
    try std.testing.expect(db.storage.slot_to_store.get(50) == null);
    try std.testing.expectEqual(@as(usize, 1), db.storage.retired_stores.items.len);

    db.storage.reapRetired(100 + 512, 512);
    try std.testing.expectEqual(stores_before - 1, db.storage.stores.count());
    try std.testing.expectEqual(@as(u64, 600), db.getRooted(&pk_c).?.lamports);
}

test "task #71: tickAccountsGc end-to-end — safeSlot watermark + shrink + reap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var db = try AccountsDb.init(std.testing.allocator, path, null);
    defer db.deinit();
    // Deterministic test knobs (init may have read env): shrink on, scan now.
    db.accounts_shrink_enabled = true;
    db.accounts_shrink_ratio_percent = 0;
    db.accounts_shrink_min_bytes = 1;
    db.accounts_shrink_hysteresis_percent = 0;
    db.accounts_gc_scan_interval_ms = 1;
    db.accounts_store_quarantine_slots = 64;
    db.accounts_gc_batch = 16;

    const owner = core.Pubkey{ .data = [_]u8{0x33} ** 32 };
    const pk_d = core.Pubkey{ .data = [_]u8{0xD4} ** 32 };
    const loc_d10 = try db.storage.writeAccount(&pk_d, &Account{ .lamports = 10, .owner = owner, .executable = false, .rent_epoch = 0, .data = "d1" }, 10);
    try db.index.insert(&pk_d, loc_d10);
    db.storage.current_bulk_store_id = null;
    const loc_d20 = try db.storage.writeAccount(&pk_d, &Account{ .lamports = 20, .owner = owner, .executable = false, .rent_epoch = 0, .data = "d2" }, 20);
    try db.index.insert(&pk_d, loc_d20);
    const old_store = loc_d10.store_id;

    // Dormancy lock: with NO onSlotCompleted (watermark 0), the tick is a no-op
    // — this was dormancy cause #3 (safeSlot()==0 even when enabled).
    db.tickAccountsGc(1000, 10);
    try std.testing.expect(db.storage.slot_to_store.get(10) != null);

    // advanceRoot drives the watermark (the new wiring) → tick shrinks store-1
    // (100% dead) and a later tick (root past quarantine) frees it.
    db.advanceRoot(1000);
    db.tickAccountsGc(1000, 20_000);
    try std.testing.expect(db.storage.slot_to_store.get(10) == null);
    try std.testing.expectEqual(@as(usize, 1), db.storage.retired_stores.items.len);
    db.advanceRoot(1000 + 65);
    db.tickAccountsGc(1000 + 65, 40_000);
    try std.testing.expect(db.storage.stores.get(old_store) == null);
    try std.testing.expectEqual(@as(u64, 20), db.getRooted(&pk_d).?.lamports);
}
