//! Phase 2 fork-choice vote-feed wiring (2026-05-26).
//!
//! Bridges the gap between Phase 1's engine (`HeaviestSubtreeForkChoice`)
//! and live cluster vote-state. Provides three things, all under one
//! sibling module so vex_consensus doesn't need to reach back into vex_svm:
//!
//!   1. `EpochStakeLookup` — satisfies `addVotes`' `stake_lookup_ctx.lookup(pubkey, slot) u64`
//!      contract by wrapping a live `accounts_db.epoch_stakes` slice. Walks
//!      to the correct epoch's entry on each lookup (handles epoch boundaries
//!      transparently).
//!
//!   2. `buildSeedBatch` — bootstrap one-time scan. Walks the snapshot's
//!      `epoch_stakes[current].vote_account_stakes`, reads each vote
//!      account's live state from AccountsDb, extracts `last_voted_slot`
//!      via `getLastVotedSlot`, and emits a `PubkeyVote` if the caller can
//!      resolve the voted slot's `bank_hash`. Voters whose vote falls
//!      outside the caller's bank-hash horizon are silently dropped (matches
//!      Agave's `progress.get_hash(slot) -> None` semantics).
//!
//!   3. `buildDeltaBatch` — per-bank post-freeze delta. Walks
//!      `bank.pending_writes` filtered to vote-program-owner. The set of
//!      voters whose vote-state mutated THIS bank. De-duplicates by pubkey
//!      (latest write wins; Phase 1's `addVotes` panics on duplicate
//!      pubkeys within a single batch).
//!
//! ## Agave reference (v4.0.0, byte-identical to v4.1.0-beta.1)
//!
//! - `core/src/consensus.rs:407` `Tower::collect_vote_lockouts`
//! - `core/src/consensus/heaviest_subtree_fork_choice.rs:1259` `compute_bank_stats`
//! - `core/src/consensus/latest_validator_votes_for_frozen_banks.rs` `check_add_vote`
//!
//! Per the agave-behavior-extractor pass (2026-05-26), Agave's flow is a
//! per-frozen-bank full scan of `bank.vote_accounts()`. Vexor's equivalent
//! is bootstrap-seed + per-bank delta from `pending_writes`; the same
//! `(voter, last_voted_slot, frozen_bank_hash)` tuple lands in
//! `latest_votes` either way, as long as the seed runs once.
//!
//! ## Hash source
//!
//! Agave: `progress.get_hash(last_voted_slot)` — the frozen bank's hash at
//! the voted slot, NOT the vote-state's internal hash field.
//! Vexor equivalent: `bank_hash_ctx.lookup(voted_slot) -> ?core.Hash`, which
//! the caller wires to `self.banks.get(voted_slot).?.bank_hash` (or any
//! richer source like SlotHashes sysvar at bootstrap).
//!
//! ## Threading
//!
//! Both `buildSeedBatch` and `buildDeltaBatch` are pure constructors — they
//! only READ from AccountsDb / pending_writes and return owned slices. The
//! caller passes the result to `fc.addVotes` and is responsible for any
//! locking around the fork-choice mutation. As of Phase 2 the only callsite
//! is the single-threaded post-freeze path in `replay_stage.zig:2535` (and
//! the single-threaded bootstrap path in `main.zig`), so no lock is needed
//! today. If a future caller adds parallel access, that caller must add
//! a lock — these constructors are lock-free intentionally.

const std = @import("std");
const core = @import("core");

const vex_consensus = @import("vex_consensus");
const HeaviestSubtreeForkChoice = vex_consensus.fork_choice.HeaviestSubtreeForkChoice;
const SlotHashKey = vex_consensus.fork_choice.SlotHashKey;
const PubkeyVote = HeaviestSubtreeForkChoice.PubkeyVote;

const vote_state_serde = @import("native/vote_state_serde.zig");
// FIX-2 (2026-06-10): canonical EpochSchedule for EpochStakeLookup — LEAF
// module import (NOT bank.zig: the standalone test-fork-choice-feed target
// compiles this file as its own root module without bank.zig's
// vex_crypto/build_options deps). bank.zig re-exports the same type.
const epoch_schedule_mod = @import("native/epoch_schedule.zig");

/// Vote-program owner pubkey (Vote111…). Inlined from
/// `vex_svm/native/vote_program.zig:30` to keep this module's import surface
/// minimal — pulling vote_program.zig in transitively drags bank.zig and
/// trips a pre-existing unrelated test-compile error there. The 32-byte
/// constant is base58-decoded from "Vote111111111111111111111111111111111111111".
const VOTE_PROGRAM_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

// ═══════════════════════════════════════════════════════════════════════════════
// EpochStakeLookup — stake_lookup_ctx for addVotes
// ═══════════════════════════════════════════════════════════════════════════════

/// Adapter that satisfies `addVotes`' `stake_lookup_ctx.lookup(pubkey, slot) u64`
/// contract. Holds a live reference to an epoch_stakes slice (no copy of stake
/// data — re-resolves on every lookup so epoch boundaries Just Work).
///
/// Parameterized over the slice element type so the test compilation can use
/// a local stand-in struct without dragging in `vex_store.snapshot_manifest`.
/// Production callsite: `EpochStakeLookup(@TypeOf(accounts_db.epoch_stakes))`
/// = `EpochStakeLookup([]const vex_store.snapshot_manifest.EpochStakesEntry)`.
///
/// Element shape contract (compile-time enforced via field access):
///   - `entry.epoch: u64`
///   - `entry.vote_account_stakes: []const VAS` where VAS has
///     `.vote_pubkey: [32]u8` and `.stake: u64`.
///
/// Performance: O(epochs × voters_in_epoch) per lookup, ~3 × ~580 = ~1700
/// comparisons. Called once per (voter, slot) inside `addVotes`. For a
/// batch of 580 voters this is ~1M comparisons per bank — under 1 ms.
/// If profile shows this in the hot path, swap to a HashMap built once
/// per epoch (TODO).
pub fn EpochStakeLookup(comptime EpochStakesSlice: type) type {
    return struct {
        const Self = @This();

        epoch_stakes: EpochStakesSlice,
        /// FIX-2 (2026-06-10, proactive-trio): the real EpochSchedule,
        /// threaded from the production caller's bank.epoch_schedule
        /// (replay_stage phase2_delta). Replaces the deleted hardcoded
        /// vote_state_serde.slotToEpoch helper (the 524288-off-by-32
        /// carrier class).
        epoch_schedule: epoch_schedule_mod.EpochSchedule,

        pub fn lookup(self: Self, pubkey: core.Pubkey, slot: core.Slot) u64 {
            const epoch = self.epoch_schedule.getEpoch(slot);
            for (self.epoch_stakes) |entry| {
                if (entry.epoch != epoch) continue;
                for (entry.vote_account_stakes) |vas| {
                    if (std.mem.eql(u8, &vas.vote_pubkey, &pubkey.data)) {
                        return vas.stake;
                    }
                }
                return 0; // epoch found, pubkey not in the staked set
            }
            return 0; // epoch not cached — caller's slot is outside the known window
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Seed / delta batch builders
// ═══════════════════════════════════════════════════════════════════════════════

/// Result counters for the bootstrap seed. Surfaced via the warn-level
/// log line so the soak-watcher can confirm the seed fired.
pub const SeedStats = struct {
    candidates: usize, // voters with non-zero stake in current_epoch
    emitted: usize, // PubkeyVote entries produced
    no_account: usize, // db.getAccount returned null for the vote pubkey
    no_last_vote: usize, // getLastVotedSlot returned null (no votes yet)
    no_bank_hash: usize, // bank_hash_ctx.lookup returned null (vote outside horizon)
};

/// Build the bootstrap PubkeyVote batch from the snapshot's vote accounts.
/// Caller owns the returned slice (free with the same allocator).
///
/// All producer-side types are `anytype` to keep the module decoupled from
/// `vex_store.snapshot_manifest` / `AccountsDb` internals (a recursive
/// import of those drags in `bank.zig` → `vex_crypto` → a heavyweight chain).
/// The contracts are:
///
/// - `db.getAccount(*const core.Pubkey) ?AccountView` where AccountView has
///   `.data: []const u8`. `*AccountsDb` satisfies this directly.
/// - `epoch_stakes` is a slice; each element has `.epoch: u64` and
///   `.vote_account_stakes` (a slice with elements that have
///   `.vote_pubkey: [32]u8` and `.stake: u64`).
/// - `bank_hash_ctx.lookup(slot: u64) ?core.Hash`. Caller wraps
///   `replay_stage.banks.get(slot)` (or a richer source like SlotHashes).
///
/// Logs the stats at warn-level so soak-watcher can see whether the seed
/// fired and how many votes landed.
pub fn buildSeedBatch(
    allocator: std.mem.Allocator,
    db: anytype,
    epoch_stakes: anytype,
    current_epoch: u64,
    bank_hash_ctx: anytype,
) !struct { votes: []PubkeyVote, stats: SeedStats } {
    var batch = std.ArrayListUnmanaged(PubkeyVote){};
    errdefer batch.deinit(allocator);

    var stats = SeedStats{
        .candidates = 0,
        .emitted = 0,
        .no_account = 0,
        .no_last_vote = 0,
        .no_bank_hash = 0,
    };

    var stakes_opt: ?@TypeOf(epoch_stakes[0].vote_account_stakes) = null;
    for (epoch_stakes) |entry| {
        if (entry.epoch == current_epoch) {
            stakes_opt = entry.vote_account_stakes;
            break;
        }
    }
    const stakes = stakes_opt orelse {
        std.log.warn(
            "[FORK-CHOICE-SEED] no epoch_stakes entry for epoch={d} (have {d} epochs cached)",
            .{ current_epoch, epoch_stakes.len },
        );
        return .{ .votes = try batch.toOwnedSlice(allocator), .stats = stats };
    };

    for (stakes) |vas| {
        if (vas.stake == 0) continue;
        stats.candidates += 1;
        const pubkey = core.Pubkey{ .data = vas.vote_pubkey };
        const account = db.getAccount(&pubkey) orelse {
            stats.no_account += 1;
            continue;
        };
        const voted_slot = vote_state_serde.getLastVotedSlot(account.data) orelse {
            stats.no_last_vote += 1;
            continue;
        };
        const bh = bank_hash_ctx.lookup(voted_slot) orelse {
            stats.no_bank_hash += 1;
            continue;
        };
        try batch.append(allocator, .{
            .pubkey = pubkey,
            .slot_hash = .{ .slot = voted_slot, .hash = bh },
        });
        stats.emitted += 1;
    }

    std.log.warn(
        "[FORK-CHOICE-SEED] epoch={d} candidates={d} emitted={d} no_account={d} no_last_vote={d} no_bank_hash={d}",
        .{
            current_epoch,
            stats.candidates,
            stats.emitted,
            stats.no_account,
            stats.no_last_vote,
            stats.no_bank_hash,
        },
    );

    return .{ .votes = try batch.toOwnedSlice(allocator), .stats = stats };
}

/// Per-bank vote-account scan stats — mirrors Agave `compute_bank_stats` book-keeping.
pub const VoteAccountBatchStats = struct {
    vote_accounts: usize, // top_votes entries scanned (≈ all known voters)
    emitted: usize, // PubkeyVote entries produced
    duplicates: usize, // always 0 (top_votes is keyed by unique pubkey); kept for log-line compat
    no_last_vote: usize, // TopVote.latestVotedSlot() returned null (empty tower)
    no_bank_hash: usize, // bank_hash_ctx.lookup returned null (vote outside frozen-bank horizon)
    // DIAG (2026-06-03, A-vs-B disambiguation): of all candidates (those with a
    // non-null latestVotedSlot), how many have a FRESH voted_slot — within
    // RECENT_WINDOW of the highest voted_slot seen this scan — and of those,
    // how many resolved a bank_hash. `recent` ≈ count of voters whose top_votes
    // entry was refreshed recently (the active set). Interpretation at steady tip:
    //   recent ≈ active_set & recent_resolved ≈ active_set → feed healthy.
    //   recent ≈ 1 → top_votes NOT refreshed at tip (candidate A: refresh path).
    //   recent ≈ active_set but recent_resolved ≈ 1 → bank_hash lookup fails for
    //     fresh votes (candidate B: bank retention at read time).
    recent: usize = 0,
    recent_resolved: usize = 0,
    max_voted: u64 = 0, // highest voted_slot among candidates (the scan frontier)
};

/// Freshness window for `recent`/`recent_resolved`: a candidate counts as "recent"
/// if its voted_slot is within this many slots of the scan's `max_voted` frontier.
/// 64 ≈ 2× the tower-root retention depth, so any voter refreshed within the last
/// ~25s of tip falls inside it.
pub const RECENT_WINDOW: u64 = 64;

/// Backwards-compat alias so the [FORK-CHOICE-DELTA] log line + caller code
/// keep compiling without churn. The semantics shifted from "per-bank delta"
/// to "per-bank full scan of vote accounts" (see redesign 2026-05-26), and
/// the fields are renamed to match.
pub const DeltaStats = VoteAccountBatchStats;

/// Build a `PubkeyVote` batch by scanning `db.top_votes` — the stable,
/// fork-aware per-voter vote summary. Caller owns the returned slice.
///
/// REDESIGN-2 (2026-06-03 — supersedes the 2026-05-26 unflushed_cache scan):
///
///   The 2026-05-26 redesign correctly aimed to "walk the stable per-bank view
///   of all vote accounts" (Agave `bank.vote_accounts()` /
///   `core/src/consensus.rs:433 Tower::collect_vote_lockouts`) but picked the
///   WRONG Vexor structure: `db.unflushed_cache`. That cache is a *write-back
///   delta*, drained independently of rooting by `flushCacheToDisk`
///   (accounts.zig:2042, "called periodically to prevent unbounded RAM growth").
///   During catch-up the flush lags so vote writes accumulate and the feed sees
///   them — but AT THE TIP the flush keeps up, so by the time `onSlotCompleted`
///   reads the cache the just-written vote accounts are already flushed out →
///   `vote_accounts=0 emitted=0` → fork choice gets no stake weight →
///   `is_same_fork=false` → the validator stops voting (the deploy-2 / 2026-06-03
///   "delinquent-at-tip while replaying cleanly" failure; the earlier "transient
///   boot anomaly" diagnosis was wrong — it is flush-timing, hence intermittent).
///
///   `db.top_votes` is the correct stable analog (Firedancer `fd_top_votes_t` /
///   `fd_vote_stakes_fork_iter`; Agave per-bank `stakes_cache.vote_accounts()`):
///   snapshot-seeded at boot (bootstrap.zig:786), upserted on EVERY vote commit
///   (accounts.zig:1062 produce-path, replay_stage.zig:5939 replay-path), and
///   only ever removed on vote-account close (lamports==0) or collapsed to a
///   rooted baseline by `pruneBelowRoot`. It SURVIVES `flushCacheToDisk` and
///   root advance. Per-voter we take `TopVote.latestVotedSlot()` (the tower top
///   of the highest-`write_slot` version — same value the legacy feed parsed via
///   `getLastVotedSlot`, now stored at write time in `tower_last_voted_slot`).
///
///   Inactive voters (last vote outside our frozen-bank horizon) are filtered
///   naturally in pass 2: `bank_hash_ctx.lookup(old_slot)` returns null →
///   `no_bank_hash` → skipped, exactly mirroring Agave `progress.get_hash → None`.
///
/// `db` is `anytype`; the contract is two fields:
///   - `top_votes: std.AutoHashMap([32]u8, TopVote)` — iterable; `key_ptr.*` is
///     the 32-byte vote pubkey, `value_ptr.latestVotedSlot() ?u64` the tower top.
///   - `top_votes_lock: std.Thread.Mutex` — held during pass 1.
/// `vex_store.accounts.AccountsDb` satisfies the contract directly.
///
/// `bank_hash_ctx` must expose `lookup(slot: u64) ?core.Hash`. Lookup is done
/// in pass 2, AFTER `top_votes_lock` is released, so the caller's
/// `bank_hash_ctx` is free to acquire its own locks (e.g. `banks_lock`)
/// without risking lock-order inversion.
pub fn buildVoteAccountBatch(
    allocator: std.mem.Allocator,
    db: anytype,
    bank_hash_ctx: anytype,
) !struct { votes: []PubkeyVote, stats: VoteAccountBatchStats } {
    var stats = VoteAccountBatchStats{
        .vote_accounts = 0,
        .emitted = 0,
        .duplicates = 0,
        .no_last_vote = 0,
        .no_bank_hash = 0,
    };

    // Pass 1 — under top_votes_lock: collect (pubkey, voted_slot) pairs.
    // top_votes is keyed by unique pubkey (no dedup needed), holds only vote
    // accounts (no owner filter needed), and the tower top was parsed at write
    // time (no getLastVotedSlot re-parse of ~1500 blobs per slot). voted_slot
    // is a u64 — safe to carry out of the lock.
    const Candidate = struct { pubkey: core.Pubkey, voted_slot: u64 };
    var candidates = std.ArrayListUnmanaged(Candidate){};
    defer candidates.deinit(allocator);

    {
        db.top_votes_lock.lock();
        defer db.top_votes_lock.unlock();

        var iter = db.top_votes.iterator();
        while (iter.next()) |entry| {
            stats.vote_accounts += 1;
            const voted_slot = entry.value_ptr.latestVotedSlot() orelse {
                stats.no_last_vote += 1;
                continue;
            };
            if (voted_slot > stats.max_voted) stats.max_voted = voted_slot;
            try candidates.append(allocator, .{
                .pubkey = core.Pubkey{ .data = entry.key_ptr.* },
                .voted_slot = voted_slot,
            });
        }
    } // top_votes_lock released here.

    // Pass 2 — outside the lock: resolve bank_hash and emit PubkeyVote entries.
    // bank_hash_ctx may acquire its own locks (e.g. banks_lock); doing it here
    // avoids any lock-order interaction with top_votes_lock.
    var batch = std.ArrayListUnmanaged(PubkeyVote){};
    errdefer batch.deinit(allocator);
    try batch.ensureTotalCapacity(allocator, candidates.items.len);

    for (candidates.items) |c| {
        // DIAG: classify freshness relative to the scan frontier BEFORE resolving,
        // so `recent` reflects top_votes refresh coverage independent of bank_hash.
        const is_recent = c.voted_slot +| RECENT_WINDOW >= stats.max_voted;
        if (is_recent) stats.recent += 1;
        const bh = bank_hash_ctx.lookup(c.voted_slot) orelse {
            stats.no_bank_hash += 1;
            continue;
        };
        if (is_recent) stats.recent_resolved += 1;
        batch.appendAssumeCapacity(.{
            .pubkey = c.pubkey,
            .slot_hash = .{ .slot = c.voted_slot, .hash = bh },
        });
        stats.emitted += 1;
    }

    return .{ .votes = try batch.toOwnedSlice(allocator), .stats = stats };
}

/// Stats for the fork-aware fresh scan (mirrors VoteAccountBatchStats' shape
/// for [SWITCH-VOTE-FRESH] log-line compat).
pub const FreshBatchStats = struct {
    candidates: usize, // staked (stake>0) voters in the epoch_stakes table
    emitted: usize, // PubkeyVote entries produced
    no_account: usize, // getAccountInSlot returned null (no vote account on this fork's ancestry)
    no_last_vote: usize, // getLastVotedSlot returned null (empty tower)
    no_bank_hash: usize, // bank_hash_ctx.lookup returned null (voted slot outside our frozen-bank horizon)
    parse_fail: usize, // account data too large for the scratch buffer (defensive; should not fire)
};

/// Scratch buffer sized for the largest known vote-state encoding (V4 frame =
/// 3762 B per bank.zig:1364's carrier-#15 precedent; 8 KiB covers every
/// historical vote-state size with wide margin).
const VOTE_ACCOUNT_SCRATCH_BYTES: usize = 8192;

/// Build a `PubkeyVote` batch by reading EVERY staked voter's vote-account
/// state DIRECTLY from `db`, fork-aware, at the exact candidate bank
/// (`slot`, `ancestors`) — no persistent cross-call cache in the path.
///
/// WHY THIS EXISTS (switch-proof gossip-arming wedge, live specimen slot
/// 422521275, 2026-07-17): `buildVoteAccountBatch` (above) sources
/// (pubkey, voted_slot) from `db.top_votes`, a side cache upserted ONLY via
/// `AccountsDb.refreshTopVoteForWrite`, itself called ONLY from
/// `flushPendingWritesToDb` / `flushPendingWritesFromIndex` /
/// `promoteRootedChain` (replay_stage.zig / accounts_db.zig). On the live
/// wedged node that cache stopped advancing at slot 422521280 (TOPVOTES-DIAG
/// log line count: 0 for the ~25,000 replayed slots since) while replay
/// itself stayed healthy at the cluster tip (bank_hash matched, no
/// divergence) — proving the CACHE went stale relative to the CANONICAL
/// account state the bank actually committed, not that replay stalled. The
/// switch-proof landed loop (fork_choice.zig checkSwitchThresholdGossip)
/// consumes exactly that stale cache via `fc.latest_votes`
/// (fed by `buildVoteAccountBatch` in replay_stage.zig's phase2_delta), so it
/// could never observe any voter but ourselves — locked_out stayed 0/T
/// forever, and switch-proof could never arm.
///
/// This is the SAME bug CLASS already fixed once in this codebase for the
/// Clock sysvar estimator (carrier #15, 2026-06-11, @414723807,
/// bank.zig:1308-1339 `computeStakeWeightedClockEstimate`): "sample PARENT-
/// BANK VOTE STATE through the fork-aware AccountsDb read path — NOT the
/// global top_votes cache." This function applies the identical fix shape to
/// the switch-proof vote source.
///
/// Agave canonical: `core/src/consensus.rs:407` `collect_vote_lockouts`,
/// called by `core/src/replay_stage.rs:4391` `compute_bank_stats` for EVERY
/// newly-frozen bank. It iterates `vote_accounts: &VoteAccountsHashMap` —
/// `bank.vote_accounts()`, the frozen BANK'S OWN live vote-program account
/// state (backed by Agave's `StakesCache`, which is updated at the account-
/// commit primitive itself, not a downstream flush-orchestration hook a
/// future execution engine could bypass) — and feeds each voter's
/// `last_voted_slot()` into `latest_validator_votes_for_frozen_banks`
/// (consensus.rs:472-479 `check_add_vote`), the SAME structure the switch-
/// proof's `max_gossip_frozen_votes()` loop reads (consensus.rs:1222). There
/// is no persistent side cache in Agave's landed path that a bypassed write
/// path could leave stale: every bank re-derives the full staked-voter view
/// from the bank's committed account state.
///
/// `db.getAccountInSlot(pubkey, slot, ancestors) ?AccountView` — fork-aware
/// read (already used for exactly this purpose by the Clock estimator and by
/// ordinary transaction execution reads).
/// `epoch_stakes` / `bank_hash_ctx` — same contracts as `buildSeedBatch`.
///
/// Cost: ~600-2000 staked-voter reads+parses per bank (the epoch_stakes
/// staked set, NOT the ~15,522-entry raw table) — the SAME per-bank cost
/// class already proven affordable by the Clock estimator's identical scan
/// (bank.zig:1370 "~600 reads/slot without strain").
pub fn buildVoteAccountBatchFresh(
    allocator: std.mem.Allocator,
    db: anytype,
    epoch_stakes: anytype,
    current_epoch: u64,
    slot: u64,
    ancestors: []const u64,
    bank_hash_ctx: anytype,
) !struct { votes: []PubkeyVote, stats: FreshBatchStats } {
    var batch = std.ArrayListUnmanaged(PubkeyVote){};
    errdefer batch.deinit(allocator);

    var stats = FreshBatchStats{
        .candidates = 0,
        .emitted = 0,
        .no_account = 0,
        .no_last_vote = 0,
        .no_bank_hash = 0,
        .parse_fail = 0,
    };

    var stakes_opt: ?@TypeOf(epoch_stakes[0].vote_account_stakes) = null;
    for (epoch_stakes) |entry| {
        if (entry.epoch == current_epoch) {
            stakes_opt = entry.vote_account_stakes;
            break;
        }
    }
    const stakes = stakes_opt orelse {
        return .{ .votes = try batch.toOwnedSlice(allocator), .stats = stats };
    };

    try batch.ensureTotalCapacity(allocator, stakes.len);

    // r55-E class (bank.zig:1360-1364 precedent): getAccountInSlot returns
    // slices into mmap'd/unflushed storage a concurrent flush can remap —
    // copy into a fixed scratch buffer before parsing.
    var data_buf: [VOTE_ACCOUNT_SCRATCH_BYTES]u8 = undefined;

    for (stakes) |vas| {
        if (vas.stake == 0) continue; // zero-stake voters contribute nothing (Agave: epoch_vote_accounts is the staked set only)
        stats.candidates += 1;
        const pubkey = core.Pubkey{ .data = vas.vote_pubkey };
        const account = db.getAccountInSlot(&pubkey, slot, ancestors) orelse {
            stats.no_account += 1;
            continue;
        };
        if (account.data.len == 0 or account.data.len > data_buf.len) {
            stats.parse_fail += 1;
            continue;
        }
        @memcpy(data_buf[0..account.data.len], account.data);
        const voted_slot = vote_state_serde.getLastVotedSlot(data_buf[0..account.data.len]) orelse {
            stats.no_last_vote += 1;
            continue;
        };
        const bh = bank_hash_ctx.lookup(voted_slot) orelse {
            stats.no_bank_hash += 1;
            continue;
        };
        batch.appendAssumeCapacity(.{
            .pubkey = pubkey,
            .slot_hash = .{ .slot = voted_slot, .hash = bh },
        });
        stats.emitted += 1;
    }

    return .{ .votes = try batch.toOwnedSlice(allocator), .stats = stats };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

// Shape-equivalent stand-ins for `vex_store.snapshot_manifest` /
// `bank.AccountWrite` / `vex_store.accounts.AccountView` — kept local so
// the test compilation doesn't drag those modules in.

const TestVoteAccountStake = struct {
    vote_pubkey: [32]u8,
    stake: u64,
};

const TestEpochStakesEntry = struct {
    epoch: u64,
    vote_account_stakes: []const TestVoteAccountStake,
    node_pubkeys: []const [32]u8 = &[_][32]u8{},
};

const TestAccountWrite = struct {
    pubkey: core.Pubkey,
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

const TestAccountView = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

const TestBankHash = struct {
    table: std.AutoHashMapUnmanaged(u64, core.Hash) = .{},

    fn deinit(self: *TestBankHash, alloc: std.mem.Allocator) void {
        self.table.deinit(alloc);
    }

    pub fn lookup(self: *const TestBankHash, slot: u64) ?core.Hash {
        return self.table.get(slot);
    }
};

test "EpochStakeLookup returns stake when epoch matches" {
    // EpochStakeLookup's signature pins to `[]const EpochStakesEntry`, so we
    // construct it via @TypeOf'd lookup behavior — for the test we just call
    // .lookup against a shape-compatible struct.
    const pk1 = [_]u8{0x11} ** 32;
    const pk2 = [_]u8{0x22} ** 32;
    const stakes = [_]TestVoteAccountStake{
        .{ .vote_pubkey = pk1, .stake = 1000 },
        .{ .vote_pubkey = pk2, .stake = 500 },
    };
    const entries = [_]TestEpochStakesEntry{
        .{ .epoch = 100, .vote_account_stakes = &stakes },
    };

    // Instantiate EpochStakeLookup against the test slice type — exercises
    // the actual production algorithm (same generic struct, different element
    // type). Production callsite will use the same generic with
    // `[]const vex_store.snapshot_manifest.EpochStakesEntry`.
    const Lookup = EpochStakeLookup([]const TestEpochStakesEntry);
    const lookup = Lookup{ .epoch_stakes = &entries, .epoch_schedule = epoch_schedule_mod.EpochSchedule.DEFAULT };

    // Pick a slot inside epoch 100 (post-warmup): slot = 524288 + (100-14)*432000.
    const slot_in_epoch_100: u64 = 524288 + (100 - 14) * 432_000;
    try testing.expectEqual(@as(u64, 1000), lookup.lookup(core.Pubkey{ .data = pk1 }, slot_in_epoch_100));
    try testing.expectEqual(@as(u64, 500), lookup.lookup(core.Pubkey{ .data = pk2 }, slot_in_epoch_100));

    // Unknown pubkey → 0
    const unknown = [_]u8{0x33} ** 32;
    try testing.expectEqual(@as(u64, 0), lookup.lookup(core.Pubkey{ .data = unknown }, slot_in_epoch_100));

    // Slot in an unknown epoch → 0
    const slot_far_future: u64 = 524288 + (200 - 14) * 432_000;
    try testing.expectEqual(@as(u64, 0), lookup.lookup(core.Pubkey{ .data = pk1 }, slot_far_future));
}

// Test stubs for buildVoteAccountBatch — match the REDESIGN-2 production
// contract (top_votes + top_votes_lock). `TestTopVote` mirrors
// `vex_store.accounts.TopVote`'s `latestVotedSlot()` duck-typed contract; the
// feed only calls that one method, so the test needn't reproduce the
// multi-version internals. Owns the HashMap; tests fill it then pass `&stub`.
const TestTopVote = struct {
    tower_last_voted_slot: u64,
    pub fn latestVotedSlot(self: *const TestTopVote) ?u64 {
        return if (self.tower_last_voted_slot == 0) null else self.tower_last_voted_slot;
    }
};
const TestDb = struct {
    top_votes: std.AutoHashMap([32]u8, TestTopVote),
    top_votes_lock: std.Thread.Mutex = .{},

    fn init(alloc: std.mem.Allocator) TestDb {
        return .{ .top_votes = std.AutoHashMap([32]u8, TestTopVote).init(alloc) };
    }
    fn deinit(self: *TestDb) void {
        self.top_votes.deinit();
    }
};

test "buildVoteAccountBatch full-scan emits one PubkeyVote per vote account" {
    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 100, core.Hash{ .data = [_]u8{0xAA} ** 32 });
    try bh.table.put(testing.allocator, 101, core.Hash{ .data = [_]u8{0xBB} ** 32 });

    // Two voters with different tower tops — exercises full-scan emission.
    var db = TestDb.init(testing.allocator);
    defer db.deinit();
    try db.top_votes.put([_]u8{0x44} ** 32, .{ .tower_last_voted_slot = 100 });
    try db.top_votes.put([_]u8{0x55} ** 32, .{ .tower_last_voted_slot = 101 });

    const out = try buildVoteAccountBatch(testing.allocator, &db, &bh);
    defer testing.allocator.free(out.votes);

    try testing.expectEqual(@as(usize, 2), out.votes.len);
    try testing.expectEqual(@as(usize, 2), out.stats.vote_accounts);
    try testing.expectEqual(@as(usize, 2), out.stats.emitted);
    try testing.expectEqual(@as(usize, 0), out.stats.no_bank_hash);
}

test "buildVoteAccountBatch skips a voter with an empty tower (no_last_vote)" {
    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 100, core.Hash{ .data = [_]u8{0xAA} ** 32 });

    var db = TestDb.init(testing.allocator);
    defer db.deinit();
    // One real voter (tower top 100) + one with an empty tower (0 → skipped).
    try db.top_votes.put([_]u8{0x44} ** 32, .{ .tower_last_voted_slot = 100 });
    try db.top_votes.put([_]u8{0x55} ** 32, .{ .tower_last_voted_slot = 0 });

    const out = try buildVoteAccountBatch(testing.allocator, &db, &bh);
    defer testing.allocator.free(out.votes);

    try testing.expectEqual(@as(usize, 1), out.votes.len);
    try testing.expectEqual(@as(usize, 2), out.stats.vote_accounts);
    try testing.expectEqual(@as(usize, 1), out.stats.emitted);
    try testing.expectEqual(@as(usize, 1), out.stats.no_last_vote);
}

test "buildVoteAccountBatch skips when bank_hash_ctx returns null" {
    var bh = TestBankHash{}; // empty — every lookup returns null
    defer bh.deinit(testing.allocator);

    var db = TestDb.init(testing.allocator);
    defer db.deinit();
    try db.top_votes.put([_]u8{0x44} ** 32, .{ .tower_last_voted_slot = 100 });

    const out = try buildVoteAccountBatch(testing.allocator, &db, &bh);
    defer testing.allocator.free(out.votes);

    try testing.expectEqual(@as(usize, 0), out.votes.len);
    try testing.expectEqual(@as(usize, 1), out.stats.vote_accounts);
    try testing.expectEqual(@as(usize, 1), out.stats.no_bank_hash);
}

test "buildVoteAccountBatch returns empty when top_votes is empty" {
    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    var db = TestDb.init(testing.allocator);
    defer db.deinit();
    // Empty top_votes → empty batch.
    const out = try buildVoteAccountBatch(testing.allocator, &db, &bh);
    defer testing.allocator.free(out.votes);
    try testing.expectEqual(@as(usize, 0), out.votes.len);
    try testing.expectEqual(@as(usize, 0), out.stats.vote_accounts);
}

test "buildSeedBatch end-to-end with stub AccountsDb" {
    // Stub AccountsDb that hands out a single canned vote-state blob per pubkey.
    const Stub = struct {
        const Self = @This();
        accounts: std.AutoHashMapUnmanaged(core.Pubkey, TestAccountView),

        pub fn getAccount(self: *Self, pubkey: *const core.Pubkey) ?TestAccountView {
            return self.accounts.get(pubkey.*);
        }
    };

    const pk1 = [_]u8{0x11} ** 32;
    const pk2 = [_]u8{0x22} ** 32;
    const vote_owner: core.Pubkey = .{ .data = VOTE_PROGRAM_ID };

    // Build two vote-state blobs: voter1 voted slot 100, voter2 voted slot 200.
    var blob1: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&blob1, 0);
    {
        var vs = vote_state_serde.VoteState.init();
        vs.version = 2;
        vs.av_count = 1;
        vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
        vs.lockout_count = 1;
        vs.lockouts[0] = .{ .slot = 100, .confirmation_count = 1 };
        _ = vote_state_serde.serializeVoteState(&vs, &blob1);
    }
    var blob2: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    @memset(&blob2, 0);
    {
        var vs = vote_state_serde.VoteState.init();
        vs.version = 2;
        vs.av_count = 1;
        vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
        vs.lockout_count = 1;
        vs.lockouts[0] = .{ .slot = 200, .confirmation_count = 1 };
        _ = vote_state_serde.serializeVoteState(&vs, &blob2);
    }

    var stub = Stub{ .accounts = .{} };
    defer stub.accounts.deinit(testing.allocator);
    try stub.accounts.put(testing.allocator, .{ .data = pk1 }, .{
        .lamports = 1,
        .owner = vote_owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &blob1,
    });
    try stub.accounts.put(testing.allocator, .{ .data = pk2 }, .{
        .lamports = 1,
        .owner = vote_owner,
        .executable = false,
        .rent_epoch = 0,
        .data = &blob2,
    });

    // bank_hash_ctx knows slot 100 but NOT slot 200 — exercises both paths.
    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 100, core.Hash{ .data = [_]u8{0xAA} ** 32 });

    // epoch_stakes: voter1 has 1000 stake, voter2 has 500 stake.
    const stakes = [_]TestVoteAccountStake{
        .{ .vote_pubkey = pk1, .stake = 1000 },
        .{ .vote_pubkey = pk2, .stake = 500 },
    };
    const entries = [_]TestEpochStakesEntry{
        .{ .epoch = 100, .vote_account_stakes = &stakes },
    };

    const out = try buildSeedBatch(testing.allocator, &stub, &entries, 100, &bh);
    defer testing.allocator.free(out.votes);

    // voter1 → emitted (slot 100 has a bank hash); voter2 → no_bank_hash.
    try testing.expectEqual(@as(usize, 2), out.stats.candidates);
    try testing.expectEqual(@as(usize, 1), out.stats.emitted);
    try testing.expectEqual(@as(usize, 1), out.stats.no_bank_hash);
    try testing.expectEqual(@as(usize, 1), out.votes.len);
    try testing.expectEqual(@as(u64, 100), out.votes[0].slot_hash.slot);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KAT — live wedge slot 422521275 (2026-07-17, fix/switchproof-gossip-arming)
//
// Reconstructs the ACTUAL captured live-testnet incident numbers from the
// incident log:
//   * rooted        = 422521202  (tower root; frozen for the whole wedge — we
//                       never voted again, so accounts_db.rooted_slot / the
//                       tower root never advances)
//   * last_vote     = 422521275  (our tower's last CAST vote — on the fork
//                       that never landed; RPC confirms only 422503891 ever
//                       landed, but Agave's own `last_voted_slot_hash()` is
//                       the tower's cast vote too — consensus.rs:960 — so
//                       this is canonical, not the bug)
//   * candidate/tip = 422525390  (first switch-slot named in the live refusal
//                       log: "InvalidRootSlot ... candidate 422525390")
//                     422532524  (tip slot from the last captured
//                       [FORK-CHOICE-DELTA] / [TOWER-LOCKOUT] lines)
//   * max_voted     = 422521274  (the EXACT plateau value `db.top_votes`
//                       froze at, live: FORK-CHOICE-DELTA "max_voted=422521274"
//                       repeating for 11,000+ consecutive replayed slots)
//
// The KAT below does NOT invent a mechanism — it drives the REAL
// `buildVoteAccountBatch` (stale, top_votes-sourced — the pre-fix production
// path) and `buildVoteAccountBatchFresh` (fork-aware direct read — the fix)
// against the SAME underlying voter state, then feeds each batch's output
// into the REAL `HeaviestSubtreeForkChoice.checkSwitchThreshold` (the same
// switch-proof engine replay_stage.zig calls) to prove:
//   1. PRE-FIX shape: the stale batch's slot (422521274) is <= last_vote
//      (422521275) → the switch-proof's strictly-newer filter (canonical,
//      Agave consensus.rs:1228) drops it → 0 stake observed → refuses
//      forever, byte-identical to the live specimen's
//      `locked_out=0/... gossip_cnt=0/...` shape.
//   2. POST-FIX shape: the fresh batch's slot reflects the voter's CURRENT
//      on-chain vote (past last_vote, on the canonical fork) → passes the
//      filter → counted → arms when stake crosses 38%.
//   3. Both-directions safety: the fresh path does NOT arm when the other
//      fork's observed stake stays under 38% — the fix does not make Vexor
//      switch more eagerly than Agave would.
const wedge_test = struct {
    const HSFC = vex_consensus.fork_choice.HeaviestSubtreeForkChoice;
    const PSLK = struct {
        entries: []const struct { pubkey: core.Pubkey, stake: u64 },
        pub fn lookup(self: @This(), pk: core.Pubkey, _: core.Slot) u64 {
            for (self.entries) |e| if (std.mem.eql(u8, &e.pubkey.data, &pk.data)) return e.stake;
            return 0;
        }
    };

    /// root(422521202) → dead(422521275) [our abandoned last-vote fork]
    ///                 → canon_mid(422525390) → canon_tip(422532524) [the
    ///                   REAL fork the rest of the cluster kept building —
    ///                   the exact candidate/tip slots from the live log].
    const Tree = struct {
        root: SlotHashKey,
        dead: SlotHashKey,
        canon_mid: SlotHashKey,
        canon_tip: SlotHashKey,
        fn k(slot: u64, tag: u8) SlotHashKey {
            return .{ .slot = slot, .hash = .{ .data = [_]u8{tag} ** 32 } };
        }
        fn build(fc: *HSFC) !Tree {
            const root = k(422521202, 0x10);
            try fc.seedRoot(root);
            const dead = k(422521275, 0xDE);
            const canon_mid = k(422525390, 0xC1);
            const canon_tip = k(422532524, 0xC2);
            try fc.addNewLeafSlot(dead, root);
            try fc.addNewLeafSlot(canon_mid, root);
            try fc.addNewLeafSlot(canon_tip, canon_mid);
            return .{ .root = root, .dead = dead, .canon_mid = canon_mid, .canon_tip = canon_tip };
        }
    };

    const FreshDb = struct {
        accounts: std.AutoHashMapUnmanaged(core.Pubkey, TestAccountView) = .{},
        pub fn getAccountInSlot(self: *const @This(), pubkey: *const core.Pubkey, _: u64, _: []const u64) ?TestAccountView {
            return self.accounts.get(pubkey.*);
        }
    };

    fn voteBlob(buf: *[vote_state_serde.VOTE_STATE_V3_SZ]u8, voted_slot: u64) void {
        @memset(buf, 0);
        var vs = vote_state_serde.VoteState.init();
        vs.version = 2;
        vs.av_count = 1;
        vs.authorized_voters[0] = .{ .epoch = 0, .pubkey = [_]u8{0} ** 32 };
        vs.lockout_count = 1;
        vs.lockouts[0] = .{ .slot = voted_slot, .confirmation_count = 1 };
        _ = vote_state_serde.serializeVoteState(&vs, buf);
    }
};

test "KAT wedge-422521275: stale top_votes batch is filtered to zero (reproduces the live refusal)" {
    // Two voters, 50%+15% of a 1000-unit total stake — well past the 38% bar
    // IF their fresh votes counted.
    const pk1 = core.Pubkey{ .data = [_]u8{0x41} ** 32 };
    const pk2 = core.Pubkey{ .data = [_]u8{0x42} ** 32 };

    // db.top_votes: BOTH voters frozen at the live-captured plateau value
    // (422521274 == last_vote - 1, exactly what [FORK-CHOICE-DELTA] logged
    // for 11,000+ consecutive slots on the live node).
    var db = TestDb.init(testing.allocator);
    defer db.deinit();
    try db.top_votes.put(pk1.data, .{ .tower_last_voted_slot = 422521274 });
    try db.top_votes.put(pk2.data, .{ .tower_last_voted_slot = 422521274 });

    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 422521274, core.Hash{ .data = [_]u8{0xF0} ** 32 });
    try bh.table.put(testing.allocator, 422532524, core.Hash{ .data = [_]u8{0xC2} ** 32 }); // == canon_tip hash

    const out = try buildVoteAccountBatch(testing.allocator, &db, &bh);
    defer testing.allocator.free(out.votes);
    try testing.expectEqual(@as(usize, 2), out.votes.len);
    // Both entries resolve (bank_hash_ctx DOES have 422521274 cached — isolating
    // the bug to the SOURCE, not the hash lookup) but at the STALE slot.
    for (out.votes) |v| try testing.expectEqual(@as(u64, 422521274), v.slot_hash.slot);

    // Feed the REAL switch-proof engine — this is exactly replay_stage.zig's
    // phase2_delta → fc.addVotes → fc.checkSwitchThreshold call shape.
    var fc = wedge_test.HSFC.init(testing.allocator);
    defer fc.deinit();
    const t = try wedge_test.Tree.build(&fc);
    const stakes = wedge_test.PSLK{ .entries = &.{
        .{ .pubkey = pk1, .stake = 500 },
        .{ .pubkey = pk2, .stake = 150 },
    } };
    _ = try fc.addVotes(out.votes, stakes);
    const d = fc.checkSwitchThreshold(422521275, t.canon_tip.slot, 1000, stakes);
    // PROVEN: byte-identical to the live specimen's
    // `locked_out=0/... authorize=false` — the strictly-newer filter
    // (canonical, consensus.rs:1228) drops both entries because 422521274 <=
    // last_vote(422521275), even though 65% of stake HAS actually moved on.
    try testing.expect(!d.would_switch);
    try testing.expectEqual(@as(u64, 0), d.locked_out_stake);
}

test "KAT wedge-422521275: fresh accounts_db read arms the switch (fix verified)" {
    const pk1 = core.Pubkey{ .data = [_]u8{0x41} ** 32 };
    const pk2 = core.Pubkey{ .data = [_]u8{0x42} ** 32 };

    // The SAME two voters' CURRENT on-chain vote-account state — they voted
    // canon_tip (422532524), same as the rest of the live cluster did while
    // we sat wedged on the dead fork.
    var blob1: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    wedge_test.voteBlob(&blob1, 422532524);
    var blob2: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    wedge_test.voteBlob(&blob2, 422532524);
    var fdb = wedge_test.FreshDb{};
    defer fdb.accounts.deinit(testing.allocator);
    const vote_owner: core.Pubkey = .{ .data = VOTE_PROGRAM_ID };
    try fdb.accounts.put(testing.allocator, pk1, .{ .lamports = 1, .owner = vote_owner, .executable = false, .rent_epoch = 0, .data = &blob1 });
    try fdb.accounts.put(testing.allocator, pk2, .{ .lamports = 1, .owner = vote_owner, .executable = false, .rent_epoch = 0, .data = &blob2 });

    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 422532524, core.Hash{ .data = [_]u8{0xC2} ** 32 }); // == canon_tip hash

    const stakes_tbl = [_]TestVoteAccountStake{
        .{ .vote_pubkey = pk1.data, .stake = 500 },
        .{ .vote_pubkey = pk2.data, .stake = 150 },
    };
    const epoch_stakes = [_]TestEpochStakesEntry{.{ .epoch = 0, .vote_account_stakes = &stakes_tbl }};

    const out = try buildVoteAccountBatchFresh(testing.allocator, &fdb, &epoch_stakes, 0, 422532524, &[_]u64{}, &bh);
    defer testing.allocator.free(out.votes);
    try testing.expectEqual(@as(usize, 2), out.votes.len);
    for (out.votes) |v| try testing.expectEqual(@as(u64, 422532524), v.slot_hash.slot);

    var fc = wedge_test.HSFC.init(testing.allocator);
    defer fc.deinit();
    const t = try wedge_test.Tree.build(&fc);
    const stakes = wedge_test.PSLK{ .entries = &.{
        .{ .pubkey = pk1, .stake = 500 },
        .{ .pubkey = pk2, .stake = 150 },
    } };
    _ = try fc.addVotes(out.votes, stakes);
    const d = fc.checkSwitchThreshold(422521275, t.canon_tip.slot, 1000, stakes);
    // THE FIX: 65% > 38% now genuinely observed (both entries pass the
    // strictly-newer filter because they carry the voters' REAL current
    // slot, not a frozen 422521274 snapshot) → arms.
    try testing.expect(d.would_switch);
    try testing.expectEqual(@as(u64, 500), d.locked_out_stake); // early-return at pk1 alone (50% > 38%)
}

test "KAT wedge-422521275 both-directions safety: fresh read does NOT arm under 38% (no over-eager switch)" {
    const pk1 = core.Pubkey{ .data = [_]u8{0x41} ** 32 };
    const pk2 = core.Pubkey{ .data = [_]u8{0x42} ** 32 };

    var blob1: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    wedge_test.voteBlob(&blob1, 422532524);
    var blob2: [vote_state_serde.VOTE_STATE_V3_SZ]u8 = undefined;
    wedge_test.voteBlob(&blob2, 422532524);
    var fdb = wedge_test.FreshDb{};
    defer fdb.accounts.deinit(testing.allocator);
    const vote_owner: core.Pubkey = .{ .data = VOTE_PROGRAM_ID };
    try fdb.accounts.put(testing.allocator, pk1, .{ .lamports = 1, .owner = vote_owner, .executable = false, .rent_epoch = 0, .data = &blob1 });
    try fdb.accounts.put(testing.allocator, pk2, .{ .lamports = 1, .owner = vote_owner, .executable = false, .rent_epoch = 0, .data = &blob2 });

    var bh = TestBankHash{};
    defer bh.deinit(testing.allocator);
    try bh.table.put(testing.allocator, 422532524, core.Hash{ .data = [_]u8{0xC2} ** 32 });

    // Same voters, but now only 20% + 15% = 35% of total stake — under the
    // 38% bar. The fresh read still sees their true (newer) votes; the fix
    // must still correctly REFUSE (equivocation risk otherwise).
    const stakes_tbl = [_]TestVoteAccountStake{
        .{ .vote_pubkey = pk1.data, .stake = 200 },
        .{ .vote_pubkey = pk2.data, .stake = 150 },
    };
    const epoch_stakes = [_]TestEpochStakesEntry{.{ .epoch = 0, .vote_account_stakes = &stakes_tbl }};

    const out = try buildVoteAccountBatchFresh(testing.allocator, &fdb, &epoch_stakes, 0, 422532524, &[_]u64{}, &bh);
    defer testing.allocator.free(out.votes);
    try testing.expectEqual(@as(usize, 2), out.votes.len);

    var fc = wedge_test.HSFC.init(testing.allocator);
    defer fc.deinit();
    const t = try wedge_test.Tree.build(&fc);
    const stakes = wedge_test.PSLK{ .entries = &.{
        .{ .pubkey = pk1, .stake = 200 },
        .{ .pubkey = pk2, .stake = 150 },
    } };
    _ = try fc.addVotes(out.votes, stakes);
    const d = fc.checkSwitchThreshold(422521275, t.canon_tip.slot, 1000, stakes);
    try testing.expect(!d.would_switch); // 35% !> 38% — correctly refuses, even with a fresh/live feed
    try testing.expectEqual(@as(u64, 350), d.locked_out_stake);
}
