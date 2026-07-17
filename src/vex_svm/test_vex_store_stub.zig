//! Minimal vex_store stub for bank.zig unit tests.
//!
//! bank.zig uses @import("vex_store").accounts.AccountsDb as an optional field.
//! In tests that only exercise EpochSchedule math and getStakeActivationStatus,
//! the AccountsDb is never instantiated (accounts_db = null by default).
//! This stub satisfies the comptime type reference without pulling in the full
//! vex_store module graph.

const std = @import("std");
const core = @import("core");

/// Minimal AccountView matching the fields bank.zig reads.
pub const AccountView = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: core.Epoch,
    data: []const u8,
};

/// accounts sub-namespace — bank.zig uses @import("vex_store").accounts.AccountsDb
/// snapshot_manifest sub-namespace — bank.zig (module-46 KEEP) references
/// @import("vex_store").snapshot_manifest.{HardFork,VoteAccountStake} at module
/// scope (bank.zig:36 HardFork / :1207 stakes). Field-faithful mirrors of
/// snapshot_manifest.zig's real value structs (both trivial POD). fix105's
/// byte-identical stub omits this namespace (bank.zig's hard_forks read forces
/// its analysis), part of why fix105's own test-bank is red at pin 011a30f.
pub const snapshot_manifest = struct {
    pub const HardFork = struct {
        slot: u64,
        count: u64,
    };
    pub const VoteAccountStake = struct {
        vote_pubkey: [32]u8,
        stake: u64,
    };
};

pub const accounts = struct {
    pub const AccountsDb = struct {
        /// hard_forks rides on the real AccountsDb (cluster-wide, immutable for
        /// replay); bank.zig's freeze() reads it for the hard-fork bank-hash
        /// mixin (getHashData). Empty in unit tests ⇒ no mixin ⇒ byte-identical
        /// hash, matching the live testnet path (parent_slot ≥ fork_slot).
        hard_forks: []const snapshot_manifest.HardFork = &[_]snapshot_manifest.HardFork{},

        /// Never called in pure-math tests — AccountsDb is always null.
        pub fn getAccount(self: *@This(), pubkey: *const core.Pubkey) ?AccountView {
            _ = self;
            _ = pubkey;
            return null;
        }

        /// Fork-aware read used throughout bank.zig's freeze/sysvar-update paths
        /// (25+ call sites). Never invoked at runtime in the unit tests (Bank's
        /// `accounts_db` is null — the freeze tests operate on empty slots), but
        /// bank.zig's whole-file KEEP migration (module 46) references it at
        /// comptime, so the stub must carry a signature-faithful method. Mirrors
        /// the real `accounts_db.zig:getAccountInSlot(self, *const core.Pubkey,
        /// core.Slot, []const core.Slot) ?AccountView`. fix105's own byte-identical
        /// stub LACKS this method (its bank.zig grew past the stub), so fix105's
        /// test-bank is red at pin 011a30f; this additive test-only extension
        /// (module-28/29 fresh-stub-instance device) makes the rebuild's target
        /// green — see REBUILD-LEDGER module-46 row.
        pub fn getAccountInSlot(
            self: *@This(),
            pubkey: *const core.Pubkey,
            slot: core.Slot,
            ancestors: []const core.Slot,
        ) ?AccountView {
            _ = self;
            _ = pubkey;
            _ = slot;
            _ = ancestors;
            return null;
        }

        /// Never called in pure-math tests.
        pub fn scanByOwner(self: *@This(), owner: *const core.Pubkey, allocator: std.mem.Allocator) ![]AccountView {
            _ = self;
            _ = owner;
            _ = allocator;
            return &[_]AccountView{};
        }
    };
};

/// recorder sub-namespace — vote_state_serde.zig uses @import("vex_store").recorder.
/// In unit tests the recorder is never invoked (callers pass null for the cluster
/// SlotHashes fallback / voter_pk); this stub just satisfies comptime resolution.
pub const recorder = struct {
    pub const VoteMismatchOutcome = enum { rejected, accepted_via_cluster_fallback };

    // Freeze-path recorder surface referenced by bank.zig (module-46 whole-file
    // KEEP). The forensic recorder is DISABLED in unit tests (isEnabled()=false),
    // so emit* bodies are never taken at runtime; signature-faithful stubs
    // (matching recorder.zig:422/1033/1005) satisfy comptime analysis of the
    // freeze/distributePartitionedRewards path. Additive fresh-stub-instance
    // extension (module-28/29 device); fix105's byte-identical stub lacks these,
    // hence its own test-bank is red at pin 011a30f — see LEDGER module-46 row.
    pub fn isEnabled() bool {
        return false;
    }
    pub fn emitFreezeAccount(
        slot: u64,
        pk: *const [32]u8,
        lamports: u64,
        owner: *const [32]u8,
        executable: bool,
        data: []const u8,
    ) void {
        _ = slot;
        _ = pk;
        _ = lamports;
        _ = owner;
        _ = executable;
        _ = data;
    }
    pub fn emitLtHashContribution(
        pk: *const [32]u8,
        lthash_prefix: u64,
        op: u8,
    ) void {
        _ = pk;
        _ = lthash_prefix;
        _ = op;
    }

    pub fn emitVoteMismatch(
        voter_pk: *const [32]u8,
        proposed_slot: u64,
        proposed_hash: u64,
        local_hash: u64,
        cluster_hash: u64,
        outcome: VoteMismatchOutcome,
    ) void {
        _ = voter_pk;
        _ = proposed_slot;
        _ = proposed_hash;
        _ = local_hash;
        _ = cluster_hash;
        _ = outcome;
    }
};
