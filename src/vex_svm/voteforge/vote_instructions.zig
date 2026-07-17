//! VOTEFORGE Stage 3 — state-transition layer, non-TowerSync instructions
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 3).
//!
//! Derived DIRECTLY from Agave 4.2.0-beta.0 (semantics authority):
//!   - `programs/vote/src/vote_processor.rs` — dispatch-arm-level checks
//!     (account counts, up-front signer gates, feature-gate ANDs).
//!   - `programs/vote/src/vote_state/mod.rs` — the actual state-transition
//!     functions (`authorize`, `update_validator_identity`,
//!     `update_commission[_bps]`, `update_commission_collector`, `withdraw`,
//!     `initialize_account[_v2]`, `deposit_delegator_rewards`).
//!   - `programs/vote/src/vote_state/handler.rs` — `VoteStateHandler`
//!     read-normalize-to-V4 / `set_new_authorized_voter` /
//!     `get_and_update_authorized_voter` / `deinitialize_vote_account_state`.
//!
//! CRITICAL GROUND-TRUTH CORRECTION vs the transplant's own model: in
//! Agave 4.2.0-beta.0, `VoteStateTargetVersion` has EXACTLY ONE variant, `V4`
//! (`handler.rs:35-38`) — `target_version` is hardcoded, NOT feature-gated, at
//! the entrypoint (`vote_processor.rs:119`). There is no conditional V3-vs-V4
//! WRITE path: every successful mutating instruction migrates any V3/V1
//! account to V4 in memory (`try_convert_to_vote_state_v4`,
//! `handler.rs:624-670`) and ALWAYS persists `VoteStateVersions::V4`. This
//! rewrite therefore reads-and-migrates unconditionally and writes V4
//! unconditionally — it does NOT thread a `vote_state_v4` feature bool into
//! any read/write decision (the transplant's `targetVersion(ic.tc)` V3/V4
//! switch reflects an OLDER Agave revision where the feature still gated the
//! write path; by 4.2 the feature has long been permanently active on
//! testnet — confirmed live-active since slot 387,596,256, per the seam's own
//! FeatureSet defaults — so this is a behavior-preserving simplification on
//! live testnet, not a divergence).
//!
//! Layering (per scope doc §F.1): consumes ONLY `vote_codec.zig` (Stage 1) and
//! `account_io.zig` (Stage 2). Zero import of `sigvote` — voteforge has always
//! been independent of the Sig transplant that briefly served as its
//! differential oracle (removed 2026-07-12). `bls_pop` (the vendored blst binding) is
//! imported directly, exactly as the live native path
//! (`native/vote_program.zig:29`) already does — it is already linked into
//! the production `vex_svm` module graph (build.zig `net_vex_svm.addImport
//! ("bls_pop", ...)`), so this adds no new build wiring.
//!
//! Stage 5 (Vote, VoteSwitch, UpdateVoteState(+Switch),
//! CompactUpdateVoteState(+Switch), TowerSync(+Switch) — discriminants
//! 2,6,8,9,12,13,14,15) has landed and is executed here directly.
//!
//! Compute-unit metering (BLS PoP verification unconditionally charges
//! `BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS = 34_500` in Agave,
//! `vote_state/mod.rs:1017-1060`, BEFORE the crypto check) is NOT modeled at
//! this layer — Vexor's compute-budget accounting is a separate subsystem one
//! layer up (Stage 4 dispatch glue's concern, matching how `vote_processor.rs`
//! itself only *consumes* CU via a closure passed down from the entrypoint,
//! not the state-transition functions computing it themselves). Flagged, not
//! a state-transition correctness gap.

const std = @import("std");
const codec = @import("vote_codec.zig");
const aio = @import("account_io.zig");
const bls_pop = @import("bls_pop");

// ─────────────────────────────────────────────────────────────────────────────
// Error taxonomy — [agave] `InstructionError` subset this layer can produce,
// plus `account_io.AccountIoError` (borrow/mutation-level) and
// `vote_codec.CodecError` (parse/serialize-level) folded in by set union.
// `error.Custom` carries its `VoteError` sub-code via `ExecContext.custom_error`
// (an out-param, since Zig error values carry no payload) — mirrors how the
// seam's `tc.custom_error: ?u32` already threads `Custom(VoteError)` sub-codes
// today (`instruction_dispatch.zig:3638`).
// ─────────────────────────────────────────────────────────────────────────────

pub const InstrError = error{
    MissingRequiredSignature,
    InvalidAccountData,
    InvalidInstructionData,
    AccountAlreadyInitialized,
    UninitializedAccount,
    InsufficientFunds,
    InvalidArgument,
    AccountNotRentExempt,
    InvalidAccountOwner,
    Custom,
} || aio.AccountIoError || codec.CodecError || std.mem.Allocator.Error;
// NOTE: [agave]/sigvote `InstructionError` has ONE overflow variant,
// `ProgramArithmeticOverflow` (`core/instruction.zig:167`) -- no separate
// `ArithmeticOverflow`. Every overflow path in this file returns
// `error.ProgramArithmeticOverflow` (supplied by `aio.AccountIoError` above)
// so error-NAME comparison against the transplant in the A/B oracle matches
// exactly, not just the outcome class.

/// [agave] `solana-vote-interface-6.0.0/src/error.rs:10-33` — implicit
/// declaration-order ordinals 0-20, identical to the transplant's
/// `sigvote/runtime/program/vote/error.zig` (cross-verified).
pub const VoteError = enum(u8) {
    vote_too_old,
    slots_mismatch,
    slot_hash_mismatch,
    empty_slots,
    timestamp_too_old,
    too_soon_to_reauthorize,
    lockout_conflict,
    new_vote_state_lockout_mismatch,
    slots_not_ordered,
    confirmations_not_ordered,
    zero_confirmations,
    confirmation_too_large,
    root_roll_back,
    confirmation_roll_back,
    slot_smaller_than_root,
    too_many_votes,
    votes_too_old_all_filtered,
    root_on_different_fork,
    active_vote_account_close,
    commission_update_too_late,
    assertion_failed,
};

/// [agave] `solana-vote-interface-6.0.0/src/instruction.rs:25-31`
pub const CommissionKind = enum(u8) { inflation_rewards = 0, block_revenue = 1 };

/// [agave] `programs/vote/src/vote_processor.rs` gating booleans, the 8 live
/// gates already threaded by the seam (`instruction_dispatch.zig:3482-3498`)
/// PLUS `vote_account_initialize_v2` (SIMD-0464 itself — `is_init_account_v2_
/// enabled` ANDs 5 flags total, `vote_processor.rs:63-70`; this 9th flag is
/// NOT among sigvote's 8 since the transplant never implements V2 for real).
pub const FeatureFlags = struct {
    vote_state_v4: bool = true,
    enable_tower_sync_ix: bool = true,
    deprecate_legacy_vote_ixs: bool = false,
    custom_commission_collector: bool = false,
    delay_commission_updates: bool = false,
    bls_pubkey_management_in_vote_account: bool = false,
    commission_rate_in_basis_points: bool = false,
    block_revenue_sharing: bool = false,
    vote_account_initialize_v2: bool = false,
    /// [agave] `invoke_context.is_alpenglow_migration_succeeded()` — gates
    /// TowerSync(+Switch) rejection (`vote_processor.rs:277-279`) and folds
    /// into `should_reject_legacy_vote_instructions` (`:78-81`) alongside
    /// `deprecate_legacy_vote_ixs`. NOT one of the 9 flags the seam threads
    /// from live `FeatureSet` accounts today (Alpenglow's master gate is
    /// ABSENT on testnet — separate-cluster-only per the current readiness
    /// audit) — defaults false, matching present live reality; re-wire from
    /// real plumbing if/when a testnet Alpenglow gate exists.
    alpenglow_migration_succeeded: bool = false,
};

pub const EpochScheduleParams = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
    first_normal_epoch: u64,
    first_normal_slot: u64,
};

/// [agave] SlotHashes sysvar cap (`sdk/slot-hashes` `MAX_ENTRIES`), matching
/// the seam's own `native/sigvote/runtime/sysvar/slot_hashes.zig:33`. Entries
/// are NEWEST-FIRST (descending slot) — the same ordering Agave's
/// `&[(Slot,Hash)]` and the seam's `SlotHashes.entries` both already carry;
/// `SlotHashesView` is a fixed-capacity, allocation-free COPY of that blob
/// (Stage 5 readiness note #3: "thread the seam's proven SlotHashes blob
/// parse... through CandidateInputs -> ExecContext as a fixed-capacity view").
pub const MAX_SLOT_HASHES: usize = 512;

pub const SlotHashEntry = struct { slot: u64, hash: [32]u8 };

pub const SlotHashesView = struct {
    entries: [MAX_SLOT_HASHES]SlotHashEntry = undefined,
    len: usize = 0,

    pub const EMPTY: SlotHashesView = .{ .len = 0 };

    pub fn slice(self: *const SlotHashesView) []const SlotHashEntry {
        return self.entries[0..self.len];
    }
};

/// Everything a Stage-3 handler needs beyond the account table: the seam's
/// Clock/EpochSchedule/FeatureSet snapshot, flattened to plain values (no
/// sysvar-cache indirection — matches account_io's "Rent-sysvar-agnostic"
/// design note, §F.1 keeps sysvar semantics one layer up). `custom_error` is
/// an out-param the caller reads after a `error.Custom` return.
///
/// `slot_hashes` (Stage 5): the Vote/TowerSync family's SlotHashes sysvar
/// snapshot, defaulted EMPTY so every `ExecContext{...}` call site (KATs,
/// `vote_program.zig` self-tests, the live seam) keeps compiling unchanged.
pub const ExecContext = struct {
    slot: u64,
    epoch: u64,
    leader_schedule_epoch: u64,
    epoch_schedule: EpochScheduleParams,
    features: FeatureFlags,
    custom_error: ?u32 = null,
    slot_hashes: SlotHashesView = SlotHashesView.EMPTY,
};

// ─────────────────────────────────────────────────────────────────────────────
// Rent — [agave] canonical `Rent::default()` / `Rent.INIT` (3480
// lamports/byte-year, 2yr exemption threshold), matching the seam's own
// `sv.sysvar.Rent.INIT` and `instruction_dispatch.zig:2125-2135`'s
// `rentExemptMinimumBalanceDefault = (len+128)*3480*2`. account_io stays
// Rent-agnostic by design (its own header) — this layer owns the formula.
// ─────────────────────────────────────────────────────────────────────────────

pub const RENT_LAMPORTS_PER_BYTE_YEAR: u64 = 3480;
pub const RENT_EXEMPTION_YEARS: u64 = 2;
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

pub fn minimumBalance(data_len: usize) u64 {
    return (@as(u64, @intCast(data_len)) + ACCOUNT_STORAGE_OVERHEAD) * RENT_LAMPORTS_PER_BYTE_YEAR * RENT_EXEMPTION_YEARS;
}
pub fn isRentExempt(lamports: u64, data_len: usize) bool {
    return lamports >= minimumBalance(data_len);
}

/// [agave] System Program ID — the all-zero pubkey (base58
/// "11111111111111111111111111111111"), used by the collector-account /
/// deposit-source ownership checks.
pub const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;

/// [agave] `VoteStateV4::size_of() == VoteStateV3::size_of() == 3762` bytes —
/// the FIXED account-data-buffer length every vote account is allocated at
/// (independent of the shorter serialized-prefix length `codec.serialize()`
/// actually writes — see `vote_codec.zig`'s stale-tail contract). Matches the
/// transplant's `VoteStateV3.MAX_VOTE_STATE_SIZE` and the seam's own
/// `native/vote_program.zig` 3762-byte length check.
pub const VOTE_ACCOUNT_DATA_LEN: usize = 3762;

// ─────────────────────────────────────────────────────────────────────────────
// Signer-set helpers — [agave] `verify_authorized_signer` (`vote_state/
// mod.rs:1006-1015`): `if signers.contains(authorized) { Ok(()) } else {
// Err(MissingRequiredSignature) }`. `signers` is the tx's FULL dedup signer
// set for this instruction (every account with `is_signer=true`, any
// position) — built once by the caller from the instruction's own account
// list, matching `instruction_context.get_signers()`.
// ─────────────────────────────────────────────────────────────────────────────

pub fn isSigner(signers: []const [32]u8, key: [32]u8) bool {
    for (signers) |s| {
        if (std.mem.eql(u8, &s, &key)) return true;
    }
    return false;
}

fn verifyAuthorizedSigner(authorized: [32]u8, signers: []const [32]u8) InstrError!void {
    if (!isSigner(signers, authorized)) return error.MissingRequiredSignature;
}

/// [agave] `Pubkey::create_with_seed` — `SHA256(base || seed || owner)`. No
/// domain-separator suffix (unlike PDA's `find_program_address`, which is a
/// different derivation entirely).
pub fn createWithSeed(base: [32]u8, seed: []const u8, owner: [32]u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&base);
    h.update(seed);
    h.update(&owner);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// V4 load/store — [agave] `get_vote_state_handler_checked` /
// `try_convert_to_vote_state_v4` (`handler.rs:624-670`) / `set_vote_account_
// state` (`handler.rs:298-320`, always-V4 write). "Uninitialized" detection:
// the codec can only parse tag V3(2)/V4(3); any other tag (a freshly-funded,
// all-zero account has tag 0) is treated as uninitialized, matching Agave's
// `is_uninitialized()` (empty `authorized_voters` — a successfully-parsed V3/
// V4 with zero authorized-voter entries is ALSO uninitialized, since the vote
// program's own purge invariant never leaves that map empty once initialized).
// ─────────────────────────────────────────────────────────────────────────────

pub fn isUninitializedData(data: []const u8) bool {
    const tag = codec.versionTag(data) catch return true;
    if (tag == codec.VERSION_TAG_V4) {
        const p = codec.VoteStateV4.parse(data) catch return true;
        return p.state.tail.authorized_voters_len == 0;
    } else if (tag == codec.VERSION_TAG_V3) {
        const p = codec.VoteStateV3.parse(data) catch return true;
        return p.state.tail.authorized_voters_len == 0;
    }
    return true;
}

fn loadV4Checked(data: []const u8, vote_pubkey: [32]u8) InstrError!codec.VoteStateV4 {
    if (isUninitializedData(data)) return error.UninitializedAccount;
    const tag = try codec.versionTag(data);
    if (tag == codec.VERSION_TAG_V4) {
        return (try codec.VoteStateV4.parse(data)).state;
    } else if (tag == codec.VERSION_TAG_V3) {
        const v3 = (try codec.VoteStateV3.parse(data)).state;
        return codec.migrateV3ToV4(&v3, vote_pubkey);
    }
    return error.InvalidAccountData;
}

fn storeV4(borrow: *aio.Borrow, state: *const codec.VoteStateV4) InstrError!void {
    const d = try borrow.dataMut();
    _ = try state.serialize(d);
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthorizedVoters map ops — [agave] `handler.rs:77-132`
// `set_new_authorized_voter`/`get_and_update_authorized_voter`, backed by
// `AuthorizedVoters::get_and_cache_authorized_voter_for_epoch`/
// `purge_authorized_voters`. Fixed-array equivalent of the BTreeMap<Epoch,
// Pubkey>, kept epoch-ascending-sorted (matches how a canonical on-chain
// account is always found — BTreeMap iteration order).
// ─────────────────────────────────────────────────────────────────────────────

fn sortAuthorizedVoters(tail: *codec.Tail) void {
    const S = struct {
        fn lessThan(_: void, a: codec.AuthorizedVoterEntry, b: codec.AuthorizedVoterEntry) bool {
            return a.epoch < b.epoch;
        }
    };
    std.mem.sort(codec.AuthorizedVoterEntry, tail.authorized_voters[0..tail.authorized_voters_len], {}, S.lessThan);
}

/// [agave] `AuthorizedVoters::purge_authorized_voters` — drops every entry
/// with `epoch < floor`.
fn purgeAuthorizedVoters(tail: *codec.Tail, floor: u64) void {
    var w: usize = 0;
    var i: usize = 0;
    while (i < tail.authorized_voters_len) : (i += 1) {
        if (tail.authorized_voters[i].epoch >= floor) {
            tail.authorized_voters[w] = tail.authorized_voters[i];
            w += 1;
        }
    }
    tail.authorized_voters_len = w;
}

/// [agave] `handler.rs:99-111` `get_and_update_authorized_voter`. Finds the
/// authorized voter for `current_epoch` (exact match, or the most recent
/// entry strictly before it — "carry forward"), CACHES that carried-forward
/// pubkey at `current_epoch` if not already present, then purges every entry
/// `< current_epoch.saturating_sub(1)` (V4's SIMD-0185 window:
/// `[current_epoch-1, current_epoch+2]`).
fn getAndUpdateAuthorizedVoter(tail: *codec.Tail, current_epoch: u64) InstrError![32]u8 {
    var have_exact = false;
    var have_carry = false;
    var carry_epoch: u64 = 0;
    var result: [32]u8 = undefined;

    for (tail.authorized_voters[0..tail.authorized_voters_len]) |av| {
        if (av.epoch == current_epoch) {
            have_exact = true;
            result = av.pubkey;
        }
        if (av.epoch <= current_epoch and (!have_carry or av.epoch > carry_epoch)) {
            carry_epoch = av.epoch;
            have_carry = true;
            if (!have_exact) result = av.pubkey;
        }
    }

    if (!have_exact) {
        if (!have_carry) return error.InvalidAccountData;
        if (tail.authorized_voters_len >= codec.MAX_AUTHORIZED_VOTERS) return error.InvalidAccountData;
        tail.authorized_voters[tail.authorized_voters_len] = .{ .epoch = current_epoch, .pubkey = result };
        tail.authorized_voters_len += 1;
        sortAuthorizedVoters(tail);
    }

    const floor = if (current_epoch == 0) 0 else current_epoch - 1;
    purgeAuthorizedVoters(tail, floor);
    return result;
}

/// Test-only public wrapper around `getAndUpdateAuthorizedVoter` — exposes
/// the unit-level epoch-carry-forward/purge behavior for direct KAT pinning
/// (mirroring `handler.rs`'s own `#[test] fn test_get_and_update_authorized_
/// voter`), independent of a full `authorize()` call.
pub fn getAndUpdateAuthorizedVoterForTest(tail: *codec.Tail, current_epoch: u64) InstrError![32]u8 {
    return getAndUpdateAuthorizedVoter(tail, current_epoch);
}

/// [agave] `handler.rs:77-94` `set_new_authorized_voter` (V4 arm — no
/// `prior_voters`/`target_epoch<=latest_epoch` guard; V3 has one but this
/// rewrite operates exclusively on the in-memory V4 view, matching Agave 4.2's
/// hardcoded target version). On a duplicate `target_epoch`, returns
/// `error.Custom` with `too_soon_to_reauthorize` staged in `custom_error` —
/// caller must read it.
fn setNewAuthorizedVoterV4(
    tail: *codec.Tail,
    bls_pubkey_compressed: *?[codec.BLS_PUBKEY_COMPRESSED_SIZE]u8,
    new_pubkey: [32]u8,
    target_epoch: u64,
    bls_pubkey: ?[codec.BLS_PUBKEY_COMPRESSED_SIZE]u8,
    ctx: *ExecContext,
) InstrError!void {
    for (tail.authorized_voters[0..tail.authorized_voters_len]) |av| {
        if (av.epoch == target_epoch) {
            ctx.custom_error = @intFromEnum(VoteError.too_soon_to_reauthorize);
            return error.Custom;
        }
    }
    if (tail.authorized_voters_len >= codec.MAX_AUTHORIZED_VOTERS) return error.InvalidAccountData;
    tail.authorized_voters[tail.authorized_voters_len] = .{ .epoch = target_epoch, .pubkey = new_pubkey };
    tail.authorized_voters_len += 1;
    sortAuthorizedVoters(tail);
    if (bls_pubkey) |bp| bls_pubkey_compressed.* = bp;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Authorize / AuthorizeChecked / AuthorizeWithSeed / AuthorizeCheckedWithSeed
// [agave] `vote_state/mod.rs:686-767` `authorize()` is the shared core all
// four funnel through.
// ─────────────────────────────────────────────────────────────────────────────

pub const VoteAuthorizeArg = union(enum) {
    voter,
    withdrawer,
    voter_with_bls: struct {
        bls_pubkey: [codec.BLS_PUBKEY_COMPRESSED_SIZE]u8,
        bls_proof_of_possession: [96]u8,
    },
};

pub fn authorize(
    table: *aio.AccountTable,
    vote_idx: usize,
    signers: []const [32]u8,
    new_authority: [32]u8,
    vote_authorize: VoteAuthorizeArg,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    const vote_pubkey = vb.pubkey();
    var state = try loadV4Checked(vb.dataConst(), vote_pubkey);

    const bls_enabled = ctx.features.bls_pubkey_management_in_vote_account;
    switch (vote_authorize) {
        .voter => {
            if (bls_enabled and state.bls_pubkey_compressed != null) return error.InvalidInstructionData;
            const target_epoch = std.math.add(u64, ctx.leader_schedule_epoch, 1) catch return error.InvalidAccountData;
            const withdrawer_signed = isSigner(signers, state.authorized_withdrawer);
            const epoch_authorized_voter = try getAndUpdateAuthorizedVoter(&state.tail, ctx.epoch);
            if (!withdrawer_signed) try verifyAuthorizedSigner(epoch_authorized_voter, signers);
            try setNewAuthorizedVoterV4(&state.tail, &state.bls_pubkey_compressed, new_authority, target_epoch, null, ctx);
        },
        .withdrawer => {
            try verifyAuthorizedSigner(state.authorized_withdrawer, signers);
            state.authorized_withdrawer = new_authority;
        },
        .voter_with_bls => |args| {
            if (!bls_enabled) return error.InvalidInstructionData;
            if (!bls_pop.verifyVoteProofOfPossession(&vote_pubkey, &args.bls_pubkey, &args.bls_proof_of_possession))
                return error.InvalidArgument;
            const target_epoch = std.math.add(u64, ctx.leader_schedule_epoch, 1) catch return error.InvalidAccountData;
            const withdrawer_signed = isSigner(signers, state.authorized_withdrawer);
            const epoch_authorized_voter = try getAndUpdateAuthorizedVoter(&state.tail, ctx.epoch);
            if (!withdrawer_signed) try verifyAuthorizedSigner(epoch_authorized_voter, signers);
            try setNewAuthorizedVoterV4(&state.tail, &state.bls_pubkey_compressed, new_authority, target_epoch, args.bls_pubkey, ctx);
        },
    }
    try storeV4(&vb, &state);
    vb.release();
}

/// [agave] `vote_processor.rs:21-61` `process_authorize_with_seed_instruction`.
/// If the base-authority account is a signer, derive the effective signer key
/// via `create_with_seed` and treat it as the (sole) signers-set entry;
/// otherwise pass an EMPTY signers slice (so `authorize()`'s checks always
/// fail `MissingRequiredSignature`) — this is how "base key must sign" is
/// enforced without a dedicated check.
pub fn authorizeWithSeed(
    table: *aio.AccountTable,
    vote_idx: usize,
    base_authority_idx: usize,
    authorization_type: VoteAuthorizeArg,
    current_authority_derived_key_owner: [32]u8,
    current_authority_derived_key_seed: []const u8,
    new_authority: [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var derived_buf: [1][32]u8 = undefined;
    var derived: []const [32]u8 = &[_][32]u8{};
    {
        var bb = try table.borrowConst(base_authority_idx);
        defer bb.release();
        if (bb.isSigner()) {
            derived_buf[0] = createWithSeed(bb.pubkey(), current_authority_derived_key_seed, current_authority_derived_key_owner);
            derived = derived_buf[0..1];
        }
    }
    try authorize(table, vote_idx, derived, new_authority, authorization_type, ctx);
}

/// [agave] `vote_processor.rs:170-188` — account index 3 (new authority) must
/// be a signer, checked BEFORE the with-seed derivation (position-level
/// `.is_signer()`, not the signers-SET check `authorize()`'s core uses).
pub fn authorizeCheckedWithSeed(
    table: *aio.AccountTable,
    vote_idx: usize,
    base_authority_idx: usize,
    new_authority_idx: usize,
    authorization_type: VoteAuthorizeArg,
    current_authority_derived_key_owner: [32]u8,
    current_authority_derived_key_seed: []const u8,
    ctx: *ExecContext,
) InstrError!void {
    const new_authority = blk: {
        var nb = try table.borrowConst(new_authority_idx);
        defer nb.release();
        if (!nb.isSigner()) return error.MissingRequiredSignature;
        break :blk nb.pubkey();
    };
    try authorizeWithSeed(table, vote_idx, base_authority_idx, authorization_type, current_authority_derived_key_owner, current_authority_derived_key_seed, new_authority, ctx);
}

/// [agave] `vote_processor.rs:315-333` — account index 3 (new voter/
/// withdrawer) must be a signer, checked first (position-level), THEN the
/// full dedup `signers` set is passed into `authorize()`'s core.
pub fn authorizeChecked(
    table: *aio.AccountTable,
    vote_idx: usize,
    new_authority_idx: usize,
    signers: []const [32]u8,
    vote_authorize: VoteAuthorizeArg,
    ctx: *ExecContext,
) InstrError!void {
    const new_authority = blk: {
        var nb = try table.borrowConst(new_authority_idx);
        defer nb.release();
        if (!nb.isSigner()) return error.MissingRequiredSignature;
        break :blk nb.pubkey();
    };
    try authorize(table, vote_idx, signers, new_authority, vote_authorize, ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. UpdateValidatorIdentity — [agave] `vote_state/mod.rs:770-794`
// ─────────────────────────────────────────────────────────────────────────────

pub fn updateValidatorIdentity(
    table: *aio.AccountTable,
    vote_idx: usize,
    new_identity_idx: usize,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    var nb = try table.borrowConst(new_identity_idx);
    defer nb.release();
    const node_pubkey = nb.pubkey();

    var state = try loadV4Checked(vb.dataConst(), vb.pubkey());
    try verifyAuthorizedSigner(state.authorized_withdrawer, signers);
    try verifyAuthorizedSigner(node_pubkey, signers);
    state.node_pubkey = node_pubkey;
    // Pre-SIMD-0232 (`custom_commission_collector` inactive), block_revenue_
    // collector is force-synced to the new identity as a side effect.
    if (!ctx.features.custom_commission_collector) {
        state.block_revenue_collector = node_pubkey;
    }
    try storeV4(&vb, &state);
    vb.release();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. UpdateCommission / UpdateCommissionBps / UpdateCommissionCollector
// [agave] `vote_state/mod.rs:797-933`
// ─────────────────────────────────────────────────────────────────────────────

fn commissionPct(bps: u16) u8 {
    const pct = bps / 100;
    return if (pct > 255) 255 else @intCast(pct);
}

/// [agave] `vote_state/mod.rs:992-1004` `is_commission_update_allowed` —
/// allowed only in the first half of a normal epoch (always allowed during
/// warmup / when `slots_per_epoch == 0`).
pub fn isCommissionUpdateAllowed(slot: u64, es: EpochScheduleParams) bool {
    if (es.slots_per_epoch == 0) return true;
    const relative = (slot -| es.first_normal_slot) % es.slots_per_epoch;
    return (relative *| 2) <= es.slots_per_epoch;
}

/// [agave] `vote_state/mod.rs:797-825`. The "is this an increase" throttle
/// check runs speculatively even if the account fails to decode (defaults to
/// `true`/enforced in that case), and only THEN does the original decode
/// error get propagated — preserved here via the `maybe_state` peek pattern.
pub fn updateCommission(
    table: *aio.AccountTable,
    vote_idx: usize,
    commission: u8,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    const disable_rule = ctx.features.delay_commission_updates;
    const maybe_state = loadV4Checked(vb.dataConst(), vb.pubkey());

    const enforce = blk: {
        if (disable_rule) break :blk false;
        if (maybe_state) |s| break :blk commission > commissionPct(s.inflation_rewards_commission_bps) else |_| break :blk true;
    };
    if (enforce and !isCommissionUpdateAllowed(ctx.slot, ctx.epoch_schedule)) {
        ctx.custom_error = @intFromEnum(VoteError.commission_update_too_late);
        return error.Custom;
    }

    var state = try maybe_state;
    try verifyAuthorizedSigner(state.authorized_withdrawer, signers);
    state.inflation_rewards_commission_bps = @as(u16, commission) * 100;
    try storeV4(&vb, &state);
    vb.release();
}

/// [agave] `vote_state/mod.rs:827-859` SIMD-0291/SIMD-0123 — NO epoch-midpoint
/// throttle at all ("No commission update rule, per SIMD-0249 and SIMD-0291").
/// Dispatch-level gate (`commission_rate_in_basis_points && delay_commission_
/// updates`) is asserted here too for defense-in-depth even though Stage 4's
/// caller should already have checked it.
pub fn updateCommissionBps(
    table: *aio.AccountTable,
    vote_idx: usize,
    commission_bps: u16,
    kind: CommissionKind,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    if (!(ctx.features.commission_rate_in_basis_points and ctx.features.delay_commission_updates))
        return error.InvalidInstructionData;
    if (kind == .block_revenue and !ctx.features.block_revenue_sharing) return error.InvalidInstructionData;

    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    var state = try loadV4Checked(vb.dataConst(), vb.pubkey());
    try verifyAuthorizedSigner(state.authorized_withdrawer, signers);
    switch (kind) {
        .inflation_rewards => state.inflation_rewards_commission_bps = commission_bps,
        .block_revenue => state.block_revenue_commission_bps = commission_bps,
    }
    try storeV4(&vb, &state);
    vb.release();
}

/// [agave] `NewCommissionCollector::validate_and_resolve_key`
/// (`vote_state/mod.rs:861-905`) + `read_new_collector_account`
/// (`vote_processor.rs:83-97`): self-aliasing short-circuit (no checks), else
/// owner==system-program -> InvalidAccountOwner, rent-exempt -> else
/// InsufficientFunds, writable -> else InvalidArgument.
fn resolveCollector(table: *aio.AccountTable, vote_idx: usize, collector_idx: usize) InstrError![32]u8 {
    var cb = try table.borrowConst(collector_idx);
    defer cb.release();
    if (std.mem.eql(u8, &cb.pubkey(), &table.records[vote_idx].pubkey)) return cb.pubkey();
    if (!std.mem.eql(u8, &cb.owner(), &SYSTEM_PROGRAM_ID)) return error.InvalidAccountOwner;
    if (!isRentExempt(cb.lamports(), cb.dataConst().len)) return error.InsufficientFunds;
    if (!cb.isWritable()) return error.InvalidArgument;
    return cb.pubkey();
}

/// [agave] `vote_state/mod.rs:908-933` SIMD-0232.
pub fn updateCommissionCollector(
    table: *aio.AccountTable,
    vote_idx: usize,
    collector_idx: usize,
    kind: CommissionKind,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    if (!ctx.features.custom_commission_collector) return error.InvalidInstructionData;

    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    var state = try loadV4Checked(vb.dataConst(), vb.pubkey());
    try verifyAuthorizedSigner(state.authorized_withdrawer, signers);
    const new_key = try resolveCollector(table, vote_idx, collector_idx);
    switch (kind) {
        .inflation_rewards => state.inflation_rewards_collector = new_key,
        .block_revenue => state.block_revenue_collector = new_key,
    }
    try storeV4(&vb, &state);
    vb.release();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Withdraw — [agave] `vote_state/mod.rs:1063-1129`
// ─────────────────────────────────────────────────────────────────────────────

pub fn withdraw(
    table: *aio.AccountTable,
    vote_idx: usize,
    recipient_idx: usize,
    lamports: u64,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    const state = try loadV4Checked(vb.dataConst(), vb.pubkey());
    try verifyAuthorizedSigner(state.authorized_withdrawer, signers);

    const remaining = std.math.sub(u64, vb.lamports(), lamports) catch return error.InsufficientFunds;
    const pending = state.pending_delegator_rewards;

    if (remaining == 0) {
        if (pending > 0) return error.InsufficientFunds;
        const reject_close = blk: {
            if (state.tail.epoch_credits_len == 0) break :blk false;
            const last_ec = state.tail.epoch_credits[state.tail.epoch_credits_len - 1];
            break :blk (ctx.epoch -| last_ec.epoch) < 2;
        };
        if (reject_close) {
            ctx.custom_error = @intFromEnum(VoteError.active_vote_account_close);
            return error.Custom;
        }
        // [agave] `VoteStateHandler::deinitialize_vote_account_state`
        // (`handler.rs:366-377`) — zeroes the ENTIRE data buffer, not just the
        // vote-state fields.
        const d = try vb.dataMut();
        @memset(d, 0);
    } else {
        const min_rent_exempt = minimumBalance(vb.dataConst().len);
        const min_balance = std.math.add(u64, min_rent_exempt, pending) catch return error.ProgramArithmeticOverflow;
        if (remaining < min_balance) return error.InsufficientFunds;
    }

    try vb.subtractLamports(lamports);
    vb.release();
    var rb = try table.borrowMut(recipient_idx);
    defer rb.release();
    try rb.addLamports(lamports);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. InitializeAccount + InitializeAccountV2 — [agave] `vote_state/
// mod.rs:1139-1209`. Both construct a `VoteStateV4` DIRECTLY (Agave's
// hardcoded-V4 target — see file header); "V1 vs V2" is purely a difference
// in INSTRUCTION INPUT shape (`VoteInit` vs `VoteInitV2`), not on-chain bytes.
// ─────────────────────────────────────────────────────────────────────────────

pub fn initializeAccount(
    table: *aio.AccountTable,
    vote_idx: usize,
    node_pubkey: [32]u8,
    authorized_voter: [32]u8,
    authorized_withdrawer: [32]u8,
    commission: u8,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    // [agave] rent-exemption checked at the DISPATCH layer, before
    // `initialize_account` is even called (`vote_processor.rs:132-136`).
    if (!isRentExempt(vb.lamports(), vb.dataConst().len)) return error.InsufficientFunds;
    if (vb.dataConst().len != VOTE_ACCOUNT_DATA_LEN) return error.InvalidAccountData;
    if (!isUninitializedData(vb.dataConst())) return error.AccountAlreadyInitialized;
    try verifyAuthorizedSigner(node_pubkey, signers);

    var state: codec.VoteStateV4 = std.mem.zeroes(codec.VoteStateV4);
    state.node_pubkey = node_pubkey;
    state.authorized_withdrawer = authorized_withdrawer;
    state.inflation_rewards_collector = vb.pubkey();
    state.block_revenue_collector = node_pubkey;
    state.inflation_rewards_commission_bps = @as(u16, commission) * 100;
    state.block_revenue_commission_bps = 10_000;
    state.pending_delegator_rewards = 0;
    state.bls_pubkey_compressed = null;
    state.tail = codec.Tail.EMPTY;
    state.tail.authorized_voters_len = 1;
    state.tail.authorized_voters[0] = .{ .epoch = ctx.epoch, .pubkey = authorized_voter };

    try storeV4(&vb, &state);
    vb.release();
}

pub const InitializeAccountV2Args = struct {
    node_pubkey: [32]u8,
    authorized_voter: [32]u8,
    authorized_voter_bls_pubkey: [codec.BLS_PUBKEY_COMPRESSED_SIZE]u8,
    authorized_voter_bls_proof_of_possession: [96]u8,
    authorized_withdrawer: [32]u8,
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,
};

/// [agave] `vote_state/mod.rs:1139-1186` SIMD-0464. No explicit rent-exemption
/// check on the VOTE account itself here (only the collector accounts get
/// one, via `validate_and_resolve_key`) — this is a real, documented
/// asymmetry vs `initializeAccount`, not an oversight (confirmed against
/// Agave source: the dispatch arm and this function both omit it).
pub fn initializeAccountV2(
    table: *aio.AccountTable,
    vote_idx: usize,
    inflation_collector_idx: usize,
    block_collector_idx: usize,
    args: InitializeAccountV2Args,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    if (!(ctx.features.bls_pubkey_management_in_vote_account and
        ctx.features.commission_rate_in_basis_points and
        ctx.features.custom_commission_collector and
        ctx.features.block_revenue_sharing and
        ctx.features.vote_account_initialize_v2))
    {
        return error.InvalidInstructionData;
    }

    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    if (vb.dataConst().len != VOTE_ACCOUNT_DATA_LEN) return error.InvalidAccountData;
    if (!isUninitializedData(vb.dataConst())) return error.AccountAlreadyInitialized;
    try verifyAuthorizedSigner(args.node_pubkey, signers);

    const inflation_collector_key = try resolveCollector(table, vote_idx, inflation_collector_idx);
    const block_collector_key = try resolveCollector(table, vote_idx, block_collector_idx);

    const vote_pubkey = vb.pubkey();
    if (!bls_pop.verifyVoteProofOfPossession(&vote_pubkey, &args.authorized_voter_bls_pubkey, &args.authorized_voter_bls_proof_of_possession))
        return error.InvalidArgument;

    var state: codec.VoteStateV4 = std.mem.zeroes(codec.VoteStateV4);
    state.node_pubkey = args.node_pubkey;
    state.authorized_withdrawer = args.authorized_withdrawer;
    state.inflation_rewards_collector = inflation_collector_key;
    state.block_revenue_collector = block_collector_key;
    state.inflation_rewards_commission_bps = args.inflation_rewards_commission_bps;
    state.block_revenue_commission_bps = args.block_revenue_commission_bps;
    state.pending_delegator_rewards = 0;
    state.bls_pubkey_compressed = args.authorized_voter_bls_pubkey;
    state.tail = codec.Tail.EMPTY;
    state.tail.authorized_voters_len = 1;
    state.tail.authorized_voters[0] = .{ .epoch = ctx.epoch, .pubkey = args.authorized_voter };

    try storeV4(&vb, &state);
    vb.release();
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DepositDelegatorRewards — [agave] `vote_state/mod.rs:936-988`, NEW in
// 4.2 (SIMD-0123). No transplant equivalent exists anywhere in the codebase
// (confirmed by research — see scope doc §D.4) — this is a from-scratch,
// Agave-source-derived, rewrite-only capability. The one instruction that
// does NOT auto-migrate V3/V1 accounts: requires an ALREADY-V4 account,
// rejects everything else with InvalidAccountData.
//
// This layer does not have a real system-program CPI available, so it
// mirrors the CPI's OBSERVABLE effects directly (self-transfer / ownership /
// balance checks + the lamport move) rather than invoking one — documented
// simplification, not a semantics gap (the state-transition outcome is
// identical either way for any input that reaches this function).
// ─────────────────────────────────────────────────────────────────────────────

pub fn depositDelegatorRewards(
    table: *aio.AccountTable,
    vote_idx: usize,
    source_idx: usize,
    deposit: u64,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    if (!(ctx.features.commission_rate_in_basis_points and
        ctx.features.custom_commission_collector and
        ctx.features.block_revenue_sharing))
    {
        return error.InvalidInstructionData;
    }

    var sb = try table.borrowMut(source_idx);
    errdefer sb.release();
    try verifyAuthorizedSigner(sb.pubkey(), signers);

    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();

    // [agave] "Can't use get_vote_state_handler_checked, since it will
    // convert the underlying vote state to v4. SIMD-0123 requires an
    // *initialized v4*." — no auto-migration for this instruction.
    const tag = try codec.versionTag(vb.dataConst());
    if (tag != codec.VERSION_TAG_V4) return error.InvalidAccountData;
    var state = (try codec.VoteStateV4.parse(vb.dataConst())).state;
    if (state.tail.authorized_voters_len == 0) return error.InvalidAccountData; // uninitialized V4

    const vote_pubkey = vb.pubkey();
    if (std.mem.eql(u8, &sb.pubkey(), &vote_pubkey)) return error.InvalidArgument; // self-transfer
    if (!std.mem.eql(u8, &sb.owner(), &SYSTEM_PROGRAM_ID)) return error.ExternalAccountLamportSpend;
    if (sb.lamports() < deposit) {
        // [agave] SystemError::ResultWithNegativeLamports maps to
        // InstructionError::Custom(1) — a SYSTEM program custom code, not a
        // VoteError; staged the same way for the caller to read.
        ctx.custom_error = 1;
        return error.Custom;
    }

    // [agave] the real debit/credit happens via a system-program CPI
    // (`system_instruction::transfer`) — it succeeds because the SOURCE
    // account is a SIGNER, not because the vote program owns it (during the
    // CPI, the executing-program context becomes System, which DOES own it).
    // `Borrow.setLamports`/`subtractLamports` model single-table-owner
    // authority (`table.program_id` == the VOTE program here) and would
    // reject debiting a system-owned account for exactly that reason — this
    // account_io model has no cross-program-CPI-authority concept, so the
    // lamport move below manipulates the records directly. This is NOT a
    // bypass of a check that should have applied to a vote-program-authority
    // mutation (there isn't one here); every check the CPI itself would
    // enforce (signer, self-transfer, balance) is already evaluated above.
    table.records[source_idx].lamports -= deposit;
    table.records[vote_idx].lamports += deposit;
    state.pending_delegator_rewards = std.math.add(u64, state.pending_delegator_rewards, deposit) catch return error.ProgramArithmeticOverflow;
    try storeV4(&vb, &state);

    vb.release();
    sb.release();
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. STAGE 5 — Vote / VoteSwitch / UpdateVoteState(+Switch) /
// CompactUpdateVoteState(+Switch) / TowerSync(+Switch) — discriminants
// 2,6,8,9,12,13,14,15. [agave] `vote_state/mod.rs` `check_and_filter_
// proposed_vote_state`/`check_slots_are_valid`/`process_new_vote_state`/
// `process_vote[_with_account/_unfiltered]`/`process_vote_state_update`/
// `do_process_vote_state_update`/`process_tower_sync`/`do_process_tower_sync`
// + `vote_state/handler.rs` `process_next_vote_slot`/`pop_expired_votes`/
// `double_lockouts`/`credits_for_vote_at_index`/`increment_credits`/
// `compute_vote_latency`/`process_timestamp`. THE consensus-critical heart —
// byte-exact against Agave, zero "close enough".
//
// `do_process_tower_sync` and `do_process_vote_state_update` are IDENTICAL
// bodies in Agave (both funnel `{lockouts,root,hash,timestamp}` through the
// SAME two functions; TowerSync's extra `block_id` is consumed at DECODE time
// only — never read by either function, confirmed against Agave source —
// informational for consensus/replay, not part of on-chain vote-state) — this
// rewrite therefore has exactly ONE core driver, `doProcessVoteStateUpdate`,
// shared by both `processVoteStateUpdate` and `processTowerSync` below.
// ─────────────────────────────────────────────────────────────────────────────

/// [agave] `VOTE_CREDITS_GRACE_SLOTS`/`VOTE_CREDITS_MAXIMUM_PER_SLOT`
/// (`solana-vote-interface-6.0.0/src/state/mod.rs:47,50`).
pub const VOTE_CREDITS_GRACE_SLOTS: u8 = 2;
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u8 = 16;
/// [agave] `INITIAL_LOCKOUT` (state/mod.rs:38) — base of the doubling lockout.
pub const INITIAL_LOCKOUT: u64 = 2;

/// Decode-capacity policy (mirrors `vote_codec.zig`'s own documented
/// precedent): Agave's `Vote.slots`/`VoteStateUpdate.lockouts`/`TowerSync.
/// lockouts` are unbounded `Vec`s at the WIRE level — only `process_new_vote_
/// state` enforces the real `MAX_LOCKOUT_HISTORY` (31) cap, returning
/// `VoteError::TooManyVotes` (a Custom program error, not a decode error).
/// Because a single instruction's data is bounded by `PACKET_DATA_SIZE`
/// (1232B) and every element costs >=2 bytes (compact) or 8-12 bytes
/// (non-compact), no legitimate OR malformed-but-decodable instruction can
/// ever carry more than ~300 elements — 256 is generous headroom, keeps the
/// decode fully stack-resident (zero allocation, Stage 4 readiness note #2),
/// and any decodable-but-oversized input still reaches the EXACT SAME
/// `TooManyVotes` outcome as Agave (decoded fully, then length-checked in
/// `processNewVoteState`, not rejected early at parse time).
pub const MAX_VOTE_SLOTS: usize = 256;
pub const MAX_PROPOSED_LOCKOUTS: usize = 256;

pub const VoteArg = struct {
    slots: [MAX_VOTE_SLOTS]u64,
    slots_len: usize,
    hash: [32]u8,
    timestamp: ?i64,
};

pub const ProposedLockout = struct { slot: u64, confirmation_count: u32 };

/// Decode target shared by UpdateVoteState/CompactUpdateVoteState/TowerSync
/// (+Switch) — see file-section header for why one shape suffices for all
/// four families.
pub const ProposedVoteState = struct {
    lockouts: [MAX_PROPOSED_LOCKOUTS]ProposedLockout,
    lockouts_len: usize,
    root: ?u64,
    hash: [32]u8,
    timestamp: ?i64,
};

fn setVoteError(ctx: *ExecContext, e: VoteError) InstrError {
    ctx.custom_error = @intFromEnum(e);
    return error.Custom;
}

/// [agave] `should_reject_legacy_vote_instructions` (`vote_processor.
/// rs:78-81`) — gates Vote/VoteSwitch/UpdateVoteState(+Switch)/
/// CompactUpdateVoteState(+Switch) (disc 2,6,8,9,12,13). TowerSync(+Switch)
/// (14,15) uses ONLY the alpenglow leg (`:277-279`), not this whole gate.
fn legacyVoteRejected(ctx: *const ExecContext) bool {
    return ctx.features.deprecate_legacy_vote_ixs or ctx.features.alpenglow_migration_succeeded;
}

// ── Lockout arithmetic — [agave] state/mod.rs:61-103 `Lockout` methods ────────

fn lockoutPeriod(confirmation_count: u32) u64 {
    const capped: u32 = @min(confirmation_count, @as(u32, codec.MAX_LOCKOUT_HISTORY));
    return std.math.pow(u64, INITIAL_LOCKOUT, capped);
}
fn lastLockedOutSlotOf(slot: u64, confirmation_count: u32) u64 {
    return slot +| lockoutPeriod(confirmation_count);
}
fn isLockedOutAtSlot(l: codec.Lockout, slot: u64) bool {
    return lastLockedOutSlotOf(l.slot, l.confirmation_count) >= slot;
}

// ── Credits — [agave] handler.rs:394-455 `credits_for_vote_at_index`/`increment_credits` ──

fn creditsForVoteAtIndex(votes: []const codec.LandedVote, index: usize) u64 {
    const latency: u8 = if (index < votes.len) votes[index].latency else 0;
    if (latency == 0) return 1;
    const diff: u8 = std.math.sub(u8, latency, VOTE_CREDITS_GRACE_SLOTS) catch 0;
    if (diff == 0) return VOTE_CREDITS_MAXIMUM_PER_SLOT;
    const credits: u8 = std.math.sub(u8, VOTE_CREDITS_MAXIMUM_PER_SLOT, diff) catch 0;
    if (credits == 0) return 1;
    return credits;
}

/// [agave] handler.rs:425-455. Array-backed equivalent of the `Vec<(Epoch,
/// u64, u64)>` push/trim-at-MAX/saturating-add sequence — net-observable
/// result identical to Rust's transient push-then-remove(0) (see inline note).
fn incrementCredits(tail: *codec.Tail, epoch: u64, credits: u64) void {
    if (tail.epoch_credits_len == 0) {
        tail.epoch_credits[0] = .{ .epoch = epoch, .credits = 0, .prev_credits = 0 };
        tail.epoch_credits_len = 1;
    } else if (epoch != tail.epoch_credits[tail.epoch_credits_len - 1].epoch) {
        const last = tail.epoch_credits[tail.epoch_credits_len - 1];
        if (last.credits != last.prev_credits) {
            // [agave] push (epoch,credits,credits), THEN trim index 0 if
            // len()>MAX. Our fixed array has capacity exactly MAX
            // (`codec.MAX_EPOCH_CREDITS_HISTORY`) — trimming FIRST when
            // already at capacity is behaviorally identical, since length
            // only ever grows by one per call.
            if (tail.epoch_credits_len == codec.MAX_EPOCH_CREDITS_HISTORY) {
                var i: usize = 0;
                while (i < tail.epoch_credits_len - 1) : (i += 1) tail.epoch_credits[i] = tail.epoch_credits[i + 1];
                tail.epoch_credits_len -= 1;
            }
            tail.epoch_credits[tail.epoch_credits_len] = .{ .epoch = epoch, .credits = last.credits, .prev_credits = last.credits };
            tail.epoch_credits_len += 1;
        } else {
            tail.epoch_credits[tail.epoch_credits_len - 1].epoch = epoch;
        }
    }
    const last_idx = tail.epoch_credits_len - 1;
    tail.epoch_credits[last_idx].credits = tail.epoch_credits[last_idx].credits +| credits;
}

fn computeVoteLatency(voted_for_slot: u64, current_slot: u64) u8 {
    const diff = current_slot -| voted_for_slot;
    return if (diff > 255) 255 else @intCast(diff);
}

/// [agave] handler.rs:457-472 `process_timestamp`.
fn processTimestamp(state: *codec.VoteStateV4, slot: u64, timestamp: i64, ctx: *ExecContext) InstrError!void {
    const last = state.tail.last_timestamp;
    const same_slot_diff_ts = (slot == last.slot) and (timestamp != last.timestamp) and (last.slot != 0);
    if (slot < last.slot or timestamp < last.timestamp or same_slot_diff_ts) {
        return setVoteError(ctx, .timestamp_too_old);
    }
    state.tail.last_timestamp = .{ .slot = slot, .timestamp = timestamp };
}

// ── Legacy Vote path — [agave] mod.rs:299-391,608-681 ─────────────────────────

fn containsSlot(state: *const codec.VoteStateV4, slot: u64) bool {
    for (state.tail.votes[0..state.tail.votes_len]) |v| {
        if (v.lockout.slot == slot) return true;
    }
    return false;
}

/// [agave] handler.rs:474-482 `pop_expired_votes`.
fn popExpiredVotes(tail: *codec.Tail, next_vote_slot: u64) void {
    while (tail.votes_len > 0) {
        if (!isLockedOutAtSlot(tail.votes[tail.votes_len - 1].lockout, next_vote_slot)) {
            tail.votes_len -= 1;
        } else break;
    }
}

/// [agave] handler.rs:484-498 `double_lockouts`.
fn doubleLockouts(votes: []codec.LandedVote) void {
    const stack_depth = votes.len;
    for (votes, 0..) |*v, i| {
        if (stack_depth > i + @as(usize, v.lockout.confirmation_count)) {
            v.lockout.confirmation_count = v.lockout.confirmation_count +| 1;
        }
    }
}

/// [agave] handler.rs:500-532 `process_next_vote_slot`.
fn processNextVoteSlot(state: *codec.VoteStateV4, next_vote_slot: u64, epoch: u64, current_slot: u64) void {
    if (state.tail.votes_len > 0 and next_vote_slot <= state.tail.votes[state.tail.votes_len - 1].lockout.slot) return;

    popExpiredVotes(&state.tail, next_vote_slot);

    const landed_vote = codec.LandedVote{
        .latency = computeVoteLatency(next_vote_slot, current_slot),
        .lockout = .{ .slot = next_vote_slot, .confirmation_count = 1 },
    };

    if (state.tail.votes_len == codec.MAX_LOCKOUT_HISTORY) {
        const credits = creditsForVoteAtIndex(state.tail.votes[0..state.tail.votes_len], 0);
        const popped = state.tail.votes[0];
        var i: usize = 0;
        while (i < state.tail.votes_len - 1) : (i += 1) state.tail.votes[i] = state.tail.votes[i + 1];
        state.tail.votes_len -= 1;
        state.tail.root_slot = popped.lockout.slot;
        incrementCredits(&state.tail, epoch, credits);
    }
    state.tail.votes[state.tail.votes_len] = landed_vote;
    state.tail.votes_len += 1;
    doubleLockouts(state.tail.votes[0..state.tail.votes_len]);
}

/// [agave] mod.rs:299-391 `check_slots_are_valid`.
fn checkSlotsAreValid(
    state: *const codec.VoteStateV4,
    vote_slots: []const u64,
    vote_hash: [32]u8,
    slot_hashes: []const SlotHashEntry,
    ctx: *ExecContext,
) InstrError!void {
    var i: usize = 0;
    var j: usize = slot_hashes.len;
    const last_voted_slot: ?u64 = if (state.tail.votes_len > 0) state.tail.votes[state.tail.votes_len - 1].lockout.slot else null;

    while (i < vote_slots.len and j > 0) {
        if (last_voted_slot) |lvs| {
            if (vote_slots[i] <= lvs) {
                i += 1;
                continue;
            }
        }
        if (vote_slots[i] != slot_hashes[j - 1].slot) {
            j -= 1;
            continue;
        }
        i += 1;
        j -= 1;
    }

    if (j == slot_hashes.len) return setVoteError(ctx, .vote_too_old);
    if (i != vote_slots.len) return setVoteError(ctx, .slots_mismatch);
    if (!std.mem.eql(u8, &slot_hashes[j].hash, &vote_hash)) return setVoteError(ctx, .slot_hash_mismatch);
}

/// [agave] mod.rs:608-621 `process_vote_unfiltered`.
fn processVoteUnfiltered(
    state: *codec.VoteStateV4,
    vote_slots: []const u64,
    vote_hash: [32]u8,
    slot_hashes: []const SlotHashEntry,
    epoch: u64,
    current_slot: u64,
    ctx: *ExecContext,
) InstrError!void {
    try checkSlotsAreValid(state, vote_slots, vote_hash, slot_hashes, ctx);
    for (vote_slots) |s| processNextVoteSlot(state, s, epoch, current_slot);
}

/// [agave] mod.rs:623-651 `process_vote`.
fn processVote(
    state: *codec.VoteStateV4,
    vote: *const VoteArg,
    slot_hashes: []const SlotHashEntry,
    epoch: u64,
    current_slot: u64,
    ctx: *ExecContext,
) InstrError!void {
    if (vote.slots_len == 0) return setVoteError(ctx, .empty_slots);
    const earliest: u64 = if (slot_hashes.len > 0) slot_hashes[slot_hashes.len - 1].slot else 0;
    var filtered: [MAX_VOTE_SLOTS]u64 = undefined;
    var filtered_len: usize = 0;
    for (vote.slots[0..vote.slots_len]) |s| {
        if (s >= earliest) {
            filtered[filtered_len] = s;
            filtered_len += 1;
        }
    }
    if (filtered_len == 0) return setVoteError(ctx, .votes_too_old_all_filtered);
    try processVoteUnfiltered(state, filtered[0..filtered_len], vote.hash, slot_hashes, epoch, current_slot, ctx);
}

/// [agave] mod.rs:1211-1233 `process_vote_with_account`. Account index 0 =
/// vote account (standard); sysvar accounts (SlotHashes@1, Clock@2) are NOT
/// re-consulted here — `ctx.slot`/`ctx.slot_hashes` already carry them
/// (account_io's sysvar-agnostic design, §F.1).
pub fn processVoteWithAccount(
    table: *aio.AccountTable,
    vote_idx: usize,
    vote: *const VoteArg,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    var state = try loadV4Checked(vb.dataConst(), vb.pubkey());

    const authorized_voter = try getAndUpdateAuthorizedVoter(&state.tail, ctx.epoch);
    try verifyAuthorizedSigner(authorized_voter, signers);

    try processVote(&state, vote, ctx.slot_hashes.slice(), ctx.epoch, ctx.slot, ctx);
    if (vote.timestamp) |ts| {
        if (vote.slots_len == 0) return setVoteError(ctx, .empty_slots);
        var max_slot: u64 = vote.slots[0];
        for (vote.slots[0..vote.slots_len]) |s| {
            if (s > max_slot) max_slot = s;
        }
        try processTimestamp(&state, max_slot, ts, ctx);
    }
    try storeV4(&vb, &state);
    vb.release();
}

// ── TowerSync / (Compact)UpdateVoteState path — [agave] mod.rs:57-297,430-607,1235-1335 ──

/// [agave] mod.rs:57-297 `check_and_filter_proposed_vote_state`. Mutates
/// `lockouts`/`lockouts_len`/`proposed_root` IN PLACE (filters + root
/// overwrite), mirroring Rust's `&mut VecDeque<Lockout>`/`&mut Option<Slot>`
/// out-params exactly.
fn checkAndFilterProposedVoteState(
    state: *const codec.VoteStateV4,
    lockouts: []ProposedLockout,
    lockouts_len: *usize,
    proposed_root: *?u64,
    proposed_hash: [32]u8,
    slot_hashes: []const SlotHashEntry,
    ctx: *ExecContext,
) InstrError!void {
    if (lockouts_len.* == 0) return setVoteError(ctx, .empty_slots);

    const last_proposed_slot = lockouts[lockouts_len.* - 1].slot;

    if (state.tail.votes_len > 0) {
        const last_vote_slot = state.tail.votes[state.tail.votes_len - 1].lockout.slot;
        if (last_proposed_slot <= last_vote_slot) return setVoteError(ctx, .vote_too_old);
    }

    if (slot_hashes.len == 0) return setVoteError(ctx, .slots_mismatch);
    const earliest_slot_hash_in_history = slot_hashes[slot_hashes.len - 1].slot;

    if (last_proposed_slot < earliest_slot_hash_in_history) return setVoteError(ctx, .vote_too_old);

    if (proposed_root.*) |root| {
        if (root < earliest_slot_hash_in_history) {
            proposed_root.* = state.tail.root_slot;
            var k: usize = state.tail.votes_len;
            while (k > 0) {
                k -= 1;
                if (state.tail.votes[k].lockout.slot <= root) {
                    proposed_root.* = state.tail.votes[k].lockout.slot;
                    break;
                }
            }
        }
    }

    var root_to_check: ?u64 = proposed_root.*;
    var proposed_lockouts_index: usize = 0;
    var slot_hashes_index: usize = slot_hashes.len;
    var filter_mask: [MAX_PROPOSED_LOCKOUTS]bool = [_]bool{false} ** MAX_PROPOSED_LOCKOUTS;

    while (proposed_lockouts_index < lockouts_len.* and slot_hashes_index > 0) {
        const proposed_vote_slot: u64 = root_to_check orelse lockouts[proposed_lockouts_index].slot;

        if (root_to_check == null and proposed_lockouts_index > 0 and
            proposed_vote_slot <= lockouts[proposed_lockouts_index - 1].slot)
        {
            return setVoteError(ctx, .slots_not_ordered);
        }

        const ancestor_slot = slot_hashes[slot_hashes_index - 1].slot;

        if (proposed_vote_slot < ancestor_slot) {
            if (slot_hashes_index == slot_hashes.len) {
                if (proposed_vote_slot >= earliest_slot_hash_in_history) return setVoteError(ctx, .assertion_failed);
                if (root_to_check == null and !containsSlot(state, proposed_vote_slot)) {
                    filter_mask[proposed_lockouts_index] = true;
                }
                if (root_to_check) |rtc| {
                    std.debug.assert(rtc == proposed_vote_slot);
                    if (rtc >= earliest_slot_hash_in_history) return setVoteError(ctx, .assertion_failed);
                    root_to_check = null;
                } else {
                    proposed_lockouts_index += 1;
                }
                continue;
            } else {
                if (root_to_check != null) return setVoteError(ctx, .root_on_different_fork);
                return setVoteError(ctx, .slots_mismatch);
            }
        } else if (proposed_vote_slot > ancestor_slot) {
            slot_hashes_index -= 1;
            continue;
        } else {
            if (root_to_check != null) {
                root_to_check = null;
            } else {
                proposed_lockouts_index += 1;
                slot_hashes_index -= 1;
            }
        }
    }

    if (proposed_lockouts_index != lockouts_len.*) return setVoteError(ctx, .slots_mismatch);

    std.debug.assert(last_proposed_slot == slot_hashes[slot_hashes_index].slot);
    if (!std.mem.eql(u8, &slot_hashes[slot_hashes_index].hash, &proposed_hash)) return setVoteError(ctx, .slot_hash_mismatch);

    var w: usize = 0;
    var r: usize = 0;
    while (r < lockouts_len.*) : (r += 1) {
        if (!filter_mask[r]) {
            lockouts[w] = lockouts[r];
            w += 1;
        }
    }
    lockouts_len.* = w;
}

/// [agave] mod.rs:430-606 `process_new_vote_state` — lockout-stack arithmetic
/// (doubling handled by the CALLER's already-supplied confirmation counts;
/// this function only VALIDATES + merges), root advance, TIMELY VOTE CREDITS.
fn processNewVoteState(
    state: *codec.VoteStateV4,
    new_lockouts: []const ProposedLockout,
    new_root: ?u64,
    timestamp: ?i64,
    epoch: u64,
    current_slot: u64,
    ctx: *ExecContext,
) InstrError!void {
    std.debug.assert(new_lockouts.len != 0);
    if (new_lockouts.len > codec.MAX_LOCKOUT_HISTORY) return setVoteError(ctx, .too_many_votes);

    if (new_root) |nr| {
        if (state.tail.root_slot) |cr| {
            if (nr < cr) return setVoteError(ctx, .root_roll_back);
        }
    } else if (state.tail.root_slot != null) {
        return setVoteError(ctx, .root_roll_back);
    }

    var previous_vote: ?ProposedLockout = null;
    for (new_lockouts) |vote| {
        if (vote.confirmation_count == 0) return setVoteError(ctx, .zero_confirmations);
        if (vote.confirmation_count > codec.MAX_LOCKOUT_HISTORY) return setVoteError(ctx, .confirmation_too_large);
        if (new_root) |nr| {
            if (vote.slot <= nr and nr != 0) return setVoteError(ctx, .slot_smaller_than_root);
        }
        if (previous_vote) |pv| {
            if (pv.slot >= vote.slot) return setVoteError(ctx, .slots_not_ordered);
            if (pv.confirmation_count <= vote.confirmation_count) return setVoteError(ctx, .confirmations_not_ordered);
            if (vote.slot > lastLockedOutSlotOf(pv.slot, pv.confirmation_count)) return setVoteError(ctx, .new_vote_state_lockout_mismatch);
        }
        previous_vote = vote;
    }

    var current_vote_state_index: usize = 0;
    var new_vote_state_index: usize = 0;
    var earned_credits: u64 = 0;

    if (new_root) |nr| {
        while (current_vote_state_index < state.tail.votes_len) {
            if (state.tail.votes[current_vote_state_index].lockout.slot <= nr) {
                earned_credits +|= creditsForVoteAtIndex(state.tail.votes[0..state.tail.votes_len], current_vote_state_index);
                current_vote_state_index += 1;
                continue;
            }
            break;
        }
    }

    var new_votes: [codec.MAX_LOCKOUT_HISTORY]codec.LandedVote = undefined;
    for (new_lockouts, 0..) |nl, idx| {
        new_votes[idx] = .{ .latency = 0, .lockout = .{ .slot = nl.slot, .confirmation_count = nl.confirmation_count } };
    }

    while (current_vote_state_index < state.tail.votes_len and new_vote_state_index < new_lockouts.len) {
        const current_vote = state.tail.votes[current_vote_state_index];
        const new_vote_slot = new_votes[new_vote_state_index].lockout.slot;
        if (current_vote.lockout.slot < new_vote_slot) {
            if (lastLockedOutSlotOf(current_vote.lockout.slot, current_vote.lockout.confirmation_count) >= new_vote_slot) return setVoteError(ctx, .lockout_conflict);
            current_vote_state_index += 1;
        } else if (current_vote.lockout.slot == new_vote_slot) {
            if (new_votes[new_vote_state_index].lockout.confirmation_count < current_vote.lockout.confirmation_count) return setVoteError(ctx, .confirmation_roll_back);
            new_votes[new_vote_state_index].latency = current_vote.latency;
            current_vote_state_index += 1;
            new_vote_state_index += 1;
        } else {
            new_vote_state_index += 1;
        }
    }

    for (new_votes[0..new_lockouts.len]) |*nv| {
        if (nv.latency == 0) nv.latency = computeVoteLatency(nv.lockout.slot, current_slot);
    }

    if (state.tail.root_slot != new_root) {
        incrementCredits(&state.tail, epoch, earned_credits);
    }
    if (timestamp) |ts| {
        const last_slot = new_votes[new_lockouts.len - 1].lockout.slot;
        try processTimestamp(state, last_slot, ts, ctx);
    }
    state.tail.root_slot = new_root;
    state.tail.votes_len = new_lockouts.len;
    @memcpy(state.tail.votes[0..new_lockouts.len], new_votes[0..new_lockouts.len]);
}

/// [agave] mod.rs:1258-1284 `do_process_vote_state_update` == mod.rs:1309-1335
/// `do_process_tower_sync` (identical bodies — see file-section header).
fn doProcessVoteStateUpdate(
    state: *codec.VoteStateV4,
    slot_hashes: []const SlotHashEntry,
    epoch: u64,
    slot: u64,
    proposed: *ProposedVoteState,
    ctx: *ExecContext,
) InstrError!void {
    try checkAndFilterProposedVoteState(state, proposed.lockouts[0..proposed.lockouts_len], &proposed.lockouts_len, &proposed.root, proposed.hash, slot_hashes, ctx);
    try processNewVoteState(state, proposed.lockouts[0..proposed.lockouts_len], proposed.root, proposed.timestamp, epoch, slot, ctx);
}

/// [agave] mod.rs:1235-1256 `process_vote_state_update` (also the entry point
/// for CompactUpdateVoteState — same state-transition, different wire decode).
pub fn processVoteStateUpdate(
    table: *aio.AccountTable,
    vote_idx: usize,
    proposed: *ProposedVoteState,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    var vb = try table.borrowMut(vote_idx);
    errdefer vb.release();
    var state = try loadV4Checked(vb.dataConst(), vb.pubkey());
    const authorized_voter = try getAndUpdateAuthorizedVoter(&state.tail, ctx.epoch);
    try verifyAuthorizedSigner(authorized_voter, signers);
    try doProcessVoteStateUpdate(&state, ctx.slot_hashes.slice(), ctx.epoch, ctx.slot, proposed, ctx);
    try storeV4(&vb, &state);
    vb.release();
}

/// [agave] mod.rs:1286-1307 `process_tower_sync`. `proposed.hash`/`.timestamp`/
/// `.root`/`.lockouts` already decoded from the TowerSync compact wire form;
/// `block_id` was consumed (not stored) at decode time — see file-section
/// header. Identical core to `processVoteStateUpdate` (both call
/// `doProcessVoteStateUpdate`) — kept as a separate public entry point only
/// because Agave's own dispatch arms are separate (`vote_processor.rs:275-291`
/// vs `:241-274`) and so this rewrite's dispatch mirrors that 1:1.
pub fn processTowerSync(
    table: *aio.AccountTable,
    vote_idx: usize,
    proposed: *ProposedVoteState,
    signers: []const [32]u8,
    ctx: *ExecContext,
) InstrError!void {
    return processVoteStateUpdate(table, vote_idx, proposed, signers, ctx);
}

/// Test-only public wrapper around `processNewVoteState` — exposes it
/// directly (bypassing `checkAndFilterProposedVoteState`), mirroring how
/// Agave's OWN test suite pins `process_new_vote_state`'s reject taxonomy via
/// `process_new_vote_state_from_lockouts` (`vote_state/mod.rs:2199-2214`) —
/// called directly, never through the full `check_and_filter_proposed_vote_
/// state` + `process_new_vote_state` pipeline (same precedent as
/// `getAndUpdateAuthorizedVoterForTest` above).
pub fn processNewVoteStateForTest(
    state: *codec.VoteStateV4,
    new_lockouts: []const ProposedLockout,
    new_root: ?u64,
    timestamp: ?i64,
    epoch: u64,
    current_slot: u64,
    ctx: *ExecContext,
) InstrError!void {
    return processNewVoteState(state, new_lockouts, new_root, timestamp, epoch, current_slot, ctx);
}

/// Test-only public wrapper around `checkAndFilterProposedVoteState` — lets
/// KATs pin its filtering/rejection behavior in isolation, independent of
/// `processNewVoteState`'s own (separate) reject taxonomy.
pub fn checkAndFilterProposedVoteStateForTest(
    state: *const codec.VoteStateV4,
    lockouts: []ProposedLockout,
    lockouts_len: *usize,
    proposed_root: *?u64,
    proposed_hash: [32]u8,
    slot_hashes: []const SlotHashEntry,
    ctx: *ExecContext,
) InstrError!void {
    return checkAndFilterProposedVoteState(state, lockouts, lockouts_len, proposed_root, proposed_hash, slot_hashes, ctx);
}

/// Test-only public wrapper around `processTimestamp`.
pub fn processTimestampForTest(state: *codec.VoteStateV4, slot: u64, timestamp: i64, ctx: *ExecContext) InstrError!void {
    return processTimestamp(state, slot, timestamp, ctx);
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction-argument decoder — [agave] `solana-vote-interface-6.0.0/src/
// instruction.rs:35-239`. `VoteInstruction` is a plain Rust enum, bincode-
// serialized as a little-endian u32 variant-index tag (declaration order,
// 0-indexed) followed by the variant's field payload in declaration order.
// Same convention recurses into nested enums (`VoteAuthorize`, `CommissionKind`
// — confirmed against the transplant's own instruction.zig comment: "kind:
// u32 LE (CommissionKind serializes as a plain u32 via sig bincode)" — bincode
// v1's default enum-discriminant width is u32 REGARDLESS of any `#[repr(u8)]`
// on the Rust type, which only affects in-memory layout, not serde/bincode
// wire format). `Option<T>` is the one bincode-special-cased exception (a
// single presence BYTE, not a u32 tag) — `vote_codec.zig`'s `Reader.optFlag`
// already encodes this same convention for account-state fields; this
// decoder does not need Option anywhere in the instruction-arg shapes below.
//
// This file owns instruction-ARGUMENT parsing; `vote_codec.zig` owns
// account-STATE parsing — deliberately separate concerns, per Stage 1's own
// header note ("this codec is exclusively account-DATA serde").
// ─────────────────────────────────────────────────────────────────────────────

const ArgReader = struct {
    buf: []const u8,
    off: usize = 0,

    fn need(self: *ArgReader, n: usize) InstrError!void {
        if (self.buf.len - self.off < n) return error.InvalidInstructionData;
    }
    fn u8v(self: *ArgReader) InstrError!u8 {
        try self.need(1);
        defer self.off += 1;
        return self.buf[self.off];
    }
    fn u16v(self: *ArgReader) InstrError!u16 {
        try self.need(2);
        defer self.off += 2;
        return std.mem.readInt(u16, self.buf[self.off..][0..2], .little);
    }
    fn u32v(self: *ArgReader) InstrError!u32 {
        try self.need(4);
        defer self.off += 4;
        return std.mem.readInt(u32, self.buf[self.off..][0..4], .little);
    }
    fn u64v(self: *ArgReader) InstrError!u64 {
        try self.need(8);
        defer self.off += 8;
        return std.mem.readInt(u64, self.buf[self.off..][0..8], .little);
    }
    fn pubkeyV(self: *ArgReader) InstrError![32]u8 {
        try self.need(32);
        defer self.off += 32;
        return self.buf[self.off..][0..32].*;
    }
    fn bytesN(self: *ArgReader, comptime n: usize) InstrError![n]u8 {
        try self.need(n);
        defer self.off += n;
        return self.buf[self.off..][0..n].*;
    }
    /// bincode `Vec<u8>`/`String`: u64 LE length prefix + raw bytes.
    /// Allocator-owned — caller frees (KATs/dispatch use an arena).
    fn bytesVec(self: *ArgReader, alloc: std.mem.Allocator) InstrError![]u8 {
        const len = try self.u64v();
        try self.need(@intCast(len));
        const out = try alloc.dupe(u8, self.buf[self.off..][0..@intCast(len)]);
        self.off += @intCast(len);
        return out;
    }
    /// bincode enum discriminant (u32 LE) mapped to a `CommissionKind`.
    fn commissionKind(self: *ArgReader) InstrError!CommissionKind {
        const tag = try self.u32v();
        return switch (tag) {
            0 => .inflation_rewards,
            1 => .block_revenue,
            else => error.InvalidInstructionData,
        };
    }
    /// bincode `Option<i64>` (`UnixTimestamp`): presence byte + LE i64.
    fn optI64(self: *ArgReader) InstrError!?i64 {
        return switch (try self.u8v()) {
            0 => null,
            1 => @as(i64, @bitCast(try self.u64v())),
            else => error.InvalidInstructionData,
        };
    }
    /// bincode `Option<u64>` (`Slot`): presence byte + LE u64.
    fn optU64(self: *ArgReader) InstrError!?u64 {
        return switch (try self.u8v()) {
            0 => null,
            1 => try self.u64v(),
            else => error.InvalidInstructionData,
        };
    }
    /// [agave] `solana_short_vec::ShortU16` decode (`solana-short-vec-3.2.2/
    /// src/lib.rs`) — 1-3 bytes, 7 bits/byte LE, continuation bit = 0x80.
    /// Faithfully rejects every malformed encoding Agave's own deserializer
    /// does: a non-first zero byte ("Alias"), a 4th+ byte ("TooLong"), a
    /// continuing 3rd byte ("ByteThreeContinues"), and a decoded value beyond
    /// u16 ("Overflow") — all folded to `InvalidInstructionData` (the same
    /// bucket bincode-deserialize-failure maps to at the seam's entrypoint).
    fn shortU16(self: *ArgReader) InstrError!u16 {
        var val: u32 = 0;
        var nth: usize = 0;
        while (true) {
            const b = try self.u8v();
            if (b == 0 and nth != 0) return error.InvalidInstructionData;
            if (nth >= 3) return error.InvalidInstructionData;
            const elem_done = (b & 0x80) == 0;
            if (nth == 2 and !elem_done) return error.InvalidInstructionData;
            const shift: u5 = @intCast(nth * 7);
            const elem_val: u32 = @as(u32, b & 0x7f) << shift;
            val |= elem_val;
            if (val > std.math.maxInt(u16)) return error.InvalidInstructionData;
            if (elem_done) return @intCast(val);
            nth += 1;
        }
    }
    /// [agave] `solana_serde_varint` LEB128 decode for `u64` (`solana-serde-
    /// varint-3.0.1/src/lib.rs`) — used for `LockoutOffset.offset` inside the
    /// compact TowerSync/UpdateVoteState wire forms. Rejects a truncated
    /// final byte and invalid (non-canonical) trailing-zero encodings exactly
    /// as Agave's own `VarInt::visit_seq` does.
    fn varintU64(self: *ArgReader) InstrError!u64 {
        var out: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const b = try self.u8v();
            const piece: u64 = @as(u64, b & 0x7f);
            out |= piece << shift;
            if (b & 0x80 == 0) {
                if (@as(u8, @truncate(out >> shift)) != b) return error.InvalidInstructionData;
                if (b == 0 and (shift != 0 or out != 0)) return error.InvalidInstructionData;
                return out;
            }
            if (shift >= 63) return error.InvalidInstructionData;
            shift += 7;
        }
    }
};

// ── Stage 5 wire decoders — [agave] instruction.rs Vote/VoteStateUpdate/
// TowerSync field orders + state/mod.rs:203-394 compact serde modules ────────

fn parseVoteArg(r: *ArgReader) InstrError!VoteArg {
    var v: VoteArg = undefined;
    const n = try r.u64v();
    if (n > MAX_VOTE_SLOTS) return error.InvalidInstructionData;
    v.slots_len = @intCast(n);
    for (0..v.slots_len) |i| v.slots[i] = try r.u64v();
    v.hash = try r.pubkeyV();
    v.timestamp = try r.optI64();
    return v;
}

/// [agave] `VoteStateUpdate`'s plain (non-compact) bincode form — disc 8/9
/// (UpdateVoteState/Switch). Field order: lockouts (Vec<Lockout>), root
/// (Option<Slot>), hash, timestamp.
fn parseVoteStateUpdateNonCompact(r: *ArgReader) InstrError!ProposedVoteState {
    var out: ProposedVoteState = undefined;
    const n = try r.u64v();
    if (n > MAX_PROPOSED_LOCKOUTS) return error.InvalidInstructionData;
    out.lockouts_len = @intCast(n);
    for (0..out.lockouts_len) |i| out.lockouts[i] = .{ .slot = try r.u64v(), .confirmation_count = try r.u32v() };
    out.root = try r.optU64();
    out.hash = try r.pubkeyV();
    out.timestamp = try r.optI64();
    return out;
}

/// [agave] `serde_compact_vote_state_update`/`serde_tower_sync` shared shape
/// — disc 12/13/14/15 ALL use this compact encoding (TowerSync is compact
/// UNCONDITIONALLY, not just the "Compact*" named variants — confirmed
/// against `instruction.rs`'s `#[serde(with = "serde_tower_sync")]` on the
/// `TowerSync`/`TowerSyncSwitch` variants themselves). Field order: root
/// (Slot, `u64::MAX` sentinel for None), lockout_offsets (short_vec<
/// LockoutOffset{varint offset, u8 confirmation_count}>, offsets are a
/// running-sum SCAN from `root.unwrap_or(0)`), hash, timestamp. `out.root`/
/// `out.lockouts[..]` are already the absolute (non-offset) form on return.
fn parseCompactLockouts(r: *ArgReader, out: *ProposedVoteState) InstrError!void {
    const root_raw = try r.u64v();
    out.root = if (root_raw != std.math.maxInt(u64)) root_raw else null;
    const n = try r.shortU16();
    if (n > MAX_PROPOSED_LOCKOUTS) return error.InvalidInstructionData;
    out.lockouts_len = n;
    var running: u64 = out.root orelse 0;
    for (0..out.lockouts_len) |i| {
        const offset = try r.varintU64();
        const slot = std.math.add(u64, running, offset) catch return error.InvalidInstructionData;
        const cc = try r.u8v();
        out.lockouts[i] = .{ .slot = slot, .confirmation_count = cc };
        running = slot;
    }
}

fn parseVoteStateUpdateCompact(r: *ArgReader) InstrError!ProposedVoteState {
    var out: ProposedVoteState = undefined;
    try parseCompactLockouts(r, &out);
    out.hash = try r.pubkeyV();
    out.timestamp = try r.optI64();
    return out;
}

/// TowerSync's compact form is `CompactTowerSync` — identical to
/// `CompactVoteStateUpdate` PLUS a trailing `block_id: Hash`. `block_id` is
/// consumed (must be present on the wire for a structurally-valid decode)
/// but never stored — see the Stage-5 section header for why (not part of
/// on-chain vote state; consensus/replay-only, per Agave source).
fn parseTowerSyncCompact(r: *ArgReader) InstrError!ProposedVoteState {
    var out: ProposedVoteState = undefined;
    try parseCompactLockouts(r, &out);
    out.hash = try r.pubkeyV();
    out.timestamp = try r.optI64();
    _ = try r.pubkeyV(); // block_id
    return out;
}

fn parseVoteAuthorize(r: *ArgReader) InstrError!VoteAuthorizeArg {
    const tag = try r.u32v();
    return switch (tag) {
        0 => .voter,
        1 => .withdrawer,
        2 => .{ .voter_with_bls = .{
            .bls_pubkey = try r.bytesN(codec.BLS_PUBKEY_COMPRESSED_SIZE),
            .bls_proof_of_possession = try r.bytesN(96),
        } },
        else => error.InvalidInstructionData,
    };
}

pub const AuthorizeArgs = struct { new_authority: [32]u8, vote_authorize: VoteAuthorizeArg };
pub const AuthorizeWithSeedArgs = struct {
    authorization_type: VoteAuthorizeArg,
    current_authority_derived_key_owner: [32]u8,
    current_authority_derived_key_seed: []const u8,
    new_authority: [32]u8,
};
pub const AuthorizeCheckedWithSeedArgs = struct {
    authorization_type: VoteAuthorizeArg,
    current_authority_derived_key_owner: [32]u8,
    current_authority_derived_key_seed: []const u8,
};
pub const InitializeAccountArgs = struct {
    node_pubkey: [32]u8,
    authorized_voter: [32]u8,
    authorized_withdrawer: [32]u8,
    commission: u8,
};

/// The union of every discriminant the seam may see. `unrouted` carries only
/// the raw tag for anything outside the 20-variant table (never emitted by a
/// conforming client, but the decoder must classify it, never panic).
pub const ParsedInstruction = union(enum) {
    initialize_account: InitializeAccountArgs,
    authorize: AuthorizeArgs,
    vote: VoteArg,
    withdraw: struct { lamports: u64 },
    update_validator_identity,
    update_commission: struct { commission: u8 },
    vote_switch: struct { vote: VoteArg, proof_hash: [32]u8 },
    authorize_checked: VoteAuthorizeArg,
    update_vote_state: ProposedVoteState,
    update_vote_state_switch: struct { proposed: ProposedVoteState, proof_hash: [32]u8 },
    authorize_with_seed: AuthorizeWithSeedArgs,
    authorize_checked_with_seed: AuthorizeCheckedWithSeedArgs,
    compact_update_vote_state: ProposedVoteState,
    compact_update_vote_state_switch: struct { proposed: ProposedVoteState, proof_hash: [32]u8 },
    tower_sync: ProposedVoteState,
    tower_sync_switch: struct { proposed: ProposedVoteState, proof_hash: [32]u8 },
    initialize_account_v2: InitializeAccountV2Args,
    update_commission_collector: struct { kind: CommissionKind },
    update_commission_bps: struct { commission_bps: u16, kind: CommissionKind },
    deposit_delegator_rewards: struct { deposit: u64 },
    unrouted: u32,
};

/// [agave] `VoteInstruction`'s 20-variant discriminant table (`instruction.
/// rs:35-239`, verified against the interface crate directly — see the
/// research citation table in this Stage's KATs). All 20 discriminants are
/// now fully decoded (Stage 5 landed the Vote/TowerSync family, discriminants
/// 2,6,8,9,12,13,14,15); only a tag outside 0-19 returns `.unrouted`.
pub fn parseInstruction(alloc: std.mem.Allocator, data: []const u8) InstrError!ParsedInstruction {
    var r = ArgReader{ .buf = data };
    const disc = try r.u32v();
    return switch (disc) {
        0 => .{ .initialize_account = .{
            .node_pubkey = try r.pubkeyV(),
            .authorized_voter = try r.pubkeyV(),
            .authorized_withdrawer = try r.pubkeyV(),
            .commission = try r.u8v(),
        } },
        1 => .{ .authorize = .{ .new_authority = try r.pubkeyV(), .vote_authorize = try parseVoteAuthorize(&r) } },
        2 => .{ .vote = try parseVoteArg(&r) },
        3 => .{ .withdraw = .{ .lamports = try r.u64v() } },
        4 => .update_validator_identity,
        5 => .{ .update_commission = .{ .commission = try r.u8v() } },
        6 => .{ .vote_switch = .{ .vote = try parseVoteArg(&r), .proof_hash = try r.pubkeyV() } },
        7 => .{ .authorize_checked = try parseVoteAuthorize(&r) },
        8 => .{ .update_vote_state = try parseVoteStateUpdateNonCompact(&r) },
        9 => .{ .update_vote_state_switch = .{ .proposed = try parseVoteStateUpdateNonCompact(&r), .proof_hash = try r.pubkeyV() } },
        10 => .{ .authorize_with_seed = .{
            .authorization_type = try parseVoteAuthorize(&r),
            .current_authority_derived_key_owner = try r.pubkeyV(),
            .current_authority_derived_key_seed = try r.bytesVec(alloc),
            .new_authority = try r.pubkeyV(),
        } },
        11 => .{ .authorize_checked_with_seed = .{
            .authorization_type = try parseVoteAuthorize(&r),
            .current_authority_derived_key_owner = try r.pubkeyV(),
            .current_authority_derived_key_seed = try r.bytesVec(alloc),
        } },
        12 => .{ .compact_update_vote_state = try parseVoteStateUpdateCompact(&r) },
        13 => .{ .compact_update_vote_state_switch = .{ .proposed = try parseVoteStateUpdateCompact(&r), .proof_hash = try r.pubkeyV() } },
        14 => .{ .tower_sync = try parseTowerSyncCompact(&r) },
        15 => .{ .tower_sync_switch = .{ .proposed = try parseTowerSyncCompact(&r), .proof_hash = try r.pubkeyV() } },
        16 => .{ .initialize_account_v2 = .{
            .node_pubkey = try r.pubkeyV(),
            .authorized_voter = try r.pubkeyV(),
            .authorized_voter_bls_pubkey = try r.bytesN(codec.BLS_PUBKEY_COMPRESSED_SIZE),
            .authorized_voter_bls_proof_of_possession = try r.bytesN(96),
            .authorized_withdrawer = try r.pubkeyV(),
            .inflation_rewards_commission_bps = try r.u16v(),
            .block_revenue_commission_bps = try r.u16v(),
        } },
        17 => .{ .update_commission_collector = .{ .kind = try r.commissionKind() } },
        18 => .{ .update_commission_bps = .{ .commission_bps = try r.u16v(), .kind = try r.commissionKind() } },
        19 => .{ .deposit_delegator_rewards = .{ .deposit = try r.u64v() } },
        else => .{ .unrouted = disc },
    };
}

/// Stage 5 landed (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 5): every
/// discriminant 0-19 is now handled directly by `execute()` — this always
/// returns `false`. Kept (not deleted) so `vote_program.zig`'s `classify()`/
/// `RouteClass.stage5` continue to compile unchanged — per the Stage 4
/// readiness note, the front door "follows automatically" from this flip,
/// with zero edits to `vote_program.zig` itself.
pub fn isStage5Discriminant(disc: u32) bool {
    _ = disc;
    return false;
}

/// Every discriminant 0-19 is now fully implemented (Stage 3's original 12
/// plus Stage 5's 8 Vote/TowerSync-family discriminants) — used by the oracle
/// router to decide real-compare vs KNOWN-GAP vs passthrough.
pub fn isStage3Discriminant(disc: u32) bool {
    return switch (disc) {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 => true,
        else => false,
    };
}

/// Of the Stage-3 discriminants, the two the transplant has NO correct
/// equivalent for (§D.4's documented gap: InitializeAccountV2 is a stub that
/// always errors, DepositDelegatorRewards doesn't exist in the union at all)
/// — the oracle router treats these as KNOWN-GAP, not MISMATCH.
pub fn isKnownGapDiscriminant(disc: u32) bool {
    return switch (disc) {
        16, 19 => true,
        else => false,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatch — maps a `ParsedInstruction` onto the family function
// above, using the STANDARD account-index positions from the [agave]
// dispatch arms cited per-family (index 0 = vote account, always). Mirrors
// `vote_processor.rs:106-428`'s match statement, one arm per discriminant.
// `table` must already contain (at minimum) every account position the
// matched arm below reads — the caller (`instruction_dispatch.
// executeVoteViaVoteforge`, the live seam)
// builds `table` from the instruction's own account list, in the SAME order
// a real transaction sends them (Agave's documented per-instruction account
// order, identical to the transplant's own `instruction.zig` `AccountIndex`
// enums — cross-checked against them where they exist).
// ─────────────────────────────────────────────────────────────────────────────

pub fn execute(table: *aio.AccountTable, parsed: ParsedInstruction, signers: []const [32]u8, ctx: *ExecContext) InstrError!void {
    switch (parsed) {
        .initialize_account => |a| try initializeAccount(table, 0, a.node_pubkey, a.authorized_voter, a.authorized_withdrawer, a.commission, signers, ctx),
        .authorize => |a| try authorize(table, 0, signers, a.new_authority, a.vote_authorize, ctx),
        .vote => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            try processVoteWithAccount(table, 0, &a, signers, ctx);
        },
        .withdraw => |a| try withdraw(table, 0, 1, a.lamports, signers, ctx),
        .update_validator_identity => try updateValidatorIdentity(table, 0, 1, signers, ctx),
        .update_commission => |a| try updateCommission(table, 0, a.commission, signers, ctx),
        .vote_switch => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            var v = a.vote;
            try processVoteWithAccount(table, 0, &v, signers, ctx);
        },
        .authorize_checked => |va| try authorizeChecked(table, 0, 3, signers, va, ctx),
        .update_vote_state => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            var p = a;
            try processVoteStateUpdate(table, 0, &p, signers, ctx);
        },
        .update_vote_state_switch => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            var p = a.proposed;
            try processVoteStateUpdate(table, 0, &p, signers, ctx);
        },
        .authorize_with_seed => |a| try authorizeWithSeed(table, 0, 2, a.authorization_type, a.current_authority_derived_key_owner, a.current_authority_derived_key_seed, a.new_authority, ctx),
        .authorize_checked_with_seed => |a| try authorizeCheckedWithSeed(table, 0, 2, 3, a.authorization_type, a.current_authority_derived_key_owner, a.current_authority_derived_key_seed, ctx),
        .compact_update_vote_state => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            var p = a;
            try processVoteStateUpdate(table, 0, &p, signers, ctx);
        },
        .compact_update_vote_state_switch => |a| {
            if (legacyVoteRejected(ctx)) return error.InvalidInstructionData;
            var p = a.proposed;
            try processVoteStateUpdate(table, 0, &p, signers, ctx);
        },
        .tower_sync => |a| {
            if (ctx.features.alpenglow_migration_succeeded) return error.InvalidInstructionData;
            var p = a;
            try processTowerSync(table, 0, &p, signers, ctx);
        },
        .tower_sync_switch => |a| {
            if (ctx.features.alpenglow_migration_succeeded) return error.InvalidInstructionData;
            var p = a.proposed;
            try processTowerSync(table, 0, &p, signers, ctx);
        },
        .initialize_account_v2 => |a| try initializeAccountV2(table, 0, 2, 3, a, signers, ctx),
        .update_commission_collector => |a| try updateCommissionCollector(table, 0, 1, a.kind, signers, ctx),
        .update_commission_bps => |a| try updateCommissionBps(table, 0, a.commission_bps, a.kind, signers, ctx),
        .deposit_delegator_rewards => |a| try depositDelegatorRewards(table, 0, 1, a.deposit, signers, ctx),
        .unrouted => return error.InvalidInstructionData,
    }
}
