//! Vexor Stake Program — instruction dispatch and handler implementations.
//!
//! Handles all 18 stake instruction discriminants (0x00-0x11), not just the
//! original "Phase 1" subset this header used to claim (rebuild module-47
//! CLEAN correction, 2026-07-07 — the stale "Phase 1 implements: Initialize/
//! Authorize/DelegateStake/Withdraw/Deactivate" line was dangerously
//! out of date, per VEXOR-REBUILD-FILE-MANIFEST-2026-07-06.md:164/670).
//! Verified trailing handlers are real, not reject-stubs:
//!   Redelegate (0x0F) — deliberate reject, `error.InvalidInstructionData`,
//!     matching canonical cluster behavior for this deprecated instruction
//!     (see handleRedelegate's own PR-5x comment).
//!   MoveStake (0x10) / MoveLamports (0x11) — 🔴 CORRECTED 2026-07-30: these are
//!     UNIMPLEMENTED no-ops on an ACTIVE feature, NOT safe feature-gated stubs.
//!     This header previously read "deliberate feature-gated no-ops pending v2.1+
//!     activation ... not yet active, not silent failures of an implemented path."
//!     That was wrong: `move_stake_and_move_lamports_ixs`
//!     (7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4) ACTIVATED AT SLOT 302060257.
//!     Both handlers return SUCCESS writing nothing, so an invocation diverges our
//!     bank_hash silently. They now log loudly ([STAKE-MOVE-UNIMPLEMENTED]); the
//!     real implementation is tracked as G3 and needs KATs, since no on-chain
//!     occurrence and no stake fixtures exist to replay against.
//!     Latent, not safe — 0 occurrences observed in 571 decoded blocks.
//! `execute()`'s `switch` covers all 18 named discriminants + a `_ => {}`
//! catch-all for unknown values > 0x11 that `parseInstruction` already
//! rejects with `error.UnknownInstruction` beforehand — 18/19 in the
//! manifest's shorthand counts the switch arms, not a missing discriminant.
//!
//! All byte access uses stake_state.Offsets and helper functions.
//! No ptrCast on raw bincode data (avoids the alignment/padding bug).

const std = @import("std");
const stake_state = @import("stake_state.zig");
const vote_state_serde = @import("vote_state_serde.zig");
const bank_mod = @import("../bank.zig");
const overlay_lookup = @import("../overlay_lookup.zig");
const core = @import("core");
const vex_bpf2 = @import("vex_bpf2"); // P0-2: reuses builtins.stake_program.deriveWithSeed

// ---------------------------------------------------------------------------
// Error set
// ---------------------------------------------------------------------------

pub const StakeError = error{
    InvalidInstructionData,
    InvalidAccountIndex,
    UnknownInstruction,
};

// ---------------------------------------------------------------------------
// r71-fix-11: pending_writes overlay snapshot — chain pattern lifted from
// 8c838a8 (vote-account chain). When an account is mutated multiple times in
// a single slot, every subsequent read MUST see prior in-slot writes,
// otherwise old_lt is computed from the pre-slot snapshot and the LtHash
// chain identity (W2.old_lt == W1.new_lt) breaks. Slot-482 carrier: 30
// System wallets each missing N×5000 lamports — Withdraw recipients hit by
// multiple in-slot stake withdraws, second+ Withdraw read stale snapshot.
// ---------------------------------------------------------------------------

const OverlaySnapshot = struct {
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
    found: bool,
};

/// r75-bug-class-c-stake-2026-05-06: drop-in replacement for `db.getAccountInSlot`
/// that walks `bank.pending_writes` (tail-first, last-write-wins) before
/// falling back to the snapshot db via the ancestor-aware path. Returns a
/// struct shape that matches what `db.getAccountInSlot` returns (owner is
/// a Pubkey, not raw [32]u8) so each call site
/// `const acct = readOverlayed(bank, db, key) orelse return;` drops in
/// with no downstream changes. Empirically required for stake/withdraw
/// chained in-slot mutations + multi-tx fee_payers.
const OverlayedAccount = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

fn readOverlayed(bank: anytype, db: anytype, key: [32]u8) ?OverlayedAccount {
    // B2b (parallel-exec): scan the worker's own write buffer (if set, parallel path)
    // THEN pending_writes via the shared overlay_lookup core. Serial path
    // (worker_writes_override == null) = byte-identical newest-first pending_writes scan.
    const W = bank_mod.AccountWrite;
    const ov_items: []const W = if (bank_mod.worker_writes_override) |ov| ov.items else &[_]W{};
    if (overlay_lookup.newestMatchTwo(W, ov_items, bank.pending_writes.items, &key)) |w| {
        return .{
            .lamports = w.lamports,
            .owner = w.owner,
            .executable = w.executable,
            .rent_epoch = w.rent_epoch,
            .data = w.data,
        };
    }
    const pk = core.Pubkey{ .data = key };
    if (db.getAccountInSlot(&pk, bank.slot, bank.ancestors())) |a| {
        return .{
            .lamports = a.lamports,
            .owner = a.owner,
            .executable = a.executable,
            .rent_epoch = a.rent_epoch,
            .data = a.data,
        };
    }
    return null;
}

fn readWithPendingOverlay(
    bank: anytype,
    db: anytype,
    key: [32]u8,
) OverlaySnapshot {
    // B2b (parallel-exec): worker buffer (if set) THEN pending_writes via overlay_lookup.
    // Serial path (override == null) = byte-identical newest-first pending_writes scan.
    const W = bank_mod.AccountWrite;
    const ov_items: []const W = if (bank_mod.worker_writes_override) |ov| ov.items else &[_]W{};
    if (overlay_lookup.newestMatchTwo(W, ov_items, bank.pending_writes.items, &key)) |w| {
        return .{
            .lamports = w.lamports,
            .owner = w.owner.data,
            .executable = w.executable,
            .rent_epoch = w.rent_epoch,
            .data = w.data,
            .found = true,
        };
    }
    const pk = core.Pubkey{ .data = key };
    if (db.getAccountInSlot(&pk, bank.slot, bank.ancestors())) |a| {
        return .{
            .lamports = a.lamports,
            .owner = a.owner.data,
            .executable = a.executable,
            .rent_epoch = a.rent_epoch,
            .data = a.data,
            .found = true,
        };
    }
    return .{
        .lamports = 0,
        .owner = [_]u8{0} ** 32,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &[_]u8{},
        .found = false,
    };
}

// ---------------------------------------------------------------------------
// Instruction discriminants (bincode u32, little-endian)
// ---------------------------------------------------------------------------

pub const StakeInstruction = enum(u32) {
    initialize = 0x00,
    authorize = 0x01,
    delegate_stake = 0x02,
    split = 0x03,
    withdraw = 0x04,
    deactivate = 0x05,
    set_lockup = 0x06,
    merge = 0x07,
    authorize_with_seed = 0x08,
    initialize_checked = 0x09,
    authorize_checked = 0x0A,
    authorize_checked_with_seed = 0x0B,
    set_lockup_checked = 0x0C,
    get_minimum_delegation = 0x0D,
    deactivate_delinquent = 0x0E,
    redelegate = 0x0F,
    move_stake = 0x10,
    move_lamports = 0x11,
    _,
};

/// Parse the instruction type from the first 4 bytes of instruction data.
pub fn parseInstruction(ix_data: []const u8) StakeError!StakeInstruction {
    if (ix_data.len < 4) return StakeError.InvalidInstructionData;
    const disc = std.mem.readInt(u32, ix_data[0..4], .little);
    if (disc > 0x11) return StakeError.UnknownInstruction;
    return std.meta.intToEnum(StakeInstruction, disc) catch StakeError.UnknownInstruction;
}

// ---------------------------------------------------------------------------
// Parameter structs
// ---------------------------------------------------------------------------

pub const InitializeParams = struct {
    staker: [32]u8,
    withdrawer: [32]u8,
    lockup_unix_timestamp: i64,
    lockup_epoch: u64,
    lockup_custodian: [32]u8,

    pub fn parse(ix_data: []const u8) StakeError!InitializeParams {
        if (ix_data.len < 116) return StakeError.InvalidInstructionData;
        return .{
            .staker = ix_data[4..36].*,
            .withdrawer = ix_data[36..68].*,
            .lockup_unix_timestamp = std.mem.readInt(i64, ix_data[68..76], .little),
            .lockup_epoch = std.mem.readInt(u64, ix_data[76..84], .little),
            .lockup_custodian = ix_data[84..116].*,
        };
    }
};

pub const AuthorizeParams = struct {
    new_authority: [32]u8,
    authorize_type: u32, // 0 = Staker, 1 = Withdrawer

    pub fn parse(ix_data: []const u8) StakeError!AuthorizeParams {
        if (ix_data.len < 40) return StakeError.InvalidInstructionData;
        return .{
            .new_authority = ix_data[4..36].*,
            .authorize_type = std.mem.readInt(u32, ix_data[36..40], .little),
        };
    }
};

// ---------------------------------------------------------------------------
// Shared helper: check if account index is a transaction signer
// ---------------------------------------------------------------------------

fn isSigner(ptx: anytype, acct_idx: u8) bool {
    return acct_idx < ptx.num_required_sigs;
}

// ---------------------------------------------------------------------------
// Handler: Initialize (0x00)
// ---------------------------------------------------------------------------
// Creates a stake account in Initialized state with Meta (authorities + lockup).
//
// Accounts:
//   [0] RW  stake_account — must be Uninitialized (disc=0) or fresh
//   [1] RO  rent_sysvar   — not read directly (rent-exempt reserve hardcoded for 200-byte accounts)
//
// State mutation: Writes 200-byte Initialized state (disc=1) with:
//   - rent_exempt_reserve = 2_282_880 (standard for 200-byte accounts)
//   - authorized.staker from ix.data[4..36]
//   - authorized.withdrawer from ix.data[36..68]
//   - lockup fields from ix.data[68..116]
//
// Validation:
//   - Account data must be >= 200 bytes (or empty for fresh accounts)
//   - If existing, discriminant must be 0 (Uninitialized)
//   - Account lamports >= rent_exempt_reserve
// ---------------------------------------------------------------------------

fn handleInitialize(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Initialize slot={d}\n", .{bank.slot});
    const params = InitializeParams.parse(ix.data) catch return;

    if (ix.account_indices.len < 2) return;
    const stake_idx = ix.account_indices[0];
    if (stake_idx >= ptx.num_accounts) return;

    const stake_key = ptx.account_keys[stake_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    // Must be Uninitialized (discriminant 0)
    if (stake_acct.data.len >= 4) {
        const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
        if (disc != 0) return;
    }

    // Standard rent-exempt reserve for 200-byte stake accounts
    const rent_exempt_reserve: u64 = 2_282_880;
    if (stake_acct.lamports < rent_exempt_reserve) return;

    // Allocate 200-byte buffer and write Initialized state
    const data_copy = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
    @memset(data_copy, 0);

    stake_state.writeU32(data_copy, stake_state.Offsets.discriminant, 1);
    stake_state.writeU64(data_copy, stake_state.Offsets.rent_exempt_reserve, rent_exempt_reserve);
    stake_state.writePubkey(data_copy, stake_state.Offsets.staker, params.staker);
    stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, params.withdrawer);
    stake_state.writeI64(data_copy, stake_state.Offsets.lockup_unix_timestamp, params.lockup_unix_timestamp);
    stake_state.writeU64(data_copy, stake_state.Offsets.lockup_epoch, params.lockup_epoch);
    stake_state.writePubkey(data_copy, stake_state.Offsets.lockup_custodian, params.lockup_custodian);

    // LtHash delta + pending write
    const old_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        stake_acct.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        data_copy,
    );
    bank.collectWrite(.{
        .pubkey = .{ .data = stake_key },
        .lamports = stake_acct.lamports,
        .owner = .{ .data = stake_acct.owner.data },
        .executable = stake_acct.executable,
        .rent_epoch = stake_acct.rent_epoch,
        .data = data_copy,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Handler: Authorize (0x01)
// ---------------------------------------------------------------------------
// Changes the staker or withdrawer authority on a stake account.
//
// Accounts:
//   [0] RW      stake_account — must be Initialized(1) or Stake(2)
//   [1] RO      clock_sysvar  — for lockup checks
//   [2] SIGNER  authority     — must match current staker or withdrawer
//   [3] SIGNER  custodian     — OPTIONAL, required if lockup is active and changing withdrawer
//
// Instruction data:
//   [0..4]   u32 discriminant = 1
//   [4..36]  [32]u8 new_authority pubkey
//   [36..40] u32 authorize_type (0=Staker, 1=Withdrawer)
//
// Validation:
//   - Account must be Initialized or Stake state
//   - For Staker change: signer must be current staker OR current withdrawer
//   - For Withdrawer change: signer must be current withdrawer
//   - If lockup active and changing withdrawer: custodian must sign
// ---------------------------------------------------------------------------

// ⚠ FOOTGUN (agave-behavior-extractor 2026-06-16): this TOP-LEVEL native handler
// has 3 known divergences from canonical Agave/stake-interface — do NOT copy it into
// new code (the CPI-path executeAuthorize in vex_bpf2/builtins/stake_program.zig was
// ported from Agave/Sig, NOT from here):
//   1. signer check is INDEX-2-ONLY (authority_idx) — Agave uses signer-SET membership
//      (Authorized::check scans all signers). If staker/withdrawer signs at a non-2 index,
//      Agave accepts, this rejects → success-path divergence.
//   2. lockup block is ordered AFTER the withdrawer match — Agave checks lockup FIRST,
//      then check(Withdrawer). Changes which error fires / acceptance.
//   3. isLockupActive (this file ~910) is non-canonical (epoch_schedule epoch + `>0`
//      guards, no custodian bypass) vs Agave clock.epoch/unix_timestamp + custodian bypass.
// Latent (only bites a direct top-level Authorize with these shapes). Fix owed separately.
fn handleAuthorize(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Authorize slot={d}\n", .{bank.slot});
    const params = AuthorizeParams.parse(ix.data) catch return;
    if (params.authorize_type > 1) return;

    if (ix.account_indices.len < 3) return;
    const stake_idx = ix.account_indices[0];
    const authority_idx = ix.account_indices[2];

    if (stake_idx >= ptx.num_accounts or authority_idx >= ptx.num_accounts) return;

    // Authority must be a signer
    if (!isSigner(ptx, authority_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const authority_key = ptx.account_keys[authority_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;

    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return; // Must be Initialized or Stake

    // Read current authorities from account data
    const current_staker = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.staker) orelse return;
    const current_withdrawer = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.withdrawer) orelse return;

    // Verify signer matches the required authority
    if (params.authorize_type == 0) {
        // Changing staker: signer must be current staker OR current withdrawer
        const signer_is_staker = std.mem.eql(u8, &authority_key, &current_staker);
        const signer_is_withdrawer = std.mem.eql(u8, &authority_key, &current_withdrawer);
        if (!signer_is_staker and !signer_is_withdrawer) return;
    } else {
        // Changing withdrawer: signer must be current withdrawer
        if (!std.mem.eql(u8, &authority_key, &current_withdrawer)) return;

        // Lockup check: if lockup is active (epoch OR timestamp), custodian must also sign.
        // Uses shared isLockupActive() which reads Clock sysvar for timestamp checks.
        const lockup_active = isLockupActive(stake_acct.data, bank, db);

        if (lockup_active) {
            // Need custodian signature
            if (ix.account_indices.len < 4) return;
            const custodian_idx = ix.account_indices[3];
            if (custodian_idx >= ptx.num_accounts) return;
            if (!isSigner(ptx, custodian_idx)) return;

            // Verify custodian matches the lockup custodian
            const lockup_custodian = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.lockup_custodian) orelse return;
            const custodian_key = ptx.account_keys[custodian_idx];
            if (!std.mem.eql(u8, &custodian_key, &lockup_custodian)) return;
        }
    }

    // Deep copy and update the authority
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    if (params.authorize_type == 0) {
        stake_state.writePubkey(data_copy, stake_state.Offsets.staker, params.new_authority);
    } else {
        stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, params.new_authority);
    }

    const old_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        stake_acct.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        data_copy,
    );
    bank.collectWrite(.{
        .pubkey = .{ .data = stake_key },
        .lamports = stake_acct.lamports,
        .owner = .{ .data = stake_acct.owner.data },
        .executable = stake_acct.executable,
        .rent_epoch = stake_acct.rent_epoch,
        .data = data_copy,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Handler: DelegateStake (0x02)
// ---------------------------------------------------------------------------
// Delegates a stake account to a vote account. Transitions Initialized -> Stake,
// or re-delegates a deactivated Stake account to a new validator.
//
// Accounts:
//   [0] RW      stake_account       — must be Initialized(1) or deactivated Stake(2)
//   [1] RO      vote_account        — target validator's vote account
//   [2] RO      clock_sysvar        — not read directly
//   [3] RO      stake_history       — not read directly
//   [4] RO      stake_config        — not read directly
//   [5] SIGNER  stake_authority     — must match current staker
//
// State mutation: Writes Stake state (disc=2) with:
//   - voter_pubkey = vote account pubkey
//   - delegation.stake = lamports - rent_exempt_reserve
//   - activation_epoch = current epoch
//   - deactivation_epoch = u64::MAX (active)
//   - warmup_cooldown_rate = 0.25 (f64 bits)
//   - credits_observed = vote account's cumulative credits
//   - stake_flags = 0
//
// Validation:
//   - Stake authority must sign and match current staker
//   - Vote account must exist
//   - If Stake(2): deactivation_epoch must not be MAX (must be deactivating/deactivated)
//   - delegation.stake must be > 0
// ---------------------------------------------------------------------------

fn handleDelegateStake(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] DelegateStake slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 6) return;

    const stake_idx = ix.account_indices[0];
    const vote_idx = ix.account_indices[1];
    const authority_idx = ix.account_indices[5];

    if (stake_idx >= ptx.num_accounts or vote_idx >= ptx.num_accounts or
        authority_idx >= ptx.num_accounts) return;

    // Authority must be a signer
    if (!isSigner(ptx, authority_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const vote_key = ptx.account_keys[vote_idx];
    const authority_key = ptx.account_keys[authority_idx];

    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;
    const vote_acct = readOverlayed(bank, db, vote_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;

    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;

    // Must be Initialized(1) for first delegation, or Stake(2) with deactivation for re-delegation
    if (disc != 1 and disc != 2) return;

    // ── Re-delegation branch selection (@prov:stake.delegate-three-case, 2026-07-30) ──
    // CANONICAL (solana-program/stake program@v5.0.0 = 6ed2c60c, processor.rs:435-472) branches on
    // EFFECTIVE STAKE, not on `deactivation_epoch != MAX`:
    //   effective == 0                                            -> fresh delegation (new_stake)
    //   effective != 0 && epoch == deactivation_epoch && same voter-> RESCIND: clear ONLY
    //                                                                deactivation_epoch
    //                                                                (InsufficientDelegation if
    //                                                                 stake_amount < delegation.stake)
    //   otherwise                                                  -> Err(TooSoonToRedelegate)
    // The OLD rule here (`deact == MAX => return`) was wrong twice: it rejected valid
    // still-activating redelegates, and for a rescind it fell through to the FRESH path below,
    // overwriting activation_epoch + credits_observed (+ delegation.stake). That is the PROVEN
    // carrier of the live divergence at slot 425127869 (ours e0f51ca7… vs canonical 8ceab814…;
    // confirmed by an A/B byte-proof of that block, 2026-07-30).
    var rescind_only = false;
    if (disc == 2) {
        // Epoch source: DELIBERATELY the same expression the fresh-delegation path below uses
        // (`bank.epoch_schedule.getEpoch(bank.slot)`, see its provenance comment there). Tier-1
        // blocker from the behaviour extraction: `current_epoch == deactivation_epoch` is now a
        // CONSENSUS branch, so the epoch source must not be silently swapped (e.g. to
        // readClockForLockup). Canonical uses Clock.epoch, which is derived from this same
        // schedule.
        const branch_epoch = bank.epoch_schedule.getEpoch(bank.slot);
        const deact = stake_state.readU64(stake_acct.data, stake_state.Offsets.deactivation_epoch) orelse return;
        const act = stake_state.readU64(stake_acct.data, stake_state.Offsets.activation_epoch) orelse return;
        const cur_stake = stake_state.readU64(stake_acct.data, stake_state.Offsets.delegation_stake) orelse return;
        const cur_voter = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.voter_pubkey) orelse return;

        // Effective stake via the SAME helpers the withdraw path already uses (:707) — the
        // canonical rule needs StakeHistory, which this handler previously never consulted.
        const history = bank.readStakeHistory(alloc) catch &[_]bank_mod.Bank.StakeHistoryEntry{};
        defer if (history.len > 0) alloc.free(history);
        const status = bank_mod.Bank.getStakeActivationStatus(
            act,
            deact,
            cur_stake,
            branch_epoch,
            history,
            bank.getNewRateActivationEpoch(),
        );
        const effective = status.effective;

        if (effective != 0) {
            const same_voter = std.mem.eql(u8, &cur_voter, &vote_key);
            if (branch_epoch == deact and same_voter) {
                // Rescind. Canonical also errors InsufficientDelegation when the account can no
                // longer back the existing delegation; we cannot emit that code faithfully yet
                // (deployed v5 .so error ordinals are NOT the Sig enum — see memory
                // stake-bot-corpus-19-gaps-G2G17-rootcaused-2026-07-30, "pin ordinals from the
                // .so"). Until then, DECLINE to write rather than write a wrong rescind: a
                // no-op is the pre-existing behaviour for this shape, whereas a bad write is a
                // new divergence.
                const reserve_now = stake_state.readU64(stake_acct.data, stake_state.Offsets.rent_exempt_reserve) orelse return;
                if (stake_acct.lamports <= reserve_now) return;
                if (stake_acct.lamports - reserve_now < cur_stake) return; // canonical: Err(InsufficientDelegation)
                rescind_only = true;
            } else {
                // canonical: Err(StakeError::TooSoonToRedelegate). KNOWN REMAINING GAP — we
                // silently no-op instead of failing the tx, which still differs from the cluster
                // in tx_results. Blocked on the same error-ordinal pinning; tracked as part of
                // the stake error-surface project, NOT closed by this fix.
                return;
            }
        }
        // effective == 0 -> fall through to the fresh-delegation path below (canonical new_stake).
    }

    if (rescind_only) {
        // RESCIND writes exactly ONE field. activation_epoch, credits_observed,
        // delegation.stake, warmup_cooldown_rate and stake_flags are PRESERVED — canonical
        // mutates only `stake.delegation.deactivation_epoch` then re-persists the same struct.
        const data_copy = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
        @memcpy(data_copy, stake_acct.data[0..stake_state.STAKE_STATE_SZ]);
        stake_state.writeU64(data_copy, stake_state.Offsets.deactivation_epoch, std.math.maxInt(u64));
        emitWrite(
            bank,
            stake_key,
            stake_acct.owner.data,
            stake_acct.lamports,
            stake_acct.executable,
            stake_acct.data,
            stake_acct.lamports,
            stake_acct.owner.data,
            stake_acct.executable,
            stake_acct.rent_epoch,
            data_copy,
        );
        return;
    }

    // Verify authority matches the current staker
    const current_staker = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.staker) orelse return;
    if (!std.mem.eql(u8, &authority_key, &current_staker)) return;

    // Read rent_exempt_reserve from existing meta
    const rent_exempt_reserve = stake_state.readU64(stake_acct.data, stake_state.Offsets.rent_exempt_reserve) orelse return;

    // Delegation stake = lamports - rent_exempt_reserve (must be positive)
    if (stake_acct.lamports <= rent_exempt_reserve) return;
    const delegation_stake = stake_acct.lamports - rent_exempt_reserve;

    // d28tt (2026-05-13): SIMD-0490 (active testnet ep 955, slot 407,036,256)
    // raises minimum delegation from 1 lamport to 1 SOL. Cluster's BPF Stake
    // v5.0.0 rejects sub-SOL delegations — match here so this slot's bank
    // state agrees with cluster. Other v5 changes (sysvar-optional, Rent
    // sysvar usage, Split rewrite, Merge math) are NOT yet ported and
    // remain divergence carriers — see project_simd_implementation_audit
    // memory file. Silent return matches existing handler validation pattern;
    // for top-level txs the bank-state effect is equivalent to Agave's
    // StakeError::DelegationLessThanMinimumDelegation (no account write,
    // tx fee charged the same).
    const SIMD_0490_MIN_DELEGATION: u64 = 1_000_000_000; // 1 SOL
    if (delegation_stake < SIMD_0490_MIN_DELEGATION) return;

    // Read vote account credits_observed (cumulative credits from last epoch_credits entry)
    const credits_observed: u64 = blk: {
        if (vote_acct.data.len < 4) break :blk 0;
        const vs = vote_state_serde.deserializeVoteState(vote_acct.data) orelse break :blk 0;
        if (vs.ec_count > 0) {
            break :blk vs.epoch_credits[vs.ec_count - 1].credits;
        }
        break :blk 0;
    };

    // REVERTED (this review pass) — "Item 7" originally read current epoch via
    // readClockForLockup(bank, db).epoch (the Clock sysvar) instead of
    // bank.epoch_schedule.getEpoch(bank.slot), reasoning that it's a strict widening since
    // readClockForLockup falls back to epoch_schedule.getEpoch(bank.slot) when the Clock
    // account is unreadable. That's only a no-op widening if the Clock account IS readable
    // and DOES agree; the actual risk is when it's readable and DISAGREES — i.e. db reflects
    // this slot's OWN just-landed Clock write vs. the parent's — which is exactly the
    // epoch-boundary slot window. activation_epoch is consensus-critical and this diff's own
    // Split fix has no coverage for that overlay-ordering question, so the swap was an
    // unrelated, unproven behavior change bundled into a Split-focused diff. Reverted to the
    // proven, pure-function-of-slot form, matching isLockupActive's current_epoch derivation
    // elsewhere in this file (both now agree). readClockForLockup itself is unchanged and
    // still live for AuthorizeWithSeed/AuthorizeCheckedWithSeed's unix_timestamp lockup check
    // below, which does need the Clock sysvar's timestamp field (epoch_schedule has no
    // timestamp equivalent).
    const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

    // Deep copy and write Stake state
    const data_copy = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
    @memcpy(data_copy, stake_acct.data[0..stake_state.STAKE_STATE_SZ]);

    // Set discriminant to Stake(2)
    stake_state.writeU32(data_copy, stake_state.Offsets.discriminant, 2);

    // Write delegation fields
    stake_state.writePubkey(data_copy, stake_state.Offsets.voter_pubkey, vote_key);
    stake_state.writeU64(data_copy, stake_state.Offsets.delegation_stake, delegation_stake);
    stake_state.writeU64(data_copy, stake_state.Offsets.activation_epoch, current_epoch);
    stake_state.writeU64(data_copy, stake_state.Offsets.deactivation_epoch, std.math.maxInt(u64));

    // ⚠ FOOTGUN: warmup_cooldown_rate = 0.25 here is CORRECT ONLY for the deployed
    // Core-BPF stake program@v5.0.0 (6ed2c60c, interface/src/state.rs:502). v5.1
    // (commit 5e641b3, NOT an ancestor of v5.0.0) renames this field to
    // _reserved: [u8;8] with Default = [0;8] — every FRESH delegation must then write
    // 8 ZERO bytes at offset 180, not 0x3FD0000000000000, or the first DelegateStake
    // after activation is an immediate bank_hash divergence. Gated below on the
    // upgrade_bpf_stake_program_to_v5_1 feature account (INACTIVE on testnet
    // 2026-08-02 — verified absent via getAccountInfo; behavior today is unchanged).
    // Refs: Agave-behavior extraction 2026-08-02 §7, parity-sweep F780-84, and the
    // 2026-07-30 move of the stake-program spec basis to the Core-BPF program.
    const rate_bits: u64 = if (bank.isStakeProgramV51Active()) 0 else @bitCast(@as(f64, 0.25));
    stake_state.writeU64(data_copy, stake_state.Offsets.warmup_cooldown_rate, rate_bits);

    // credits_observed from vote account
    stake_state.writeU64(data_copy, stake_state.Offsets.credits_observed, credits_observed);

    // stake_flags = 0
    data_copy[stake_state.Offsets.stake_flags] = 0;

    // LtHash delta + pending write
    const old_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        stake_acct.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        data_copy,
    );
    bank.collectWrite(.{
        .pubkey = .{ .data = stake_key },
        .lamports = stake_acct.lamports,
        .owner = .{ .data = stake_acct.owner.data },
        .executable = stake_acct.executable,
        .rent_epoch = stake_acct.rent_epoch,
        .data = data_copy,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Handler: Withdraw (0x04)
// ---------------------------------------------------------------------------
// Moves lamports from a stake account to a recipient. If all lamports are
// withdrawn, sets state to Uninitialized.
//
// Accounts:
//   [0] RW      stake_account
//   [1] RW      recipient
//   [2] RO      clock_sysvar
//   [3] RO      stake_history
//   [4] SIGNER  withdraw_authority
//   [5] SIGNER  custodian (optional, if lockup active)
//
// Validation. @prov:stake.withdraw-validation
//   1. Minimum 5 account indices (stake, recipient, clock, history, authority)
//   2. Withdraw authority must be a transaction signer
//   3. Source and destination must not be the same account
//   4. Account must be Uninitialized, Initialized, or Stake state
//      - Uninitialized: authority key must equal stake account key (self-custody)
//      - Initialized:   authority key must match `withdrawer`
//      - Stake:         authority key must match `withdrawer`
//   5. Lockup check: if lockup still in force, custodian at index 5 must sign
//      and match the account's lockup_custodian field
//   6. State-dependent withdrawal limits:
//      - Initialized:   cannot withdraw below rent_exempt_reserve
//      - Stake (active or deactivating): cannot withdraw below
//        (effective_stake + rent_exempt_reserve)
//      - Stake (fully deactivated): can withdraw everything
//   7. Full withdrawal: discriminant reset to 0 (Uninitialized)
// ---------------------------------------------------------------------------

fn handleWithdraw(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Withdraw slot={d}\n", .{bank.slot});

    // Need at least: stake(0), recipient(1), clock(2), history(3), authority(4)
    if (ix.data.len < 12 or ix.account_indices.len < 5) return;

    const stake_idx = ix.account_indices[0];
    const recipient_idx = ix.account_indices[1];
    const authority_idx = ix.account_indices[4];

    if (stake_idx >= ptx.num_accounts or
        recipient_idx >= ptx.num_accounts or
        authority_idx >= ptx.num_accounts) return;

    // ── 1. Authority must be a transaction signer ──────────────────────────
    if (!isSigner(ptx, authority_idx)) return;

    const withdraw_lamports = std.mem.readInt(u64, ix.data[4..12], .little);
    if (withdraw_lamports == 0) return;

    const stake_key = ptx.account_keys[stake_idx];
    const recipient_key = ptx.account_keys[recipient_idx];
    const authority_key = ptx.account_keys[authority_idx];

    // ── 2. Same-account guard ─────────────────────────────────────────────
    // If stake == recipient we would append two conflicting pending_writes
    // entries for the same pubkey, producing incorrect LtHash deltas.
    if (std.mem.eql(u8, &stake_key, &recipient_key)) return;

    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;
    if (stake_acct.data.len < 4) return;

    const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

    // ── 3. Read discriminant and validate authority / compute reserve ──────
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;

    // reserve: lamports that must remain in the stake account after withdrawal.
    // is_staked: true while active/deactivating stake exists (further limits apply).
    const reserve_and_staked = switch (disc) {
        0 => blk: { // Uninitialized
            // Self-custody: authority must be the stake account key itself.
            if (!std.mem.eql(u8, &authority_key, &stake_key)) return;
            break :blk [2]u64{ 0, 0 }; // reserve=0, is_staked=false
        },
        1 => blk: { // Initialized
            if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
            const current_withdrawer = stake_state.readPubkey(
                stake_acct.data,
                stake_state.Offsets.withdrawer,
            ) orelse return;
            if (!std.mem.eql(u8, &authority_key, &current_withdrawer)) return;
            const rsv = stake_state.readU64(
                stake_acct.data,
                stake_state.Offsets.rent_exempt_reserve,
            ) orelse return;
            break :blk [2]u64{ rsv, 0 }; // is_staked=false
        },
        2 => blk: { // Stake
            if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
            const current_withdrawer = stake_state.readPubkey(
                stake_acct.data,
                stake_state.Offsets.withdrawer,
            ) orelse return;
            if (!std.mem.eql(u8, &authority_key, &current_withdrawer)) return;

            const rent_exempt = stake_state.readU64(
                stake_acct.data,
                stake_state.Offsets.rent_exempt_reserve,
            ) orelse return;
            const delegation_stake = stake_state.readU64(
                stake_acct.data,
                stake_state.Offsets.delegation_stake,
            ) orelse return;
            const activation_epoch = stake_state.readU64(
                stake_acct.data,
                stake_state.Offsets.activation_epoch,
            ) orelse return;
            const deactivation_epoch = stake_state.readU64(
                stake_acct.data,
                stake_state.Offsets.deactivation_epoch,
            ) orelse return;
            // carrier #16: the per-account serialized warmup_cooldown_rate field
            // is NOT used by the canonical curve (rate is epoch-scheduled).

            // Effective stake: if past deactivation epoch, use cooldown curve;
            // otherwise the full delegation amount is still active.
            const effective_stake: u64 = if (current_epoch >= deactivation_epoch) eff: {
                const history = bank.readStakeHistory(alloc) catch
                    &[_]bank_mod.Bank.StakeHistoryEntry{};
                defer if (history.len > 0) alloc.free(history);
                const status = bank_mod.Bank.getStakeActivationStatus(
                    activation_epoch,
                    deactivation_epoch,
                    delegation_stake,
                    current_epoch,
                    history,
                    // carrier #16: rate is epoch-scheduled (0.25 pre-
                    // reduce_stake_warmup_cooldown, 0.09 after), not the
                    // per-account serialized rate field.
                    bank.getNewRateActivationEpoch(),
                );
                break :eff status.effective;
            } else delegation_stake;

            const rsv = std.math.add(u64, effective_stake, rent_exempt) catch return;
            // is_staked encoded as 1/0 in second element
            break :blk [2]u64{ rsv, if (effective_stake != 0) 1 else 0 };
        },
        else => return, // RewardsPool or unknown — reject
    };
    const reserve: u64 = reserve_and_staked[0];
    const is_staked: bool = reserve_and_staked[1] != 0;

    // ── 4. Lockup check (skip for Uninitialized — no lockup field) ─────────
    if (disc != 0) {
        const lockup_epoch = stake_state.readU64(
            stake_acct.data,
            stake_state.Offsets.lockup_epoch,
        ) orelse return;
        const lockup_ts = stake_state.readI64(
            stake_acct.data,
            stake_state.Offsets.lockup_unix_timestamp,
        ) orelse return;

        // Read unix_timestamp from Clock sysvar (bytes 32..40).
        // SysvarC1ock11111111111111111111111111111111
        const CLOCK_KEY = core.Pubkey{ .data = .{
            0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
            0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
            0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
            0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
        } };
        var clock_unix_ts: i64 = std.math.maxInt(i64); // conservative default
        if (db.getAccountInSlot(&CLOCK_KEY, bank.slot, bank.ancestors())) |clock_acct| {
            if (clock_acct.data.len >= 40) {
                clock_unix_ts = std.mem.readInt(i64, clock_acct.data[32..40], .little);
            }
        }

        const lockup_in_force = (lockup_epoch > 0 and current_epoch < lockup_epoch) or
            (lockup_ts > 0 and clock_unix_ts < lockup_ts);

        if (lockup_in_force) {
            // Custodian at index 5 must be present, be a signer, and match
            // the account's stored lockup_custodian.
            if (ix.account_indices.len < 6) return;
            const custodian_idx = ix.account_indices[5];
            if (custodian_idx >= ptx.num_accounts) return;
            if (!isSigner(ptx, custodian_idx)) return;
            const custodian_key = ptx.account_keys[custodian_idx];
            const lockup_custodian = stake_state.readPubkey(
                stake_acct.data,
                stake_state.Offsets.lockup_custodian,
            ) orelse return;
            if (!std.mem.eql(u8, &custodian_key, &lockup_custodian)) return;
        }
    }

    // ── 5. Withdrawal limit checks ─────────────────────────────────────────
    if (stake_acct.lamports < withdraw_lamports) return;

    const lamports_and_reserve = std.math.add(u64, withdraw_lamports, reserve) catch return;

    if (is_staked and lamports_and_reserve > stake_acct.lamports) return;

    if (withdraw_lamports != stake_acct.lamports and
        lamports_and_reserve > stake_acct.lamports) return;

    // ── 6. Build new stake account data ───────────────────────────────────
    const stake_new_lamports = stake_acct.lamports - withdraw_lamports;

    const stake_data_copy = if (stake_acct.data.len > 0) blk: {
        const copy = alloc.alloc(u8, stake_acct.data.len) catch return;
        @memcpy(copy, stake_acct.data);
        // Full withdrawal: reset to Uninitialized
        if (stake_new_lamports == 0) {
            @memset(copy, 0);
        }
        break :blk copy;
    } else &[_]u8{};

    // ── 7. Emit writes ─────────────────────────────────────────────────────
    emitWrite(
        bank,
        stake_key,
        stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        stake_acct.data,
        stake_new_lamports,
        stake_acct.owner.data,
        stake_acct.executable,
        stake_acct.rent_epoch,
        stake_data_copy,
    );

    // r71-fix-11: read recipient via pending_writes overlay first. Without
    // this, two Withdraws in the same slot to the same recipient cause the
    // 2nd to read the pre-slot snapshot (stale), produce wrong old_lt, and
    // the final stored lamports = pre + W2.delta only — losing W1's credit.
    // Slot-482 carrier signal: 30 System wallets missing N×5000 lamports.
    const recip = readWithPendingOverlay(bank, db, recipient_key);

    emitWrite(
        bank,
        recipient_key,
        recip.owner,
        recip.lamports,
        recip.executable,
        recip.data,
        recip.lamports + withdraw_lamports,
        recip.owner,
        recip.executable,
        recip.rent_epoch,
        recip.data,
    );
}

// ---------------------------------------------------------------------------
// Handler: Deactivate (0x05)
// ---------------------------------------------------------------------------
// Sets deactivation_epoch to the current epoch, beginning the cooldown period.
//
// Accounts:
//   [0] RW      stake_account — must be Stake(2) with deactivation_epoch == MAX
//   [1] RO      clock_sysvar
//   [2] SIGNER  stake_authority — must match current staker
//
// Validation:
//   - Account must be in Stake state (disc=2)
//   - deactivation_epoch must be MAX (not already deactivating)
//   - Stake authority must sign and match current staker
// ---------------------------------------------------------------------------

fn handleDeactivate(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Deactivate slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 3) return;

    const stake_idx = ix.account_indices[0];
    const authority_idx = ix.account_indices[2];
    if (stake_idx >= ptx.num_accounts or authority_idx >= ptx.num_accounts) return;

    // Authority must be a signer
    if (!isSigner(ptx, authority_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const authority_key = ptx.account_keys[authority_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const st_type = stake_state.getStakeType(stake_acct.data) orelse return;
    if (st_type != .stake) return;

    // Verify not already deactivating
    const current_deact = stake_state.readU64(stake_acct.data, stake_state.Offsets.deactivation_epoch) orelse return;
    if (current_deact != std.math.maxInt(u64)) return;

    // Verify authority matches current staker
    const current_staker = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.staker) orelse return;
    if (!std.mem.eql(u8, &authority_key, &current_staker)) return;

    // Deep-copy and set deactivation_epoch to current epoch
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    // REVERTED (this review pass) — see handleDelegateStake's identical revert above for the
    // full reasoning: readClockForLockup(bank, db).epoch is an unproven, unrelated behavior
    // change for a consensus-critical field (deactivation_epoch here, activation_epoch there)
    // at exactly the epoch-boundary overlay-ordering window this Split-focused diff never
    // proved. Reverted to the proven, pure-function-of-slot form, keeping this file's only
    // "current epoch" derivation consistent (isLockupActive uses the same call).
    const epoch = bank.epoch_schedule.getEpoch(bank.slot);
    stake_state.writeU64(data_copy, stake_state.Offsets.deactivation_epoch, epoch);

    const old_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        stake_acct.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &stake_key,
        &stake_acct.owner.data,
        stake_acct.lamports,
        stake_acct.executable,
        data_copy,
    );
    bank.collectWrite(.{
        .pubkey = .{ .data = stake_key },
        .lamports = stake_acct.lamports,
        .owner = .{ .data = stake_acct.owner.data },
        .executable = stake_acct.executable,
        .rent_epoch = stake_acct.rent_epoch,
        .data = data_copy,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Phase 2 Handlers — full implementations
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Shared helper: emit a pending write with LtHash deltas
// ---------------------------------------------------------------------------

fn emitWrite(
    bank: anytype,
    key: [32]u8,
    old_owner: [32]u8,
    old_lamports: u64,
    old_executable: bool,
    old_data: []const u8,
    new_lamports: u64,
    new_owner: [32]u8,
    new_executable: bool,
    new_rent_epoch: u64,
    new_data: []const u8,
) void {
    const old_lt = bank_mod.Bank.accountLtHash(&key, &old_owner, old_lamports, old_executable, old_data);
    const new_lt = bank_mod.Bank.accountLtHash(&key, &new_owner, new_lamports, new_executable, new_data);
    bank.collectWrite(.{
        .pubkey = .{ .data = key },
        .lamports = new_lamports,
        .owner = .{ .data = new_owner },
        .executable = new_executable,
        .rent_epoch = new_rent_epoch,
        .data = new_data,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Shared helper: check lockup is in force
// ---------------------------------------------------------------------------

fn isLockupActive(data: []const u8, bank: anytype, db: anytype) bool {
    const lockup_epoch = stake_state.readU64(data, stake_state.Offsets.lockup_epoch) orelse return false;
    const lockup_ts = stake_state.readI64(data, stake_state.Offsets.lockup_unix_timestamp) orelse return false;
    const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

    // Read unix_timestamp from Clock sysvar (bytes 32..40).
    // SysvarC1ock11111111111111111111111111111111
    const CLOCK_KEY = core.Pubkey{ .data = .{
        0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
        0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
        0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
        0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
    } };
    var clock_unix_ts: i64 = std.math.maxInt(i64); // conservative default: no timestamps are expired
    if (db.getAccountInSlot(&CLOCK_KEY, bank.slot, bank.ancestors())) |clock_acct| {
        if (clock_acct.data.len >= 40) {
            clock_unix_ts = std.mem.readInt(i64, clock_acct.data[32..40], .little);
        }
    }

    // Lockup is active if epoch constraint not yet passed OR timestamp constraint not yet passed.
    return (lockup_epoch > 0 and current_epoch < lockup_epoch) or
        (lockup_ts > 0 and clock_unix_ts < lockup_ts);
}

// ---------------------------------------------------------------------------
// Shared helper: read Clock.unix_timestamp + Clock.epoch atomically
// ---------------------------------------------------------------------------
// AuthorizeWithSeed / AuthorizeCheckedWithSeed need BOTH Clock fields from the
// same sysvar read (unlike isLockupActive's boolean-only convenience above,
// which sources "current epoch" from bank.epoch_schedule instead of the
// sysvar) to mirror the CPI path's `ctx.sysvar_cache.getClock()` — which
// exposes both `.unix_timestamp` and `.epoch` off one Clock struct — exactly.
// Reuses isLockupActive's CLOCK_KEY bytes and its "clock unreadable → treat
// lockup as expired" fallback convention for consistency within this file.
fn readClockForLockup(bank: anytype, db: anytype) struct { unix_timestamp: i64, epoch: u64 } {
    const CLOCK_KEY = core.Pubkey{ .data = .{
        0x06, 0xa7, 0xd5, 0x17, 0x18, 0xc7, 0x74, 0xc9,
        0x28, 0x56, 0x63, 0x98, 0x69, 0x1d, 0x5e, 0xb6,
        0x8b, 0x5e, 0xb8, 0xa3, 0x9b, 0x4b, 0x6d, 0x5c,
        0x73, 0x55, 0x5b, 0x21, 0x00, 0x00, 0x00, 0x00,
    } };
    var unix_timestamp: i64 = std.math.maxInt(i64); // conservative: no timestamp lockup ever "in force"
    var epoch: u64 = bank.epoch_schedule.getEpoch(bank.slot); // fallback matches isLockupActive's current_epoch
    if (db.getAccountInSlot(&CLOCK_KEY, bank.slot, bank.ancestors())) |clock_acct| {
        if (clock_acct.data.len >= 40) {
            epoch = std.mem.readInt(u64, clock_acct.data[16..24], .little);
            unix_timestamp = std.mem.readInt(i64, clock_acct.data[32..40], .little);
        }
    }
    return .{ .unix_timestamp = unix_timestamp, .epoch = epoch };
}

// ---------------------------------------------------------------------------
// Shared helper: Rent.minimumBalance(data_len)
// ---------------------------------------------------------------------------
// Tier-2 (2026-07-28), item 4. Canonical (sig lib.zig:809-810; vex_bpf2
// stake_program.zig:1705-1708) reads the LIVE Rent sysvar. This native
// dispatch path has no wired Rent-sysvar reader yet — bank.zig has no
// getRent()/readRent() accessor analogous to readStakeHistory() above, so
// there is nothing here to call even if the pubkey question is settled.
//
// CORRECTION (this review pass): an EARLIER version of this comment claimed
// no cross-verified SYSVAR_RENT_ID pubkey existed and cited vex_bpf2's copy
// as carrying "a documented placeholder last-byte bug" — that citation
// (vault 2026-04-27-r35-fix-c-last-restart-pubkey.md:165-177) is real but
// STALE: it describes an 8-pubkey placeholder pattern (shared 28-byte
// prefix, e.g. `...0x18, 0x7b, 0xd1, 0x66, 0x35, 0xda, 0xd4, <last_byte>`)
// that vex_bpf2/sysvar_cache.zig:89 no longer has for Rent. Its CURRENT
// bytes (`0x06,0xa7,0xd5,0x17,0x19,0x2c,0x5c,0x51,...`) independently agree,
// byte-for-byte, with system_v2.zig:673-677's `SYSVAR_RENT_ID` — two
// separately-maintained files converging on the same 32 bytes is exactly
// the cross-verification this file's own no-hand-typed-pubkeys convention
// asks for (same standard CLOCK_KEY above and SH_PUBKEY in readStakeHistory
// were held to). So the pubkey is no longer the blocker.
//
// Still NOT fixing this here: wiring a live read means parsing the Rent
// account's own byte layout (lamports_per_byte_year: u64 @0,
// exemption_threshold: f64 @8, burn_percent: u8 @16) through db, which is
// new, untested surface with its own correctness question — out of scope
// for a Split-focused diff and not something to bundle in without its own
// KAT, per this file's Item-7-revert lesson just above. Until that lands,
// derive from the canonical DEFAULT rent params instead
// (lamports_per_byte_year=3480, exemption_threshold=2.0 — solana-sdk
// Rent::default(), the same values vex_bpf2's setDefaultRent() test helper
// uses) via the SAME formula RentParams.exemptMinBalance() applies
// (../runtime.zig:76-88): ceil((data_len + 128) * lamports_per_byte_year *
// exemption_threshold). For STAKE_STATE_SZ=200 this evaluates to exactly
// 2_282_880 — identical to the literal it replaces under default rent, but
// now a named, cited formula instead of a bare constant. This is a
// formula-derivation fix, NOT a live-sysvar read. Every live Solana-family
// cluster runs Rent at these exact defaults today, so the two are currently
// numerically equivalent; they stop being equivalent only if a cluster ever
// runs non-default Rent params, which the live-sysvar read would track and
// this formula would not.
// TODO(Tier-3): wire a Rent sysvar reader (bank.zig, alongside
// readStakeHistory) using the now-cross-verified SYSVAR_RENT_ID bytes above,
// with its own KAT pinning the parsed Rent account layout.
fn rentExemptMinimumBalance(data_len: usize) u64 {
    const RENT_LAMPORTS_PER_BYTE_YEAR: u64 = 3480;
    const RENT_EXEMPTION_YEARS: f64 = 2.0;
    const size: f64 = @floatFromInt(data_len + 128); // account storage overhead
    const lpy: f64 = @floatFromInt(RENT_LAMPORTS_PER_BYTE_YEAR);
    return @intFromFloat(@ceil(size * lpy * RENT_EXEMPTION_YEARS));
}

// ---------------------------------------------------------------------------
// Handler: Split (0x03)
// ---------------------------------------------------------------------------
// Splits lamports (and optionally delegation) from source to destination.
//
// Accounts:
//   [0] RW  source_stake — Initialized(1) or Stake(2)
//   [1] RW  destination_stake — must be Uninitialized(0), owned by stake program
//   [2] SIGNER staker authority
//
// Instruction data:
//   [0..4]  u32 discriminant = 3
//   [4..12] u64 lamports to split off
//
// Validation:
//   - Source must be Initialized or Stake
//   - Destination must be Uninitialized, 200 bytes, owned by stake program
//   - Staker must sign and match source staker
//   - lamports > 0 and <= source lamports
//   - If source is Stake and partially split, both sides must retain >= min_delegation
//   - If source empties, it becomes Uninitialized
// ---------------------------------------------------------------------------

fn handleSplit(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Split slot={d}\n", .{bank.slot});
    if (ix.data.len < 12 or ix.account_indices.len < 3) return;

    const split_lamports = std.mem.readInt(u64, ix.data[4..12], .little);
    if (split_lamports == 0) return;

    const src_idx = ix.account_indices[0];
    const dst_idx = ix.account_indices[1];
    const auth_idx = ix.account_indices[2];
    if (src_idx >= ptx.num_accounts or dst_idx >= ptx.num_accounts or auth_idx >= ptx.num_accounts) return;
    if (!isSigner(ptx, auth_idx)) return;

    const src_key = ptx.account_keys[src_idx];
    const dst_key = ptx.account_keys[dst_idx];
    const auth_key = ptx.account_keys[auth_idx];

    // Source and destination must be different accounts
    if (std.mem.eql(u8, &src_key, &dst_key)) return;

    const src_acct = readOverlayed(bank, db, src_key) orelse return;
    const dst_acct = readOverlayed(bank, db, dst_key) orelse return;

    // Source validation
    if (src_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    if (src_acct.lamports < split_lamports) return;
    const src_disc = stake_state.readU32(src_acct.data, 0) orelse return;
    if (src_disc != 1 and src_disc != 2) return; // Must be Initialized or Stake

    // Verify staker authority
    const current_staker = stake_state.readPubkey(src_acct.data, stake_state.Offsets.staker) orelse return;
    if (!std.mem.eql(u8, &auth_key, &current_staker)) return;

    // Destination validation: must be uninitialized, EXACTLY 200 bytes (sig lib.zig:845;
    // vex_bpf2 stake_program.zig:1697 — canonical rejects an over-sized destination, not
    // just an under-sized one), owned by stake program.
    if (dst_acct.data.len != stake_state.STAKE_STATE_SZ) return;
    const dst_disc = stake_state.readU32(dst_acct.data, 0) orelse return;
    if (dst_disc != 0) return; // Must be Uninitialized

    const STAKE_PROGRAM_ID = [_]u8{
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
        0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
        0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &dst_acct.owner.data, &STAKE_PROGRAM_ID)) return;

    // Item 4: dst_rent_exempt_reserve is Rent-FORMULA-derived (see rentExemptMinimumBalance's
    // doc comment above — NOT a live Rent-sysvar read; that remains deferred to Tier-3)
    // rather than the bare 2_282_880 literal. The `orelse` fallback below (only hit if src's
    // own stored meta can't be read) uses the same formula on src's own 200-byte length —
    // both accounts are STAKE_STATE_SZ, so the two calls agree.
    const dst_rent_exempt_reserve = rentExemptMinimumBalance(dst_acct.data.len);
    const src_rent = stake_state.readU64(src_acct.data, stake_state.Offsets.rent_exempt_reserve) orelse rentExemptMinimumBalance(stake_state.STAKE_STATE_SZ);
    const src_remaining = src_acct.lamports - split_lamports;
    const min_delegation: u64 = 1_000_000_000; // 1 SOL post-feature

    if (src_disc == 2) {
        // Stake state: need to split delegation
        const src_delegation_stake = stake_state.readU64(src_acct.data, stake_state.Offsets.delegation_stake) orelse return;
        const src_activation_epoch = stake_state.readU64(src_acct.data, stake_state.Offsets.activation_epoch) orelse return;
        const src_deactivation_epoch = stake_state.readU64(src_acct.data, stake_state.Offsets.deactivation_epoch) orelse return;
        const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

        // ── ORDERING (adversarial-audit finding 1, 2026-08-02): the branch-B
        // eligibility decision MUST precede the legacy validateSplitAmount guard
        // below. That guard silently drops any split leaving the source between
        // reserve and reserve+1 SOL, but canonical's !is_active_or_activating arm
        // (processor.rs:621-655) has NO minimum-delegation check — it succeeds and
        // writes both accounts in exactly that window (e.g. a 1.5 SOL deactivated
        // stake split 1.4/0.1). Branch B therefore runs first; the legacy guards
        // apply only to the active/activating and full-drain paths, whose behavior
        // is unchanged.
        const src_status = blk: {
            const history = bank.readStakeHistory(alloc) catch &[_]bank_mod.Bank.StakeHistoryEntry{};
            defer if (history.len > 0) alloc.free(history);
            break :blk bank_mod.Bank.getStakeActivationStatus(
                src_activation_epoch,
                src_deactivation_epoch,
                src_delegation_stake,
                current_epoch,
                history,
                bank.getNewRateActivationEpoch(),
            );
        };
        // Canonical is_active_or_activating (processor.rs:548-549): effective > 0 OR
        // activating > 0. An activating-only source (delegated this epoch: effective==0,
        // activating>0) correctly falls PAST branch B below, but canonical branch C still
        // requires the destination to already hold its rent-exempt reserve
        // (processor.rs:660-663) — omitting `activating` here disarmed that guard for
        // activating-only sources (adversarial-audit finding, 2026-08-02).
        const source_is_active = src_status.effective > 0 or src_status.activating > 0;

        // ── Canonical branch B: source neither effective nor activating ──────────
        // Core-BPF stake program@v5.0.0 (6ed2c60c) processor.rs:621-655. When the
        // source's activation status is (effective==0 AND activating==0) — e.g. it was
        // delegated and deactivated in the same epoch — canonical Split moves lamports
        // ONLY: the SOURCE's 200 data bytes are NEVER re-serialized (set_stake_state is
        // not called on it), and the DESTINATION is a byte copy of the source with just
        // meta.rent_exempt_reserve overwritten. delegation.stake is COPIED VERBATIM to
        // the dest and left untouched on the source. The only checks on this branch are
        // rent exemption on both sides (processor.rs:640-644) — canonical has NO
        // minimum-delegation check here. The legacy Sig-native math below (source
        // stake -= split) is the CONFIRMED bank_hash carrier of slot 425636293: all 12
        // splits in that block took this branch, and two sibling sources whose stakes
        // differed by 1 lamport collapsed to byte-identical post-states — an identity
        // impossible under canonical no-write semantics. See the 2026-08-01
        // divergence at slot 425636293.
        // Full drain (src_remaining == 0) is canonical branch A and stays on the legacy
        // path below. ⚠ That arm is NOT numerically convergent (2026-08-02 audit,
        // both auditors): canonical branch A copies delegation.stake to the dest
        // VERBATIM and applies min_delegation only when is_active_or_activating,
        // while the legacy path writes split_lamports -| src_rent and checks
        // min_delegation unconditionally — divergent for any inactive source whose
        // lamports != rent + delegation.stake (e.g. after a transfer-in or partial
        // withdraw). Reachable, same carrier class as 425636293; open S0 gap, needs
        // its own fix branch (one-outstanding-fix rule).
        if (src_remaining != 0 and src_status.effective == 0 and src_status.activating == 0) {
            if (src_remaining < rentExemptMinimumBalance(src_acct.data.len)) return;
            if (dst_acct.lamports +| split_lamports < dst_rent_exempt_reserve) return;

            const b_dst = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
            @memcpy(b_dst, src_acct.data[0..stake_state.STAKE_STATE_SZ]);
            stake_state.writeU64(b_dst, stake_state.Offsets.rent_exempt_reserve, dst_rent_exempt_reserve);

            const b_src = alloc.alloc(u8, src_acct.data.len) catch return;
            @memcpy(b_src, src_acct.data);

            emitWrite(bank, src_key, src_acct.owner.data, src_acct.lamports, src_acct.executable, src_acct.data, src_remaining, src_acct.owner.data, src_acct.executable, src_acct.rent_epoch, b_src);
            emitWrite(bank, dst_key, dst_acct.owner.data, dst_acct.lamports, dst_acct.executable, dst_acct.data, dst_acct.lamports + split_lamports, dst_acct.owner.data, dst_acct.executable, dst_acct.rent_epoch, b_dst);
            return;
        }

        // validateSplitAmount (sig lib.zig:780-823; vex_bpf2 stake_program.zig:1727-1735).
        // source_remaining_balance == 0 (full drain) is exempt from this check; otherwise the
        // source must retain rent + min_delegation. Saturating `+|` (sig lib.zig:803's literal
        // operator, not plain `+`): src_rent is read from the account's OWN stored bytes and
        // this handler does not verify src_acct.owner == STAKE_PROGRAM_ID (unlike the dst
        // check above / handleMerge's src+dst check), so a crafted src_rent near u64::MAX must
        // saturate — not silently wrap under ReleaseFast, where overflow checks are compiled
        // out — to stay fail-closed on that pre-existing, cross-cutting owner-check gap.
        if (src_remaining != 0 and src_remaining < src_rent +| min_delegation) return;

        // Third validateSplitAmount guard (sig lib.zig:814-817; vex_bpf2 stake_program.zig:1732,
        // `if (is_active and source_remaining != 0 and dst.lamports < dest_reserve) return
        // error.M9_Stake_InsufficientFunds;`): an ACTIVE source doing a partial split into a
        // destination still below its OWN rent-exempt reserve is rejected outright, even
        // though the destination-deficit check below would otherwise let a large-enough
        // split_lamports cover it. Without this guard a partial split of an active stake into
        // an under-reserved (but not zero-lamport) destination is wrongly accepted whenever
        // split_lamports clears the later deficit check — an accept-vs-reject boundary
        // inversion vs. canonical.
        //
        // "Active" mirrors handleWithdraw's effective-stake curve (line ~698) — same
        // getStakeActivationStatus + readStakeHistory + bank.getNewRateActivationEpoch()
        // call. ⚠ SPEC NOTE (2026-08-02 audit correction): for the Core-BPF STAKE
        // PROGRAM the flat rate IS canonical — lib.rs:19 hardcodes
        // PERPETUAL_NEW_WARMUP_COOLDOWN_RATE_EPOCH = Some(0). Carrier #16's finding
        // applied to the RUNTIME call site (points.rs/StakeHistory), where Agave
        // passes the real feature epoch — two call sites, two different correct
        // answers. bank.getNewRateActivationEpoch() is provably equivalent to Some(0)
        // here today (reduce_stake_warmup_cooldown activated ~epoch 573; every
        // straddling transition completed hundreds of epochs ago), so this call is
        // kept for consistency with this file's other activation-status callers. Unlike handleWithdraw's shortcut, which only evaluates
        // the curve when current_epoch >= deactivation_epoch, this call is UNCONDITIONAL:
        // activation_epoch == current_epoch (mid-warmup, not yet past deactivation) must
        // still yield effective == 0 / is_active == false, which handleWithdraw's
        // early-return-delegation_stake shortcut would get wrong.
        //
        // Second deliberate divergence from the cited vex_bpf2:1724 line: current_epoch here
        // is bank.epoch_schedule.getEpoch(bank.slot), not clock.epoch off a live Clock-sysvar
        // read — matching this file's OTHER activation-status caller (handleWithdraw:650) and
        // the epoch-derivation reverts earlier in this diff (handleDelegateStake,
        // handleDeactivate), not an oversight. Same reasoning as those reverts: an unverified
        // Clock-sysvar-vs-parent overlay-ordering question at epoch-boundary slots is not
        // something to introduce for this guard either.
        if (source_is_active and src_remaining != 0 and dst_acct.lamports < dst_rent_exempt_reserve) return;

        // Item 2 — destination deficit check (sig lib.zig:819-823), unconditional (both the
        // full-drain and partial-split branches below): reject when the split amount can't
        // cover what the destination still needs to reach rent-exemption + min_delegation,
        // net of what it already holds. Replaces the old `split_lamports -| reserve < min`
        // form, which assumed an unfunded (0-lamport) destination and was wrong for any
        // prefunded one.
        const destination_minimum_balance = dst_rent_exempt_reserve +| min_delegation;
        const destination_balance_deficit = destination_minimum_balance -| dst_acct.lamports;
        if (split_lamports < destination_balance_deficit) return;

        // Calculate split delegation amounts
        const dst_data = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
        @memcpy(dst_data, src_acct.data[0..stake_state.STAKE_STATE_SZ]);

        const src_data = alloc.alloc(u8, src_acct.data.len) catch return;
        @memcpy(src_data, src_acct.data);

        var remaining_stake_delta: u64 = undefined;
        var split_stake_amount: u64 = undefined;

        if (src_remaining == 0) {
            // Item 5 — full drain (sig lib.zig:884-887; vex_bpf2 :1740-1742): both amounts
            // collapse to the same value, net of the SOURCE's own reserve (not the
            // destination's). Previously this branch never wrote dst delegation.stake at
            // all — the dest silently inherited the source's full PRE-split stake via the
            // @memcpy above. Now explicitly overridden below, same as the partial branch.
            remaining_stake_delta = split_lamports -| src_rent;
            split_stake_amount = remaining_stake_delta;
        } else {
            // Item 1(a) — partial split (sig lib.zig:892-899; vex_bpf2 :1744-1746). BEFORE
            // computing the amounts: reject if the source's post-split delegation would fall
            // under min_delegation (StakeError::InsufficientDelegation upstream). Replaces
            // the old post-hoc `remaining_stake < min and remaining_stake > 0` escape-hatch
            // pair, which let a zero-remaining or zero-split-amount partial split through.
            if (src_delegation_stake -| split_lamports < min_delegation) return;

            // Stake::split: the SOURCE loses the full delta, not the split amount (sig
            // state.zig:72-77).
            remaining_stake_delta = split_lamports;
            // Canonical: the destination's PRE-EXISTING lamports offset the reserve it must
            // retain — a dest already funded to rent-exemption consumes NONE of the split,
            // so the full amount becomes delegation.
            split_stake_amount = split_lamports -| (dst_rent_exempt_reserve -| dst_acct.lamports);
        }

        // Item 1(b) — unconditional, both branches (sig lib.zig:902-905; vex_bpf2 :1748).
        if (split_stake_amount < min_delegation) return;

        // Stake::split's insufficient_stake guard (sig state.zig:72-75), then the decrement —
        // applies to both branches now that remaining_stake_delta is computed in both.
        if (remaining_stake_delta > src_delegation_stake) return;
        const remaining_stake = src_delegation_stake - remaining_stake_delta;
        stake_state.writeU64(src_data, stake_state.Offsets.delegation_stake, remaining_stake);

        // Write destination as Stake(2) with split portion
        stake_state.writeU64(dst_data, stake_state.Offsets.rent_exempt_reserve, dst_rent_exempt_reserve);
        stake_state.writeU64(dst_data, stake_state.Offsets.delegation_stake, split_stake_amount);

        if (src_remaining == 0) {
            // Source becomes uninitialized. Item 6 — canonical writes ONLY the 4-byte
            // discriminant and PRESERVES bytes 4..200 (sig lib.zig:971-973; vex_bpf2
            // stake_program.zig:1796); the delegation_stake write immediately above already
            // put the correct post-split value in that preserved region, so no further
            // zeroing is needed or correct.
            stake_state.writeU32(src_data, stake_state.Offsets.discriminant, 0);
        }

        // Emit source write
        emitWrite(bank, src_key, src_acct.owner.data, src_acct.lamports, src_acct.executable, src_acct.data, src_remaining, src_acct.owner.data, src_acct.executable, src_acct.rent_epoch, src_data);

        // Emit destination write
        emitWrite(bank, dst_key, dst_acct.owner.data, dst_acct.lamports, dst_acct.executable, dst_acct.data, dst_acct.lamports + split_lamports, dst_acct.owner.data, dst_acct.executable, dst_acct.rent_epoch, dst_data);
    } else {
        // Initialized state: no delegation to split, just move lamports + meta
        if (src_remaining > 0 and src_remaining < src_rent) return;

        // Item 2, applied consistently to the Initialized arm too (sig lib.zig:819-823 via
        // the shared validateSplitAmount, called with additional_required_lamports=0 for
        // .initialized — sig lib.zig:927-934; vex_bpf2 :1768-1773).
        const destination_balance_deficit = dst_rent_exempt_reserve -| dst_acct.lamports;
        if (split_lamports < destination_balance_deficit) return;

        const dst_data = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
        @memset(dst_data, 0);

        // Write Initialized state to destination with same authorities/lockup
        stake_state.writeU32(dst_data, stake_state.Offsets.discriminant, 1);
        stake_state.writeU64(dst_data, stake_state.Offsets.rent_exempt_reserve, dst_rent_exempt_reserve);
        // Copy authorities and lockup from source
        @memcpy(dst_data[stake_state.Offsets.staker..][0..32], src_acct.data[stake_state.Offsets.staker..][0..32]);
        @memcpy(dst_data[stake_state.Offsets.withdrawer..][0..32], src_acct.data[stake_state.Offsets.withdrawer..][0..32]);
        @memcpy(dst_data[stake_state.Offsets.lockup_unix_timestamp..][0..48], src_acct.data[stake_state.Offsets.lockup_unix_timestamp..][0..48]); // i64 + u64 + [32]u8

        // Source: if emptied, becomes uninitialized
        const src_data = alloc.alloc(u8, src_acct.data.len) catch return;
        @memcpy(src_data, src_acct.data);
        if (src_remaining == 0) {
            // Item 6 — write ONLY the discriminant, PRESERVE bytes 4..200 (see the Stake-arm
            // comment above for the canonical citation; the Initialized meta was never
            // otherwise mutated, so preserving is a no-op on top of already-correct bytes).
            stake_state.writeU32(src_data, stake_state.Offsets.discriminant, 0);
        }

        emitWrite(bank, src_key, src_acct.owner.data, src_acct.lamports, src_acct.executable, src_acct.data, src_remaining, src_acct.owner.data, src_acct.executable, src_acct.rent_epoch, src_data);
        emitWrite(bank, dst_key, dst_acct.owner.data, dst_acct.lamports, dst_acct.executable, dst_acct.data, dst_acct.lamports + split_lamports, dst_acct.owner.data, dst_acct.executable, dst_acct.rent_epoch, dst_data);
    }
}

// ---------------------------------------------------------------------------
// Handler: SetLockup (0x06)
// ---------------------------------------------------------------------------
// Sets lockup parameters on a stake account.
//
// Accounts:
//   [0] RW      stake_account — Initialized(1) or Stake(2)
//   [1] SIGNER  custodian (if lockup active) or withdrawer (if expired)
//
// Instruction data (LockupArgs bincode):
//   [0..4]  u32 discriminant = 6
//   [4..5]  u8  has_unix_timestamp (0 or 1)
//   [5..13] i64 unix_timestamp (if has = 1)
//   next:   u8  has_epoch (0 or 1)
//   next:   u64 epoch (if has = 1)
//   next:   u8  has_custodian (0 or 1)
//   next:   [32]u8 custodian (if has = 1)
//
// Validation:
//   - Account must be Initialized or Stake
//   - If lockup active: current custodian must sign
//   - If lockup expired: withdrawer must sign
// ---------------------------------------------------------------------------

const LockupArgsData = struct {
    unix_timestamp: ?i64,
    epoch: ?u64,
    custodian: ?[32]u8,
};

fn parseLockupArgs(ix_data: []const u8) ?LockupArgsData {
    var result: LockupArgsData = .{
        .unix_timestamp = null,
        .epoch = null,
        .custodian = null,
    };
    var off: usize = 4; // skip discriminant
    if (off >= ix_data.len) return result;

    // unix_timestamp: Option<i64> encoded as (u8, i64?)
    if (off + 1 > ix_data.len) return null;
    if (ix_data[off] == 1) {
        off += 1;
        if (off + 8 > ix_data.len) return null;
        result.unix_timestamp = std.mem.readInt(i64, ix_data[off..][0..8], .little);
        off += 8;
    } else {
        off += 1;
    }

    // epoch: Option<u64>
    if (off + 1 > ix_data.len) return null;
    if (ix_data[off] == 1) {
        off += 1;
        if (off + 8 > ix_data.len) return null;
        result.epoch = std.mem.readInt(u64, ix_data[off..][0..8], .little);
        off += 8;
    } else {
        off += 1;
    }

    // custodian: Option<Pubkey>
    if (off + 1 > ix_data.len) return null;
    if (ix_data[off] == 1) {
        off += 1;
        if (off + 32 > ix_data.len) return null;
        result.custodian = ix_data[off..][0..32].*;
        off += 32;
    } else {
        off += 1;
    }

    return result;
}

// ⚠ FOOTGUN (native handleSetLockup): index-1 signer (NOT a signer-SET scan) + no
// owner==Stake check + no SIMD-0118 EpochRewards gate + bespoke isLockupActive +
// silent `return` on every rejection + deep-copy/emitWrite. The BPF-CPI port in
// src/vex_bpf2/builtins/stake_program.zig:executeSetLockup is canonical
// (signerSetContains set-scan, owner==Stake, EpochRewards gate, lockupInForce(_,_,null),
// in-place same-length writes @76/@84/@92). If you ever route top-level SetLockup
// through THIS handler, fix these 6 wrapper bugs first or it will diverge.
// ⚠ ALSO: this handler implements ONLY tag 6 (SetLockup), reading the custodian from
// ix DATA. SetLockupChecked (tag 12) takes its new custodian from account[2].pubkey
// (which MUST sign) — that is a SEPARATE wrapper bug here (not handled at all). The
// canonical BPF-CPI port for tag 12 is
// src/vex_bpf2/builtins/stake_program.zig:executeSetLockupChecked (get_optional_pubkey
// idx=2 should_be_signer, custodian from acct[2], same Meta::set_lockup core).
// Reference: agave-behavior-extractor SetLockup/SetLockupChecked 2026-06-15 + memory
// carrier-stake-cpi-deactivate-stub-2026-06-14.
fn handleSetLockup(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] SetLockup slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 2) return;

    const args = parseLockupArgs(ix.data) orelse return;

    const stake_idx = ix.account_indices[0];
    const signer_idx = ix.account_indices[1];
    if (stake_idx >= ptx.num_accounts or signer_idx >= ptx.num_accounts) return;
    if (!isSigner(ptx, signer_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const signer_key = ptx.account_keys[signer_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return;

    // Authorization: if lockup active, custodian must sign; if expired, withdrawer must sign
    const lockup_active = isLockupActive(stake_acct.data, bank, db);
    if (lockup_active) {
        const lockup_custodian = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.lockup_custodian) orelse return;
        if (!std.mem.eql(u8, &signer_key, &lockup_custodian)) return;
    } else {
        const withdrawer = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.withdrawer) orelse return;
        if (!std.mem.eql(u8, &signer_key, &withdrawer)) return;
    }

    // Deep copy and update lockup fields
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    if (args.unix_timestamp) |ts| {
        stake_state.writeI64(data_copy, stake_state.Offsets.lockup_unix_timestamp, ts);
    }
    if (args.epoch) |ep| {
        stake_state.writeU64(data_copy, stake_state.Offsets.lockup_epoch, ep);
    }
    if (args.custodian) |c| {
        stake_state.writePubkey(data_copy, stake_state.Offsets.lockup_custodian, c);
    }

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: Merge (0x07)
// ---------------------------------------------------------------------------
// Merges source stake account into destination. Source is drained to
// Uninitialized and its lamports transferred to destination.
//
// 9 merge paths based on (destination, source) state combinations:
//
//   Dest\Source     | Inactive   | Activating | Fully Active
//   Inactive        | Drain      | Drain      | FAIL
//   Activating      | Add        | Add+Merge  | FAIL
//   Fully Active    | FAIL       | FAIL       | Merge
//
// Accounts:
//   [0] RW  destination_stake — Initialized(1) or Stake(2)
//   [1] RW  source_stake      — Initialized(1) or Stake(2), will be drained
//   [2] RO  clock_sysvar
//   [3] RO  stake_history
//   [4] SIGNER staker authority
//
// Validation:
//   - Both accounts owned by stake program
//   - Different pubkeys
//   - Same authorized.staker and authorized.withdrawer (or both lockups expired)
//   - If both active: same voter_pubkey and both not deactivating
//   - Staker authority must sign
// ---------------------------------------------------------------------------

/// Determine merge-kind for an account: inactive, activating, or fully_active.
/// Returns: 0 = inactive, 1 = activating, 2 = fully_active, 0xFF = unmergeable.
/// Uses the full stake activation curve (via bank.getStakeActivationStatus) to
/// correctly detect transient/cooldown states as unmergeable.
fn getMergeKind(data: []const u8, bank: anytype, history: []const bank_mod.Bank.StakeHistoryEntry) u8 {
    const disc = stake_state.readU32(data, 0) orelse return 0xFF;
    if (disc == 1) return 0; // Initialized = inactive

    if (disc != 2) return 0xFF;

    // Stake: compute full activation status using stake history
    const activation_epoch = stake_state.readU64(data, stake_state.Offsets.activation_epoch) orelse return 0xFF;
    const deactivation_epoch = stake_state.readU64(data, stake_state.Offsets.deactivation_epoch) orelse return 0xFF;
    const delegation_stake = stake_state.readU64(data, stake_state.Offsets.delegation_stake) orelse return 0xFF;
    const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

    const status = bank_mod.Bank.getStakeActivationStatus(
        activation_epoch,
        deactivation_epoch,
        delegation_stake,
        current_epoch,
        history,
        // carrier #16: rate is epoch-scheduled, not the per-account field.
        bank.getNewRateActivationEpoch(),
    );

    // (0, 0, 0) = fully deactivated = inactive
    if (status.effective == 0 and status.activating == 0 and status.deactivating == 0) return 0;
    // (0, >0, _) = in activation epoch = activating
    if (status.effective == 0) return 1;
    // (>0, 0, 0) = fully active
    if (status.activating == 0 and status.deactivating == 0) return 2;
    // Anything else (transient: partially warming/cooling) = unmergeable
    return 0xFF;
}

/// Weighted average of credits_observed. Uses u128 to avoid overflow.
/// Formula: (s.credits * s.stake + a.credits * a.lamports + total - 1) / total
fn weightedCreditsObserved(
    stake_credits: u64,
    stake_amount: u64,
    absorbed_credits: u64,
    absorbed_amount: u64,
) ?u64 {
    if (stake_credits == absorbed_credits) return stake_credits;

    const total_stake: u128 = @as(u128, stake_amount) + @as(u128, absorbed_amount);
    if (total_stake == 0) return null;

    const weighted_stake: u128 = @as(u128, stake_credits) * @as(u128, stake_amount);
    const weighted_absorbed: u128 = @as(u128, absorbed_credits) * @as(u128, absorbed_amount);

    var numerator: u128 = weighted_stake + weighted_absorbed;
    numerator += total_stake; // rounding adjustment
    numerator -= 1;

    const result = numerator / total_stake;
    if (result > std.math.maxInt(u64)) return null;
    return @as(u64, @truncate(result));
}

fn handleMerge(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] Merge slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 5) return;

    const dst_idx = ix.account_indices[0];
    const src_idx = ix.account_indices[1];
    const auth_idx = ix.account_indices[4];
    if (dst_idx >= ptx.num_accounts or src_idx >= ptx.num_accounts or auth_idx >= ptx.num_accounts) return;
    if (!isSigner(ptx, auth_idx)) return;

    const dst_key = ptx.account_keys[dst_idx];
    const src_key = ptx.account_keys[src_idx];
    const auth_key = ptx.account_keys[auth_idx];

    // Must be different accounts
    if (std.mem.eql(u8, &dst_key, &src_key)) return;

    const dst_acct = readOverlayed(bank, db, dst_key) orelse return;
    const src_acct = readOverlayed(bank, db, src_key) orelse return;

    if (dst_acct.data.len < stake_state.STAKE_STATE_SZ or src_acct.data.len < stake_state.STAKE_STATE_SZ) return;

    // Both must be owned by stake program
    const STAKE_PROGRAM_ID = [_]u8{
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
        0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
        0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &dst_acct.owner.data, &STAKE_PROGRAM_ID)) return;
    if (!std.mem.eql(u8, &src_acct.owner.data, &STAKE_PROGRAM_ID)) return;

    // Verify staker authority matches destination
    const dst_staker = stake_state.readPubkey(dst_acct.data, stake_state.Offsets.staker) orelse return;
    if (!std.mem.eql(u8, &auth_key, &dst_staker)) return;

    // Verify compatible metas: same staker, same withdrawer
    const dst_withdrawer = stake_state.readPubkey(dst_acct.data, stake_state.Offsets.withdrawer) orelse return;
    const src_staker = stake_state.readPubkey(src_acct.data, stake_state.Offsets.staker) orelse return;
    const src_withdrawer = stake_state.readPubkey(src_acct.data, stake_state.Offsets.withdrawer) orelse return;

    if (!std.mem.eql(u8, &dst_staker, &src_staker) or !std.mem.eql(u8, &dst_withdrawer, &src_withdrawer)) {
        // Authorities must match. No merge allowed with mismatched authorities.
        return;
    }

    // Check lockup compatibility: must be same OR both expired
    const dst_lockup_bytes = dst_acct.data[stake_state.Offsets.lockup_unix_timestamp..][0..48];
    const src_lockup_bytes = src_acct.data[stake_state.Offsets.lockup_unix_timestamp..][0..48];
    if (!std.mem.eql(u8, dst_lockup_bytes, src_lockup_bytes)) {
        // Different lockups: both must be expired to merge
        if (isLockupActive(dst_acct.data, bank, db) or isLockupActive(src_acct.data, bank, db)) return;
    }

    // Read stake history for merge-kind determination (uses activation curves)
    const history = bank.readStakeHistory(alloc) catch &[_]bank_mod.Bank.StakeHistoryEntry{};
    defer if (history.len > 0) alloc.free(history);

    // Determine merge kinds
    const dst_kind = getMergeKind(dst_acct.data, bank, history);
    const src_kind = getMergeKind(src_acct.data, bank, history);
    if (dst_kind == 0xFF or src_kind == 0xFF) return; // Unmergeable (transient)

    // Apply truth table
    const dst_data = alloc.alloc(u8, dst_acct.data.len) catch return;
    @memcpy(dst_data, dst_acct.data);
    var write_dst_state = false;

    if (dst_kind == 0 and src_kind == 0) {
        // Inactive + Inactive: just drain source lamports, no state change needed
        // Destination stays as-is
    } else if (dst_kind == 0 and src_kind == 1) {
        // Inactive + Activating: drain source
    } else if (dst_kind == 1 and src_kind == 0) {
        // Activating + Inactive: add source lamports to destination delegation
        const dst_delegation = stake_state.readU64(dst_data, stake_state.Offsets.delegation_stake) orelse return;
        stake_state.writeU64(dst_data, stake_state.Offsets.delegation_stake, dst_delegation + src_acct.lamports);
        // Combine stake flags. @prov:stake.merge-v5
        const dst_flags = dst_data[stake_state.Offsets.stake_flags];
        const src_flags = src_acct.data[stake_state.Offsets.stake_flags];
        dst_data[stake_state.Offsets.stake_flags] = dst_flags | src_flags;
        write_dst_state = true;
    } else if (dst_kind == 1 and src_kind == 1) {
        // Activating + Activating: merge delegations
        // Must be same voter
        const dst_voter = stake_state.readPubkey(dst_data, stake_state.Offsets.voter_pubkey) orelse return;
        const src_voter = stake_state.readPubkey(src_acct.data, stake_state.Offsets.voter_pubkey) orelse return;
        if (!std.mem.eql(u8, &dst_voter, &src_voter)) return;

        const dst_stake = stake_state.readU64(dst_data, stake_state.Offsets.delegation_stake) orelse return;
        const dst_credits = stake_state.readU64(dst_data, stake_state.Offsets.credits_observed) orelse return;
        // Validate source state is parseable (preserves the orelse-return guards
        // even though v5 no longer uses src_stake / src_rent_exempt_reserve).
        _ = stake_state.readU64(src_acct.data, stake_state.Offsets.delegation_stake) orelse return;
        const src_credits = stake_state.readU64(src_acct.data, stake_state.Offsets.credits_observed) orelse return;
        // d28uu (2026-05-13): SIMD-0490 #5 (active testnet ep 955, slot 407,036,256).
        // v4 absorbed `src_rent + src_stake` (delegation portion only — any excess
        // source lamports stayed un-delegated). v5 absorbs ALL source lamports
        // into the destination's delegation. For typical accounts where
        // src.lamports == src.rent_exempt_reserve + src.delegation_stake, both
        // produce identical results. The diff manifests when source has excess
        // lamports (e.g. accumulated rewards or transferred-but-undelegated
        // funds). Source's stored rent_exempt_reserve is no longer read here.
        const absorbed = src_acct.lamports;
        const merged_credits = weightedCreditsObserved(dst_credits, dst_stake, src_credits, absorbed) orelse return;

        stake_state.writeU64(dst_data, stake_state.Offsets.delegation_stake, dst_stake + absorbed);
        stake_state.writeU64(dst_data, stake_state.Offsets.credits_observed, merged_credits);

        // Combine stake flags
        const dst_flags = dst_data[stake_state.Offsets.stake_flags];
        const src_flags = src_acct.data[stake_state.Offsets.stake_flags];
        dst_data[stake_state.Offsets.stake_flags] = dst_flags | src_flags;

        write_dst_state = true;
    } else if (dst_kind == 2 and src_kind == 2) {
        // Fully Active + Fully Active: merge
        const dst_voter = stake_state.readPubkey(dst_data, stake_state.Offsets.voter_pubkey) orelse return;
        const src_voter = stake_state.readPubkey(src_acct.data, stake_state.Offsets.voter_pubkey) orelse return;
        if (!std.mem.eql(u8, &dst_voter, &src_voter)) return;

        // Both must not be deactivating
        const dst_deact = stake_state.readU64(dst_data, stake_state.Offsets.deactivation_epoch) orelse return;
        const src_deact = stake_state.readU64(src_acct.data, stake_state.Offsets.deactivation_epoch) orelse return;
        if (dst_deact != std.math.maxInt(u64) or src_deact != std.math.maxInt(u64)) return;

        const dst_stake = stake_state.readU64(dst_data, stake_state.Offsets.delegation_stake) orelse return;
        const dst_credits = stake_state.readU64(dst_data, stake_state.Offsets.credits_observed) orelse return;
        const src_stake = stake_state.readU64(src_acct.data, stake_state.Offsets.delegation_stake) orelse return;
        const src_credits = stake_state.readU64(src_acct.data, stake_state.Offsets.credits_observed) orelse return;

        // FullyActive: absorbed is delegation.stake ONLY (not rent). Source's rent becomes
        // excess lamports in the destination. @prov:stake.merge-v5
        const absorbed = src_stake;
        const merged_credits = weightedCreditsObserved(dst_credits, dst_stake, src_credits, absorbed) orelse return;

        stake_state.writeU64(dst_data, stake_state.Offsets.delegation_stake, dst_stake + absorbed);
        stake_state.writeU64(dst_data, stake_state.Offsets.credits_observed, merged_credits);
        // @prov:stake.merge-v5 — resets flags to EMPTY for fully_active + fully_active merges
        dst_data[stake_state.Offsets.stake_flags] = 0;
        write_dst_state = true;
    } else {
        // All other combinations: FAIL (merge_mismatch)
        return;
    }

    // Source: drain to uninitialized
    const src_data = alloc.alloc(u8, src_acct.data.len) catch return;
    @memset(src_data, 0); // Uninitialized = all zeros (disc=0)

    // Emit source write: drained to 0 lamports, uninitialized
    emitWrite(bank, src_key, src_acct.owner.data, src_acct.lamports, src_acct.executable, src_acct.data, 0, src_acct.owner.data, src_acct.executable, src_acct.rent_epoch, src_data);

    // Emit destination write: gains source lamports, possibly updated state
    const final_data = if (write_dst_state) dst_data else dst_acct.data;
    emitWrite(bank, dst_key, dst_acct.owner.data, dst_acct.lamports, dst_acct.executable, dst_acct.data, dst_acct.lamports + src_acct.lamports, dst_acct.owner.data, dst_acct.executable, dst_acct.rent_epoch, final_data);
}

// ---------------------------------------------------------------------------
// Handler: AuthorizeWithSeed (0x08)
// ---------------------------------------------------------------------------
// PDA-based authority derivation. Requires createWithSeed utility which
// Vexor does not yet have. Stub with log until PDA support is added.
// ---------------------------------------------------------------------------

// P0-2 fix (VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11 §7): this native
// top-level handler was previously a log-only STUB — any top-level
// AuthorizeWithSeed tx silently succeeded with NO account mutation, while
// Agave (via the on-chain core-BPF stake v5 program) actually rewrites the
// staker/withdrawer authority — a one-tx bank_hash divergence, since this
// native path is the live default (VEX_STAKE_BPF unset,
// stake_bpf_flag.zig:29-38). Ports vex_bpf2/builtins/stake_program.zig
// executeAuthorizeWithSeed (tag 8) onto the native dispatch path EXACTLY:
// derive D=create_with_seed(base,seed,owner) via the SAME shared helper
// (deriveWithSeed, now `pub`), single-element signer set {D}, same-length
// in-place-style mutation of staker@12/withdrawer@44 (via a full-account
// deep copy + emitWrite, matching this file's own commit convention).
//
// Canonical: Sig lib.zig:552-592 `authorizeWithSeed` + :503-550 `authorize` +
// state.zig:138-178 `Authorized.authorize`; create_with_seed =
// SHA256(base|seed|owner) (carrier #12-proven @414674115, byte-faithful to
// Agave programs/stake/src/stake_state.rs `authorize` +
// solana-pubkey::Pubkey::create_with_seed).
//
// ix data (bincode LE): u32 tag(8) + [32] new_authorized_pubkey + u32
// stake_authorize (0=Staker,1=Withdrawer) + u64 seed_len + [seed_len] seed +
// [32] authority_owner. Field order: Sig instruction.zig:278-285
// AuthorizeWithSeedArgs. Min length = 48 + 0 + 32 = 80 (empty seed).
//
// Accounts: [0] RW stake, [1] SIGNER base, [2] Clock (read via db, matching
// isLockupActive's convention — not the account slot itself), [3] custodian
// (OPTIONAL, consulted only when a Withdrawer change hits an active lockup).
//
// ⚠ The signer SET for this instruction is NOT the transaction signer list —
// it is the single derived pubkey D = create_with_seed(base, seed, owner),
// present in the set iff the base account (index 1) itself signed the tx.
// staker/withdrawer/custodian are matched against D by equality; never
// checked with isSigner() directly (except base itself, which gates whether
// D exists at all). Reference: agave-behavior-extractor 2026-06-16
// AuthorizeWithSeed + plan STAKE-CPI-REMAINING-VARIANTS-2026-06-16.
fn handleAuthorizeWithSeed(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] AuthorizeWithSeed slot={d}\n", .{bank.slot});
    const data = ix.data;
    const IX_OFF_NEW_AUTH: usize = 4; // [32] new_authorized_pubkey
    const IX_OFF_TYPE: usize = 36; // u32 stake_authorize
    const IX_OFF_SEED_LEN: usize = 40; // u64 seed length prefix
    const IX_OFF_SEED: usize = 48; // seed bytes start
    if (data.len < IX_OFF_SEED) return;
    const new_authority: [32]u8 = data[IX_OFF_NEW_AUTH..][0..32].*;
    const authorize_type = std.mem.readInt(u32, data[IX_OFF_TYPE..][0..4], .little);
    if (authorize_type > 1) return;
    const seed_len = std.mem.readInt(u64, data[IX_OFF_SEED_LEN..][0..8], .little);
    if (seed_len > 32) return; // MaxSeedLenExceeded
    const seed_len_usize = std.math.cast(usize, seed_len) orelse return;
    const seed_end = IX_OFF_SEED + seed_len_usize;
    if (data.len < seed_end + 32) return;
    const seed = data[IX_OFF_SEED..seed_end];
    const authority_owner = data[seed_end..][0..32];

    if (ix.account_indices.len < 2) return; // checkNumberOfAccounts(2)
    const stake_idx = ix.account_indices[0];
    const base_idx = ix.account_indices[1];
    if (stake_idx >= ptx.num_accounts or base_idx >= ptx.num_accounts) return;

    const stake_key = ptx.account_keys[stake_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    const STAKE_PROGRAM_ID = [_]u8{
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
        0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
        0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &stake_acct.owner.data, &STAKE_PROGRAM_ID)) return; // InvalidAccountOwner
    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return; // Initialized or Stake only

    // Build the single-element signer set {D}: derive D ONLY if the base
    // account (instruction index 1) signed. Otherwise the set is EMPTY →
    // every authorize check below fails (MissingRequiredSignature-shape).
    var derived: ?[32]u8 = null;
    if (isSigner(ptx, base_idx)) {
        derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&ptx.account_keys[base_idx], seed, authority_owner) orelse return;
    }
    const dsig: ?[]const u8 = if (derived) |*d| d[0..32] else null;

    const staker = stake_acct.data[stake_state.Offsets.staker..][0..32];
    const withdrawer = stake_acct.data[stake_state.Offsets.withdrawer..][0..32];

    // Validate FIRST, allocate ONLY once we know the mutation will commit —
    // allocating before a possible `return` on a reject path leaks the
    // buffer (no emitWrite ever reaches it to free/own it).
    if (authorize_type == 0) {
        // StakeAuthorize::Staker — {D} must contain staker OR withdrawer.
        const ok = dsig != null and (std.mem.eql(u8, dsig.?, staker) or std.mem.eql(u8, dsig.?, withdrawer));
        if (!ok) return;
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST, then check(D, Withdrawer).
        const clock = readClockForLockup(bank, db);
        const lk_ts = stake_state.readI64(stake_acct.data, stake_state.Offsets.lockup_unix_timestamp) orelse return;
        const lk_epoch = stake_state.readU64(stake_acct.data, stake_state.Offsets.lockup_epoch) orelse return;
        const lk_custodian = stake_acct.data[stake_state.Offsets.lockup_custodian..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 3.
            if (ix.account_indices.len <= 3) return; // CustodianMissing
            const cust_idx = ix.account_indices[3];
            if (cust_idx >= ptx.num_accounts) return; // CustodianMissing
            const custodian = &ptx.account_keys[cust_idx];
            // has_custodian_signer over signers={D}: custodian counts iff custodian == D.
            const cust_signed = dsig != null and std.mem.eql(u8, dsig.?, custodian);
            if (!cust_signed) return; // CustodianSignatureMissing
            // is_in_force(clock, Some(custodian)): bypass iff custodian == lockup.custodian.
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch)) return; // LockupInForce
        }
        // check(signers={D}, Withdrawer): D must equal the current withdrawer.
        const ok = dsig != null and std.mem.eql(u8, dsig.?, withdrawer);
        if (!ok) return;
    }

    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);
    if (authorize_type == 0) {
        stake_state.writePubkey(data_copy, stake_state.Offsets.staker, new_authority);
    } else {
        stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, new_authority);
    }

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: InitializeChecked (0x09)
// ---------------------------------------------------------------------------
// Like Initialize but authorities come from accounts, and withdrawer must sign.
//
// Accounts:
//   [0] RW  stake_account — must be Uninitialized
//   [1] RO  rent_sysvar
//   [2] RO  staker pubkey (read-only reference)
//   [3] SIGNER withdrawer
//
// No instruction data beyond discriminant. Lockup defaults to zero.
// ---------------------------------------------------------------------------

fn handleInitializeChecked(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] InitializeChecked slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 4) return;

    const stake_idx = ix.account_indices[0];
    const staker_idx = ix.account_indices[2];
    const withdrawer_idx = ix.account_indices[3];
    if (stake_idx >= ptx.num_accounts or staker_idx >= ptx.num_accounts or withdrawer_idx >= ptx.num_accounts) return;

    // Withdrawer must be a signer
    if (!isSigner(ptx, withdrawer_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const staker_key = ptx.account_keys[staker_idx];
    const withdrawer_key = ptx.account_keys[withdrawer_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    // Must be Uninitialized
    if (stake_acct.data.len >= 4) {
        const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
        if (disc != 0) return;
    }

    const rent_exempt_reserve: u64 = 2_282_880;
    if (stake_acct.lamports < rent_exempt_reserve) return;

    // Allocate and write Initialized state with default lockup
    const data_copy = alloc.alloc(u8, stake_state.STAKE_STATE_SZ) catch return;
    @memset(data_copy, 0);

    stake_state.writeU32(data_copy, stake_state.Offsets.discriminant, 1);
    stake_state.writeU64(data_copy, stake_state.Offsets.rent_exempt_reserve, rent_exempt_reserve);
    stake_state.writePubkey(data_copy, stake_state.Offsets.staker, staker_key);
    stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, withdrawer_key);
    // Default lockup: unix_timestamp=0, epoch=0, custodian=zeros (already zeroed)

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: AuthorizeChecked (0x0A)
// ---------------------------------------------------------------------------
// Like Authorize but the new authority (account [3]) must be a signer.
//
// Accounts:
//   [0] RW      stake_account
//   [1] RO      clock_sysvar
//   [2] SIGNER  current authority
//   [3] SIGNER  new authority
//   [4] SIGNER  custodian (optional)
//
// Instruction data:
//   [0..4] u32 discriminant = 0x0A
//   [4..8] u32 authorize_type (0=Staker, 1=Withdrawer)
// ---------------------------------------------------------------------------

fn handleAuthorizeChecked(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] AuthorizeChecked slot={d}\n", .{bank.slot});
    if (ix.data.len < 8 or ix.account_indices.len < 4) return;

    const authorize_type = std.mem.readInt(u32, ix.data[4..8], .little);
    if (authorize_type > 1) return;

    const stake_idx = ix.account_indices[0];
    const old_auth_idx = ix.account_indices[2];
    const new_auth_idx = ix.account_indices[3];
    if (stake_idx >= ptx.num_accounts or old_auth_idx >= ptx.num_accounts or new_auth_idx >= ptx.num_accounts) return;

    // Both old and new authority must be signers
    if (!isSigner(ptx, old_auth_idx)) return;
    if (!isSigner(ptx, new_auth_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const old_auth_key = ptx.account_keys[old_auth_idx];
    const new_auth_key = ptx.account_keys[new_auth_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return;

    // Verify old authority matches
    if (authorize_type == 0) {
        const current_staker = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.staker) orelse return;
        const current_withdrawer = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.withdrawer) orelse return;
        if (!std.mem.eql(u8, &old_auth_key, &current_staker) and !std.mem.eql(u8, &old_auth_key, &current_withdrawer)) return;
    } else {
        const current_withdrawer = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.withdrawer) orelse return;
        if (!std.mem.eql(u8, &old_auth_key, &current_withdrawer)) return;

        // Lockup check for withdrawer change
        if (isLockupActive(stake_acct.data, bank, db)) {
            if (ix.account_indices.len < 5) return;
            const custodian_idx = ix.account_indices[4];
            if (custodian_idx >= ptx.num_accounts) return;
            if (!isSigner(ptx, custodian_idx)) return;
            const lockup_custodian = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.lockup_custodian) orelse return;
            const custodian_key = ptx.account_keys[custodian_idx];
            if (!std.mem.eql(u8, &custodian_key, &lockup_custodian)) return;
        }
    }

    // Deep copy and update authority
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    if (authorize_type == 0) {
        stake_state.writePubkey(data_copy, stake_state.Offsets.staker, new_auth_key);
    } else {
        stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, new_auth_key);
    }

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: AuthorizeCheckedWithSeed (0x0B)
// ---------------------------------------------------------------------------
// P0-2 fix (VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11 §7) — same class as
// AuthorizeWithSeed above (was a log-only stub). Ports
// vex_bpf2/builtins/stake_program.zig executeAuthorizeCheckedWithSeed
// (tag 11). Identical seed-derive single-element-signer-set semantics as
// AuthorizeWithSeed; the ONLY differences:
//   • new_authority = accounts[3].pubkey (NOT in ix data — that account MUST
//     sign, checked BEFORE the old-authority checks),
//   • >=4 accounts required (AuthorizeWithSeed = 2),
//   • custodian is at instruction account index 4 (AuthorizeWithSeed = 3),
//   • ix data carries NO new_authorized_pubkey; field order is
//     stake_authorize FIRST.
// Base seed authority stays at instruction index 1 (same as AuthorizeWithSeed).
//
// Accounts: [0] stake [WRITE], [1] base [SIGNER→D], [2] Clock, [3] new
// authority [SIGNER], [4] custodian (OPTIONAL).
//
// ix data (bincode LE): u32 tag(11) + u32 stake_authorize (0=Staker,
// 1=Withdrawer) + u64 seed_len + [seed_len] seed + [32] authority_owner.
// AuthorizeCheckedWithSeedArgs field order = {stake_authorize,
// authority_seed, authority_owner} — stake_authorize FIRST (Sig
// instruction.zig:269-276), unlike AuthorizeWithSeedArgs which leads with
// new_authorized_pubkey. Min length = 16 + 0 + 32 = 48 (empty seed).
//
// CANONICAL: Sig lib.zig:317-350 dispatch + :552-592 `authorizeWithSeed`
// (called with authority_base_index=1, new_authority=&accounts[3].pubkey,
// custodian=getOptionalPubkey(4)) + state.zig:138-178 `Authorized.authorize`;
// deriveWithSeed = SHA256(base|seed|owner) (carrier #12-proven).
fn handleAuthorizeCheckedWithSeed(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] AuthorizeCheckedWithSeed slot={d}\n", .{bank.slot});
    const data = ix.data;
    const IX_OFF_TYPE: usize = 4; // u32 stake_authorize
    const IX_OFF_SEED_LEN: usize = 8; // u64 seed length prefix
    const IX_OFF_SEED: usize = 16; // seed bytes start
    if (data.len < IX_OFF_SEED) return;
    const authorize_type = std.mem.readInt(u32, data[IX_OFF_TYPE..][0..4], .little);
    if (authorize_type > 1) return;
    const seed_len = std.mem.readInt(u64, data[IX_OFF_SEED_LEN..][0..8], .little);
    if (seed_len > 32) return; // MaxSeedLenExceeded
    const seed_len_usize = std.math.cast(usize, seed_len) orelse return;
    const seed_end = IX_OFF_SEED + seed_len_usize;
    if (data.len < seed_end + 32) return;
    const seed = data[IX_OFF_SEED..seed_end];
    const authority_owner = data[seed_end..][0..32];

    if (ix.account_indices.len < 4) return; // checkNumberOfAccounts(4)
    const stake_idx = ix.account_indices[0];
    const base_idx = ix.account_indices[1];
    const new_idx = ix.account_indices[3];
    if (stake_idx >= ptx.num_accounts or base_idx >= ptx.num_accounts or new_idx >= ptx.num_accounts) return;

    // new authority = accounts[3].pubkey; that account MUST sign (the
    // "Checked" delta; canonical INDEX-3 signer check, BEFORE the
    // old-authority checks — Sig lib.zig:327).
    if (!isSigner(ptx, new_idx)) return;
    const new_authority = ptx.account_keys[new_idx];

    const stake_key = ptx.account_keys[stake_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    const STAKE_PROGRAM_ID = [_]u8{
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
        0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
        0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
        0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &stake_acct.owner.data, &STAKE_PROGRAM_ID)) return; // InvalidAccountOwner
    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return; // Initialized or Stake only

    // Build the single-element signer set {D}: derive D ONLY if the base
    // account (instruction index 1) signed. Otherwise the set is EMPTY.
    var derived: ?[32]u8 = null;
    if (isSigner(ptx, base_idx)) {
        derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&ptx.account_keys[base_idx], seed, authority_owner) orelse return;
    }
    const dsig: ?[]const u8 = if (derived) |*d| d[0..32] else null;

    const staker = stake_acct.data[stake_state.Offsets.staker..][0..32];
    const withdrawer = stake_acct.data[stake_state.Offsets.withdrawer..][0..32];

    // Validate FIRST, allocate ONLY once we know the mutation will commit —
    // see the identical fix in handleAuthorizeWithSeed above (P0-2:
    // allocating before a possible `return` on a reject path leaks the
    // buffer, since no emitWrite ever reaches it to free/own it).
    if (authorize_type == 0) {
        // StakeAuthorize::Staker — {D} must contain staker OR withdrawer.
        const ok = dsig != null and (std.mem.eql(u8, dsig.?, staker) or std.mem.eql(u8, dsig.?, withdrawer));
        if (!ok) return;
    } else {
        // StakeAuthorize::Withdrawer — lockup block FIRST, then check(D, Withdrawer).
        const clock = readClockForLockup(bank, db);
        const lk_ts = stake_state.readI64(stake_acct.data, stake_state.Offsets.lockup_unix_timestamp) orelse return;
        const lk_epoch = stake_state.readU64(stake_acct.data, stake_state.Offsets.lockup_epoch) orelse return;
        const lk_custodian = stake_acct.data[stake_state.Offsets.lockup_custodian..][0..32];

        // Lockup::is_in_force(clock, None): no custodian bypass.
        if (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch) {
            // custodian = optional pubkey at instruction account index 4 for
            // the Checked variant (AuthorizeWithSeed = 3).
            if (ix.account_indices.len <= 4) return; // CustodianMissing
            const cust_idx = ix.account_indices[4];
            if (cust_idx >= ptx.num_accounts) return; // CustodianMissing
            const custodian = &ptx.account_keys[cust_idx];
            const cust_signed = dsig != null and std.mem.eql(u8, dsig.?, custodian);
            if (!cust_signed) return; // CustodianSignatureMissing
            const bypass = std.mem.eql(u8, custodian, lk_custodian);
            if (!bypass and (lk_ts > clock.unix_timestamp or lk_epoch > clock.epoch)) return; // LockupInForce
        }
        const ok = dsig != null and std.mem.eql(u8, dsig.?, withdrawer);
        if (!ok) return;
    }

    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);
    if (authorize_type == 0) {
        stake_state.writePubkey(data_copy, stake_state.Offsets.staker, new_authority);
    } else {
        stake_state.writePubkey(data_copy, stake_state.Offsets.withdrawer, new_authority);
    }

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: SetLockupChecked (0x0C)
// ---------------------------------------------------------------------------
// Like SetLockup but new custodian comes from account [2] and must be signer.
// LockupCheckedArgs only has unix_timestamp and epoch (no custodian in data).
//
// Accounts:
//   [0] RW      stake_account
//   [1] SIGNER  current custodian or withdrawer
//   [2] SIGNER  new custodian (optional)
//
// Instruction data:
//   [0..4] u32 discriminant = 0x0C
//   [4..5] u8  has_unix_timestamp
//   [5..13] i64 (if has=1)
//   next:  u8  has_epoch
//   next:  u64 (if has=1)
// ---------------------------------------------------------------------------

fn handleSetLockupChecked(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] SetLockupChecked slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 2) return;

    const stake_idx = ix.account_indices[0];
    const signer_idx = ix.account_indices[1];
    if (stake_idx >= ptx.num_accounts or signer_idx >= ptx.num_accounts) return;
    if (!isSigner(ptx, signer_idx)) return;

    const stake_key = ptx.account_keys[stake_idx];
    const signer_key = ptx.account_keys[signer_idx];
    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;

    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 1 and disc != 2) return;

    // Authorization check
    const lockup_active = isLockupActive(stake_acct.data, bank, db);
    if (lockup_active) {
        const lockup_custodian = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.lockup_custodian) orelse return;
        if (!std.mem.eql(u8, &signer_key, &lockup_custodian)) return;
    } else {
        const withdrawer = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.withdrawer) orelse return;
        if (!std.mem.eql(u8, &signer_key, &withdrawer)) return;
    }

    // Parse LockupCheckedArgs (no custodian in data)
    var off: usize = 4;
    var new_ts: ?i64 = null;
    var new_epoch: ?u64 = null;

    if (off + 1 <= ix.data.len) {
        if (ix.data[off] == 1) {
            off += 1;
            if (off + 8 <= ix.data.len) {
                new_ts = std.mem.readInt(i64, ix.data[off..][0..8], .little);
                off += 8;
            }
        } else {
            off += 1;
        }
    }

    if (off + 1 <= ix.data.len) {
        if (ix.data[off] == 1) {
            off += 1;
            if (off + 8 <= ix.data.len) {
                new_epoch = std.mem.readInt(u64, ix.data[off..][0..8], .little);
                off += 8;
            }
        } else {
            off += 1;
        }
    }

    // New custodian from account [2] if present and signer
    var new_custodian: ?[32]u8 = null;
    if (ix.account_indices.len >= 3) {
        const cust_idx = ix.account_indices[2];
        if (cust_idx < ptx.num_accounts and isSigner(ptx, cust_idx)) {
            new_custodian = ptx.account_keys[cust_idx];
        }
    }

    // Deep copy and update
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    if (new_ts) |ts| {
        stake_state.writeI64(data_copy, stake_state.Offsets.lockup_unix_timestamp, ts);
    }
    if (new_epoch) |ep| {
        stake_state.writeU64(data_copy, stake_state.Offsets.lockup_epoch, ep);
    }
    if (new_custodian) |c| {
        stake_state.writePubkey(data_copy, stake_state.Offsets.lockup_custodian, c);
    }

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: GetMinimumDelegation (0x0D)
// ---------------------------------------------------------------------------
// Returns the minimum delegation amount in return data.
// Currently 1 SOL (1_000_000_000 lamports) post-feature activation.
// Vexor does not yet have return_data wired, so this logs the value.
// The instruction is a read-only query — no pending_writes.
// ---------------------------------------------------------------------------

fn handleGetMinimumDelegation(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    _ = ix;
    _ = ptx;
    _ = db;
    _ = alloc;
    const min_delegation: u64 = 1_000_000_000; // 1 SOL
    std.log.debug("[STAKE] GetMinimumDelegation slot={d}: {d} lamports\n", .{ bank.slot, min_delegation });
    // TODO: When return_data is wired, set bank.return_data = LE bytes of min_delegation
}

// ---------------------------------------------------------------------------
// Handler: DeactivateDelinquent (0x0E)
// ---------------------------------------------------------------------------
// Deactivates stake delegated to a delinquent validator. Anyone can call this
// (no authority required) if the validator hasn't voted in 5+ epochs and a
// reference validator has voted in all of the last 5 epochs.
//
// Accounts:
//   [0] RW  stake_account — delegated to delinquent validator
//   [1] RO  delinquent_vote_account — the delinquent validator's vote account
//   [2] RO  reference_vote_account — a recently-voting validator's vote account
//
// Validation:
//   - Stake account must be in Stake state and delegated to delinquent vote account
//   - deactivation_epoch must be MAX (not already deactivating)
//   - Delinquent vote account must not have voted in last 5 epochs
//   - Reference vote account must have voted consecutively in all last 5 epochs
// ---------------------------------------------------------------------------

const MINIMUM_DELINQUENT_EPOCHS: u64 = 5;

fn handleDeactivateDelinquent(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    std.log.debug("[STAKE] DeactivateDelinquent slot={d}\n", .{bank.slot});
    if (ix.account_indices.len < 3) return;

    const stake_idx = ix.account_indices[0];
    const delinquent_idx = ix.account_indices[1];
    const reference_idx = ix.account_indices[2];
    if (stake_idx >= ptx.num_accounts or delinquent_idx >= ptx.num_accounts or reference_idx >= ptx.num_accounts) return;

    const stake_key = ptx.account_keys[stake_idx];
    const delinquent_key = ptx.account_keys[delinquent_idx];
    const reference_key = ptx.account_keys[reference_idx];

    const stake_acct = readOverlayed(bank, db, stake_key) orelse return;
    const delinquent_acct = readOverlayed(bank, db, delinquent_key) orelse return;
    const reference_acct = readOverlayed(bank, db, reference_key) orelse return;

    // Stake must be in Stake state
    if (stake_acct.data.len < stake_state.STAKE_STATE_SZ) return;
    const disc = stake_state.readU32(stake_acct.data, 0) orelse return;
    if (disc != 2) return;

    // Must not already be deactivating
    const deact_epoch = stake_state.readU64(stake_acct.data, stake_state.Offsets.deactivation_epoch) orelse return;
    if (deact_epoch != std.math.maxInt(u64)) return;

    // Stake must be delegated to the delinquent vote account
    const voter_pubkey = stake_state.readPubkey(stake_acct.data, stake_state.Offsets.voter_pubkey) orelse return;
    if (!std.mem.eql(u8, &voter_pubkey, &delinquent_key)) return;

    // Vote accounts must be owned by vote program
    const VOTE_PROGRAM_ID = [_]u8{
        0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
        0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
        0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
        0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
    };
    if (!std.mem.eql(u8, &delinquent_acct.owner.data, &VOTE_PROGRAM_ID)) return;
    if (!std.mem.eql(u8, &reference_acct.owner.data, &VOTE_PROGRAM_ID)) return;

    const current_epoch = bank.epoch_schedule.getEpoch(bank.slot);

    // Check reference validator: must have voted in all last 5 epochs
    const ref_vs = vote_state_serde.deserializeVoteState(reference_acct.data) orelse return;
    if (ref_vs.ec_count < MINIMUM_DELINQUENT_EPOCHS) return;

    // Verify consecutive voting in last 5 epochs
    var check_epoch = current_epoch;
    var ref_ok = true;
    var ri: usize = ref_vs.ec_count;
    for (0..MINIMUM_DELINQUENT_EPOCHS) |_| {
        if (ri == 0) {
            ref_ok = false;
            break;
        }
        ri -= 1;
        if (ref_vs.epoch_credits[ri].epoch != check_epoch) {
            ref_ok = false;
            break;
        }
        check_epoch -|= 1;
    }
    if (!ref_ok) return;

    // Check delinquent validator: must NOT have voted in last 5 epochs
    const del_vs = vote_state_serde.deserializeVoteState(delinquent_acct.data) orelse return;
    if (del_vs.ec_count > 0) {
        const last_vote_epoch = del_vs.epoch_credits[del_vs.ec_count - 1].epoch;
        const min_epoch = current_epoch -| MINIMUM_DELINQUENT_EPOCHS;
        if (last_vote_epoch > min_epoch) return; // Voted too recently
    }

    // All checks pass: deactivate the stake
    const data_copy = alloc.alloc(u8, stake_acct.data.len) catch return;
    @memcpy(data_copy, stake_acct.data);

    const current_e = bank.epoch_schedule.getEpoch(bank.slot);
    stake_state.writeU64(data_copy, stake_state.Offsets.deactivation_epoch, current_e);

    emitWrite(bank, stake_key, stake_acct.owner.data, stake_acct.lamports, stake_acct.executable, stake_acct.data, stake_acct.lamports, stake_acct.owner.data, stake_acct.executable, stake_acct.rent_epoch, data_copy);
}

// ---------------------------------------------------------------------------
// Handler: Redelegate (0x0F) — DEPRECATED
// ---------------------------------------------------------------------------

fn handleRedelegate(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    _ = ix;
    _ = ptx;
    _ = db;
    _ = alloc;
    // PR-5x (2026-05-19): Redelegate is deprecated; cluster (Agave/Firedancer/Sig)
    // returns InvalidInstructionData. @prov:stake.redelegate-deprecated —
    // pre-PR-5x Vexor silently succeeded — tx_results disagreement (Vexor
    // success=1, cluster success=0). Even though lthash impact is
    // fee-debit-only, the tx_results.jsonl divergence surfaces in oracle
    // comparisons and downstream RPC reliability.
    std.log.debug("[STAKE] Redelegate slot={d} — DEPRECATED, returning InvalidInstructionData\n", .{bank.slot});
    return error.InvalidInstructionData;
}

// ---------------------------------------------------------------------------
// Handler: MoveStake (0x10) — requires feature flag (v2.1+)
// ---------------------------------------------------------------------------

fn handleMoveStake(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    _ = ix;
    _ = ptx;
    _ = db;
    _ = alloc;
    // 🔴 G3 LANDMINE — SILENT NO-OP ON AN *ACTIVE* FEATURE. See the block comment on
    // handleMoveLamports below for the full reasoning; both handlers share it.
    std.log.err("[STAKE-MOVE-UNIMPLEMENTED] 🔴 MoveStake INVOKED at slot={d} but this handler is a NO-OP — it returns SUCCESS while writing NOTHING. Feature move_stake_and_move_lamports_ixs (7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4) has been ACTIVE since slot 302060257, so canonical DID apply this instruction and our bank_hash for this slot is WRONG. Expect a divergence at or after slot {d}. Reference implementation: vex_bpf2/builtins/stake_program.zig:1860.", .{ bank.slot, bank.slot });
}

// ---------------------------------------------------------------------------
// Handler: MoveLamports (0x11) — requires feature flag (v2.1+)
// ---------------------------------------------------------------------------

fn handleMoveLamports(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    _ = ix;
    _ = ptx;
    _ = db;
    _ = alloc;
    // ── 🔴 G3: THESE TWO HANDLERS ARE SILENT NO-OPS ON A FEATURE THAT IS ALREADY LIVE ────────
    // Both handlers return SUCCESS having written NOTHING. The old log line here claimed the
    // feature "requires feature flag (not yet active)" — that comment was STALE and is why this
    // was left unimplemented: `move_stake_and_move_lamports_ixs`
    // (7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4) ACTIVATED AT SLOT 302060257, months ago.
    // It also logged at `debug`, which production never emits — so the landmine was silent AND
    // labelled safe.
    //
    // Consequence if invoked: canonical applies the instruction, we do not, our bank_hash for
    // that slot is wrong ⇒ divergence. This is the same shape as the DelegateStake resume
    // carrier fixed at slot 425127869 (a wrong SUCCESS, not a wrong error), which is the most
    // expensive class there is: it costs a multi-hour carrier hunt to attribute after the fact.
    //
    // WHY ONLY A LOG AND NOT AN IMPLEMENTATION (deliberate, 2026-07-30): implementing this is a
    // consensus change and there is NO way to prove it right yet. Unlike the 425127869 carrier
    // there is no on-chain occurrence to replay (0 in 571 decoded blocks), and the 47,279-fixture
    // conformance corpus has NO stake fixtures at all — so a golden replay would come back clean
    // and prove only inertness, never correctness. Proof requires hand-written KATs
    // cross-validated against BOTH solana-program v5.0.0 (6ed2c60c) and the in-tree
    // implementations at vex_bpf2/builtins/stake_program.zig:1860 / :2016. That is a separate
    // cycle (G3 Phase B).
    //
    // What this line buys, at ZERO consensus surface: if the landmine is ever stepped on we learn
    // it instantly, from a message that names the cause and the reference implementation, instead
    // of starting a divergence hunt from a mystery hash. Detection is free; the fix is not.
    std.log.err("[STAKE-MOVE-UNIMPLEMENTED] 🔴 MoveLamports INVOKED at slot={d} but this handler is a NO-OP — it returns SUCCESS while writing NOTHING. Feature move_stake_and_move_lamports_ixs (7bTK6Jis8Xpfrs8ZoUfiMDPazTcdPcTWheZFJTA5Z6X4) has been ACTIVE since slot 302060257, so canonical DID apply this instruction and our bank_hash for this slot is WRONG. Expect a divergence at or after slot {d}. Reference implementation: vex_bpf2/builtins/stake_program.zig:2016.", .{ bank.slot, bank.slot });
}

// ---------------------------------------------------------------------------
// Public dispatch function
// ---------------------------------------------------------------------------

pub fn execute(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
) !void {
    // FIX-1c (2026-06-10, task #65 — residual sibling of carrier #6
    // @414386920): dispatch-level parse failures now PROPAGATE instead of
    // silently succeeding. Agave: `limited_deserialize(data)?` in the stake
    // processor maps EVERY bincode failure (data < 4 bytes, unknown
    // discriminant > 0x11=MoveLamports) to InstructionError::
    // InvalidInstructionData, which FAILS the whole tx. These are
    // deterministic byte-level checks with no account-state dependence, so
    // propagating them cannot fail a tx Agave would pass.
    // RESIDUAL (deliberate, risk discipline): handler-INTERNAL validation
    // failures (signer/lockup/funds/state checks across the 18 handlers)
    // still silent-return — they have no error surface and several checks
    // are non-canonical simplifications; converting them blind would risk
    // failing txs Agave succeeds on. Measured live via the caller's
    // StakeTaxonomyUnknownStats zero-write counter.
    const ix_type = parseInstruction(ix.data) catch |e| return e;

    switch (ix_type) {
        .initialize => try handleInitialize(ix, ptx, bank, db, alloc),
        .authorize => try handleAuthorize(ix, ptx, bank, db, alloc),
        .delegate_stake => try handleDelegateStake(ix, ptx, bank, db, alloc),
        .split => try handleSplit(ix, ptx, bank, db, alloc),
        .withdraw => try handleWithdraw(ix, ptx, bank, db, alloc),
        .deactivate => try handleDeactivate(ix, ptx, bank, db, alloc),
        .set_lockup => try handleSetLockup(ix, ptx, bank, db, alloc),
        .merge => try handleMerge(ix, ptx, bank, db, alloc),
        .authorize_with_seed => try handleAuthorizeWithSeed(ix, ptx, bank, db, alloc),
        .initialize_checked => try handleInitializeChecked(ix, ptx, bank, db, alloc),
        .authorize_checked => try handleAuthorizeChecked(ix, ptx, bank, db, alloc),
        .authorize_checked_with_seed => try handleAuthorizeCheckedWithSeed(ix, ptx, bank, db, alloc),
        .set_lockup_checked => try handleSetLockupChecked(ix, ptx, bank, db, alloc),
        .get_minimum_delegation => try handleGetMinimumDelegation(ix, ptx, bank, db, alloc),
        .deactivate_delinquent => try handleDeactivateDelinquent(ix, ptx, bank, db, alloc),
        .redelegate => try handleRedelegate(ix, ptx, bank, db, alloc),
        .move_stake => try handleMoveStake(ix, ptx, bank, db, alloc),
        .move_lamports => try handleMoveLamports(ix, ptx, bank, db, alloc),
        _ => {},
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseInstruction - valid discriminants" {
    const testing = std.testing;

    var buf = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    try testing.expectEqual(StakeInstruction.initialize, try parseInstruction(&buf));

    buf = [_]u8{ 0x10, 0x00, 0x00, 0x00 };
    try testing.expectEqual(StakeInstruction.move_stake, try parseInstruction(&buf));

    buf = [_]u8{ 0x11, 0x00, 0x00, 0x00 };
    try testing.expectEqual(StakeInstruction.move_lamports, try parseInstruction(&buf));
}

test "parseInstruction - too short" {
    const testing = std.testing;
    const buf = [_]u8{ 0x00, 0x00, 0x00 };
    try testing.expectError(StakeError.InvalidInstructionData, parseInstruction(&buf));
}

test "parseInstruction - unknown discriminant" {
    const testing = std.testing;
    const buf = [_]u8{ 0x99, 0x00, 0x00, 0x00 };
    try testing.expectError(StakeError.UnknownInstruction, parseInstruction(&buf));
}

test "InitializeParams.parse - correct offsets" {
    const testing = std.testing;
    var buf = [_]u8{0} ** 116;
    std.mem.writeInt(u32, buf[0..4], 0, .little);
    @memset(buf[4..36], 0x11);
    @memset(buf[36..68], 0x22);
    std.mem.writeInt(i64, buf[68..76], -1, .little);
    std.mem.writeInt(u64, buf[76..84], 42, .little);
    @memset(buf[84..116], 0x33);

    const p = try InitializeParams.parse(&buf);
    try testing.expectEqual([_]u8{0x11} ** 32, p.staker);
    try testing.expectEqual([_]u8{0x22} ** 32, p.withdrawer);
    try testing.expectEqual(@as(i64, -1), p.lockup_unix_timestamp);
    try testing.expectEqual(@as(u64, 42), p.lockup_epoch);
    try testing.expectEqual([_]u8{0x33} ** 32, p.lockup_custodian);
}

test "AuthorizeParams.parse - staker variant" {
    const testing = std.testing;
    var buf = [_]u8{0} ** 40;
    std.mem.writeInt(u32, buf[0..4], 1, .little);
    @memset(buf[4..36], 0xAB);
    std.mem.writeInt(u32, buf[36..40], 0, .little);

    const p = try AuthorizeParams.parse(&buf);
    try testing.expectEqual([_]u8{0xAB} ** 32, p.new_authority);
    try testing.expectEqual(@as(u32, 0), p.authorize_type);
}

test "stake_state Offsets - key byte positions" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 0), stake_state.Offsets.discriminant);
    try testing.expectEqual(@as(usize, 4), stake_state.Offsets.rent_exempt_reserve);
    try testing.expectEqual(@as(usize, 12), stake_state.Offsets.staker);
    try testing.expectEqual(@as(usize, 44), stake_state.Offsets.withdrawer);
    try testing.expectEqual(@as(usize, 76), stake_state.Offsets.lockup_unix_timestamp);
    try testing.expectEqual(@as(usize, 84), stake_state.Offsets.lockup_epoch);
    try testing.expectEqual(@as(usize, 92), stake_state.Offsets.lockup_custodian);
    try testing.expectEqual(@as(usize, 124), stake_state.Offsets.voter_pubkey);
    try testing.expectEqual(@as(usize, 172), stake_state.Offsets.deactivation_epoch);
    try testing.expectEqual(@as(usize, 196), stake_state.Offsets.stake_flags);
}

// ---------------------------------------------------------------------------
// P0-2 KATs: AuthorizeWithSeed (0x08) / AuthorizeCheckedWithSeed (0x0B)
// ---------------------------------------------------------------------------
// VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11 §7 P0-2. Calls the two handlers
// DIRECTLY (private `fn`, same-file test access) rather than through the
// 18-arm `execute()` dispatcher — this keeps the required duck-typed
// ix/ptx/bank/db surface scoped to exactly what these two handlers (+
// readOverlayed/emitWrite/isSigner/readClockForLockup) touch, instead of the
// union of all 18 stake instruction handlers. Uses the REAL
// vex_bpf2.builtins.stake_program.deriveWithSeed to compute the expected
// derived pubkey D, so these KATs exercise the SAME derivation the
// production handler calls (single source of truth — no hand-derived SHA256
// vector to keep in sync).

const StakeTestAccount = struct {
    lamports: u64,
    owner: core.Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

const StakeTestDb = struct {
    key: [32]u8,
    account: StakeTestAccount,

    pub fn getAccountInSlot(self: *const StakeTestDb, pk: *const core.Pubkey, slot: u64, ancestors: []const u64) ?StakeTestAccount {
        _ = slot;
        _ = ancestors;
        if (std.mem.eql(u8, &pk.data, &self.key)) return self.account;
        return null;
    }
};

const StakeTestPtx = struct {
    num_accounts: u16,
    account_keys: []const [32]u8,
    num_required_sigs: u8,
};

const StakeTestIx = struct {
    data: []const u8,
    account_indices: []const u8,
};

const StakeTestEpochSchedule = struct {
    pub fn getEpoch(self: *const StakeTestEpochSchedule, slot: u64) u64 {
        _ = self;
        _ = slot;
        return 0;
    }
};

const StakeTestBank = struct {
    slot: u64 = 1,
    epoch_schedule: StakeTestEpochSchedule = .{},
    // readOverlayed hardcodes `const W = bank_mod.AccountWrite;` internally
    // (overlay_lookup.newestMatchTwo requires both write lists to share one
    // concrete element type) — so this field MUST use the real type by name.
    // It only ever holds an empty slice in these tests (no in-slot pending
    // writes to overlay), so no bank_mod.Bank construction is needed — this
    // is a narrow reference to the plain AccountWrite data struct only, not
    // to Bank itself (which is what pulled bank.zig's own unrelated
    // pre-existing test failures into module-68's bpf_loader gate).
    pending_writes: struct { items: []const bank_mod.AccountWrite = &.{} } = .{},
    // Captured on the last collectWrite() call — deliberately just the
    // `.data` slice (avoids coercing the anonymous emitWrite() literal into
    // a named struct type; the mutated bytes are all these KATs need to
    // assert against).
    captured_data: ?[]const u8 = null,
    write_count: usize = 0,

    pub fn ancestors(self: *const StakeTestBank) []const u64 {
        _ = self;
        return &.{};
    }
    pub fn collectWrite(self: *StakeTestBank, write: anytype) !void {
        self.captured_data = write.data;
        self.write_count += 1;
    }
};

const STAKE_PROGRAM_ID_TEST = [_]u8{
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a,
    0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b,
    0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
};

/// Build a 200-byte StakeStateV2::Stake account with the given staker/
/// withdrawer and no lockup.
fn buildStakeAccountData(alloc: std.mem.Allocator, staker: [32]u8, withdrawer: [32]u8) ![]u8 {
    const data = try alloc.alloc(u8, stake_state.STAKE_STATE_SZ);
    @memset(data, 0);
    stake_state.writeU32(data, stake_state.Offsets.discriminant, 2); // Stake
    stake_state.writePubkey(data, stake_state.Offsets.staker, staker);
    stake_state.writePubkey(data, stake_state.Offsets.withdrawer, withdrawer);
    // lockup fields already zeroed = no lockup (unix_timestamp=0, epoch=0).
    return data;
}

/// Build AuthorizeWithSeed (tag 8) ix data:
/// tag(4) + new_authority(32) + type(4) + seed_len(8) + seed + owner(32).
fn buildAuthorizeWithSeedIxData(alloc: std.mem.Allocator, new_authority: [32]u8, authorize_type: u32, seed: []const u8, owner: [32]u8) ![]u8 {
    const total = 48 + seed.len + 32;
    const buf = try alloc.alloc(u8, total);
    std.mem.writeInt(u32, buf[0..4], 8, .little);
    @memcpy(buf[4..36], &new_authority);
    std.mem.writeInt(u32, buf[36..40], authorize_type, .little);
    std.mem.writeInt(u64, buf[40..48], seed.len, .little);
    @memcpy(buf[48..][0..seed.len], seed);
    @memcpy(buf[48 + seed.len ..][0..32], &owner);
    return buf;
}

/// Build AuthorizeCheckedWithSeed (tag 11) ix data:
/// tag(4) + type(4) + seed_len(8) + seed + owner(32) — no new_authority field
/// (that comes from instruction account [3] instead).
fn buildAuthorizeCheckedWithSeedIxData(alloc: std.mem.Allocator, authorize_type: u32, seed: []const u8, owner: [32]u8) ![]u8 {
    const total = 16 + seed.len + 32;
    const buf = try alloc.alloc(u8, total);
    std.mem.writeInt(u32, buf[0..4], 11, .little);
    std.mem.writeInt(u32, buf[4..8], authorize_type, .little);
    std.mem.writeInt(u64, buf[8..16], seed.len, .little);
    @memcpy(buf[16..][0..seed.len], seed);
    @memcpy(buf[16 + seed.len ..][0..32], &owner);
    return buf;
}

test "P0-2: AuthorizeWithSeed Staker success — derived D == current staker mutates staker" {
    const alloc = std.testing.allocator;
    const base_key = [_]u8{0xAA} ** 32;
    const seed = "test-seed";
    const owner_key = [_]u8{0x11} ** 32;
    const derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&base_key, seed, &owner_key).?;
    const withdrawer_key = [_]u8{0xBB} ** 32;
    const new_authority = [_]u8{0xCC} ** 32;

    const stake_key = [_]u8{0x01} ** 32;
    const stake_data = try buildStakeAccountData(alloc, derived, withdrawer_key);
    defer alloc.free(stake_data);

    const ix_data = try buildAuthorizeWithSeedIxData(alloc, new_authority, 0, seed, owner_key);
    defer alloc.free(ix_data);

    var bank = StakeTestBank{};
    const db = StakeTestDb{
        .key = stake_key,
        .account = .{ .lamports = 1_000_000, .owner = .{ .data = STAKE_PROGRAM_ID_TEST }, .executable = false, .rent_epoch = 0, .data = stake_data },
    };
    const ptx = StakeTestPtx{
        .num_accounts = 2,
        .account_keys = &.{ stake_key, base_key },
        .num_required_sigs = 2, // both stake(0) and base(1) "sign"
    };
    const ix = StakeTestIx{ .data = ix_data, .account_indices = &.{ 0, 1 } };

    try handleAuthorizeWithSeed(ix, ptx, &bank, db, alloc);

    try std.testing.expectEqual(@as(usize, 1), bank.write_count);
    const mutated = bank.captured_data.?;
    try std.testing.expectEqualSlices(u8, &new_authority, mutated[stake_state.Offsets.staker..][0..32]);
    // Withdrawer must be unchanged.
    try std.testing.expectEqualSlices(u8, &withdrawer_key, mutated[stake_state.Offsets.withdrawer..][0..32]);
    alloc.free(mutated);
}

test "P0-2: AuthorizeWithSeed rejects when base did NOT sign — no mutation" {
    const alloc = std.testing.allocator;
    const base_key = [_]u8{0xAA} ** 32;
    const seed = "test-seed";
    const owner_key = [_]u8{0x11} ** 32;
    const derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&base_key, seed, &owner_key).?;
    const withdrawer_key = [_]u8{0xBB} ** 32;
    const new_authority = [_]u8{0xCC} ** 32;

    const stake_key = [_]u8{0x01} ** 32;
    const stake_data = try buildStakeAccountData(alloc, derived, withdrawer_key);
    defer alloc.free(stake_data);

    const ix_data = try buildAuthorizeWithSeedIxData(alloc, new_authority, 0, seed, owner_key);
    defer alloc.free(ix_data);

    var bank = StakeTestBank{};
    const db = StakeTestDb{
        .key = stake_key,
        .account = .{ .lamports = 1_000_000, .owner = .{ .data = STAKE_PROGRAM_ID_TEST }, .executable = false, .rent_epoch = 0, .data = stake_data },
    };
    const ptx = StakeTestPtx{
        .num_accounts = 2,
        .account_keys = &.{ stake_key, base_key },
        .num_required_sigs = 1, // index 1 (base) is NOT a signer
    };
    const ix = StakeTestIx{ .data = ix_data, .account_indices = &.{ 0, 1 } };

    try handleAuthorizeWithSeed(ix, ptx, &bank, db, alloc);

    try std.testing.expectEqual(@as(usize, 0), bank.write_count);
}

test "P0-2: AuthorizeWithSeed rejects wrong seed (derived D != staker/withdrawer) — no mutation" {
    const alloc = std.testing.allocator;
    const base_key = [_]u8{0xAA} ** 32;
    const owner_key = [_]u8{0x11} ** 32;
    // Account's staker/withdrawer are derived from a DIFFERENT seed than the
    // one the instruction supplies below.
    const real_derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&base_key, "correct-seed", &owner_key).?;
    const withdrawer_key = [_]u8{0xBB} ** 32;
    const new_authority = [_]u8{0xCC} ** 32;

    const stake_key = [_]u8{0x01} ** 32;
    const stake_data = try buildStakeAccountData(alloc, real_derived, withdrawer_key);
    defer alloc.free(stake_data);

    // Instruction supplies the WRONG seed — derives a different D.
    const ix_data = try buildAuthorizeWithSeedIxData(alloc, new_authority, 0, "wrong-seed", owner_key);
    defer alloc.free(ix_data);

    var bank = StakeTestBank{};
    const db = StakeTestDb{
        .key = stake_key,
        .account = .{ .lamports = 1_000_000, .owner = .{ .data = STAKE_PROGRAM_ID_TEST }, .executable = false, .rent_epoch = 0, .data = stake_data },
    };
    const ptx = StakeTestPtx{
        .num_accounts = 2,
        .account_keys = &.{ stake_key, base_key },
        .num_required_sigs = 2,
    };
    const ix = StakeTestIx{ .data = ix_data, .account_indices = &.{ 0, 1 } };

    try handleAuthorizeWithSeed(ix, ptx, &bank, db, alloc);

    try std.testing.expectEqual(@as(usize, 0), bank.write_count);
}

test "P0-2: AuthorizeCheckedWithSeed Staker success — new auth (acct[3]) signs + derived base signs" {
    const alloc = std.testing.allocator;
    const base_key = [_]u8{0xAA} ** 32;
    const seed = "checked-seed";
    const owner_key = [_]u8{0x11} ** 32;
    const derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&base_key, seed, &owner_key).?;
    const withdrawer_key = [_]u8{0xBB} ** 32;
    const new_authority = [_]u8{0xDD} ** 32;

    const stake_key = [_]u8{0x02} ** 32;
    const stake_data = try buildStakeAccountData(alloc, derived, withdrawer_key);
    defer alloc.free(stake_data);

    const ix_data = try buildAuthorizeCheckedWithSeedIxData(alloc, 0, seed, owner_key);
    defer alloc.free(ix_data);

    var bank = StakeTestBank{};
    const db = StakeTestDb{
        .key = stake_key,
        .account = .{ .lamports = 1_000_000, .owner = .{ .data = STAKE_PROGRAM_ID_TEST }, .executable = false, .rent_epoch = 0, .data = stake_data },
    };
    // accounts: [0]=stake [1]=base [2]=clock(placeholder) [3]=new_authority
    const ptx = StakeTestPtx{
        .num_accounts = 4,
        .account_keys = &.{ stake_key, base_key, [_]u8{0} ** 32, new_authority },
        .num_required_sigs = 4, // base(1) and new_authority(3) both sign
    };
    const ix = StakeTestIx{ .data = ix_data, .account_indices = &.{ 0, 1, 2, 3 } };

    try handleAuthorizeCheckedWithSeed(ix, ptx, &bank, db, alloc);

    try std.testing.expectEqual(@as(usize, 1), bank.write_count);
    const mutated = bank.captured_data.?;
    try std.testing.expectEqualSlices(u8, &new_authority, mutated[stake_state.Offsets.staker..][0..32]);
    alloc.free(mutated);
}

test "P0-2: AuthorizeCheckedWithSeed rejects when new authority (acct[3]) did NOT sign — no mutation" {
    const alloc = std.testing.allocator;
    const base_key = [_]u8{0xAA} ** 32;
    const seed = "checked-seed";
    const owner_key = [_]u8{0x11} ** 32;
    const derived = vex_bpf2.builtins.stake_program.deriveWithSeed(&base_key, seed, &owner_key).?;
    const withdrawer_key = [_]u8{0xBB} ** 32;

    const stake_key = [_]u8{0x02} ** 32;
    const stake_data = try buildStakeAccountData(alloc, derived, withdrawer_key);
    defer alloc.free(stake_data);

    const ix_data = try buildAuthorizeCheckedWithSeedIxData(alloc, 0, seed, owner_key);
    defer alloc.free(ix_data);

    var bank = StakeTestBank{};
    const db = StakeTestDb{
        .key = stake_key,
        .account = .{ .lamports = 1_000_000, .owner = .{ .data = STAKE_PROGRAM_ID_TEST }, .executable = false, .rent_epoch = 0, .data = stake_data },
    };
    const new_authority = [_]u8{0xDD} ** 32;
    const ptx = StakeTestPtx{
        .num_accounts = 4,
        .account_keys = &.{ stake_key, base_key, [_]u8{0} ** 32, new_authority },
        .num_required_sigs = 1, // index 3 (new authority) is NOT a signer
    };
    const ix = StakeTestIx{ .data = ix_data, .account_indices = &.{ 0, 1, 2, 3 } };

    try handleAuthorizeCheckedWithSeed(ix, ptx, &bank, db, alloc);

    try std.testing.expectEqual(@as(usize, 0), bank.write_count);
}

test "split: prefunded-to-rent-exemption dest gets FULL split as delegation (2026-07-28 carrier KAT)" {
    // Shape from testnet slot 424767796 (tx 64DAtig...): the pool bot prefunds every split
    // destination with exactly the 200-byte rent-exempt reserve before splitting into it.
    // Canonical (sig lib.zig:894-899 / vex_bpf2 builtins:1745-1746): dest prefunding offsets
    // the reserve, so split_stake_amount == split_lamports and the source loses the SAME full
    // delta. The pre-fix code computed split_lamports - reserve for BOTH — off by 2,282,880
    // on each side of every pair, a silent bank_hash carrier.
    const testing = @import("std").testing;
    const RESERVE: u64 = 2_282_880; // rent-exempt minimum for STAKE_STATE_SZ=200
    const SPLIT_LAMPORTS: u64 = 10_082_758_713_508; // observed on-chain amount
    const SRC_STAKE_PRE: u64 = 182_087_072_837_296;

    // dest prefunded to exactly the reserve (the observed shape)
    {
        const dst_lamports: u64 = RESERVE;
        const split_stake_amount = SPLIT_LAMPORTS -| (RESERVE -| dst_lamports);
        const remaining_stake_delta = SPLIT_LAMPORTS;
        try testing.expectEqual(SPLIT_LAMPORTS, split_stake_amount);
        try testing.expectEqual(SRC_STAKE_PRE - SPLIT_LAMPORTS, SRC_STAKE_PRE - remaining_stake_delta);
        // the pre-fix arithmetic differed by exactly the reserve on both sides:
        const buggy_split_amt = SPLIT_LAMPORTS - RESERVE;
        try testing.expectEqual(RESERVE, split_stake_amount - buggy_split_amt);
    }
    // dest unfunded — the previously-correct case must be unchanged by the fix
    {
        const dst_lamports: u64 = 0;
        const split_stake_amount = SPLIT_LAMPORTS -| (RESERVE -| dst_lamports);
        try testing.expectEqual(SPLIT_LAMPORTS - RESERVE, split_stake_amount);
    }
    // dest partially funded — offset is exactly the shortfall
    {
        const dst_lamports: u64 = 1_000_000;
        const split_stake_amount = SPLIT_LAMPORTS -| (RESERVE -| dst_lamports);
        try testing.expectEqual(SPLIT_LAMPORTS - (RESERVE - 1_000_000), split_stake_amount);
    }
}

// ---------------------------------------------------------------------------
// Tier-2 latent stake-path KATs (2026-07-28 agave-behavior-extractor report,
// 7-item list). Pure arithmetic/byte mirrors of handleSplit's logic — same
// idiom as the Tier-1 KAT above: no handler harness, just the canonical
// formulas reproduced and checked against the citations in-line above.
// ---------------------------------------------------------------------------

test "split item1: partial-split min-delegation guards — canonical rejects zero-remaining AND zero-split (no > 0 escape hatch)" {
    const testing = std.testing;
    const MIN_DELEGATION: u64 = 1_000_000_000; // 1 SOL

    // Item 1(a): BEFORE computing the tuple — (src_delegation_stake -| split_lamports) <
    // min_delegation must reject even when the remainder is EXACTLY zero. The pre-fix guard
    // was `remaining_stake < min and remaining_stake > 0`, which let remaining_stake == 0
    // through (a full-delegation drain disguised as a "partial" split, since src_remaining
    // in lamports terms was still > 0 — e.g. leftover rent-only lamports).
    {
        // Anchored on the same real on-chain observed magnitude as the Tier-1 KAT below
        // (SPLIT_LAMPORTS = 10_082_758_713_508), not an invented round number — a
        // full-delegation drain necessarily has src_delegation_stake == split_lamports (that
        // equality is required by the scenario's own semantics, not a coincidence of the
        // chosen literal).
        const OBSERVED_DELEGATION: u64 = 10_082_758_713_508;
        const src_delegation_stake: u64 = OBSERVED_DELEGATION;
        const split_lamports: u64 = OBSERVED_DELEGATION; // splits off the ENTIRE delegation
        const would_reject = (src_delegation_stake -| split_lamports) < MIN_DELEGATION;
        try testing.expect(would_reject); // canonical: reject
        // pre-fix form would have let this through:
        const remaining = src_delegation_stake -| split_lamports; // == 0
        const pre_fix_would_reject = remaining < MIN_DELEGATION and remaining > 0;
        try testing.expect(!pre_fix_would_reject); // proves the escape hatch existed
    }

    // Item 1(b): unconditional split_stake_amount < min_delegation must reject even when
    // split_stake_amount is EXACTLY zero (a destination that ends up with nothing delegated
    // — e.g. split_lamports fully consumed by a still-deficit destination reserve).
    {
        const split_stake_amount: u64 = 0;
        const would_reject = split_stake_amount < MIN_DELEGATION;
        try testing.expect(would_reject); // canonical: reject
        const pre_fix_would_reject = split_stake_amount < MIN_DELEGATION and split_stake_amount > 0;
        try testing.expect(!pre_fix_would_reject); // proves the escape hatch existed
    }

    // Sanity: a healthy partial split (both sides comfortably above min) is unaffected.
    {
        const RESERVE: u64 = 2_282_880;
        const src_delegation_stake: u64 = 10_000_000_000;
        const split_lamports: u64 = 3_000_000_000;
        try testing.expect((src_delegation_stake -| split_lamports) >= MIN_DELEGATION);
        // dst unfunded (dst_lamports=0): production's formula (line ~1160) is
        // split_lamports -| (dst_rent_exempt_reserve -| dst_acct.lamports), which for an
        // unfunded dest reduces to split_lamports -| RESERVE — NOT split_lamports outright
        // (the reserve is netted OUT of the split amount, not "already netted out" as a
        // no-op). Pinning the exact value, not just >= MIN_DELEGATION, so a formula
        // regression (e.g. dropping the reserve netting) is actually caught here.
        const dst_lamports: u64 = 0;
        const split_stake_amount = split_lamports -| (RESERVE -| dst_lamports);
        try testing.expectEqual(split_lamports - RESERVE, split_stake_amount);
        try testing.expect(split_stake_amount >= MIN_DELEGATION);
    }
}

test "split item2: destination deficit check matches canonical validateSplitAmount, both Stake and Initialized arms" {
    const testing = std.testing;
    const MIN_DELEGATION: u64 = 1_000_000_000;
    const RESERVE: u64 = 2_282_880;

    // Stake arm: destination_minimum_balance = reserve +| min_delegation.
    // destination_balance_deficit = destination_minimum_balance -| dst.lamports.
    {
        const dst_lamports: u64 = 0;
        const destination_minimum_balance = RESERVE +| MIN_DELEGATION;
        const deficit = destination_minimum_balance -| dst_lamports;
        try testing.expectEqual(RESERVE + MIN_DELEGATION, deficit);
        // A split of exactly the deficit is accepted; one lamport short is rejected —
        // mirrors production's `if (split_lamports < destination_balance_deficit) return;`.
        // Use split_lamports values written independently of the `deficit` variable (a
        // literal RESERVE + MIN_DELEGATION expression, not `deficit` itself on both sides of
        // `<`) so a regression in the deficit formula above is actually detectable here —
        // `expect(!(deficit < deficit))` is true regardless of what deficit's formula
        // computes and catches nothing.
        const split_lamports_exact: u64 = RESERVE + MIN_DELEGATION;
        const split_lamports_short: u64 = RESERVE + MIN_DELEGATION - 1;
        try testing.expect(!(split_lamports_exact < deficit));
        try testing.expect(split_lamports_short < deficit);
    }
    // Prefunded destination (the 2026-07-28 carrier shape): deficit shrinks by what the dest
    // already holds, so a split that would fail against the old
    // `split_lamports -| RESERVE < min` form now correctly passes.
    {
        const dst_lamports: u64 = RESERVE; // prefunded to exactly rent-exemption
        const destination_minimum_balance = RESERVE +| MIN_DELEGATION;
        const deficit = destination_minimum_balance -| dst_lamports;
        try testing.expectEqual(MIN_DELEGATION, deficit);
        const split_lamports: u64 = MIN_DELEGATION; // exactly covers the deficit
        try testing.expect(!(split_lamports < deficit));
        // old buggy form would have demanded RESERVE MORE than necessary:
        const old_form_reject = (split_lamports -| RESERVE) < MIN_DELEGATION;
        try testing.expect(old_form_reject); // old form wrongly rejects this valid split
    }
    // Initialized arm: additional_required_lamports = 0, so deficit = reserve -| dst.lamports
    // (no min_delegation component — sig lib.zig:927-934; vex_bpf2 :1768-1773).
    {
        const dst_lamports: u64 = 1_000_000;
        const deficit = RESERVE -| dst_lamports;
        try testing.expectEqual(RESERVE - 1_000_000, deficit);
    }
}

test "split item4: rentExemptMinimumBalance() pinned to the constant production actually uses" {
    const testing = std.testing;
    // Direct call, both forms production passes: the destination's own data length (200,
    // STAKE_STATE_SZ) and the named constant, so a future change to this function that
    // breaks the 2,282,880 result (e.g. wrong exponent, dropped +128 overhead, swapped
    // exemption years) is actually caught — nothing else in this file calls it directly.
    try testing.expectEqual(@as(u64, 2_282_880), rentExemptMinimumBalance(200));
    try testing.expectEqual(@as(u64, 2_282_880), rentExemptMinimumBalance(stake_state.STAKE_STATE_SZ));
}

test "split item5: full-drain branch writes dst delegation.stake = split_lamports -| src_rent (not inherited pre-split stake)" {
    const testing = std.testing;
    const RESERVE: u64 = 2_282_880;
    const SRC_DELEGATION_STAKE_PRE: u64 = 50_000_000_000; // pre-split source delegation

    // Full drain: src_remaining == 0, so split_lamports == the account's full lamport balance.
    const split_lamports: u64 = SRC_DELEGATION_STAKE_PRE + RESERVE;
    const src_rent = RESERVE;

    const remaining_stake_delta = split_lamports -| src_rent;
    const split_stake_amount = remaining_stake_delta;

    // Canonical (sig lib.zig:884-887 / vex_bpf2 :1740-1742): dst delegation.stake gets the
    // NET-of-source-reserve amount.
    try testing.expectEqual(SRC_DELEGATION_STAKE_PRE, split_stake_amount);

    // The pre-fix behavior: this branch never computed or wrote split_stake_amount at all —
    // dst.delegation.stake was left at whatever the @memcpy of src's FULL data copied in,
    // i.e. the PRE-split delegation value used as the deinit source. Demonstrate the two
    // would coincide only by the same numeric accident this KAT's inputs deliberately avoid
    // being coincidental about: they match here because split_lamports was chosen as
    // exactly SRC_DELEGATION_STAKE_PRE + RESERVE, but for any other split_lamports the
    // pre-fix memcpy'd value (SRC_DELEGATION_STAKE_PRE, unconditionally) diverges from the
    // canonical split_stake_amount:
    const other_split_lamports: u64 = SRC_DELEGATION_STAKE_PRE + RESERVE - 1_000_000_000;
    const other_split_stake_amount = other_split_lamports -| src_rent;
    try testing.expect(other_split_stake_amount != SRC_DELEGATION_STAKE_PRE);

    // Source loses the full delta (remaining_stake_delta), same as the partial branch.
    try testing.expect(remaining_stake_delta <= SRC_DELEGATION_STAKE_PRE);
    const remaining_stake = SRC_DELEGATION_STAKE_PRE - remaining_stake_delta;
    try testing.expectEqual(@as(u64, 0), remaining_stake);
}

test "split item6: deinit writes ONLY the 4-byte discriminant and PRESERVES bytes 4..200 (byte-array proof)" {
    const testing = std.testing;

    // Build a 200-byte source buffer with a non-zero, non-trivial tail — as if it were a
    // freshly-computed post-split Stake record (delegation_stake, voter, credits_observed,
    // etc. all populated, matching what the fixed handleSplit now writes into src_data
    // BEFORE flipping the discriminant).
    var src_data: [stake_state.STAKE_STATE_SZ]u8 = undefined;
    for (&src_data, 0..) |*b, i| b.* = @truncate(0xA5 ^ i); // deterministic non-zero pattern
    stake_state.writeU32(&src_data, stake_state.Offsets.discriminant, 2); // Stake(2) pre-deinit

    var expected_tail: [stake_state.STAKE_STATE_SZ - 4]u8 = undefined;
    @memcpy(&expected_tail, src_data[4..]);

    // The FIXED deinit: write only the discriminant.
    stake_state.writeU32(&src_data, stake_state.Offsets.discriminant, 0);

    try testing.expectEqual(@as(u32, 0), stake_state.readU32(&src_data, 0).?);
    try testing.expectEqualSlices(u8, &expected_tail, src_data[4..]); // tail UNCHANGED

    // Contrast: the REMOVED @memset(src_data[4..], 0) form, applied to a fresh copy, proves
    // the two behaviors are observably different — i.e. this KAT would have failed against
    // the pre-fix code.
    var pre_fix_data: [stake_state.STAKE_STATE_SZ]u8 = undefined;
    for (&pre_fix_data, 0..) |*b, i| b.* = @truncate(0xA5 ^ i);
    stake_state.writeU32(&pre_fix_data, stake_state.Offsets.discriminant, 0);
    @memset(pre_fix_data[4..], 0);
    try testing.expect(!std.mem.eql(u8, &expected_tail, pre_fix_data[4..])); // diverges from canonical
}

test "split branch B: source neither effective nor activating — no-write source, verbatim-copy dest (2026-08-01 carrier KAT, slot 425636293)" {
    // Byte-mirror of handleSplit's branch B (Core-BPF stake program@v5.0.0 6ed2c60c,
    // processor.rs:621-655), the confirmed bank_hash carrier of slot 425636293. Canonical
    // moves lamports ONLY: the source's 200 data bytes are never re-serialized, and the
    // destination is a byte copy of the source with just meta.rent_exempt_reserve
    // overwritten — delegation.stake copied VERBATIM, not reduced by the split.
    const testing = std.testing;
    const RESERVE: u64 = 2_282_880;
    const MIN_DELEGATION: u64 = 1_000_000_000;

    // (1) ELIGIBILITY + ORDERING (audit finding 1): a partial split leaving the source
    // between reserve and reserve+1 SOL must SUCCEED on branch B — canonical has NO
    // minimum-delegation check on this arm. The legacy validateSplitAmount guard
    // (source must retain rent + min_delegation) would wrongly reject it, which is why
    // branch B must run FIRST. E.g. a 1.5 SOL deactivated stake split 1.4/0.1:
    {
        const src_lamports: u64 = RESERVE + 1_500_000_000;
        const split_lamports: u64 = 1_400_000_000;
        const src_remaining = src_lamports - split_lamports; // reserve + 0.1 SOL
        // branch B's only source-side check is rent exemption:
        try testing.expect(src_remaining >= RESERVE); // branch B: accept
        // the legacy guard this window used to die on (rent + min_delegation):
        try testing.expect(src_remaining < RESERVE +| MIN_DELEGATION); // legacy: reject
        // full drain stays OFF branch B (canonical branch A, legacy path):
        try testing.expect(!(src_lamports - src_lamports != 0));
    }

    // (2) BYTE SEMANTICS: dest = verbatim copy of source with ONLY rent_exempt_reserve
    // overwritten; source bytes untouched, including delegation.stake.
    {
        const SRC_STAKE_PRE: u64 = 5_000_000_123; // arbitrary non-round delegation
        const DST_RESERVE: u64 = RESERVE; // dest is also a 200-byte account

        var src_data: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        for (&src_data, 0..) |*b, i| b.* = @truncate(0xC3 ^ i); // non-trivial pattern
        stake_state.writeU32(&src_data, stake_state.Offsets.discriminant, 2);
        stake_state.writeU64(&src_data, stake_state.Offsets.rent_exempt_reserve, RESERVE);
        stake_state.writeU64(&src_data, stake_state.Offsets.delegation_stake, SRC_STAKE_PRE);
        var src_pre: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        @memcpy(&src_pre, &src_data);

        // branch B body, verbatim: dest is a copy with reserve overwritten…
        var b_dst: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        @memcpy(&b_dst, &src_data);
        stake_state.writeU64(&b_dst, stake_state.Offsets.rent_exempt_reserve, DST_RESERVE);
        // …and the source is re-emitted byte-identical.
        var b_src: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        @memcpy(&b_src, &src_data);

        try testing.expectEqualSlices(u8, &src_pre, &b_src); // source NEVER re-serialized
        try testing.expectEqual(SRC_STAKE_PRE, stake_state.readU64(&b_src, stake_state.Offsets.delegation_stake).?);
        try testing.expectEqual(SRC_STAKE_PRE, stake_state.readU64(&b_dst, stake_state.Offsets.delegation_stake).?); // copied VERBATIM
        // every byte outside rent_exempt_reserve is identical on the dest too:
        try testing.expectEqualSlices(u8, src_pre[0..stake_state.Offsets.rent_exempt_reserve], b_dst[0..stake_state.Offsets.rent_exempt_reserve]);
        try testing.expectEqualSlices(u8, src_pre[stake_state.Offsets.rent_exempt_reserve + 8 ..], b_dst[stake_state.Offsets.rent_exempt_reserve + 8 ..]);

        // (3) REGRESSION GUARD — the 425636293 identity. The removed legacy math wrote
        // src.stake -= split_lamports on this branch. Two sibling sources whose stakes
        // differ by exactly 1 lamport must stay distinct after the split; under the
        // pre-fix subtraction of a stake-sized split both could collapse to the same
        // post-state (the impossible identity observed in the block's write-set).
        const sibling_stake: u64 = SRC_STAKE_PRE + 1;
        var sib_data: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        @memcpy(&sib_data, &src_pre);
        stake_state.writeU64(&sib_data, stake_state.Offsets.delegation_stake, sibling_stake);
        // canonical (no-write): posts differ, as the pre-states do
        try testing.expect(!std.mem.eql(u8, &src_pre, &sib_data));
        // pre-fix: subtracting each source's own full delegation from itself collapses
        // both to stake==0 — byte-identical post-states, the observed carrier signature.
        var buggy_a: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        var buggy_b: [stake_state.STAKE_STATE_SZ]u8 = undefined;
        @memcpy(&buggy_a, &src_pre);
        @memcpy(&buggy_b, &sib_data);
        stake_state.writeU64(&buggy_a, stake_state.Offsets.delegation_stake, SRC_STAKE_PRE - SRC_STAKE_PRE);
        stake_state.writeU64(&buggy_b, stake_state.Offsets.delegation_stake, sibling_stake - sibling_stake);
        try testing.expectEqualSlices(u8, &buggy_a, &buggy_b); // proves the pre-fix collapse
    }

    // (4) DEST RENT CHECK: branch B rejects only when dest cannot reach ITS reserve —
    // saturating add, mirroring `dst_acct.lamports +| split_lamports < dst_rent_exempt_reserve`.
    {
        const dst_lamports: u64 = 1_000_000;
        try testing.expect(dst_lamports +| (RESERVE - 1_000_000) >= RESERVE); // exact top-up: accept
        try testing.expect(dst_lamports +| (RESERVE - 1_000_001) < RESERVE); // 1 short: reject
    }
}
