//! produce_admit.zig — THE ADMIT DECISION for block production.
//!
//! ── Why this file exists ─────────────────────────────────────────────────────────────────────────
//! Vexor grew TWO executors: replay's full `instruction_dispatch` (the golden-gate-proven ladder) and
//! a mini "block_executor" that understood only System discriminants 0/2, used to decide what to pack.
//! Votes were therefore unpackable, and every future program would have had to be re-taught to the
//! mini-executor — a bug CLASS, not a bug.
//!
//! The fix routes production through the SAME golden-proven executor replay uses. That closes the
//! semantic gap, but it moves a different risk to the front: if the ADMIT bit were derived from
//! "did the executor finish", then widening the executor would silently widen the admit set, which
//! is the very coupling that produced the defect. Worse, Vexor's ladder is MORE PERMISSIVE than
//! Agave (see the containment note below), so "our executor completed it" does NOT imply "the
//! cluster will load it".
//!
//! So the admit bit is computed HERE: a finite, affirmative, DEFAULT-REJECT enumeration evaluated
//! BEFORE the engine runs and never derived from it.
//!
//! ── The safety boundary (the asymmetry that governs every decision below) ────────────────────────
//!   UNDER-admit (we drop a tx replay would have processed) ⇒ a smaller or EMPTY block. Self-healing,
//!     it is today's state, and it costs at most a leader slot.
//!   OVER-admit  (we pack a tx the cluster cannot LOAD)     ⇒ get_first_error ⇒ execute_batch Err ⇒
//!     THE CLUSTER MARKS THE SLOT DEAD, on the FIRST occurrence, irreversibly.
//! A DEAD block is strictly worse than an EMPTY one. Therefore every ambiguous, un-evaluable or
//! unrecognised case resolves to `refuse`/`reject`, never to `admit`.
//!
//! ── Three verdicts, because "no" has two very different meanings ─────────────────────────────────
//! `reject` = evaluated, and the cluster would reject it (a real, attributable per-tx outcome).
//! `refuse` = NOT evaluable here (unarmed, unsupported shape, missing precondition). A refuse means
//!            "this code declines to reason about this tx", which is a statement about US, not the
//!            tx. Keeping them distinct is what lets an operator tell "the oracle is working and the
//!            traffic is bad" from "the oracle is refusing everything and the block is empty for a
//!            reason that has nothing to do with the traffic" — two states that look IDENTICAL at
//!            the block level (both produce an empty block) and are otherwise debugged in opposite
//!            directions.
//!
//! ── Containment: what this file covers that the loopback CANNOT ──────────────────────────────────
//! Vexor's replay has ZERO occurrences of AccountLoadedTwice, TooManyAccountLocks,
//! ProgramAccountNotFound and InvalidProgramForExecution, and it never verifies precompile
//! instruction payloads. Agave treats all of them as LOAD-stage errors ⇒ dead slot. Because loopback
//! replay runs the SAME permissive Vexor code, a produce-vs-replay comparison agrees with itself and
//! proves nothing about those classes. NO offline test can close that gap. What closes it is the
//! affirmative checks below plus the `.vote_only` arm filter — NOT the loopback.
//!
//! ── Standalone by construction ───────────────────────────────────────────────────────────────────
//! No replay_stage / bank / accounts_db imports. It operates on plain views the caller fills, so it
//! is directly test-rootable (the vote_arming.zig pattern) without dragging in the replay module
//! graph. That is why the program-id bytes are duplicated below rather than imported.

const std = @import("std");

// ── Program IDs ──────────────────────────────────────────────────────────────────────────────────
// Pinned copies of replay_stage.NATIVE_PROGRAM_IDS / the loader IDs. Duplicated (not imported) to
// keep this module standalone — see the header. A transcription error here is UNDER-admit and
// therefore safe: a wrong VOTE constant makes the `.vote_only` filter refuse every vote, which
// yields empty blocks (today's behaviour), never a dead one.

pub const SYSTEM_PROGRAM_ID = [_]u8{0} ** 32;
pub const VOTE_PROGRAM_ID = [_]u8{ 0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3, 0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00 };
pub const STAKE_PROGRAM_ID = [_]u8{ 0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2, 0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00 };
pub const COMPUTE_BUDGET_PROGRAM_ID = [_]u8{ 0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32, 0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7, 0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b, 0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00 };
pub const ZK_ELGAMAL_PROGRAM_ID = [_]u8{ 0x08, 0x63, 0x75, 0xac, 0xe2, 0xae, 0xea, 0x28, 0x1a, 0x6b, 0x37, 0x4d, 0x68, 0x1b, 0xa7, 0x6a, 0x53, 0xcc, 0xf6, 0x38, 0xc0, 0x74, 0x55, 0x93, 0x6c, 0x05, 0xd0, 0x65, 0x40, 0x00, 0x00, 0x00 };

pub const BPF_LOADER_UPGRADEABLE_ID = [_]u8{ 0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0, 0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b, 0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2, 0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00 };
pub const BPF_LOADER_V2_ID = [_]u8{ 0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e, 0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69, 0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43, 0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00 };
pub const BPF_LOADER_DEPRECATED_ID = [_]u8{ 0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b, 0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9, 0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14, 0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00 };

/// Agave's MAX_TX_ACCOUNT_LOCKS. Exceeding it is TooManyAccountLocks at LOAD ⇒ dead slot.
pub const MAX_TX_ACCOUNT_LOCKS: usize = 64;

// ── Types ────────────────────────────────────────────────────────────────────────────────────────

pub const Verdict = enum {
    /// Pack it. The ONLY value that may ever be returned on an un-evaluated path is not this one.
    admit,
    /// Evaluated; the cluster would reject it.
    reject,
    /// Not evaluable here (unarmed / unsupported shape / missing precondition).
    refuse,
};

/// How much of the produce path is armed. NAMED VALUES ONLY (no bare 0/1), parsed from
/// VEX_PRODUCE_EXEC. DEFAULT `.off` — the deliverable is INERT unless an operator names a value.
///
/// Only `.vote_only` is sanctioned for this iteration. `.native`/`.all` are parseable so the shape
/// exists, but widening past `.vote_only` requires first closing the permissiveness gap described in
/// the header — the allowlist IS the containment for it.
pub const ArmState = enum {
    off,
    vote_only,
    native,
    all,

    /// Unrecognised / absent ⇒ `.off`. Unknown input must never arm anything.
    pub fn parse(v: ?[]const u8) ArmState {
        const s = v orelse return .off;
        if (std.mem.eql(u8, s, "vote_only")) return .vote_only;
        if (std.mem.eql(u8, s, "native")) return .native;
        if (std.mem.eql(u8, s, "all")) return .all;
        if (std.mem.eql(u8, s, "off")) return .off;
        return .off;
    }
};

/// A read of one account as the producing state sees it. `exists=false` means "absent" — which is
/// distinct from "present with zero lamports"; conflating them is how a missing program account
/// becomes a plausible empty system account (the `orelse Account{.lamports=0}` default that
/// block_executor used).
pub const AccountView = struct {
    exists: bool = false,
    lamports: u64 = 0,
    owner: [32]u8 = [_]u8{0} ** 32,
    executable: bool = false,
    data_len: usize = 0,
};

pub const Reader = struct {
    ctx: *anyopaque,
    readFn: *const fn (*anyopaque, [32]u8) AccountView,

    pub fn read(self: Reader, key: [32]u8) AccountView {
        return self.readFn(self.ctx, key);
    }
};

/// The already-resolved view of a transaction. `program_ids` are RESOLVED program ids, one per
/// instruction — resolution (including the out-of-range program_id_index case) is the caller's job,
/// and an unresolvable index must be refused by the caller BEFORE building this.
pub const TxView = struct {
    account_keys: []const [32]u8,
    num_required_sigs: u8,
    num_readonly_signed: u8,
    num_readonly_unsigned: u8,
    is_versioned: bool,
    recent_blockhash: [32]u8,
    program_ids: []const [32]u8,
    fee_payer: [32]u8,
};

pub const AdmitEnv = struct {
    arm: ArmState,
    /// The producing bank's recent (<=150) blockhash window.
    blockhash_window: []const [32]u8,
    /// Whether cross-block AlreadyProcessed dedup is actually available. FAIL-CLOSED: false ⇒ every
    /// tx is refused. Votes are precisely the traffic that gets re-gossiped and retried, and Agave
    /// treats AlreadyProcessed as a LOAD-stage error ⇒ dead slot.
    status_cache_armed: bool,
    already_processed: bool,
    /// base + priority fee for this tx (the SAME number replay will debit).
    total_fee: u64,
    rent_min_for_len: *const fn (usize) u64,
};

/// Slot-level arming preconditions. Every one must hold before the oracle may arm for a slot; any
/// false ⇒ fall through to an empty block, which is exactly today's behaviour.
pub const SlotPreconditions = struct {
    parent_frozen: bool,
    has_accounts_db: bool,
    status_cache_armed: bool,
    blockhash_window_len: usize,
    parent_slot_hashes_present: bool,
    /// True when the slot being produced starts a NEW epoch. Refuse: apply_feature_activations and
    /// processEpochBoundary are NOT replicated on the scratch bank. One empty block per epoch is
    /// free; a boundary divergence is a fork.
    epoch_boundary: bool,
    /// bank_mod.worker_writes_override must be null — a non-null threadlocal write sink would send
    /// the oracle's writes somewhere other than the scratch bank. An explicit REFUSE, never an
    /// assert: asserts compile out in ReleaseFast, which is what we ship.
    worker_override_clear: bool,
    live_features_present: bool,
};

pub fn slotArmable(p: SlotPreconditions) bool {
    return p.parent_frozen and
        p.has_accounts_db and
        p.status_cache_armed and
        p.blockhash_window_len > 0 and
        p.parent_slot_hashes_present and
        !p.epoch_boundary and
        p.worker_override_clear and
        p.live_features_present;
}

fn isNativeBuiltin(id: [32]u8) bool {
    return std.mem.eql(u8, &id, &SYSTEM_PROGRAM_ID) or
        std.mem.eql(u8, &id, &VOTE_PROGRAM_ID) or
        std.mem.eql(u8, &id, &STAKE_PROGRAM_ID) or
        std.mem.eql(u8, &id, &COMPUTE_BUDGET_PROGRAM_ID) or
        std.mem.eql(u8, &id, &ZK_ELGAMAL_PROGRAM_ID);
}

fn isLoader(id: [32]u8) bool {
    return std.mem.eql(u8, &id, &BPF_LOADER_UPGRADEABLE_ID) or
        std.mem.eql(u8, &id, &BPF_LOADER_V2_ID) or
        std.mem.eql(u8, &id, &BPF_LOADER_DEPRECATED_ID);
}

/// Does the arm state permit this program to be packed at all? SUBTRACTIVE and evaluated OUTSIDE any
/// executor branch — widening the executor cannot widen this set.
fn armPermits(arm: ArmState, id: [32]u8) bool {
    return switch (arm) {
        .off => false,
        .vote_only => std.mem.eql(u8, &id, &VOTE_PROGRAM_ID) or
            std.mem.eql(u8, &id, &COMPUTE_BUDGET_PROGRAM_ID),
        .native => isNativeBuiltin(id),
        .all => true,
    };
}

// ── The decision ─────────────────────────────────────────────────────────────────────────────────

/// WHY a transaction was not packed. This exists because "the oracle correctly refused everything"
/// and "the oracle is broken and refuses everything" produce the IDENTICAL observable — an empty
/// block — and are debugged in opposite directions. Without named attribution the natural response
/// to a flat vote metric is to start relaxing checks, which is precisely the path from a safe empty
/// block to a fatal dead one.
pub const Reason = enum {
    ok,
    arm_off,
    versioned,
    dup_key,
    too_many_locks,
    empty_window,
    stale_blockhash,
    status_cache_off,
    already_processed,
    payer_missing,
    payer_owner,
    payer_nonce,
    payer_funds,
    program_missing,
    program_not_executable,
    program_owner,
    arm_filter,
};

pub const Decision = struct {
    verdict: Verdict,
    reason: Reason,
};

/// Decide whether one transaction may be packed, in Agave's LOAD order. DEFAULT REJECT: the single
/// `.admit` below is reached only by falling through every arm.
///
/// Ordering follows Agave's load stage so that whichever check would have killed the block on the
/// cluster is the one that fires here, which keeps the per-reason tally diagnostically truthful.
pub fn checkTx(v: TxView, r: Reader, e: AdmitEnv) Verdict {
    return checkTxDetailed(v, r, e).verdict;
}

pub fn checkTxDetailed(v: TxView, r: Reader, e: AdmitEnv) Decision {
    // 1. Unarmed ⇒ nothing is evaluable. This is the first latch that keeps the change INERT.
    if (e.arm == .off) return .{ .verdict = .refuse, .reason = .arm_off };

    // 2. Versioned (v0) transactions are refused in ALL arm states this iteration. Two independent
    //    reasons, either sufficient: (a) address-lookup-table resolution would have to agree
    //    byte-for-byte with what replay resolves against a DIFFERENT bank state; (b) `txCostSum` has a
    //    DOCUMENTED writable-account UNDER-count for v0 (ALT-loaded writable accounts are not counted
    //    — see block_produce.zig's `txCostSum` / `txWritableAccountKeys` notes), and
    //    under-counting cost can push the block past Agave's check_block_cost_limits, which is
    //    BLOCK-FATAL. Refusing v0 costs throughput we do not currently have and closes both.
    if (v.is_versioned) return .{ .verdict = .refuse, .reason = .versioned };

    // 3. AccountLoadedTwice. ABSENT from Vexor replay entirely, so loopback would happily process a
    //    tx the cluster kills at load. O(n^2) over <=64 keys is trivial and needs no allocation.
    for (v.account_keys, 0..) |a, i| {
        for (v.account_keys[i + 1 ..]) |b| {
            if (std.mem.eql(u8, &a, &b)) return .{ .verdict = .reject, .reason = .dup_key };
        }
    }

    // 4. TooManyAccountLocks. Also ABSENT from Vexor replay.
    if (v.account_keys.len > MAX_TX_ACCOUNT_LOCKS) return .{ .verdict = .reject, .reason = .too_many_locks };

    // 5. Blockhash age. FAIL-OPEN FIX: block_executor guarded this with
    //    `if (self.known_blockhashes.len > 0)`, so an EMPTY window silently SKIPPED the check and
    //    admitted stale-blockhash txs — the fail-open direction is the dead-block direction. An empty
    //    window now refuses everything.
    if (e.blockhash_window.len == 0) return .{ .verdict = .refuse, .reason = .empty_window };
    {
        var found = false;
        for (e.blockhash_window) |bh| {
            if (std.mem.eql(u8, &bh, &v.recent_blockhash)) {
                found = true;
                break;
            }
        }
        if (!found) return .{ .verdict = .reject, .reason = .stale_blockhash };
    }

    // 6. Cross-block AlreadyProcessed. FAIL-CLOSED: without the status cache we cannot know whether a
    //    re-gossiped vote already landed in a recent block, and Agave treats AlreadyProcessed as a
    //    LOAD-stage error ⇒ DEAD SLOT. Votes are exactly the retried traffic, so this is not a
    //    theoretical arm.
    if (!e.status_cache_armed) return .{ .verdict = .refuse, .reason = .status_cache_off };
    if (e.already_processed) return .{ .verdict = .reject, .reason = .already_processed };

    // 7. Fee payer. Agave: InvalidAccountForFee / InsufficientFundsForFee, both LOAD-stage fatal.
    {
        const fp = r.read(v.fee_payer);
        if (!fp.exists) return .{ .verdict = .reject, .reason = .payer_missing };
        if (!std.mem.eql(u8, &fp.owner, &SYSTEM_PROGRAM_ID)) return .{ .verdict = .reject, .reason = .payer_owner };
        // A System-owned account carrying data is nonce-shaped. Durable-nonce fee payment has its own
        // advance-nonce semantics we do not replicate here, so it is un-evaluable, not rejectable.
        if (fp.data_len != 0) return .{ .verdict = .refuse, .reason = .payer_nonce };
        const need = e.rent_min_for_len(fp.data_len) +| e.total_fee;
        if (fp.lamports < need) return .{ .verdict = .reject, .reason = .payer_funds };
    }

    // 8. Every program account must be loadable AND invocable. ProgramAccountNotFound and
    //    InvalidProgramForExecution are both ABSENT from Vexor replay, and this is what closes
    //    block_executor's `orelse Account{.lamports=0}` default, which turned a MISSING program
    //    account into a plausible empty system account.
    for (v.program_ids) |pid| {
        // Native builtins have no ELF and are not "executable" accounts in the loader sense; they are
        // dispatched by id. Checking their account shape would reject every vote.
        if (isNativeBuiltin(pid)) continue;
        const pa = r.read(pid);
        if (!pa.exists) return .{ .verdict = .reject, .reason = .program_missing };
        if (!pa.executable) return .{ .verdict = .reject, .reason = .program_not_executable };
        if (!isLoader(pa.owner)) return .{ .verdict = .reject, .reason = .program_owner };
    }

    // 9. Arm filter. SUBTRACTIVE and last: a program that passes every load check above is still not
    //    packed unless the operator has armed its class. Note this is NOT "variant (c)" (teaching a
    //    mini-executor one program at a time) — the engine behind it is already fully general; this
    //    is a deployment filter in front of it, and widening it changes ZERO executor code paths.
    for (v.program_ids) |pid| {
        if (!armPermits(e.arm, pid)) return .{ .verdict = .refuse, .reason = .arm_filter };
    }

    return .{ .verdict = .admit, .reason = .ok };
}
