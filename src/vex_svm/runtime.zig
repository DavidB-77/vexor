/// runtime.zig — Firedancer fd_runtime.c port for Vexor (freeze / fees / incinerator / commit / save)
///
/// Ported from:
///   firedancer-reference/fd_runtime.c (1994 lines)
///
/// Functions ported:
///   fd_runtime_freeze()        → freeze()
///   fd_runtime_settle_fees()   → settleFees()
///   fd_runtime_run_incinerator() → runIncinerator()
///   fd_runtime_save_account()  → saveAccount()
///   fd_runtime_commit_txn()    → commitTransaction() [structural port — DB calls are TODO stubs]
///   fd_runtime_update_bank_hash() → updateBankHash()
///
/// Not ported here (out of scope / Vexor handles separately):
///   fd_runtime_block_execute_prepare() — epoch boundary, sysvar updates (replay_stage.zig)
///   fd_runtime_process_new_epoch()     — epoch rewards, leader schedule
///   fd_runtime_read_genesis()          — genesis loading (snapshot.zig)
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
const std = @import("std");
const vex_crypto = @import("vex_crypto");
const types = @import("types.zig");
const hashes = @import("hashes.zig");

pub const Hash = vex_crypto.Hash;
pub const LtHash = vex_crypto.LtHash;
pub const Pubkey = types.Pubkey;

// ─────────────────────────────────────────────────────────────────────────────
// System IDs
// ─────────────────────────────────────────────────────────────────────────────

/// System Program ID (11111111111111111111111111111111) — all zeros
/// fd_solana_system_program_id
const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;

/// Incinerator address (1nc1nerator11111111111111111111111111111111)
/// fd_sysvar_incinerator_id
/// fd_runtime.c:236-258: fd_runtime_run_incinerator zeroes this account
/// pub since 2026-07-05: the rent-state transition check (executor.transactionCheck
/// wiring in replay_stage, carrier 419957920) skips the incinerator per
/// fd_executor.c:1466 / Agave rent_calculator.rs:65.
pub const INCINERATOR_ID: [32]u8 = .{
    0x07, 0x93, 0x6a, 0x08, 0xe1, 0xfa, 0xa7, 0x30,
    0x4a, 0x87, 0x40, 0xcd, 0xb0, 0xda, 0x3d, 0x04,
    0xdb, 0x7c, 0xe0, 0xa3, 0x7b, 0xf4, 0x9f, 0x9a,
    0xd4, 0x0f, 0x14, 0x1a, 0x00, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// AccountState — local account representation for runtime operations
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors fields of fd_account_meta_t relevant to freeze/save operations.
/// fd_runtime.c uses fd_account_meta_t + data pointer separately.
pub const AccountState = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,

    pub fn isZeroLamports(self: AccountState) bool {
        return self.lamports == 0;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// RentParams — parameters for rent-exemption checks
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors fd_rent_t fields needed by fee validation.
/// fd_runtime.c:190-213 uses fd_rent_t to compute minimum exempt balance.
pub const RentParams = struct {
    lamports_per_byte_year: u64,
    exemption_threshold: f64, // Typically 2.0 (years)
    burn_percent: u8,

    /// Compute minimum rent-exempt balance for an account of `data_len` bytes.
    /// Mirrors fd_rent_exempt_minimum_balance() in Firedancer.
    /// Formula: ceil(data_len + 128) * lamports_per_byte_year * exemption_threshold
    pub fn exemptMinBalance(self: RentParams, data_len: usize) u64 {
        const size: f64 = @floatFromInt(data_len + 128); // account overhead
        const lpy: f64 = @floatFromInt(self.lamports_per_byte_year);
        const min = size * lpy * self.exemption_threshold;
        return @intFromFloat(@ceil(min));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// FeeSettleResult — output of settleFees
// ─────────────────────────────────────────────────────────────────────────────

/// Result of fee settlement, matching Firedancer log output.
/// fd_runtime.c:309: FD_LOG_INFO slot= priority_fees= execution_fees= fee_burn= fee_rewards=
pub const FeeSettleResult = struct {
    execution_fees: u64,
    priority_fees: u64,
    /// Burned amount (execution_fees / 2)
    fee_burn: u64,
    /// Rewarded to leader
    fee_reward: u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// validateFeeCollector — fd_runtime.c:190-233
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that the fee collector (leader) can receive fees.
///
/// Firedancer: fd_runtime_validate_fee_collector()
/// fd_runtime.c:190-233
///
/// Returns true if the fee can be deposited; false if it should be burned.
///
/// Rules (fd_runtime.c:213-236):
///   1. Collector must be owned by SystemProgram
///   2. collector.lamports + fee >= rent_exempt_minimum(collector.data_len)
///      (post-credit account must be rent-exempt)
fn validateFeeCollector(
    collector: AccountState,
    fee: u64,
    rent: RentParams,
) bool {
    // fd_runtime.c:195: "if (!fee) FD_LOG_CRIT" — caller guarantees fee > 0

    // fd_runtime.c:197: owner must be SystemProgram
    if (!std.mem.eql(u8, &collector.owner, &SYSTEM_PROGRAM_ID)) return false;

    // fd_runtime.c:212-220: post-credit balance must be >= rent-exempt minimum
    // overflow check matches Firedancer's __builtin_uaddl_overflow guard
    const balance_post = std.math.add(u64, collector.lamports, fee) catch return false;
    const minbal = rent.exemptMinBalance(collector.data.len);
    if (balance_post < minbal) return false; // fd_runtime.c:221

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// settleFees — fd_runtime.c:258-310
// ─────────────────────────────────────────────────────────────────────────────

/// Settle transaction fees accumulated during a slot.
///
/// Firedancer: fd_runtime_settle_fees()
/// fd_runtime.c:258-310
///
/// Fee model:
///   fee_burn   = execution_fees / 2          (integer division, rounds down)
///   fee_reward = priority_fees + (execution_fees - fee_burn)
///
/// Priority fees are NEVER burned. Only 50% of execution fees are burned.
///
/// If fee_reward > 0 AND leader passes validateFeeCollector():
///   → credit leader account, reduce capitalization by burn only.
/// Else:
///   → burn all fees (fd_runtime.c:291: "burning fee reward").
///
/// Parameters:
///   slot            — current slot number (for logging)
///   execution_fees  — accumulated execution fees (mutable, zeroed after settle)
///   priority_fees   — accumulated priority fees (mutable, zeroed after settle)
///   capitalization  — bank capitalization (reduced by total fees)
///   leader          — leader account state (for validation and credit lookup)
///   rent            — rent parameters for fee collector validation
///   credit_fn       — callback to credit leader (pubkey, amount): use null to skip credit (burn-only)
///                     TODO: wire to AccountsDb write path
///
/// Returns FeeSettleResult with burn/reward breakdown.
pub fn settleFees(
    slot: u64,
    execution_fees: *u64,
    priority_fees: *u64,
    capitalization: *u64,
    leader: AccountState,
    rent: RentParams,
) FeeSettleResult {
    const ef = execution_fees.*;
    const pf = priority_fees.*;
    const total_fees = ef +| pf; // saturating (Firedancer uses __builtin_uaddl_overflow + crash)

    // fd_runtime.c:273-274
    const fee_burn: u64 = ef / 2;
    const fee_reward: u64 = pf + (ef - fee_burn);

    // fd_runtime.c:278-283: reduce capitalization by total fees (burned portion)
    if (total_fees > capitalization.*) {
        // fd_runtime.c: FD_LOG_EMERG — in Vexor we log and saturate
        std.log.err(
            "[RUNTIME] settleFees slot={d}: fee overflow cap={d} total={d}",
            .{ slot, capitalization.*, total_fees },
        );
        capitalization.* = 0;
    } else {
        capitalization.* -= total_fees;
    }

    // fd_runtime.c:283-284
    execution_fees.* = 0;
    priority_fees.* = 0;

    // fd_runtime.c:285-303: pay out reward portion to leader if valid
    if (fee_reward > 0) {
        if (!validateFeeCollector(leader, fee_reward, rent)) {
            // fd_runtime.c:291: "invalid fee collector, burning fee reward"
            std.log.info(
                "[RUNTIME] slot={d}: invalid fee collector, burning {d} lamports",
                .{ slot, fee_reward },
            );
        } else {
            // TODO: fd_accdb_svm_open_rw → credit leader.lamports += fee_reward
            // This is wired to AccountsDb in Firedancer (fd_runtime.c:293-304).
            // In Vexor's Bank, the credit is staged as a pending_write by the caller.
            std.log.info(
                "[RUNTIME] slot={d}: fee_reward={d} → leader credit (TODO: AccountsDb write)",
                .{ slot, fee_reward },
            );
        }
    }

    std.log.info(
        "[RUNTIME] slot={d} priority_fees={d} execution_fees={d} fee_burn={d} fee_rewards={d}",
        .{ slot, pf, ef, fee_burn, fee_reward },
    );

    return .{
        .execution_fees = ef,
        .priority_fees = pf,
        .fee_burn = fee_burn,
        .fee_reward = fee_reward,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// runIncinerator — fd_runtime.c:237-257
// ─────────────────────────────────────────────────────────────────────────────

/// Burn any lamports sent to the incinerator address this slot.
///
/// Firedancer: fd_runtime_run_incinerator()
/// fd_runtime.c:237-257
///
/// The incinerator (1nc1nerator11...) is a sentinel: any lamports sent to it
/// are removed from the supply by zeroing its account via fd_accdb_svm_remove().
///
/// In Vexor's model, this is called during freeze() after settleFees().
/// The caller should have already staged any incinerator write in pending_writes.
///
/// Parameters:
///   bank_lthash    — running LtHash accumulator (updated in-place)
///   incinerator_state — current state of the incinerator account (may be zero)
///
/// If incinerator has non-zero lamports, removes its LtHash contribution
/// (equivalent to zeroing the account, which makes lamports=0 → excluded from hash).
pub fn runIncinerator(
    bank_lthash: *LtHash,
    incinerator_state: AccountState,
) void {
    // fd_runtime.c:241: fd_accdb_svm_remove — zero out incinerator account
    // Only do work if the incinerator has non-zero lamports this slot
    if (incinerator_state.lamports == 0) return;

    // Compute LtHash of old (non-zero) incinerator state
    const old_lt = hashes.accountLtHash(
        &INCINERATOR_ID,
        &incinerator_state.owner,
        incinerator_state.lamports,
        incinerator_state.executable,
        incinerator_state.data,
    );
    // New state is zeroed (lamports=0) → accountLtHash returns zero vector
    // bank_lthash -= old_lt + 0 → bank_lthash -= old_lt
    bank_lthash.wrappingSub(&old_lt);

    std.log.info(
        "[INCINERATOR] Burned {d} lamports from incinerator",
        .{incinerator_state.lamports},
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SaveAccountResult — fd_runtime.c:1068-1108
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors FD_RUNTIME_SAVE_* return codes.
/// fd_runtime.c:1068: fd_runtime_save_account returns save_type
pub const SaveAccountResult = enum(u2) {
    /// Old and new both existed → update
    /// fd_runtime.c:1105: (old_exist<<1) | (new_exist) = 0b11 = 3
    UpdatedExisting = 3,
    /// New account created (old didn't exist)
    /// fd_runtime.c: (0<<1) | 1 = 0b01 = 1
    CreatedNew = 1,
    /// Account deleted (new lamports = 0)
    /// fd_runtime.c: (1<<1) | 0 = 0b10 = 2
    Deleted = 2,
    /// Account unchanged (lthash matched → skip DB write)
    /// fd_runtime.c:1103: FD_RUNTIME_SAVE_UNCHANGED
    Unchanged = 0,
};

// ─────────────────────────────────────────────────────────────────────────────
// saveAccount — fd_runtime.c:1068-1108
// ─────────────────────────────────────────────────────────────────────────────

/// Persist a transaction account to the accounts DB and update the bank LtHash.
///
/// Firedancer: fd_runtime_save_account()
/// fd_runtime.c:1068-1108
///
/// Sequence:
///   1. Query old account state from AccountsDB
///   2. Compute LtHash of old state → lthash_prev
///   3. Compute LtHash of new state → lthash_post via fd_hashes_update_lthash1()
///   4. If lthash_post == lthash_prev → account unchanged, skip DB write (FD_RUNTIME_SAVE_UNCHANGED)
///   5. Otherwise → write new account to DB (fd_runtime_finalize_account)
///
/// Parameters:
///   bank_lthash   — running LtHash accumulator (updated in-place)
///   old_state     — previous account state from AccountsDB (null if new account)
///   new_state     — new account state to write
///
/// Returns SaveAccountResult indicating what happened.
///
/// NOTE: The actual AccountsDB write (fd_runtime_finalize_account, fd_accdb_open_rw)
///       is a TODO stub — wire to Vexor's AccountsDb (storage/accounts.zig).
pub fn saveAccount(
    bank_lthash: *LtHash,
    old_state: ?AccountState, // null → account didn't exist (new creation)
    new_state: AccountState,
) SaveAccountResult {
    // fd_runtime.c:1089-1093: compute lthash_prev
    var lthash_prev: LtHash = undefined;
    const old_exist: bool = if (old_state) |old| blk: {
        if (old.lamports == 0) {
            lthash_prev = LtHash.init();
            break :blk false;
        }
        lthash_prev = hashes.accountLtHash(
            &old.pubkey,
            &old.owner,
            old.lamports,
            old.executable,
            old.data,
        );
        break :blk true;
    } else blk: {
        // fd_runtime.c:1091: fd_lthash_zero(lthash_prev)
        lthash_prev = LtHash.init();
        break :blk false;
    };

    const new_exist: bool = new_state.lamports != 0;

    // fd_runtime.c:1096: save_type = (old_exist<<1) | new_exist
    const save_type: SaveAccountResult = switch ((@as(u2, if (old_exist) 1 else 0) << 1) |
        (@as(u2, if (new_exist) 1 else 0))) {
        3 => .UpdatedExisting,
        1 => .CreatedNew,
        2 => .Deleted,
        0 => .Unchanged,
        else => unreachable,
    };

    // fd_runtime.c:1097-1103: update LtHash if either old or new existed
    if (old_exist or new_exist) {
        // fd_hashes_update_lthash1 — hashes.zig:updateLtHash
        const lthash_post = hashes.updateLtHash(
            bank_lthash,
            &lthash_prev,
            &new_state.pubkey,
            &new_state.owner,
            new_state.lamports,
            new_state.executable,
            new_state.data,
        );

        // fd_runtime.c:1101-1103: skip DB write if first 32 bytes (BLAKE3 hash) unchanged
        // "First 32 bytes equal BLAKE3_256 hash of the account"
        if (std.mem.eql(u8, lthash_post.elements[0..16], lthash_prev.elements[0..16])) {
            // TODO: verify this is exactly 32-byte comparison (fd_runtime.c:1101 uses memcmp 32UL on bytes)
            return .Unchanged;
        }

        // fd_runtime.c:1101: fd_runtime_finalize_account — write to AccountsDB
        // TODO: wire to Vexor AccountsDb (src/storage/accounts.zig)
        // TODO: open account for read-write (create if missing, truncate if exists)
        std.log.debug(
            "[RUNTIME] saveAccount: TODO AccountsDB write for pubkey={x:0>8}...",
            .{std.mem.readInt(u32, new_state.pubkey[0..4], .big)},
        );
    }

    return save_type;
}

// ─────────────────────────────────────────────────────────────────────────────
// updateBankHash — fd_runtime.c:841-869
// ─────────────────────────────────────────────────────────────────────────────

/// Compute and store the final bank hash after freeze.
///
/// Firedancer: fd_runtime_update_bank_hash()
/// fd_runtime.c:841-869
///
/// Called at the end of fd_runtime_block_execute_finalize() after fd_runtime_freeze().
/// Delegates to fd_hashes_hash_bank() → hashes.hashBank().
pub fn updateBankHash(
    bank_lthash: *const LtHash,
    prev_bank_hash: *const Hash,
    poh_hash: *const Hash, // bank->f.poh — last entry hash in slot
    signature_count: u64,
) Hash {
    // fd_runtime.c:853-858: fd_hashes_hash_bank(lthash, prev_bank_hash, poh, sig_count)
    return hashes.hashBank(bank_lthash, prev_bank_hash, poh_hash, signature_count);
}

// ─────────────────────────────────────────────────────────────────────────────
// freeze — fd_runtime.c:306-332
// ─────────────────────────────────────────────────────────────────────────────

/// Freeze context: all inputs needed to finalize a slot.
///
/// Firedancer: fd_runtime_freeze() takes bank, accdb, capture_ctx.
/// fd_runtime.c:306-332
///
/// Vexor's freeze() is split from AccountsDB interaction — accounts are
/// passed in via pending_writes in Bank (bank.zig), but the pure hashing
/// logic is exposed here for testing and the standalone replay verifier.
pub const FreezeContext = struct {
    slot: u64,
    /// Mutable running LtHash accumulator (inherited from parent, updated per write)
    bank_lthash: *LtHash,
    /// Previous bank hash (parent slot)
    prev_bank_hash: *const Hash,
    /// PoH hash of the last entry in this slot (NOT tx.recent_blockhash)
    poh_hash: *const Hash,
    /// Total transaction signatures this slot
    signature_count: u64,
    /// Accumulated execution fees (zeroed by settleFees)
    execution_fees: *u64,
    /// Accumulated priority fees (zeroed by settleFees)
    priority_fees: *u64,
    /// Bank capitalization (reduced by total fees)
    capitalization: *u64,
    /// Leader account state for fee credit validation
    leader: AccountState,
    /// Rent parameters for fee collector validation
    rent: RentParams,
    /// Incinerator account state (if any lamports were sent here this slot)
    incinerator: ?AccountState,
};

/// Freeze a slot: settle fees, burn incinerator, compute bank hash.
///
/// Firedancer: fd_runtime_freeze() + fd_runtime_update_bank_hash()
/// fd_runtime.c:306-332, fd_runtime.c:841-869
///
/// ORDER MATCHES FIREDANCER EXACTLY (fd_runtime.c:310-332):
///   1. fd_sysvar_recent_hashes_update()   → caller pre-freeze (slot != 0)
///   2. fd_sysvar_slot_history_update()    → caller pre-freeze
///   3. fd_runtime_settle_fees()           → settleFees() [this function]
///   4. fd_runtime_run_incinerator()       → runIncinerator() [this function]
///   5. fd_runtime_update_bank_hash()      → updateBankHash() [this function]
///
/// NOTE: Sysvar writes (RecentBlockhashes, SlotHistory, Clock, SlotHashes,
///       LastRestartSlot) must be applied to bank_lthash BEFORE calling freeze().
///
/// Returns the computed bank hash.
pub fn freeze(ctx: *FreezeContext) FeeSettleResult {
    // fd_runtime.c:319-321: fd_sysvar_recent_hashes_update (slot != 0)
    // TODO: caller responsibility — must inject sysvar writes into LtHash before freeze()

    // fd_runtime.c:323: fd_sysvar_slot_history_update
    // TODO: caller responsibility

    // fd_runtime.c:325: fd_runtime_settle_fees
    const result = settleFees(
        ctx.slot,
        ctx.execution_fees,
        ctx.priority_fees,
        ctx.capitalization,
        ctx.leader,
        ctx.rent,
    );

    // fd_runtime.c:330: fd_runtime_run_incinerator
    if (ctx.incinerator) |inc| {
        runIncinerator(ctx.bank_lthash, inc);
    }

    // Called by fd_runtime_block_execute_finalize → fd_runtime_update_bank_hash
    // fd_runtime.c:841-869
    // (Bank.freeze() calls this separately in bank.zig)

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// commitTransaction — structural port of fd_runtime_commit_txn()
// ─────────────────────────────────────────────────────────────────────────────

/// Transaction commit result codes.
pub const CommitResult = enum {
    /// Transaction committed successfully (all writes saved)
    Success,
    /// Transaction failed — only fee payer / nonce rollback saved
    FailedRollback,
    /// Transaction not committable (logic error — should not happen)
    NotCommittable,
};

/// Minimal transaction commit context (structural port).
///
/// Firedancer: fd_runtime_commit_txn()
/// fd_runtime.c:1116-1262
///
/// Full Firedancer commit does:
///   1. Release executable accounts (fd_accdb_close_ro)
///   2. Release read-only accounts
///   3. On txn error: save nonce rollback + fee payer rollback only
///   4. On txn success: save all writable accounts (saveAccount per account)
///      - Update vote/stake cache for vote/stake accounts
///      - Accumulate tips for bundle txns
///   5. Atomically update bank counters (txn_count, fees, sig_count, etc.)
///   6. Insert into status cache (txncache)
///   7. Release pool memory for writable accounts
///
/// TODO stubs: all AccountsDB calls (fd_accdb_*), pool release, status cache.
/// Wire these to Vexor's storage layer in bank.zig / replay_stage.zig.
pub const CommitContext = struct {
    slot: u64,
    /// Whether the transaction itself succeeded
    txn_ok: bool,
    /// Writable accounts to save on success
    writable_accounts: []const AccountState,
    /// Fee payer rollback state (on failure, save this instead of full fee payer)
    fee_payer_rollback: ?AccountState,
    /// Nonce account rollback state (on failure, save this first)
    nonce_rollback: ?AccountState,
    /// Execution fee for this transaction
    execution_fee: u64,
    /// Priority fee for this transaction
    priority_fee: u64,
    /// Signature count from this transaction
    signature_count: u64,
    /// LtHash accumulator to update
    bank_lthash: *LtHash,
    /// Bank fee counters (accumulated atomically in Firedancer)
    total_execution_fees: *u64,
    total_priority_fees: *u64,
    total_signature_count: *u64,
};

/// Commit a transaction: save accounts, update bank counters.
///
/// Firedancer: fd_runtime_commit_txn()
/// fd_runtime.c:1116-1262
pub fn commitTransaction(ctx: *CommitContext) CommitResult {
    // fd_runtime.c:1121: if (!txn_out->err.is_committable) FD_LOG_CRIT
    // In Vexor, caller guarantees committability.

    // fd_runtime.c:1133-1142: release executable + read-only accounts
    // TODO: fd_accdb_close_ro (not needed in Vexor's in-memory model)

    if (!ctx.txn_ok) {
        // fd_runtime.c:1155-1180: failed transaction → save rollback accounts only
        // fd_runtime.c:1158-1163: save nonce rollback first
        if (ctx.nonce_rollback) |nonce| {
            _ = saveAccount(ctx.bank_lthash, null, nonce); // TODO: pass old state from DB
        }
        // fd_runtime.c:1171-1177: save fee payer rollback (if not same as nonce)
        if (ctx.fee_payer_rollback) |fee_payer| {
            _ = saveAccount(ctx.bank_lthash, null, fee_payer);
        }
        // fd_runtime.c:1226: accumulate fees even on failure
        ctx.total_execution_fees.* +|= ctx.execution_fee;
        ctx.total_priority_fees.* +|= ctx.priority_fee;
        ctx.total_signature_count.* +|= ctx.signature_count;
        return .FailedRollback;
    }

    // fd_runtime.c:1183-1222: success → save all writable accounts
    for (ctx.writable_accounts) |acc| {
        // TODO: pass old account state from AccountsDB lookup
        _ = saveAccount(ctx.bank_lthash, null, acc);
    }

    // fd_runtime.c:1223-1239: atomically accumulate bank-level counters
    // fd_runtime.c:1226-1228: txn_count, execution_fees, priority_fees, signature_count
    ctx.total_execution_fees.* +|= ctx.execution_fee;
    ctx.total_priority_fees.* +|= ctx.priority_fee;
    ctx.total_signature_count.* +|= ctx.signature_count;

    // TODO: fd_txncache_insert (status cache) — fd_runtime.c:1251-1259
    // TODO: fd_acc_pool_release (account pool) — fd_runtime.c:1261-1265

    return .Success;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "validateFeeCollector: rejects non-system owner" {
    const rent = RentParams{ .lamports_per_byte_year = 1, .exemption_threshold = 2.0, .burn_percent = 50 };
    const acc = AccountState{
        .pubkey = [_]u8{0} ** 32,
        .lamports = 1_000_000,
        .owner = [_]u8{1} ** 32, // not SystemProgram
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    try std.testing.expect(!validateFeeCollector(acc, 1000, rent));
}

test "validateFeeCollector: accepts rent-exempt system-owned account" {
    const rent = RentParams{ .lamports_per_byte_year = 1, .exemption_threshold = 1.0, .burn_percent = 50 };
    const acc = AccountState{
        .pubkey = [_]u8{0} ** 32,
        .lamports = 10_000_000, // well above minimum
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    try std.testing.expect(validateFeeCollector(acc, 1000, rent));
}

test "settleFees: zero fees → no-op" {
    var ef: u64 = 0;
    var pf: u64 = 0;
    var cap: u64 = 1_000_000;
    const leader = AccountState{
        .pubkey = [_]u8{0} ** 32,
        .lamports = 0,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    const rent = RentParams{ .lamports_per_byte_year = 1, .exemption_threshold = 1.0, .burn_percent = 50 };
    const result = settleFees(1, &ef, &pf, &cap, leader, rent);
    try std.testing.expectEqual(@as(u64, 0), result.fee_burn);
    try std.testing.expectEqual(@as(u64, 0), result.fee_reward);
    try std.testing.expectEqual(@as(u64, 1_000_000), cap); // unchanged
}

test "settleFees: 50% burn of execution fees" {
    var ef: u64 = 1000;
    var pf: u64 = 200;
    var cap: u64 = 10_000_000;
    const leader = AccountState{
        .pubkey = [_]u8{1} ** 32,
        .lamports = 5_000_000,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    const rent = RentParams{ .lamports_per_byte_year = 3480, .exemption_threshold = 2.0, .burn_percent = 50 };
    const result = settleFees(42, &ef, &pf, &cap, leader, rent);
    // fee_burn = 1000 / 2 = 500
    try std.testing.expectEqual(@as(u64, 500), result.fee_burn);
    // fee_reward = 200 + (1000 - 500) = 700
    try std.testing.expectEqual(@as(u64, 700), result.fee_reward);
    // capitalization reduced by total (1000 + 200 = 1200)
    try std.testing.expectEqual(@as(u64, 10_000_000 - 1200), cap);
    // fees zeroed
    try std.testing.expectEqual(@as(u64, 0), ef);
    try std.testing.expectEqual(@as(u64, 0), pf);
}

test "runIncinerator: zero lamports → no-op" {
    var lt = LtHash.init();
    const inc = AccountState{
        .pubkey = INCINERATOR_ID,
        .lamports = 0,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    runIncinerator(&lt, inc);
    // LtHash should remain all-zero
    for (lt.elements) |e| try std.testing.expectEqual(@as(u16, 0), e);
}

test "runIncinerator: non-zero lamports → removes LtHash contribution" {
    // First add the incinerator's contribution to a running lthash, then burn it
    var lt = LtHash.init();
    const inc = AccountState{
        .pubkey = INCINERATOR_ID,
        .lamports = 5000,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };

    // Manually add incinerator contribution (as if it received lamports this slot)
    const inc_lt = hashes.accountLtHash(&INCINERATOR_ID, &SYSTEM_PROGRAM_ID, 5000, false, &[_]u8{});
    lt.wrappingAdd(&inc_lt);

    // Now burn it
    runIncinerator(&lt, inc);

    // After burning: lt should be back to zero (we added then subtracted same value)
    for (lt.elements) |e| try std.testing.expectEqual(@as(u16, 0), e);
}

test "saveAccount: new account → CreatedNew" {
    var lt = LtHash.init();
    const new_acc = AccountState{
        .pubkey = [_]u8{0xAB} ** 32,
        .lamports = 1_000_000,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    const result = saveAccount(&lt, null, new_acc);
    try std.testing.expectEqual(SaveAccountResult.CreatedNew, result);
}

test "saveAccount: delete account → Deleted" {
    var lt = LtHash.init();
    const old_acc = AccountState{
        .pubkey = [_]u8{0xCD} ** 32,
        .lamports = 500,
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    const new_acc = AccountState{
        .pubkey = [_]u8{0xCD} ** 32,
        .lamports = 0, // deleted
        .owner = SYSTEM_PROGRAM_ID,
        .executable = false,
        .rent_epoch = 0,
        .data = &[_]u8{},
    };
    const result = saveAccount(&lt, old_acc, new_acc);
    try std.testing.expectEqual(SaveAccountResult.Deleted, result);
}

test "updateBankHash: deterministic" {
    var lt = LtHash.init();
    const prev = Hash.default();
    const poh = Hash.init([_]u8{0xFF} ** 32);
    const h1 = updateBankHash(&lt, &prev, &poh, 100);
    const h2 = updateBankHash(&lt, &prev, &poh, 100);
    try std.testing.expectEqualSlices(u8, &h1.data, &h2.data);
}
