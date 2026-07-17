//! kat_failed_tx_rollback.zig — regression KAT for CARRIER #6 @414386920:
//! failed-tx write-rollback leak.
//!
//! Ground truth (cluster getBlock + bank_hash_details @414386920, Agave
//! 4.1.0-beta.3; artifacts carrier-414386920/ +
//! /tmp/cluster_414386920_details.json):
//!   tx#509 3cJtzZioHYcLj9mBnbKnnbVc4yakzryPLJj1XZtiL46EebqiwGdwvkRuLq3KCTvQ
//!   9eympwKshGHa8Y9oLfgumrjf (SPL Stake Pool):
//!     ix[0,1] ComputeBudget, ix[2] UpdateValidatorListBalance SUCCEEDS and
//!     writes the 730,009-byte ValidatorList
//!     G5N6K3qW86GSkNEpywcbJk42LjEZoshzECFg1LNVjSLa, ix[3]
//!     UpdateValidatorListBalance CPIs native Stake Merge → Custom(0x6) →
//!     tx err InstructionError[3, Custom(6)].
//!   Canonical semantics (account_saver.rs:53-148 + rollback_accounts.rs):
//!   the WHOLE tx's account writes are discarded; only the fee debit (and the
//!   durable-nonce advance, when applicable) persist.
//!   Vexor also failed ix[3] (fee-payer post-balance byte-exact vs cluster)
//!   but LEAKED ix[2]'s ValidatorList write (recorder
//!   slot-414386920.writes.jsonl: phantom pk dffd79b6…23, new_dlen=730009)
//!   → 1 phantom account → accounts_lt_hash → bank_hash divergence.
//!
//! PRE-FIX the instruction loops (replay_stage.zig DAG + serial) ran every
//! handler with `catch {}` (loop CONTINUED past a failed instruction) and
//! every instruction's mutations were committed eagerly with NO tx-scoped
//! rollback — this KAT does not even compile at the parent commit (the
//! rollback helpers don't exist), and its core assertion (phantom write
//! absent after a failed tx) is the exact inverse of the recorded pre-fix
//! evidence. POST-FIX: rollbackFailedTx truncates the tx's appended writes
//! back to the tx mark, keeping only the durable-nonce advance.
//!
//! Drives the REAL replay_stage helpers (txDurableNoncePk,
//! rollbackFailedTxWrites, rollbackFailedTx) against a real Bank with the
//! carrier's exact pubkeys.
//!
//! Run: zig build test-failed-tx-rollback-414386920

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_crypto = @import("vex_crypto");
const core = @import("core");

const Bank = vex_svm.Bank;
const Hash = vex_svm.Hash;
const replay = vex_svm.replay_stage;

// ── base58 decode (comptime; same helper as kat_commit_owner_414352136.zig) ──
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn b58(comptime s: []const u8) [32]u8 {
    @setEvalBranchQuota(100000);
    var bytes: [64]u8 = [_]u8{0} ** 64;
    var len: usize = 0;
    for (s) |c| {
        const di = std.mem.indexOfScalar(u8, B58, c) orelse @compileError("bad b58");
        var carry: usize = di;
        var i: usize = 0;
        while (i < len or carry != 0) : (i += 1) {
            if (i < len) carry += @as(usize, bytes[i]) * 58;
            bytes[i] = @intCast(carry & 0xff);
            carry >>= 8;
            if (i + 1 > len) len = i + 1;
        }
    }
    var zeros: usize = 0;
    for (s) |c| {
        if (c == '1') zeros += 1 else break;
    }
    var out: [32]u8 = [_]u8{0} ** 32;
    var j: usize = 0;
    while (j < len) : (j += 1) out[zeros + (len - 1 - j)] = bytes[j];
    return out;
}

// ── carrier vectors (cluster-canonical) ─────────────────────────────────────
/// The phantom: SPL Stake Pool ValidatorList (recorder pk
/// dffd79b6faf8e97b51e851abd7463955c834cfb8281c0f5717d9e8f688e4d923).
const VALIDATOR_LIST = b58("G5N6K3qW86GSkNEpywcbJk42LjEZoshzECFg1LNVjSLa");
const STAKE_POOL_PROG = b58("SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy");
const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;
const COMPUTE_BUDGET = b58("ComputeBudget111111111111111111111111111111");

const FEE_PAYER: [32]u8 = [_]u8{0xAA} ** 32;
const NONCE_PK: [32]u8 = [_]u8{0xBB} ** 32;
const OTHER_PK: [32]u8 = [_]u8{0xCC} ** 32;

const SEED_SLOT: core.Slot = 0;
const BANK_SLOT: core.Slot = 414386920;

fn mkBank(alloc: std.mem.Allocator) !*Bank {
    return try Bank.init(
        alloc,
        BANK_SLOT,
        SEED_SLOT,
        Hash{ .data = [_]u8{0} ** 32 },
        vex_crypto.LtHash.init(),
        Hash{ .data = [_]u8{0} ** 32 },
    );
}

/// Append a representative AccountWrite the same way the handlers do
/// (bank.collectWrite with computed lt deltas).
fn appendWrite(bank: *Bank, pk: [32]u8, owner: [32]u8, lamports: u64, data: []const u8) !void {
    const new_lt = Bank.accountLtHash(&pk, &owner, lamports, false, data);
    try bank.collectWrite(.{
        .pubkey = .{ .data = pk },
        .lamports = lamports,
        .owner = .{ .data = owner },
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = data,
        .old_lt = vex_crypto.LtHash.init(),
        .new_lt = new_lt,
    });
}

// ── ParsedTx builders ───────────────────────────────────────────────────────
// Layout used by both: keys[0]=fee payer (writable signer), keys[1]=writable
// non-signer (nonce / validator-list), keys[2]=readonly (program id slot).
// Legacy header: num_required_sigs=1, num_readonly_signed=0,
// num_readonly_unsigned=1, static_key_count=num_accounts=4.
const TxFixture = struct {
    keys: [4][32]u8,
    blockhash: [32]u8 = [_]u8{0x11} ** 32,
    ix_datas: [4][8]u8 = undefined,
    ix_accts: [4][2]u8 = undefined,
    instrs: [4]replay.ParsedInstruction = undefined,
    ptx: replay.ParsedTx = undefined,

    /// Carrier-shaped NON-nonce tx: ix0/ix1 ComputeBudget (keys[3]),
    /// ix2 StakePool (keys[2]) writing keys[1], ix3 StakePool (fails).
    fn initCarrier(self: *TxFixture) void {
        self.keys = .{ FEE_PAYER, VALIDATOR_LIST, STAKE_POOL_PROG, COMPUTE_BUDGET };
        self.ix_datas[0] = [_]u8{ 2, 0, 0, 0, 0, 0, 0, 0 }; // CB
        self.ix_datas[1] = [_]u8{ 3, 0, 0, 0, 0, 0, 0, 0 }; // CB
        self.ix_datas[2] = [_]u8{ 7, 0, 0, 0, 0, 0, 0, 0 }; // UpdateValidatorListBalance-ish
        self.ix_datas[3] = [_]u8{ 7, 0, 0, 0, 0, 0, 0, 0 };
        self.ix_accts[0] = .{ 0, 0 };
        self.ix_accts[1] = .{ 0, 0 };
        self.ix_accts[2] = .{ 1, 0 };
        self.ix_accts[3] = .{ 1, 0 };
        self.instrs = .{
            .{ .program_id_index = 3, .account_indices = self.ix_accts[0][0..1], .data = &self.ix_datas[0] },
            .{ .program_id_index = 3, .account_indices = self.ix_accts[1][0..1], .data = &self.ix_datas[1] },
            .{ .program_id_index = 2, .account_indices = self.ix_accts[2][0..1], .data = &self.ix_datas[2] },
            .{ .program_id_index = 2, .account_indices = self.ix_accts[3][0..1], .data = &self.ix_datas[3] },
        };
        self.fillPtx();
    }

    /// Durable-nonce tx: ix0 = System AdvanceNonceAccount (disc 4, nonce =
    /// keys[1]), ix1 = StakePool ix that fails.
    fn initNonce(self: *TxFixture) void {
        self.keys = .{ FEE_PAYER, NONCE_PK, STAKE_POOL_PROG, SYSTEM_ID };
        self.ix_datas[0] = [_]u8{ 4, 0, 0, 0, 0, 0, 0, 0 }; // AdvanceNonceAccount
        self.ix_datas[1] = [_]u8{ 7, 0, 0, 0, 0, 0, 0, 0 };
        self.ix_accts[0] = .{ 1, 0 }; // nonce account first
        self.ix_accts[1] = .{ 1, 0 };
        self.instrs[0] = .{ .program_id_index = 3, .account_indices = self.ix_accts[0][0..2], .data = &self.ix_datas[0] };
        self.instrs[1] = .{ .program_id_index = 2, .account_indices = self.ix_accts[1][0..1], .data = &self.ix_datas[1] };
        self.instrs[2] = self.instrs[1];
        self.instrs[3] = self.instrs[1];
        self.fillPtx();
        self.ptx.num_instructions = 2;
    }

    fn fillPtx(self: *TxFixture) void {
        self.ptx = .{
            .num_sigs = 1,
            .num_required_sigs = 1,
            .num_readonly_signed = 0,
            .num_readonly_unsigned = 2, // keys[2..4) readonly (program ids)
            .account_keys = self.keys[0..],
            .num_accounts = 4,
            .blockhash = &self.blockhash,
            .instructions = self.instrs[0..],
            .num_instructions = 4,
            .fee_payer = self.keys[0],
            .static_key_count = 4,
        };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "carrier @414386920: failed tx rolls back leaked instruction write; fee debit survives" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    // Fee debit lands BEFORE the instruction loop (serial fee block / DAG
    // Phase 1) — i.e. below the tx mark.
    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 1_000_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;
    try std.testing.expectEqual(@as(usize, 1), tx_mark);

    // ix2 succeeds and (pre-fix) leaks: the ValidatorList write — THE phantom.
    var vl_data = [_]u8{0xD1} ** 256; // representative slice of the 730,009 B
    try appendWrite(bank, VALIDATOR_LIST, STAKE_POOL_PROG, 5_084_354_560, &vl_data);
    try std.testing.expectEqual(@as(usize, 2), bank.pending_writes.items.len);

    // ix3 fails genuinely (BPF r0!=0 → error.M4_RunFailed at the dispatch
    // call site). Run the REAL failed-tx handler with the REAL carrier tx
    // shape (non-nonce → FeePayerOnly rollback).
    var fx: TxFixture = undefined;
    fx.initCarrier();
    try std.testing.expect(replay.txDurableNoncePk(&fx.ptx) == null);

    const rb_before = replay.TxRollbackStats.txs_failed_rolled_back;
    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 3, .err = error.M4_RunFailed });

    // THE carrier assertion: the phantom write is GONE — only the fee debit
    // remains (Agave account_saver collect_accounts_for_failed_tx ⇒
    // RollbackAccounts::FeePayerOnly). Pre-fix the ValidatorList write
    // survived to flush/lt (recorder slot-414386920.writes.jsonl).
    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
    try std.testing.expectEqual(@as(u64, 1_000_000 - 5_000), bank.pending_writes.items[0].lamports);
    for (bank.pending_writes.items) |w| {
        try std.testing.expect(!std.mem.eql(u8, &w.pubkey.data, &VALIDATOR_LIST));
    }

    // Loud accounting fired.
    try std.testing.expectEqual(rb_before + 1, replay.TxRollbackStats.txs_failed_rolled_back);
}

test "durable-nonce tx: advanced nonce write survives rollback (SeparateNonceAndFeePayer)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    // Fee debit (below mark).
    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 2_000_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    // ix0 AdvanceNonceAccount succeeded → 80-byte advanced nonce state.
    var advanced_nonce = [_]u8{0} ** 80;
    advanced_nonce[0] = 1; // Versions::Current
    advanced_nonce[4] = 1; // State::Initialized
    @memset(advanced_nonce[40..72], 0x42); // new durable_nonce bytes
    try appendWrite(bank, NONCE_PK, SYSTEM_ID, 1_447_680, &advanced_nonce);

    // ix1 wrote something else, then failed mid-instruction? No — ix1's OWN
    // writes never commit (a failed instruction commits nothing); what leaks
    // pre-fix is EARLIER instructions' writes. Simulate an extra successful
    // write from a hypothetical ix between advance and failure.
    var other_data = [_]u8{0xEE} ** 32;
    try appendWrite(bank, OTHER_PK, STAKE_POOL_PROG, 777, &other_data);

    var fx: TxFixture = undefined;
    fx.initNonce();
    const npk = replay.txDurableNoncePk(&fx.ptx);
    try std.testing.expect(npk != null);
    try std.testing.expectEqualSlices(u8, &NONCE_PK, &npk.?);

    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 1, .err = error.M4_RunFailed });

    // Survivors: fee debit + the ADVANCED nonce (rollback_accounts.rs:82-87
    // SeparateNonceAndFeePayer; nonce_info.rs validation-advance survives).
    try std.testing.expectEqual(@as(usize, 2), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
    const nw = &bank.pending_writes.items[1];
    try std.testing.expectEqualSlices(u8, &NONCE_PK, &nw.pubkey.data);
    try std.testing.expectEqualSlices(u8, &advanced_nonce, nw.data);
    try std.testing.expectEqual(@as(u64, 1_447_680), nw.lamports);
    // OTHER_PK rolled back.
    for (bank.pending_writes.items) |w| {
        try std.testing.expect(!std.mem.eql(u8, &w.pubkey.data, &OTHER_PK));
    }
}

test "durable-nonce tx failing AT ix0 (the advance itself): nothing kept beyond fee" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 500_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    var fx: TxFixture = undefined;
    fx.initNonce();
    // ix0 failed → no advance write exists; ix_idx=0 must NOT engage the
    // nonce keep (Agave: validation-advance synthesis is the deferred
    // residual; execution-side there is nothing to keep).
    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 0, .err = error.MissingRequiredSignature });
    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
}

test "nonce keep is FIRST-write-only: a later same-tx nonce mutation is discarded" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 100_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    var advance = [_]u8{0x42} ** 80;
    try appendWrite(bank, NONCE_PK, SYSTEM_ID, 1_447_680, &advance);
    var later = [_]u8{0x99} ** 80; // hypothetical later mutation of the nonce acct
    try appendWrite(bank, NONCE_PK, SYSTEM_ID, 1_447_680, &later);

    const res = replay.rollbackFailedTxWrites(bank, tx_mark, NONCE_PK);
    try std.testing.expect(res.nonce_kept);
    try std.testing.expectEqual(@as(usize, 1), res.rolled); // the later nonce write
    try std.testing.expectEqual(@as(usize, 2), bank.pending_writes.items.len);
    // The kept write is the FIRST (the advance) — Agave rollback stores the
    // validation-time advance, not later execution mutations.
    try std.testing.expectEqualSlices(u8, &advance, bank.pending_writes.items[1].data);
}

test "txDurableNoncePk negatives: wrong position / program / discriminant" {
    var fx: TxFixture = undefined;

    // AdvanceNonce NOT at ix0 → not a durable-nonce tx (Agave only inspects
    // the message's first instruction).
    fx.initCarrier();
    fx.ix_datas[1] = [_]u8{ 4, 0, 0, 0, 0, 0, 0, 0 };
    fx.instrs[1] = .{ .program_id_index = 3, .account_indices = fx.ix_accts[1][0..1], .data = &fx.ix_datas[1] };
    try std.testing.expect(replay.txDurableNoncePk(&fx.ptx) == null);

    // ix0 System but disc != 4 (Transfer=2).
    fx.initNonce();
    fx.ix_datas[0] = [_]u8{ 2, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(replay.txDurableNoncePk(&fx.ptx) == null);

    // ix0 disc 4 but program is NOT System.
    fx.initNonce();
    fx.instrs[0].program_id_index = 2; // stake pool program
    try std.testing.expect(replay.txDurableNoncePk(&fx.ptx) == null);
}

// ════════════════════════════════════════════════════════════════════════════
// fix/proactive-trio FIX-1 (2026-06-10, task #65) — residual leak siblings of
// carrier #6: V1-ELF abort swallow (1a), vote handler swallow (1b), stake
// handler swallow (1c). Tests below extend the carrier-#6 family.
// ════════════════════════════════════════════════════════════════════════════

const vex_bpf = @import("vex_bpf");

test "FIX-1b: vote ix fails after a writing ix → earlier write rolled back, fee survives" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    // Fee debit below the tx mark (survives — RollbackAccounts::fee_payer).
    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 1_000_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    // ix0 (e.g. a System transfer or memo-adjacent write) succeeded and wrote.
    var w_data = [_]u8{0xA7} ** 64;
    try appendWrite(bank, OTHER_PK, SYSTEM_ID, 123_456, &w_data);

    // ix1 = Vote instruction that genuinely fails (the Sig vote-program
    // transplant returns InstructionError; VoteTooOld arrives as
    // Custom(VoteError::VoteTooOld) — COMMON live traffic). Agave
    // vote_processor.rs: every InstructionError FAILS the whole tx; the
    // "successful-tx-with-filtered-vote" notion lives at CONSENSUS level,
    // not in the vote processor. Pre-FIX-1b executeVoteViaSig swallowed the
    // error into VoteDbg.mutate_fail and the loop kept ix0's write.
    var fx: TxFixture = undefined;
    fx.initCarrier(); // shape irrelevant for non-nonce rollback (FeePayerOnly)
    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 1, .err = error.Custom });

    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
    for (bank.pending_writes.items) |w| {
        try std.testing.expect(!std.mem.eql(u8, &w.pubkey.data, &OTHER_PK));
    }
}

test "FIX-1c: stake dispatch parse failures PROPAGATE from executeStakeInstruction" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    // Minimal stub AccountsDb: parse failures happen BEFORE any account
    // read, but the generic instantiation still needs the method + shape.
    const StubAcct = struct {
        lamports: u64,
        owner: core.Pubkey,
        executable: bool,
        rent_epoch: u64,
        data: []const u8,
    };
    const StubDb = struct {
        const Self = @This();
        pub fn getAccountInSlot(_: *Self, _: *const core.Pubkey, _: u64, _: []const u64) ?StubAcct {
            return null;
        }
    };
    var db = StubDb{};

    var fx: TxFixture = undefined;
    fx.initCarrier();

    // Unknown discriminant 0x99 → Agave limited_deserialize →
    // InstructionError::InvalidInstructionData → tx fails. Vexor's parse
    // names it UnknownInstruction; both classify GENUINE. Pre-FIX-1c this
    // returned void (success, zero writes).
    var bad_disc = [_]u8{ 0x99, 0, 0, 0 };
    var bad_ix = replay.ParsedInstruction{
        .program_id_index = 2,
        .account_indices = fx.ix_accts[0][0..1],
        .data = &bad_disc,
    };
    try std.testing.expectError(
        error.UnknownInstruction,
        replay.executeStakeInstruction(bad_ix, &fx.ptx, bank, &db, alloc),
    );

    // Data shorter than the 4-byte discriminant → InvalidInstructionData.
    var short = [_]u8{ 0x02, 0x00 };
    bad_ix.data = &short;
    try std.testing.expectError(
        error.InvalidInstructionData,
        replay.executeStakeInstruction(bad_ix, &fx.ptx, bank, &db, alloc),
    );

    // Nothing leaked into pending_writes by either failure.
    try std.testing.expectEqual(@as(usize, 0), bank.pending_writes.items.len);
}

test "FIX-1c: stake ix fails after a writing ix → earlier write rolled back" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 800_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    var w_data = [_]u8{0x5C} ** 200; // ix0 stake-account write that must NOT survive
    try appendWrite(bank, OTHER_PK, STAKE_POOL_PROG, 2_282_880, &w_data);

    var fx: TxFixture = undefined;
    fx.initCarrier();
    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 1, .err = error.InvalidInstructionData });

    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
}

// ── FIX-1a: V1 interpreter outcome classification ───────────────────────────
// Drives the REAL SbpfExecutor with hand-assembled sBPF programs (no ELF):
// the executor must classify a completed run with r0 != 0 as .program_error
// (executeBpfProgramCore then propagates error.V1_ProgramFailed to the
// loops) and a clean r0 == 0 run as .ok. Pre-fix both were
// indistinguishable empty-mutation SUCCESSES.

fn mkV1Program(alloc: std.mem.Allocator, text: []const u8) !vex_bpf.LoadedProgram {
    const rodata = try alloc.dupe(u8, text);
    return .{
        .rodata_combined = rodata,
        .text_offset = 0,
        .text_size = rodata.len,
        .entry_pc = 0,
        .sbpf_version = .v1,
        .rodata_vaddr = 0x100000000, // VM_RODATA_START
        .symbols = std.StringHashMap(u64).init(alloc),
        .function_registry = .{},
        .allocator = alloc,
    };
}

test "FIX-1a: V1 run with r0!=0 → .program_error; r0==0 → .ok" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const acct = [_]vex_bpf.AccountEntry{.{
        .pubkey = .{ .data = OTHER_PK },
        .owner = .{ .data = SYSTEM_ID },
        .lamports = 1,
        .data = &[_]u8{},
        .executable = false,
        .rent_epoch = 0,
        .is_signer = false,
        .is_writable = true,
    }};

    // MOV64_IMM r0, 1 ; EXIT  → program completes, returns error code 1.
    const text_fail = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    var prog_fail = try mkV1Program(alloc, &text_fail);
    var exec1 = try vex_bpf.SbpfExecutor.init(alloc);
    defer alloc.destroy(exec1);
    const pid = core.Pubkey{ .data = STAKE_POOL_PROG };
    const muts1 = try exec1.execute(&prog_fail, &acct, &[_]u8{}, &pid);
    try std.testing.expectEqual(@as(usize, 0), muts1.len);
    try std.testing.expectEqual(vex_bpf.TopLevelRunOutcome.program_error, exec1.last_top_outcome);

    // MOV64_IMM r0, 0 ; EXIT  → clean success.
    const text_ok = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    var prog_ok = try mkV1Program(alloc, &text_ok);
    var exec2 = try vex_bpf.SbpfExecutor.init(alloc);
    defer alloc.destroy(exec2);
    const muts2 = try exec2.execute(&prog_ok, &acct, &[_]u8{}, &pid);
    _ = muts2;
    try std.testing.expectEqual(vex_bpf.TopLevelRunOutcome.ok, exec2.last_top_outcome);
}

test "FIX-1a: V1 genuine program failure rolls the tx back via the loop contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const bank = try mkBank(alloc);
    defer bank.deinit();

    try appendWrite(bank, FEE_PAYER, SYSTEM_ID, 600_000 - 5_000, &[_]u8{});
    const tx_mark = bank.pending_writes.items.len;

    var w_data = [_]u8{0xE2} ** 48;
    try appendWrite(bank, VALIDATOR_LIST, STAKE_POOL_PROG, 999, &w_data);

    var fx: TxFixture = undefined;
    fx.initCarrier();
    replay.rollbackFailedTx(bank, &fx.ptx, tx_mark, .{ .ix_idx = 3, .err = error.V1_ProgramFailed });

    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    try std.testing.expectEqualSlices(u8, &FEE_PAYER, &bank.pending_writes.items[0].pubkey.data);
}
