//! Vexor Native System Program Handler — Inline CPI (W3, vex-152)
//!
//! When a BPF program calls `sol_invoke_signed` with target program_id =
//! 11111111111111111111111111111111 (System), the SBPF executor's CPI handler
//! dispatches here instead of returning ExecutionError.Exit (which had been
//! the previous behavior, leaving cpi=0 across thousands of executions and
//! causing ATA / Router / panic-loop programs to see no post-state).
//!
//! Pattern follows vex-022's `spl_token_cpi.zig` (commit f86fa02): we receive
//! mutable views into the *outer* VM's input buffer (write-through pointers
//! that land in the region mapped at INPUT_START), so the BPF caller sees
//! the post-CPI state when control returns to it without any merge step.
//!
//! Scope (Phase 1):
//!   - Transfer  (ix=2)             — lamports debit/credit, full
//!   - CreateAccount (ix=0)         — lamports + space + owner, full
//!   - Allocate (ix=8)              — data_len grow on caller-owned acct
//!   - Assign (ix=1)                — owner change on caller-owned acct
//!   - CreateAccountWithSeed (ix=3) — STUBBED (returns ERR_NOT_SUPPORTED)
//!   - AllocateWithSeed (ix=9)      — STUBBED (returns ERR_NOT_SUPPORTED)
//!   - AssignWithSeed (ix=10)       — STUBBED (returns ERR_NOT_SUPPORTED)
//!   - TransferWithSeed (ix=11)     — STUBBED (returns ERR_NOT_SUPPORTED)
//!   - Nonce ix (4..7, 12)          — STUBBED (returns ERR_NOT_SUPPORTED)
//!
//! Stub semantics: returns a non-zero r0 (Solana InstructionError encoding,
//! u64 ≠ 0). The BPF caller's `?` operator on the inner result will branch
//! through Err, which is the correct "instruction failed" path — NOT silent
//! Exit (which previously caused empty mutations + RPC-shadow fallback).
//!
//! Owner write-through: SolAccountInfoC.owner_addr (offset +32) points into
//! the outer VM's input region (16-byte aligned, at INPUT_START + 4 + ...).
//! Region.fromSlice(INPUT_START, input_buf.items) is a *mutable* region, so
//! `mm.vmap(.mutable, owner_vm, 32)` succeeds and bytes written there are
//! visible to the caller. They will NOT, however, propagate into the BPF
//! deserialise → AccountMutation.owner pipeline on this branch — that wiring
//! is W2's responsibility (vex-039 owner plumbing, not yet on this branch).
//!
//! References: @prov:bpf.system-cpi (Sig update_caller_account + system handler
//! logic cross-checks), plus this repo's vex_svm/native/system.zig and
//! vex_bpf/spl_token_cpi.zig (f86fa02) CPI write-through pattern.
//!
//! NOT supported: PDA signer-seed validation. Phase-1 CPI ignores r4/r5
//! (signers_seeds_ptr / signers_seeds_len). System Assign + CreateAccount
//! protected by signature checks at the OUTER tx level catch most misuse;
//! malicious BPF callers that try to forge signers via fake seeds will not
//! be detected here. Phase-2 PDA verification is queued separately.

const std = @import("std");

// ── System program instruction discriminants (little-endian u32) ────────────
pub const IX_CREATE_ACCOUNT: u32 = 0;
pub const IX_ASSIGN: u32 = 1;
pub const IX_TRANSFER: u32 = 2;
pub const IX_CREATE_ACCOUNT_WITH_SEED: u32 = 3;
pub const IX_ADVANCE_NONCE: u32 = 4;
pub const IX_WITHDRAW_NONCE: u32 = 5;
pub const IX_INITIALIZE_NONCE: u32 = 6;
pub const IX_AUTHORIZE_NONCE: u32 = 7;
pub const IX_ALLOCATE: u32 = 8;
pub const IX_ALLOCATE_WITH_SEED: u32 = 9;
pub const IX_ASSIGN_WITH_SEED: u32 = 10;
pub const IX_TRANSFER_WITH_SEED: u32 = 11;
pub const IX_UPGRADE_NONCE: u32 = 12;

// ── Solana SystemError → r0 encoding ────────────────────────────────────────
// We return non-zero r0 so the BPF caller's `Result::?` propagates Err.
// Exact codes match Solana SystemError variants where possible; for cases
// outside SystemError we use generic InstructionError values (≥ 0xC).
pub const ERR_INSUFFICIENT_FUNDS: u64 = 1; // 0x01 SystemError::ResultWithNegativeLamports
pub const ERR_INVALID_INSTRUCTION: u64 = 2; // generic
pub const ERR_INVALID_ACCOUNT_DATA: u64 = 0x0A; // InstructionError::InvalidAccountData
pub const ERR_ACCOUNT_DATA_TOO_SMALL: u64 = 0x0B;
pub const ERR_ACCOUNT_ALREADY_INIT: u64 = 0x05; // InstructionError::AccountAlreadyInitialized
pub const ERR_INVALID_OWNER: u64 = 0x14;
pub const ERR_NOT_SUPPORTED: u64 = 0x29; // InstructionError::UnsupportedSysvar (re-purposed)
pub const ERR_OVERFLOW: u64 = 0x10; // InstructionError::ArithmeticOverflow
pub const ERR_INVALID_ARGUMENT: u64 = 0x03;
pub const ERR_EXTERNAL_LAMPORT_SPEND: u64 = 0x06; // SystemError::ExternalAccountLamportSpend

// Maximum data length permitted by Solana System program.
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024; // 10 MiB

// All-zero pubkey (System program ID and "owned-by-system" sentinel).
pub const SYSTEM_PROGRAM_ID = [_]u8{0} ** 32;

/// Mutable view into one CPI account inside the outer VM's input region.
/// All four fields (lamports, data, data_len header, owner) are write-through
/// pointers — modifying these slices mutates the BPF input region directly.
pub const AccountSlice = struct {
    /// 8 bytes, little-endian u64 — lamports for this account
    lamports_ptr: []u8,
    /// account data bytes (length = current data_len; capacity = +MAX_REALLOC)
    data: []u8,
    /// 8 bytes, little-endian u64 — data_len header sitting immediately
    /// before `data` in the input region. The outer deserialise() reads
    /// THIS to learn the post-execution data_len; we must update it on grow.
    /// May be empty if the parser couldn't locate it; in that case Allocate /
    /// CreateAccount cannot grow data and must return ERR_INVALID_ACCOUNT_DATA.
    data_len_hdr: []u8,
    /// 32 bytes — the owner pubkey for this account, write-through.
    owner_ptr: []u8,
    /// Realloc capacity: how many bytes immediately following `data` are
    /// safely writable (zero-filled by serialise). Caller computes from
    /// MAX_REALLOC + (data_len header).
    realloc_capacity: usize,
    /// Cached pubkey (read-only copy; for matching against AccountMeta).
    pubkey: [32]u8,
    is_writable: bool,

    pub inline fn lamports(self: AccountSlice) u64 {
        return std.mem.readInt(u64, self.lamports_ptr[0..8], .little);
    }
    pub inline fn setLamports(self: AccountSlice, v: u64) void {
        std.mem.writeInt(u64, self.lamports_ptr[0..8], v, .little);
    }
    pub inline fn dataLen(self: AccountSlice) u64 {
        if (self.data_len_hdr.len < 8) return self.data.len;
        return std.mem.readInt(u64, self.data_len_hdr[0..8], .little);
    }
    pub inline fn setDataLen(self: AccountSlice, v: u64) bool {
        if (self.data_len_hdr.len < 8) return false;
        std.mem.writeInt(u64, self.data_len_hdr[0..8], v, .little);
        return true;
    }
    pub inline fn setOwner(self: AccountSlice, owner: [32]u8) void {
        if (self.owner_ptr.len >= 32) @memcpy(self.owner_ptr[0..32], &owner);
    }
    pub inline fn isSystemOwned(self: AccountSlice) bool {
        if (self.owner_ptr.len < 32) return false;
        for (self.owner_ptr[0..32]) |b| if (b != 0) return false;
        return true;
    }
};

// ── Instruction handlers ─────────────────────────────────────────────────────

/// Transfer (ix=2): lamports debit/credit between two System-owned accounts.
/// accounts: [from, to]
pub fn execTransfer(from: AccountSlice, to: AccountSlice, amount: u64) u64 {
    if (amount == 0) return 0; // no-op success
    if (!from.is_writable or !to.is_writable) return ERR_INVALID_ARGUMENT;
    // Invariant: cannot debit a non-System-owned account. @prov:bpf.system-cpi
    if (!from.isSystemOwned()) return ERR_EXTERNAL_LAMPORT_SPEND;
    // System program also requires source has zero data (or we'd be
    // overwriting a program/data account). @prov:bpf.system-cpi
    if (from.data.len != 0) return ERR_INVALID_ARGUMENT;

    const from_l = from.lamports();
    if (from_l < amount) return ERR_INSUFFICIENT_FUNDS;
    const to_l = to.lamports();
    const new_to = std.math.add(u64, to_l, amount) catch return ERR_OVERFLOW;

    // Commit only after all checks passed. @prov:bpf.system-cpi
    from.setLamports(from_l - amount);
    to.setLamports(new_to);
    return 0;
}

/// CreateAccount (ix=0): debit `from`, credit `to`, set owner+space on `to`.
/// accounts: [from, to]
pub fn execCreateAccount(
    from: AccountSlice,
    to: AccountSlice,
    lamports: u64,
    space: u64,
    owner: [32]u8,
) u64 {
    if (!from.is_writable or !to.is_writable) return ERR_INVALID_ARGUMENT;
    if (!from.isSystemOwned()) return ERR_EXTERNAL_LAMPORT_SPEND;
    if (from.data.len != 0) return ERR_INVALID_ARGUMENT;
    // Target must currently be uninitialized: zero data, zero lamports*, system-owned.
    // *Actually CreateAccount allows pre-funded targets in Solana, but it FAILS if
    //  target already has non-zero data OR non-system owner. Match that.
    if (to.dataLen() != 0) return ERR_ACCOUNT_ALREADY_INIT;
    if (!to.isSystemOwned()) return ERR_ACCOUNT_ALREADY_INIT;
    if (space > MAX_PERMITTED_DATA_LENGTH) return ERR_INVALID_ARGUMENT;
    // We need the realloc region to fit the requested space.
    if (space > to.realloc_capacity) return ERR_INVALID_ACCOUNT_DATA;

    const from_l = from.lamports();
    if (from_l < lamports) return ERR_INSUFFICIENT_FUNDS;
    const to_l = to.lamports();
    const new_to = std.math.add(u64, to_l, lamports) catch return ERR_OVERFLOW;

    // Commit
    from.setLamports(from_l - lamports);
    to.setLamports(new_to);
    if (!to.setDataLen(space)) return ERR_INVALID_ACCOUNT_DATA;
    // Zero the newly-allocated space (serialise pre-zeroed the realloc region,
    // but be defensive in case of re-use within a tx).
    if (space > 0 and to.data.len + to.realloc_capacity >= space) {
        // `data` is the slice with original .len; but the underlying buffer
        // extends `realloc_capacity` further. Build the full reachable slice
        // from the data pointer.
        const full_ptr = to.data.ptr;
        const full_len = to.data.len + to.realloc_capacity;
        const full = full_ptr[0..full_len];
        @memset(full[0..@as(usize, @intCast(space))], 0);
    }
    to.setOwner(owner);
    return 0;
}

/// Allocate (ix=8): set data_len on a System-owned, currently-empty account.
/// accounts: [target]
pub fn execAllocate(target: AccountSlice, space: u64) u64 {
    if (!target.is_writable) return ERR_INVALID_ARGUMENT;
    if (!target.isSystemOwned()) return ERR_INVALID_OWNER;
    if (target.dataLen() != 0) return ERR_ACCOUNT_ALREADY_INIT;
    if (space > MAX_PERMITTED_DATA_LENGTH) return ERR_INVALID_ARGUMENT;
    if (space > target.realloc_capacity) return ERR_INVALID_ACCOUNT_DATA;

    if (!target.setDataLen(space)) return ERR_INVALID_ACCOUNT_DATA;
    if (space > 0) {
        const full_ptr = target.data.ptr;
        const full_len = target.data.len + target.realloc_capacity;
        const full = full_ptr[0..full_len];
        @memset(full[0..@as(usize, @intCast(space))], 0);
    }
    return 0;
}

/// Assign (ix=1): set owner on a System-owned account.
/// accounts: [target]
pub fn execAssign(target: AccountSlice, new_owner: [32]u8) u64 {
    if (!target.is_writable) return ERR_INVALID_ARGUMENT;
    // System program requires the *current* owner to be System (you can only
    // re-assign accounts you own). The signer check happens at outer tx level.
    if (!target.isSystemOwned()) return ERR_INVALID_OWNER;
    target.setOwner(new_owner);
    return 0;
}

// ── Test helpers ────────────────────────────────────────────────────────────

test "transfer happy path" {
    var lam_from: [8]u8 = undefined;
    std.mem.writeInt(u64, &lam_from, 1_000_000, .little);
    var lam_to: [8]u8 = undefined;
    std.mem.writeInt(u64, &lam_to, 0, .little);
    var dlen_from: [8]u8 = .{0} ** 8;
    var dlen_to: [8]u8 = .{0} ** 8;
    var own_from: [32]u8 = .{0} ** 32;
    var own_to: [32]u8 = .{0} ** 32;
    var data_from: [0]u8 = .{};
    var data_to: [0]u8 = .{};

    const from = AccountSlice{
        .lamports_ptr = &lam_from,
        .data = &data_from,
        .data_len_hdr = &dlen_from,
        .owner_ptr = &own_from,
        .realloc_capacity = 0,
        .pubkey = .{0} ** 32,
        .is_writable = true,
    };
    const to = AccountSlice{
        .lamports_ptr = &lam_to,
        .data = &data_to,
        .data_len_hdr = &dlen_to,
        .owner_ptr = &own_to,
        .realloc_capacity = 0,
        .pubkey = .{1} ** 32,
        .is_writable = true,
    };
    try std.testing.expectEqual(@as(u64, 0), execTransfer(from, to, 100_000));
    try std.testing.expectEqual(@as(u64, 900_000), from.lamports());
    try std.testing.expectEqual(@as(u64, 100_000), to.lamports());
}

test "transfer insufficient funds" {
    var lam_from: [8]u8 = undefined;
    std.mem.writeInt(u64, &lam_from, 50, .little);
    var lam_to: [8]u8 = .{0} ** 8;
    var dlen: [8]u8 = .{0} ** 8;
    var own: [32]u8 = .{0} ** 32;
    var data: [0]u8 = .{};
    const from = AccountSlice{
        .lamports_ptr = &lam_from,
        .data = &data,
        .data_len_hdr = &dlen,
        .owner_ptr = &own,
        .realloc_capacity = 0,
        .pubkey = .{0} ** 32,
        .is_writable = true,
    };
    const to = AccountSlice{
        .lamports_ptr = &lam_to,
        .data = &data,
        .data_len_hdr = &dlen,
        .owner_ptr = &own,
        .realloc_capacity = 0,
        .pubkey = .{1} ** 32,
        .is_writable = true,
    };
    try std.testing.expectEqual(ERR_INSUFFICIENT_FUNDS, execTransfer(from, to, 100));
}

test "assign owner change" {
    var lam: [8]u8 = .{0} ** 8;
    var dlen: [8]u8 = .{0} ** 8;
    var own: [32]u8 = .{0} ** 32;
    var data: [0]u8 = .{};
    const tgt = AccountSlice{
        .lamports_ptr = &lam,
        .data = &data,
        .data_len_hdr = &dlen,
        .owner_ptr = &own,
        .realloc_capacity = 0,
        .pubkey = .{0} ** 32,
        .is_writable = true,
    };
    const new_owner: [32]u8 = .{0xAB} ** 32;
    try std.testing.expectEqual(@as(u64, 0), execAssign(tgt, new_owner));
    for (own) |b| try std.testing.expectEqual(@as(u8, 0xAB), b);
}

test "allocate sets data_len" {
    var lam: [8]u8 = .{0} ** 8;
    var dlen: [8]u8 = .{0} ** 8;
    var own: [32]u8 = .{0} ** 32;
    var buf: [128]u8 = .{0xCC} ** 128; // pretend full input region (data + realloc)
    const tgt = AccountSlice{
        .lamports_ptr = &lam,
        .data = buf[0..0], // current data_len = 0
        .data_len_hdr = &dlen,
        .owner_ptr = &own,
        .realloc_capacity = 128,
        .pubkey = .{0} ** 32,
        .is_writable = true,
    };
    try std.testing.expectEqual(@as(u64, 0), execAllocate(tgt, 64));
    try std.testing.expectEqual(@as(u64, 64), std.mem.readInt(u64, &dlen, .little));
    for (buf[0..64]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
