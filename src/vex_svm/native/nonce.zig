/// nonce.zig — Durable Nonce Program for Vexor
/// @prov:svm.nonce-port
///
/// Ported from:
///   firedancer/src/flamenco/runtime/program/fd_system_program_nonce.c (860 lines)
///
/// Also referenced:
///   sig/src/runtime/nonce.zig
///
/// Functions ported:
///   fd_system_program_exec_advance_nonce_account()    → execAdvanceNonce()
///   fd_system_program_exec_withdraw_nonce_account()   → execWithdrawNonce()
///   fd_system_program_exec_initialize_nonce_account() → execInitializeNonce()
///   fd_system_program_exec_authorize_nonce_account()  → execAuthorizeNonce()
///   fd_system_program_exec_upgrade_nonce_account()    → execUpgradeNonce()
///   fd_durable_nonce_from_blockhash()                 → durableNonceFromHash()
///   fd_system_program_set_nonce_state()               → setNonceState()
///
/// Account layout (by instruction):
///   AdvanceNonce:    [0]=nonce_acct(writable), [1]=recent_blockhashes, [optional 2]=authority
///   WithdrawNonce:   [0]=nonce_acct(writable), [1]=dest(writable), [2]=recent_blockhashes, [3]=rent
///   InitializeNonce: [0]=nonce_acct(writable), [1]=recent_blockhashes, [2]=rent
///   AuthorizeNonce:  [0]=nonce_acct(writable)
///   UpgradeNonce:    [0]=nonce_acct(writable)
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// Minimal account view — mirrors fd_borrowed_account_t fields used here.
// (Same pattern as vote_v2.zig BorrowedAccount)
// ─────────────────────────────────────────────────────────────────────────────
pub const BorrowedAccount = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    data: []u8,
    rent_epoch: u64,
    executable: bool,
    is_signer: bool,
    is_writable: bool,
};

// ─────────────────────────────────────────────────────────────────────────────
// Error set
// ─────────────────────────────────────────────────────────────────────────────
pub const NonceError = error{
    MissingAccount,
    MissingRequiredSignature,
    InvalidAccountData,
    InsufficientFunds,
    InvalidArgument,
    /// Nonce has not advanced (same as current slot's blockhash).
    /// FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED
    NonceBlockhashNotExpired,
    /// No blockhashes available.
    /// FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES
    NoRecentBlockhashes,
    /// Already initialized.
    AccountAlreadyInitialized,
    /// Nonce account data too small for state.
    AccountDataTooSmall,
    ArithmeticOverflow,
    Unimplemented,
};

// ─────────────────────────────────────────────────────────────────────────────
// Wire constants
// ─────────────────────────────────────────────────────────────────────────────

/// Serialized size of a NonceStateVersions (bincode).
/// sig/src/runtime/nonce.zig:20
pub const NONCE_STATE_SERIALIZED_SIZE: usize = 80;

/// Prefix for durable-nonce hash derivation.
/// fd_system_program_nonce.c:79-84
/// sig/src/runtime/nonce.zig:8
pub const DURABLE_NONCE_HASH_PREFIX = "DURABLE_NONCE";

// ─────────────────────────────────────────────────────────────────────────────
// NonceStateVersion discriminants (wire format)
// fd_system_program_nonce.c:156-166
// ─────────────────────────────────────────────────────────────────────────────
pub const NonceVersionTag = enum(u32) {
    legacy = 0,
    current = 1,
    _,
};

/// Inner state discriminant.
pub const NonceStateTag = enum(u32) {
    uninitialized = 0,
    initialized = 1,
    _,
};

// ─────────────────────────────────────────────────────────────────────────────
// NonceData — the "initialized" payload
// sig/src/runtime/nonce.zig:77-84
// ─────────────────────────────────────────────────────────────────────────────
pub const NonceData = struct {
    /// The pubkey authorised to sign nonce transactions.
    authority: [32]u8,
    /// Durable nonce value (SHA256-derived from a blockhash).
    durable_nonce: [32]u8,
    /// lamports_per_signature at the time the nonce was last advanced.
    lamports_per_signature: u64,
};

// ─────────────────────────────────────────────────────────────────────────────
// NonceState — tagged union over uninitialized / initialized
// ─────────────────────────────────────────────────────────────────────────────
pub const NonceState = union(NonceStateTag) {
    uninitialized: void,
    initialized: NonceData,
};

// ─────────────────────────────────────────────────────────────────────────────
// NonceStateVersions — outer versioned wrapper (legacy | current)
// ─────────────────────────────────────────────────────────────────────────────
pub const NonceStateVersions = union(NonceVersionTag) {
    legacy: NonceState,
    current: NonceState,

    /// Extract the inner state regardless of version.
    pub fn getState(self: NonceStateVersions) NonceState {
        return switch (self) {
            .legacy => |s| s,
            .current => |s| s,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Bincode helpers
// These implement the wire format used by Solana for nonce account data.
// ─────────────────────────────────────────────────────────────────────────────

/// Decode NonceStateVersions from 80 bytes of account data.
/// fd_system_program_nonce.c:145-151 (fd_bincode_decode_static(nonce_state_versions,...))
/// sig/src/runtime/nonce.zig:58-65
pub fn decodeNonceState(data: []const u8) NonceError!NonceStateVersions {
    if (data.len < NONCE_STATE_SERIALIZED_SIZE) return NonceError.InvalidAccountData;

    const ver_tag = std.mem.readInt(u32, data[0..4], .little);
    const state_tag = std.mem.readInt(u32, data[4..8], .little);

    const inner: NonceState = switch (@as(NonceStateTag, @enumFromInt(state_tag))) {
        .uninitialized => .uninitialized,
        .initialized => blk: {
            if (data.len < 8 + 32 + 32 + 8) return NonceError.InvalidAccountData;
            var nd = NonceData{
                .authority = undefined,
                .durable_nonce = undefined,
                .lamports_per_signature = std.mem.readInt(u64, data[8 + 32 + 32 ..][0..8], .little),
            };
            @memcpy(&nd.authority, data[8..40]);
            @memcpy(&nd.durable_nonce, data[40..72]);
            break :blk .{ .initialized = nd };
        },
        _ => return NonceError.InvalidAccountData,
    };

    return switch (@as(NonceVersionTag, @enumFromInt(ver_tag))) {
        .legacy => .{ .legacy = inner },
        .current => .{ .current = inner },
        _ => NonceError.InvalidAccountData,
    };
}

/// Encode NonceStateVersions into exactly 80 bytes, writing to `out`.
/// Mirrors fd_system_program_set_nonce_state → fd_nonce_state_versions_encode.
pub fn encodeNonceState(vsv: NonceStateVersions, out: []u8) NonceError!void {
    if (out.len < NONCE_STATE_SERIALIZED_SIZE) return NonceError.AccountDataTooSmall;
    @memset(out[0..NONCE_STATE_SERIALIZED_SIZE], 0);

    const ver_tag: u32 = @intFromEnum(std.meta.activeTag(vsv));
    const inner = vsv.getState();
    const state_tag: u32 = @intFromEnum(std.meta.activeTag(inner));

    std.mem.writeInt(u32, out[0..4], ver_tag, .little);
    std.mem.writeInt(u32, out[4..8], state_tag, .little);

    switch (inner) {
        .uninitialized => {},
        .initialized => |nd| {
            @memcpy(out[8..40], &nd.authority);
            @memcpy(out[40..72], &nd.durable_nonce);
            std.mem.writeInt(u64, out[72..80], nd.lamports_per_signature, .little);
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// durableNonceFromHash
// fd_system_program_nonce.c:78-84
// sig/src/runtime/nonce.zig:98-100
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a durable-nonce value from a blockhash.
/// SHA256("DURABLE_NONCE" || blockhash)
pub fn durableNonceFromHash(blockhash: *const [32]u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(DURABLE_NONCE_HASH_PREFIX);
    hasher.update(blockhash);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// InstrCtx — minimal instruction context for nonce operations
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal instruction context: accounts + signer mask + sysvar data.
///
/// In the full Vexor runtime this will be unified with the system program's
/// InstrCtx.  For now, callers provide the nonce-specific sysvar bytes.
pub const InstrCtx = struct {
    accounts: []BorrowedAccount,
    signer_mask: u64,

    /// Current most-recent blockhash (from RecentBlockhashes sysvar).
    recent_blockhash: [32]u8,
    /// lamports_per_signature from the most-recent blockhash entry.
    lamports_per_signature: u64,
    /// Whether the RecentBlockhashes sysvar is empty.
    recent_blockhashes_empty: bool,

    /// Minimum rent-exempt lamport balance for `data_len` bytes.
    rent_minimum_balance_fn: ?*const fn (data_len: u64) u64,

    pub fn isSigner(self: *const InstrCtx, idx: usize) bool {
        if (idx >= 64) return false;
        return (self.signer_mask >> @intCast(idx)) & 1 != 0;
    }

    /// Returns true if any account in the accounts list whose pubkey
    /// matches `key` is also a signer.
    /// fd_system_program_nonce.c:174-180 (fd_exec_instr_ctx_any_signed)
    pub fn anySigned(self: *const InstrCtx, key: *const [32]u8) bool {
        for (self.accounts, 0..) |acc, i| {
            if (std.mem.eql(u8, &acc.pubkey, key) and self.isSigner(i)) return true;
        }
        return false;
    }

    pub fn getAccount(self: *const InstrCtx, idx: usize) NonceError!*BorrowedAccount {
        if (idx >= self.accounts.len) return NonceError.MissingAccount;
        return &self.accounts[idx];
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// execAdvanceNonce
// fd_system_program_nonce.c:129-286
// https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L20-L70
// ─────────────────────────────────────────────────────────────────────────────

/// Advance the durable nonce to the next blockhash.
///
/// Accounts:
///   [0] nonce account (writable)
///   [1] RecentBlockhashes sysvar (checked)
///   [optional 2] explicit authority (if not in account 0)
pub fn execAdvanceNonce(ctx: *const InstrCtx) NonceError!void {
    if (ctx.accounts.len < 1) return NonceError.MissingAccount;

    // fd_system_program_nonce.c:249-280 — recent blockhashes must be non-empty
    if (ctx.recent_blockhashes_empty) {
        std.log.warn("[Nonce] advance: recent blockhash list is empty", .{});
        return NonceError.NoRecentBlockhashes;
    }

    const nonce_acct = try ctx.getAccount(0);

    // fd_system_program_nonce.c:135-141 — account must be writable
    if (!nonce_acct.is_writable) return NonceError.InvalidArgument;

    // Decode nonce state
    const vsv = try decodeNonceState(nonce_acct.data);
    const state = vsv.getState();

    switch (state) {
        .uninitialized => {
            std.log.warn("[Nonce] advance: account state is invalid (uninitialized)", .{});
            return NonceError.InvalidAccountData;
        },
        .initialized => |nd| {
            // fd_system_program_nonce.c:174-180 — authority must sign
            if (!ctx.anySigned(&nd.authority)) return NonceError.MissingRequiredSignature;

            // fd_system_program_nonce.c:182-191 — compute next durable nonce
            const next_nonce = durableNonceFromHash(&ctx.recent_blockhash);

            // fd_system_program_nonce.c:193-199 — must differ from current
            if (std.mem.eql(u8, &nd.durable_nonce, &next_nonce)) {
                std.log.warn("[Nonce] advance: nonce can only advance once per slot", .{});
                return NonceError.NonceBlockhashNotExpired;
            }

            // fd_system_program_nonce.c:201-215 — write new state
            const new_data = NonceData{
                .authority = nd.authority,
                .durable_nonce = next_nonce,
                .lamports_per_signature = ctx.lamports_per_signature,
            };
            const new_vsv = NonceStateVersions{ .current = .{ .initialized = new_data } };
            try encodeNonceState(new_vsv, nonce_acct.data);
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execWithdrawNonce
// fd_system_program_nonce.c:288-494
// https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L72-L151
// ─────────────────────────────────────────────────────────────────────────────

/// Withdraw lamports from a nonce account.
///
/// Accounts:
///   [0] nonce account (writable)
///   [1] destination account (writable)
///   [2] RecentBlockhashes sysvar
///   [3] Rent sysvar
pub fn execWithdrawNonce(ctx: *const InstrCtx, requested_lamports: u64) NonceError!void {
    if (ctx.accounts.len < 2) return NonceError.MissingAccount;

    const nonce_acct = try ctx.getAccount(0);

    // fd_system_program_nonce.c:307-313 — nonce account must be writable
    // Agave 4.1.0-beta.3 system_instruction.rs:90-97
    if (!nonce_acct.is_writable) return NonceError.InvalidArgument;

    const vsv = try decodeNonceState(nonce_acct.data);
    const state = vsv.getState();

    // 2026-06-10 (nonce wiring, carrier @414201776): restructured to match
    // Agave 4.1.0-beta.3 system_instruction.rs:112-153 EXACTLY — the signer
    // check happens INSIDE each branch (before the closing-path set_state),
    // not once after the switch. The previous shape also had a compile bug
    // (`nonce_acct.pubkey.data` — BorrowedAccount.pubkey is [32]u8) that was
    // latent because this function was never wired/referenced.
    switch (state) {
        .uninitialized => {
            // Agave system_instruction.rs:113-124 — balance check, then the
            // nonce account itself must have signed.
            if (requested_lamports > nonce_acct.lamports) {
                std.log.warn("[Nonce] withdraw: insufficient lamports {} need {}", .{
                    nonce_acct.lamports, requested_lamports,
                });
                return NonceError.InsufficientFunds;
            }
            if (!ctx.anySigned(&nonce_acct.pubkey)) return NonceError.MissingRequiredSignature;
        },
        .initialized => |nd| {
            // Agave system_instruction.rs:125-152
            if (requested_lamports == nonce_acct.lamports) {
                // Closing the account: durable nonce must not match the
                // current bank's durable nonce (rs:126-134), authority must
                // sign (rs:135), THEN reset to uninitialized (rs:136).
                const next_nonce = durableNonceFromHash(&ctx.recent_blockhash);
                if (std.mem.eql(u8, &nd.durable_nonce, &next_nonce)) {
                    std.log.warn("[Nonce] withdraw: nonce can only advance once per slot", .{});
                    return NonceError.NonceBlockhashNotExpired;
                }
                if (!ctx.anySigned(&nd.authority)) return NonceError.MissingRequiredSignature;
                const new_vsv = NonceStateVersions{ .current = .uninitialized };
                try encodeNonceState(new_vsv, nonce_acct.data);
            } else {
                // Partial withdrawal: must leave enough for rent exemption
                // (rs:139-150), authority must sign (rs:151).
                const rent_min: u64 = if (ctx.rent_minimum_balance_fn) |f|
                    f(@intCast(nonce_acct.data.len))
                else
                    0;
                // Agave checked_add → InsufficientFunds on overflow (rs:21-23)
                const required = std.math.add(u64, requested_lamports, rent_min) catch
                    return NonceError.InsufficientFunds;
                if (required > nonce_acct.lamports) {
                    std.log.warn("[Nonce] withdraw: insufficient lamports {} need {}", .{
                        nonce_acct.lamports, required,
                    });
                    return NonceError.InsufficientFunds;
                }
                if (!ctx.anySigned(&nd.authority)) return NonceError.MissingRequiredSignature;
            }
        },
    }

    // Agave system_instruction.rs:155-159 — move lamports.
    //
    // Self-withdraw guard (dest == nonce account): Agave's instruction
    // accounts share ONE underlying transaction account, so sub-then-add
    // nets to zero. Vexor's caller builds SEPARATE AccountMeta copies per
    // instruction-account slot, so an explicit skip is required — same bug
    // class as system_v2.transferVerified's r75-bug-class-d self-transfer.
    const dest_acct = try ctx.getAccount(1);
    if (!std.mem.eql(u8, &dest_acct.pubkey, &nonce_acct.pubkey)) {
        nonce_acct.lamports = std.math.sub(u64, nonce_acct.lamports, requested_lamports) catch
            return NonceError.ArithmeticOverflow;
        dest_acct.lamports = std.math.add(u64, dest_acct.lamports, requested_lamports) catch
            return NonceError.ArithmeticOverflow;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execInitializeNonce
// fd_system_program_nonce.c:497-667
// https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L153-L198
// ─────────────────────────────────────────────────────────────────────────────

/// Initialize a nonce account with the given authority.
///
/// Accounts:
///   [0] nonce account (writable, must be uninitialized, size=80)
///   [1] RecentBlockhashes sysvar
///   [2] Rent sysvar
pub fn execInitializeNonce(ctx: *const InstrCtx, authorized: *const [32]u8) NonceError!void {
    if (ctx.accounts.len < 1) return NonceError.MissingAccount;

    // fd_system_program_nonce.c:620-621
    if (ctx.recent_blockhashes_empty) {
        std.log.warn("[Nonce] initialize: recent blockhash list is empty", .{});
        return NonceError.NoRecentBlockhashes;
    }

    const nonce_acct = try ctx.getAccount(0);

    // fd_system_program_nonce.c:507-515 — must be writable
    if (!nonce_acct.is_writable) return NonceError.InvalidArgument;

    if (nonce_acct.data.len < NONCE_STATE_SERIALIZED_SIZE) return NonceError.InvalidAccountData;

    const vsv = try decodeNonceState(nonce_acct.data);
    const state = vsv.getState();

    switch (state) {
        .initialized => {
            // fd_system_program_nonce.c:594-602 — already initialized
            std.log.warn("[Nonce] initialize: account state is invalid (already initialized)", .{});
            return NonceError.InvalidAccountData;
        },
        .uninitialized => {
            // fd_system_program_nonce.c:541-556 — rent-exempt check
            if (ctx.rent_minimum_balance_fn) |rent_fn| {
                const min_balance = rent_fn(@intCast(nonce_acct.data.len));
                if (nonce_acct.lamports < min_balance) {
                    std.log.warn("[Nonce] initialize: insufficient lamports {} need {}", .{
                        nonce_acct.lamports, min_balance,
                    });
                    return NonceError.InsufficientFunds;
                }
            }

            // fd_system_program_nonce.c:558-566 — derive durable nonce
            const durable_nonce = durableNonceFromHash(&ctx.recent_blockhash);

            // fd_system_program_nonce.c:568-588 — write initialized state
            const new_data = NonceData{
                .authority = authorized.*,
                .durable_nonce = durable_nonce,
                .lamports_per_signature = ctx.lamports_per_signature,
            };
            const new_vsv = NonceStateVersions{ .current = .{ .initialized = new_data } };
            try encodeNonceState(new_vsv, nonce_acct.data);
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execAuthorizeNonce
// fd_system_program_nonce.c:669-784
// https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L200-L236
// ─────────────────────────────────────────────────────────────────────────────

/// Change the authority of a nonce account.
///
/// Accounts:
///   [0] nonce account (writable)
pub fn execAuthorizeNonce(ctx: *const InstrCtx, new_authority: *const [32]u8) NonceError!void {
    if (ctx.accounts.len < 1) return NonceError.MissingAccount;

    const nonce_acct = try ctx.getAccount(0);

    // fd_system_program_nonce.c:681-687 — must be writable
    if (!nonce_acct.is_writable) return NonceError.InvalidArgument;

    const vsv = try decodeNonceState(nonce_acct.data);
    const state = vsv.getState();

    switch (state) {
        .uninitialized => {
            std.log.warn("[Nonce] authorize: account state is invalid (uninitialized)", .{});
            return NonceError.InvalidAccountData;
        },
        .initialized => |nd| {
            // fd_system_program_nonce.c:718-725 — current authority must sign
            if (!ctx.anySigned(&nd.authority)) return NonceError.MissingRequiredSignature;

            // fd_system_program_nonce.c:728-740 — update authority
            const new_data = NonceData{
                .authority = new_authority.*,
                .durable_nonce = nd.durable_nonce,
                .lamports_per_signature = nd.lamports_per_signature,
            };
            // 2026-06-10 Agave-faithfulness fix: Versions::authorize PRESERVES
            // the version variant — "Preserve Version variant since cannot
            // change durable_nonce field here" (solana-nonce-3.2.0
            // versions.rs:100-108). The previous code always wrote back
            // `current`, which would silently upgrade a Legacy nonce's
            // version tag → 4-byte divergence vs cluster.
            const new_vsv: NonceStateVersions = switch (vsv) {
                .legacy => .{ .legacy = .{ .initialized = new_data } },
                .current => .{ .current = .{ .initialized = new_data } },
            };
            try encodeNonceState(new_vsv, nonce_acct.data);
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// execUpgradeNonce
// Agave: programs/system/src/system_instruction.rs  UpgradeNonceAccount
// sig/src/runtime/nonce.zig:44-56
// ─────────────────────────────────────────────────────────────────────────────

/// Upgrade a legacy nonce account to the "current" version.
///
/// Accounts:
///   [0] nonce account (writable)
pub fn execUpgradeNonce(ctx: *const InstrCtx) NonceError!void {
    if (ctx.accounts.len < 1) return NonceError.MissingAccount;

    const nonce_acct = try ctx.getAccount(0);
    if (!nonce_acct.is_writable) return NonceError.InvalidArgument;

    const vsv = try decodeNonceState(nonce_acct.data);

    // Agave 4.1.0-beta.3 system_processor.rs:473-493: Versions::upgrade()
    // returns None for Current (already upgraded) AND for Legacy+Uninitialized;
    // the processor maps None → InstructionError::InvalidArgument. The
    // previous code returned OK for Current (silent no-op divergence on tx
    // status) and InvalidAccountData for Legacy+Uninitialized — both wrong.
    switch (vsv) {
        .current => {
            return NonceError.InvalidArgument;
        },
        .legacy => |inner| {
            switch (inner) {
                .uninitialized => return NonceError.InvalidArgument,
                .initialized => |nd| {
                    // sig/src/runtime/nonce.zig:49-53 — re-derive nonce from stored hash
                    var new_nd = nd;
                    new_nd.durable_nonce = durableNonceFromHash(&nd.durable_nonce);
                    const new_vsv = NonceStateVersions{ .current = .{ .initialized = new_nd } };
                    try encodeNonceState(new_vsv, nonce_acct.data);
                },
            }
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

test "durableNonceFromHash is deterministic" {
    const bh: [32]u8 = .{0xab} ** 32;
    const n1 = durableNonceFromHash(&bh);
    const n2 = durableNonceFromHash(&bh);
    try std.testing.expectEqual(n1, n2);
    // Must differ from the input
    try std.testing.expect(!std.mem.eql(u8, &n1, &bh));
}

test "encode/decode round-trip: uninitialized" {
    var buf: [80]u8 = .{0} ** 80;
    const vsv = NonceStateVersions{ .current = .uninitialized };
    try encodeNonceState(vsv, &buf);
    const decoded = try decodeNonceState(&buf);
    try std.testing.expect(decoded.getState() == .uninitialized);
}

test "encode/decode round-trip: initialized" {
    const authority: [32]u8 = .{0x11} ** 32;
    const dn: [32]u8 = .{0x22} ** 32;
    const lps: u64 = 5000;

    var buf: [80]u8 = .{0} ** 80;
    const vsv = NonceStateVersions{ .current = .{ .initialized = .{
        .authority = authority,
        .durable_nonce = dn,
        .lamports_per_signature = lps,
    } } };
    try encodeNonceState(vsv, &buf);

    const decoded = try decodeNonceState(&buf);
    const data = decoded.getState().initialized;
    try std.testing.expectEqual(authority, data.authority);
    try std.testing.expectEqual(dn, data.durable_nonce);
    try std.testing.expectEqual(lps, data.lamports_per_signature);
}

test "execInitializeNonce: round-trip via encode/decode" {
    // This verifies the encode/decode path used by execInitializeNonce.
    const recent_bh: [32]u8 = .{0x55} ** 32;
    const authority: [32]u8 = .{0xAA} ** 32;
    const lps: u64 = 5000;

    const durable_nonce = durableNonceFromHash(&recent_bh);

    var buf: [80]u8 = .{0} ** 80;
    // Write uninitialized current state
    const init_vsv = NonceStateVersions{ .current = .uninitialized };
    try encodeNonceState(init_vsv, &buf);

    // After execInitializeNonce the state should be initialized.
    const new_data = NonceData{
        .authority = authority,
        .durable_nonce = durable_nonce,
        .lamports_per_signature = lps,
    };
    const new_vsv = NonceStateVersions{ .current = .{ .initialized = new_data } };
    try encodeNonceState(new_vsv, &buf);

    const decoded = try decodeNonceState(&buf);
    const nd = decoded.getState().initialized;
    try std.testing.expectEqual(authority, nd.authority);
    try std.testing.expectEqual(durable_nonce, nd.durable_nonce);
    try std.testing.expectEqual(lps, nd.lamports_per_signature);
}
