//! Vexor BPF2 — M9: Config native builtin program.
//!
//! ── Spec source ───────────────────────────────────────────────────────────
//!   • agave-3.x (legacy, since beta.7 dropped to Core BPF):
//!       programs/config/src/config_processor.rs
//!   • sig: src/runtime/program/config/lib.zig (ID + COMPUTE_UNITS only;
//!     no execute logic ported in sig either)
//!
//! ── Behavior summary ──────────────────────────────────────────────────────
//! The Config program writes arbitrary bincode-encoded data into a
//! pre-existing config account, gated by a list of authorised signers
//! stored INSIDE the config account's existing data. There is exactly ONE
//! instruction (no tag byte): `process_instruction(ix_data)` where
//! `ix_data = bincode( (Vec<(Pubkey, bool)>, T) )` — a vector of
//! (signer_pubkey, is_signer) tuples followed by the raw user payload.
//!
//! Steps:
//!   1. Decode `(keys, payload)` from ix_data.
//!   2. Confirm the config account (account[0]) exists and is owned by
//!      ConfigProgram + writable.
//!   3. Decode the EXISTING config account data to extract its prior
//!      authorised-signer set.
//!   4. For every signer in `keys`: must be a real signer of the tx
//!      AND must be present in the prior authorised-signer set.
//!   5. Overwrite account[0].data with `(keys, payload)` re-encoded.
//!
//! ── Port status ───────────────────────────────────────────────────────────
//!   • Wave-3 deliverable in this session: minimal happy-path port +
//!     authorised-signer pre-state check. Bincode encoding shape is
//!     hand-rolled (Vec<u8> length-prefix is a u64 LE; Pubkey is 32 raw
//!     bytes; bool is a single 0x00/0x01 byte) — verified against agave-3
//!     `config_processor::process_instruction`.
//!   • Cold variants: none — Config has only the one no-tag instruction.
//!   • If/when this implementation must field a real on-chain config
//!     account, it is gated behind a fix_ledger-backed parity test before
//!     wireup. Until then handlers that touch account-resident data
//!     return `M9_Config_VariantPending_FullParityNotYetVerified` so any
//!     accidental wiring fails loudly rather than silently.
//!
//! ── SIMD inventory ────────────────────────────────────────────────────────
//!   None active that change handler behavior. Future SIMD to migrate
//!   Config to Core BPF (TBD pubkey) would deactivate this builtin
//!   entirely; until then it stays here.
//!
//! ── fix_ledger anchors ────────────────────────────────────────────────────
//!   None directly.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const InvokeContext = ic.InvokeContext;
const Pubkey32 = ic.Pubkey32;
const trace = @import("mod.zig").trace;
const CONFIG_PROGRAM_ID = @import("mod.zig").CONFIG_PROGRAM_ID;

pub const COMPUTE_UNITS: u64 = 450; // sig: program/config/lib.zig

pub const Error = error{
    M9_Config_OutOfCompute,
    M9_Config_NoActiveFrame,
    M9_Config_AccountIndexOutOfBounds,
    M9_Config_NotEnoughAccounts,
    M9_Config_AccountNotWritable,
    M9_Config_BadOwner,
    M9_Config_InvalidInstructionData,
    M9_Config_DataTooLong,
    M9_Config_MissingRequiredSignature,
    M9_Config_NewSignerNotInPriorList,
    /// Config account data could not be decoded as ConfigKeys (Agave
    /// `InvalidAccountData` = 3).
    M9_Config_InvalidAccountData,
    /// Duplicate (pubkey, is_signer) tuple among the new keys — rejected by
    /// `dedupe_config_program_signers` (ACTIVE; Agave `InvalidArgument` = 1).
    M9_Config_DuplicateKey,
    /// Set when the rebuild has not yet validated a code-path against an
    /// on-chain config-account fixture. Hit only when a caller passes a
    /// non-empty prior config payload — the happy-path-only port is gated
    /// by this until parity is verified end-to-end.
    M9_Config_VariantPending_FullParityNotYetVerified,
};

/// Hard cap on the size of a config account's data payload. Mirrors agave's
/// transaction-loading default (10 MB). Anything bigger is malformed.
const MAX_CONFIG_DATA_LEN: usize = 10 * 1024 * 1024;

pub fn execute(ctx: *InvokeContext, ix_data: []const u8) Error!void {
    ctx.consumeCompute(COMPUTE_UNITS) catch return error.M9_Config_OutOfCompute;
    trace("M9.config.execute (data_len={d})", .{ix_data.len});

    const frame = ctx.currentFrame() orelse return error.M9_Config_NoActiveFrame;
    if (frame.account_indices.len < 1) return error.M9_Config_NotEnoughAccounts;

    // ── Parse the NEW ConfigKeys from the front of ix_data ─────────────────
    // Layout: [compact-u16 keys_len][keys_len × (Pubkey32 + u8 is_signer)][payload…].
    // keys_len is a Solana SHORTVEC (compact-u16), NOT a bincode u64 — FD decodes
    // it via fd_bincode_compact_u16_decode (fd_types.c fd_config_keys_decode:5-9).
    // VERIFIED against on-chain bytes: slot 419002721 tx#3 ix_data AND account
    // DrpZ…'s data both begin 0x02 = 2 keys (1 + 2×33 + payload). Payload is the
    // REMAINDER (not length-prefixed); trailing bytes allowed. Canonical bound:
    // total instruction data ≤ TXN_MTU (FD fd_config_program.c:35).
    const FD_TXN_MTU: usize = 1232;
    if (ix_data.len > FD_TXN_MTU) return error.M9_Config_InvalidInstructionData;
    var npos: usize = 0;
    const num_new = readCompactU16(ix_data, &npos) orelse return error.M9_Config_InvalidInstructionData;
    const new_keys_start = npos;
    const new_keys_bytes = @as(usize, num_new) * 33; // num_new ≤ 65535 → no overflow
    if (ix_data.len < new_keys_start + new_keys_bytes) return error.M9_Config_InvalidInstructionData;
    // Strict bincode-bool: is_signer byte ∈ {0,1}. Agave's `deserialize`
    // rejects 2+ → InvalidInstructionData (attacker-reachable if skipped).
    {
        var i: usize = 0;
        while (i < num_new) : (i += 1) {
            if (ix_data[new_keys_start + i * 33 + 32] > 1) return error.M9_Config_InvalidInstructionData;
        }
    }

    // ── Resolve config account = instruction-account[0] ────────────────────
    const cfg_idx = frame.account_indices[0];
    if (cfg_idx >= ctx.tx.accounts.len) return error.M9_Config_AccountIndexOutOfBounds;
    const cfg = &ctx.tx.accounts[cfg_idx];
    const config_account_key = cfg.pubkey;
    const is_config_account_signer = cfg.is_signer;

    // Owner must be the Config program (canonical id bytes, not currentProgramId).
    if (!std.mem.eql(u8, &cfg.owner, &CONFIG_PROGRAM_ID)) return error.M9_Config_BadOwner;

    // ── Parse CURRENT ConfigKeys from the account's existing data ──────────
    // Same shortvec layout. A freshly-created config account is zero-filled →
    // compact-u16 reads 0 keys (first deploy). We never re-serialize; we only
    // read the prior signer set.
    var cpos: usize = 0;
    const num_cur = readCompactU16(cfg.data, &cpos) orelse return error.M9_Config_InvalidAccountData;
    const cur_keys_start = cpos;
    const cur_keys_bytes = @as(usize, num_cur) * 33;
    if (cfg.data.len < cur_keys_start + cur_keys_bytes) return error.M9_Config_InvalidAccountData;
    // Validate current is_signer bytes ∈ {0,1} and count prior signer keys.
    var current_signer_count: usize = 0;
    {
        var i: usize = 0;
        while (i < num_cur) : (i += 1) {
            const sflag = cfg.data[cur_keys_start + i * 33 + 32];
            if (sflag > 1) return error.M9_Config_InvalidAccountData;
            if (sflag == 1) current_signer_count += 1;
        }
    }

    // ── Authorisation (agave config_processor.rs:44-126, FD c.91-209) ──────
    // First-init (no prior signer keys) requires the config account to sign.
    if (current_signer_count == 0 and !is_config_account_signer)
        return error.M9_Config_MissingRequiredSignature;

    // Positional signer validation over the NEW signer keys. `counter` is the
    // 1-based ordinal among is_signer keys; the K-th signer key must be the
    // instruction account at index K (a key equal to the config account key
    // consumes an ordinal WITHOUT occupying a positional slot). This is NOT a
    // pubkey search — order matters.
    var counter: usize = 0;
    {
        var i: usize = 0;
        while (i < num_new) : (i += 1) {
            const off = new_keys_start + i * 33;
            if (ix_data[off + 32] != 1) continue; // is_signer keys only
            counter += 1;
            const signer_key: [32]u8 = ix_data[off..][0..32].*;
            if (!std.mem.eql(u8, &signer_key, &config_account_key)) {
                // instruction-account[counter] must be exactly this signer AND sign.
                if (counter >= frame.account_indices.len)
                    return error.M9_Config_MissingRequiredSignature;
                const sa_idx = frame.account_indices[counter];
                if (sa_idx >= ctx.tx.accounts.len)
                    return error.M9_Config_MissingRequiredSignature;
                const sa = &ctx.tx.accounts[sa_idx];
                if (!sa.is_signer) return error.M9_Config_MissingRequiredSignature;
                if (!std.mem.eql(u8, &sa.pubkey, &signer_key))
                    return error.M9_Config_MissingRequiredSignature;
                // After first deploy (ANY prior keys), a new signer must also
                // have been in the prior signer set.
                if (num_cur > 0 and !currentSignersContain(cfg.data, cur_keys_start, num_cur, &signer_key))
                    return error.M9_Config_MissingRequiredSignature;
            } else if (!is_config_account_signer) {
                return error.M9_Config_MissingRequiredSignature;
            }
        }
    }

    // Reject duplicate (pubkey, is_signer) tuples among the NEW keys
    // (`dedupe_config_program_signers` ACTIVE since slot 86,060,263 →
    // Agave `InvalidArgument`). Compare the full 33-byte tuple.
    {
        var i: usize = 0;
        while (i < num_new) : (i += 1) {
            const off_i = new_keys_start + i * 33;
            var j: usize = i + 1;
            while (j < num_new) : (j += 1) {
                const off_j = new_keys_start + j * 33;
                if (std.mem.eql(u8, ix_data[off_i .. off_i + 33], ix_data[off_j .. off_j + 33]))
                    return error.M9_Config_DuplicateKey;
            }
        }
    }

    // Every prior signer must also have signed this update.
    if (current_signer_count > counter) return error.M9_Config_MissingRequiredSignature;

    // ── Write-back ─────────────────────────────────────────────────────────
    if (!cfg.is_writable) return error.M9_Config_AccountNotWritable;
    if (cfg.data.len < ix_data.len) return error.M9_Config_InvalidInstructionData;
    // Verbatim copy of exactly ix_data.len bytes. The tail [ix_data.len..] is
    // PRESERVED (NOT zeroed) — matches agave config_processor.rs:131-133 and FD
    // fd_config_program.c:232 (`fd_memcpy(data, ix_data, data_sz)`; no memset).
    // ⚠ FOOTGUN: zeroing the tail diverges bank_hash on any UPDATE where new
    // data < account.data.len (e.g. slot 419002721 tx#3: 255B into an 860B
    // account). Reference: agave-behavior-extractor 2026-07-01.
    @memcpy(cfg.data[0..ix_data.len], ix_data);
}

/// True if `pk` appears as an is_signer key in the prior ConfigKeys blob
/// (`current_signer_keys.contains(signer)` in agave). Scans in place — no
/// allocation, unbounded key count (matches agave's unbounded deserialize;
/// FD caps at 37 keys, not reachable for real accounts).
fn currentSignersContain(cur_data: []const u8, cur_keys_start: usize, num_cur: u16, pk: *const [32]u8) bool {
    var i: usize = 0;
    while (i < num_cur) : (i += 1) {
        const off = cur_keys_start + i * 33;
        if (cur_data[off + 32] == 1 and std.mem.eql(u8, cur_data[off .. off + 32], pk))
            return true;
    }
    return false;
}

/// Canonical Solana compact-u16 (shortvec) reader — the encoding Agave/FD use
/// for `ConfigKeys.keys` length (fd_bincode_compact_u16_decode). Mirrors the
/// proven `compute_budget.readCompactU16` but with a u32 accumulator + range
/// check so a malformed 3-byte value returns null (→ Invalid*Data) rather than
/// panicking on a u16 shift overflow in the consensus path. Advances `pos`.
fn readCompactU16(data: []const u8, pos: *usize) ?u16 {
    var result: u32 = 0;
    var shift: u5 = 0;
    var nbytes: usize = 0;
    while (nbytes < 3) : (nbytes += 1) {
        if (pos.* >= data.len) return null;
        const b = data[pos.*];
        pos.* += 1;
        result |= @as(u32, b & 0x7f) << shift;
        if (b & 0x80 == 0) {
            if (result > 0xffff) return null;
            // STRICT decode: reject NON-MINIMAL (aliased) encodings. Agave's
            // ShortU16/serde `visit_u16` and FD's fd_bincode_compact_u16_decode
            // (fd_bincode.h:visit_u16 → returns ERR on `size != min_size`) both
            // REJECT e.g. 0x80 0x00 (=0 in 2 bytes). If we ACCEPTED where they
            // REJECT, a crafted validator-info tx would parse for us but fault
            // for the cluster → a NEW carrier of the exact class we're closing.
            // minimal(v) = 1 (v<0x80) | 2 (v<0x4000) | 3 (else); reject mismatch.
            const min_bytes: usize = if (result < 0x80) 1 else if (result < 0x4000) 2 else 3;
            if (nbytes + 1 != min_bytes) return null;
            return @intCast(result);
        }
        shift += 7;
    }
    return null; // >3 bytes = malformed compact-u16
}

pub fn selfTest() bool {
    return COMPUTE_UNITS == 450;
}

// ── Tests ─────────────────────────────────────────────────────────────────

const Harness = @import("test_harness.zig");

test "M9 config: OutOfCompute when meter is short" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 100, &.{});
    defer h.deinit();
    try t.expectError(error.M9_Config_OutOfCompute, execute(h.ctx, &.{}));
}

test "M9 config: rejects empty ix_data" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{});
    defer h.deinit();
    try h.pushFrame(0, &.{});
    defer h.popFrame();
    try t.expectError(error.M9_Config_NotEnoughAccounts, execute(h.ctx, &.{}));
}

test "M9 config: rejects ix_data smaller than length-prefix" {
    const t = std.testing;
    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .lamports = 1, .data_len = 64, .owner = @import("mod.zig").CONFIG_PROGRAM_ID, .is_writable = true, .is_signer = false },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    defer h.popFrame();
    try t.expectError(error.M9_Config_InvalidInstructionData, execute(h.ctx, &[_]u8{ 0x01, 0x02 }));
}

test "M9 config: slot 419002721 carrier — real on-chain bytes, verbatim write + tail preserved" {
    const t = std.testing;
    // REAL on-chain bytes from slot 419002721 tx#3 (a validator-info UpdateConfig,
    // "HSDT Tokyo"). Pre-fix, this UPDATE hit a VariantPending stub → M9_NoFallback
    // → SILENTLY swallowed by the migration fallthrough → 0 mutations → DrpZ's data
    // left unwritten → missing lt_hash contribution → bank_hash carrier 128904….
    // This KAT runs the COMPILED execute() on the exact bytes and asserts canonical
    // Agave/FD behaviour: verbatim copy of ix_data + tail [ix_data.len..] PRESERVED.
    // It is ALSO a regression lock on the compact-u16 length decode: a u64 read of
    // the first 8 bytes (the bug caught 2026-07-01) makes num_keys enormous → the
    // `ix_data.len < new_keys_start + new_keys_bytes` guard fires → this test FAILS.
    // Fixture generated from getBlock(419002721)+getAccountInfo(DrpZ) 2026-07-01.
    const IX_DATA = [_]u8{ 0x02, 0x07, 0x51, 0x97, 0x01, 0x74, 0x48, 0xf2, 0xac, 0x5d, 0xc2, 0x3c, 0x9e, 0xbc, 0x7a, 0xc7, 0x8c, 0x0a, 0x27, 0x25, 0x7a, 0xc6, 0x14, 0x45, 0x8d, 0xe0, 0xa4, 0xf1, 0x6f, 0x80, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x45, 0x09, 0x85, 0x3c, 0xbd, 0x51, 0x70, 0x7b, 0x1e, 0xa5, 0x28, 0x2d, 0x13, 0x02, 0x4d, 0xd8, 0xb6, 0xbc, 0x5c, 0xed, 0x08, 0x3f, 0xab, 0x72, 0xf7, 0x31, 0x89, 0xcc, 0xe1, 0x42, 0x6d, 0x01, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x22, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x3a, 0x22, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2d, 0x67, 0x72, 0x61, 0x64, 0x65, 0x20, 0x53, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x22, 0x2c, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x22, 0x48, 0x53, 0x44, 0x54, 0x20, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x22, 0x2c, 0x22, 0x77, 0x65, 0x62, 0x73, 0x69, 0x74, 0x65, 0x22, 0x3a, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x2e, 0x63, 0x6f, 0x2f, 0x22, 0x7d };
    const PRIOR = [_]u8{ 0x02, 0x07, 0x51, 0x97, 0x01, 0x74, 0x48, 0xf2, 0xac, 0x5d, 0xc2, 0x3c, 0x9e, 0xbc, 0x7a, 0xc7, 0x8c, 0x0a, 0x27, 0x25, 0x7a, 0xc6, 0x14, 0x45, 0x8d, 0xe0, 0xa4, 0xf1, 0x6f, 0x80, 0x00, 0x00, 0x00, 0x00, 0xe9, 0x45, 0x09, 0x85, 0x3c, 0xbd, 0x51, 0x70, 0x7b, 0x1e, 0xa5, 0x28, 0x2d, 0x13, 0x02, 0x4d, 0xd8, 0xb6, 0xbc, 0x5c, 0xed, 0x08, 0x3f, 0xab, 0x72, 0xf7, 0x31, 0x89, 0xcc, 0xe1, 0x42, 0x6d, 0x01, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x22, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x22, 0x3a, 0x22, 0x49, 0x6e, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2d, 0x67, 0x72, 0x61, 0x64, 0x65, 0x20, 0x53, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x20, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x22, 0x2c, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x22, 0x48, 0x53, 0x44, 0x54, 0x20, 0x54, 0x6f, 0x6b, 0x79, 0x6f, 0x22, 0x2c, 0x22, 0x77, 0x65, 0x62, 0x73, 0x69, 0x74, 0x65, 0x22, 0x3a, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x2e, 0x63, 0x6f, 0x2f, 0x22, 0x7d, 0x22, 0x2c, 0x22, 0x77, 0x65, 0x62, 0x73, 0x69, 0x74, 0x65, 0x22, 0x3a, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x2e, 0x63, 0x6f, 0x2f, 0x22, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const CFG_PK = [_]u8{ 0xbf, 0x0f, 0x79, 0xac, 0x5e, 0xc7, 0x82, 0x42, 0x9b, 0x0b, 0xa3, 0xf1, 0x11, 0x13, 0x4e, 0x3d, 0xc3, 0x1a, 0x56, 0xb5, 0x4a, 0x78, 0x08, 0xaf, 0xbe, 0xe2, 0xad, 0xf8, 0xed, 0x6e, 0x1a, 0x06 };
    const AUTH_PK = [_]u8{ 0xe9, 0x45, 0x09, 0x85, 0x3c, 0xbd, 0x51, 0x70, 0x7b, 0x1e, 0xa5, 0x28, 0x2d, 0x13, 0x02, 0x4d, 0xd8, 0xb6, 0xbc, 0x5c, 0xed, 0x08, 0x3f, 0xab, 0x72, 0xf7, 0x31, 0x89, 0xcc, 0xe1, 0x42, 0x6d };
    const CONFIG_ID = @import("mod.zig").CONFIG_PROGRAM_ID;

    var h = try Harness.init(t.allocator, 1_000, &.{
        .{ .pubkey = CFG_PK, .lamports = 5_366_160, .data_len = PRIOR.len, .owner = CONFIG_ID, .is_writable = true, .is_signer = false },
        .{ .pubkey = AUTH_PK, .lamports = 1, .data_len = 0, .is_writable = false, .is_signer = true },
    });
    defer h.deinit();
    // Seed the config account with the real PRIOR on-chain state.
    @memcpy(h.accounts[0].data[0..PRIOR.len], &PRIOR);
    try h.pushFrame(0, &.{ 0, 1 });
    defer h.popFrame();

    // Must SUCCEED. Pre-fix: carrier via silent swallow. u64-length bug: the < guard
    // fires → M9_Config_InvalidInstructionData → this line fails.
    try execute(h.ctx, &IX_DATA);

    // Canonical write-back: verbatim copy of exactly ix_data.len bytes …
    try t.expectEqualSlices(u8, &IX_DATA, h.accounts[0].data[0..IX_DATA.len]);
    // … and the tail [ix_data.len..] PRESERVED, not zeroed — the carrier's exact bug.
    try t.expectEqualSlices(u8, PRIOR[IX_DATA.len..], h.accounts[0].data[IX_DATA.len..]);
}
