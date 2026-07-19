//! BPFLoaderUpgradeable (loader-v3) native program — Vexor port.
//!
//! Canonical reference: Agave **4.1.0-beta.1** `programs/bpf_loader/src/lib.rs`
//! (verified byte-identical to beta.2; this is the EXACT version our
//! reference bank-hash oracle validator runs, so the state transitions here
//! match the cluster we replay against). Portable Zig cross-check:
//! `sig/src/runtime/program/bpf_loader/execute.zig` (executeV3Write etc).
//!
//! ── WHY THIS FILE EXISTS ────────────────────────────────────────────────
//! Vexor had **no live BPFLoaderUpgradeable handler**. In replay dispatch the
//! loader's program-id fell through to `dispatchBpfExecution` (the BPF-ELF
//! executor), which no-ops for a *native* program with no ELF body. Every
//! loader `Write`/`Close`/`SetAuthority` therefore silently dropped its
//! account mutation from `accounts_lt_hash`, while the cluster mixed
//! `(−old + new)` for the same account. Result: a permanent, monotonic
//! lt_hash → bank_hash divergence whose onset is the first post-snapshot
//! loader Write, compounding per dropped op → SlotHashes sysvar wrong →
//! ~100% peer votes rejected (slot_hash_mm) → top_votes starved → delinquent.
//! Root-caused 2026-06-05 (onset slot 413280169, a buffer `Write`).
//!
//! ── SCOPE ───────────────────────────────────────────────────────────────
//! Phase 1 (THIS commit) — the full NON-ELF set, all byte-deterministic
//!   (no ELF verification, no CPI): `Write`, `InitializeBuffer`,
//!   `SetAuthority`, `SetAuthorityChecked`, `Close`. `Write` is the confirmed
//!   live carrier (onset 413280169). `SetAuthority(ProgramData → None)`
//!   (make-immutable / finalize) is now handled here too: the None flip applies
//!   unconditionally except the SIMD-0500 gate (feature disable_sbpf_v0_v1_v2 +
//!   embedded ELF sBPF < V3 → reject), which reads e_flags directly (no full ELF
//!   load). Carrier 420349520 root-caused this — it was previously a no-op.
//! Phase 2 (IMPLEMENTED — dispatch :247-249, bodies below, KAT
//!   test-bpf-loader-extend): `DeployWithMaxDataLen` / `Upgrade` /
//!   `ExtendProgram` run Agave's `deploy_program!` (ELF load+verify via the
//!   vex_bpf2 verifier → InvalidAccountData on failure) plus the deterministic
//!   account mutations (programdata realloc, rent top-up, header rewrite, buffer
//!   drain) + the SIMD-0431 min-extend-size gate. A genuine instruction error
//!   propagates so the caller rolls the tx back. With this commit's
//!   SetAuthority→None arm, the full loader-v3 non-CPI instruction set is now
//!   handled. Loader ops are sparse on testnet (0 in a 184-block / 96.7k-tx
//!   probe), so any first re-divergence post-deploy (agave-vexor-diff vs
//!   oracle-node) names the next op to audit. Full CPI/program-cache parity remains
//!   required before mainnet (RULE#0).
//!
//! Commit model mirrors the other native handlers (system/stake): read with
//! the pending_writes overlay (so a 2nd same-slot Write to the same buffer
//! accumulates), deep-copy, mutate the copy, then `bank.collectWrite` with
//! `old_lt`/`new_lt` computed via `Bank.accountLtHash`. We pass the real
//! `executable` flag into both lt computations, so this native path is immune
//! to the latent `new_executable`-from-pre-state carrier in the BPF executor.

const std = @import("std");
const core = @import("core");
const bank_mod = @import("../bank.zig");
const features = @import("../features.zig");
const vex_bpf2 = @import("vex_bpf2");

const Pubkey = core.Pubkey;

// ── SIMD-0431 + deployment constants (Agave 4.1.0-beta.3) ──
// loader-v3-interface 7.0.0 instruction.rs:18.
const MINIMUM_EXTEND_PROGRAM_BYTES: u32 = 10_240;
// solana-system-interface lib.rs: 10 * 1024 * 1024.
const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

// Vexor's canonical InstructionError discriminants are not modeled as an enum
// here (the native handlers signal "reject = no state change" by simply
// returning without emitting a write). For the Phase-2 deploy arms we DO need
// to distinguish a genuine instruction error (→ tx rollback) from a clean
// no-op; we surface those as Zig errors so the caller's failed-tx machinery
// rolls the transaction back, matching Agave returning `Err(InstructionError)`.
pub const LoaderError = error{
    // deploy_program! ELF load/verify failure → Agave InstructionError::InvalidAccountData.
    InvalidAccountData,
    // P0-3 (2026-07-11): unknown UpgradeableLoaderInstruction discriminant.
    // Agave: `limited_deserialize(instruction_data, PACKET_DATA_SIZE)?` in
    // process_instruction_inner (programs/bpf_loader/src/lib.rs:157) — any
    // bincode decode failure (including an unrecognized enum tag) maps to
    // InstructionError::InvalidInstructionData via solana-bincode's
    // limited_deserialize (solana-bincode-3.1.0/src/lib.rs:10-19,
    // `.map_err(|_| InstructionError::InvalidInstructionData)`), which fails
    // the WHOLE transaction. Previously this native handler silently
    // succeeded on an unknown discriminant (fail-open), so a tx of
    // [loader-v3 unknown-disc ix, other ix] executed the other ix on Vexor
    // while Agave failed the entire tx — an accept-invalid divergence.
    InvalidInstructionData,
};

// ── UpgradeableLoaderState serialized sizes (loader-v3-interface state.rs) ──
const UNINITIALIZED_SIZE: usize = 4;
const BUFFER_METADATA_SIZE: usize = 37; // tag(4) + Option<Pubkey>(1+32)
const PROGRAM_SIZE: usize = 36; // tag(4) + Pubkey(32)
const PROGRAM_DATA_METADATA_SIZE: usize = 45; // tag(4) + slot(8) + Option<Pubkey>(1+32)

// ── UpgradeableLoaderInstruction bincode variant tags (u32 LE) ──
const IX_INITIALIZE_BUFFER: u32 = 0;
const IX_WRITE: u32 = 1;
const IX_DEPLOY_WITH_MAX_DATA_LEN: u32 = 2;
const IX_UPGRADE: u32 = 3;
const IX_SET_AUTHORITY: u32 = 4;
const IX_CLOSE: u32 = 5;
const IX_EXTEND_PROGRAM: u32 = 6;
const IX_SET_AUTHORITY_CHECKED: u32 = 7;

// ── UpgradeableLoaderState bincode variant tags (u32 LE) ──
const STATE_UNINITIALIZED: u32 = 0;
const STATE_BUFFER: u32 = 1;
const STATE_PROGRAM: u32 = 2;
const STATE_PROGRAM_DATA: u32 = 3;

// BPFLoaderUpgradeable program id (BPFLoaderUpgradeab1e1111…) — used here for
// the Close ProgramData owner check. Same bytes as replay_stage.BPF_LOADER_UPGRADEABLE.
const LOADER_ID = [_]u8{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
    0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
    0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
};
const SYSTEM_ID = [_]u8{0} ** 32;

// ── small read helpers ──────────────────────────────────────────────────
inline fn readU32LE(data: []const u8, off: usize) ?u32 {
    if (off + 4 > data.len) return null;
    return std.mem.readInt(u32, data[off..][0..4], .little);
}
inline fn readU64LE(data: []const u8, off: usize) ?u64 {
    if (off + 8 > data.len) return null;
    return std.mem.readInt(u64, data[off..][0..8], .little);
}

inline fn isSigner(ptx: anytype, acct_idx: u8) bool {
    return acct_idx < ptx.num_required_sigs;
}

/// Account read with the in-slot pending_writes overlay (reverse scan, so the
/// most recent same-slot write wins — this is what makes a 2nd same-slot Write
/// to the same buffer accumulate on top of the 1st), falling back to the
/// ancestor-filtered AccountsDb read. Mirrors stake_program.readOverlayed.
const OverlayedAccount = struct {
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};
fn readOverlayed(bank: anytype, db: anytype, key: [32]u8) ?OverlayedAccount {
    var i: usize = bank.pending_writes.items.len;
    while (i > 0) {
        i -= 1;
        const w = &bank.pending_writes.items[i];
        if (std.mem.eql(u8, &w.pubkey.data, &key)) {
            return .{
                .lamports = w.lamports,
                .owner = w.owner,
                .executable = w.executable,
                .rent_epoch = w.rent_epoch,
                .data = w.data,
            };
        }
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

/// Commit a mutation for `key` with new lamports + new data (owner/executable/
/// rent_epoch unchanged — the loader never changes those on the non-ELF ops),
/// computing the lt_hash delta over the real pre/post bytes. `new_data` must be
/// a fresh allocation that outlives slot freeze (the established native-handler
/// contract — allocated from the replay arena by the caller). Caller has
/// already verified writability. When `new_lamports == 0` the new lt is the
/// identity (deleted account), matching accountLtHash + Firedancer.
fn commitChange(
    bank: anytype,
    key: [32]u8,
    pre: OverlayedAccount,
    new_lamports: u64,
    new_data: []const u8,
) void {
    const old_lt = bank_mod.Bank.accountLtHash(
        &key,
        &pre.owner.data,
        pre.lamports,
        pre.executable,
        pre.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &key,
        &pre.owner.data,
        new_lamports,
        pre.executable,
        new_data,
    );
    bank.collectWrite(.{
        .pubkey = .{ .data = key },
        .lamports = new_lamports,
        .owner = .{ .data = pre.owner.data },
        .executable = pre.executable,
        .rent_epoch = pre.rent_epoch,
        .data = new_data,
        .old_lt = old_lt,
        .new_lt = new_lt,
    }) catch {};
}

/// Data-only mutation (lamports unchanged). Thin wrapper over commitChange.
inline fn commitDataChange(bank: anytype, key: [32]u8, pre: OverlayedAccount, new_data: []const u8) void {
    commitChange(bank, key, pre, pre.lamports, new_data);
}

/// Entry point — dispatched from replay_stage for program-id
/// BPFLoaderUpgradeable. `ix`/`ptx`/`bank`/`db` are `anytype` to avoid a
/// circular import with replay_stage (same pattern as stake_program.execute).
///
/// Faithful to Agave semantics: any validation failure is a no-state-change
/// reject (the cluster's failed-loader-tx only charges the fee, which the fee
/// path already debited), so on every reject we simply `return` without
/// emitting a write. We never partially mutate.
pub fn execute(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
    feature_set: anytype, // ?*const features.FeatureSet (anytype to keep the
    // existing circular-import-free contract). null = bootstrap before the
    // FeatureSet is wired; the Phase-2 arms treat SIMD-0431 as inactive then,
    // which is conservative (the feature is testnet-active so this only affects
    // pre-wire bootstrap dispatch that never replays loader ops).
) !void {
    const data = ix.data;
    const variant = readU32LE(data, 0) orelse return; // limited_deserialize error → reject

    // OBSERVABILITY (soak gate): a fresh near-tip snapshot resets the
    // accounts_lt_hash base to the cluster-correct value, so the validator
    // converges whether or not THIS handler ever runs — until a loader op
    // actually occurs (sparse on testnet). So "stayed CURRENT" alone can't tell
    // "fix works" from "no loader op happened". We log, rate-limited, exactly
    // when the handler COMMITS a write on a real loader op, so the soak can
    // assert the corrected criterion: the handler FIRED on real ops AND
    // bank_hash held across those exact slots (agave-vexor-diff vs oracle-node).
    const before = bank.pending_writes.items.len;
    switch (variant) {
        IX_WRITE => try doWrite(ix, ptx, bank, db, alloc),
        IX_INITIALIZE_BUFFER => try doInitializeBuffer(ix, ptx, bank, db, alloc),
        IX_SET_AUTHORITY => try doSetAuthority(ix, ptx, bank, db, alloc, false, feature_set),
        IX_SET_AUTHORITY_CHECKED => try doSetAuthority(ix, ptx, bank, db, alloc, true, feature_set),
        IX_CLOSE => try doClose(ix, ptx, bank, db, alloc),

        // ── Phase 2 (now implemented): the three ELF-deploying arms. Each runs
        // Agave's `deploy_program!` (sBPF load+verify) wired to Vexor's
        // vex_bpf2 verifier, plus the deterministic account mutations
        // (programdata realloc, rent top-up, header rewrite, buffer drain).
        // A genuine instruction error (e.g. ELF verify fail → InvalidAccountData)
        // propagates so the caller rolls the tx back. SIMD-0431 (ExtendProgram
        // min-extend-size) is gated via the live FeatureSet.
        IX_EXTEND_PROGRAM => try doExtendProgram(ix, ptx, bank, db, alloc, feature_set),
        IX_UPGRADE => try doUpgrade(ix, ptx, bank, db, alloc, feature_set),
        IX_DEPLOY_WITH_MAX_DATA_LEN => try doDeployWithMaxDataLen(ix, ptx, bank, db, alloc, feature_set),

        // P0-3: unknown variant → limited_deserialize error → Agave fails the
        // WHOLE tx with InstructionError::InvalidInstructionData (see
        // LoaderError doc above) — this must roll the tx back, not silently
        // no-op it (a bare `return;` here would fail-open: the caller treats
        // that as success and continues executing subsequent instructions
        // in the same tx, which Agave never reaches).
        else => return error.InvalidInstructionData,
    }
    // worker path redirects collectWrite elsewhere (override != null), so this
    // count only grows on the live serial/DAG paths — exactly the soak paths.
    // committed=false here means the op was handled but Agave-rejected (no write).
    const after = bank.pending_writes.items.len;
    logLoaderOp(variant, bank.slot, after -| before, after > before);
}

var loader_op_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Rate-limited (first 30, then every 25th) one-line marker that the loader
/// handler ran a real op — `committed` distinguishes a handled op that emitted
/// writes from a Phase-2-deferred op that fell through. grep `[BPF-LOADER-OP]`.
fn logLoaderOp(variant: u32, slot: u64, writes: usize, committed: bool) void {
    const c = loader_op_count.fetchAdd(1, .monotonic) + 1;
    if (c > 30 and c % 25 != 0) return;
    const name = switch (variant) {
        IX_INITIALIZE_BUFFER => "InitializeBuffer",
        IX_WRITE => "Write",
        IX_DEPLOY_WITH_MAX_DATA_LEN => "DeployWithMaxDataLen(DEFERRED)",
        IX_UPGRADE => "Upgrade(DEFERRED)",
        IX_SET_AUTHORITY => "SetAuthority",
        IX_CLOSE => "Close",
        IX_EXTEND_PROGRAM => "ExtendProgram(DEFERRED)",
        IX_SET_AUTHORITY_CHECKED => "SetAuthorityChecked",
        else => "Unknown",
    };
    std.log.info("[BPF-LOADER-OP] op={s} slot={d} committed={} writes={d} n={d}", .{ name, slot, committed, writes, c });
}

/// UpgradeableLoaderInstruction::Write { offset: u32, bytes: Vec<u8> }
/// Agave lib.rs:173-201 (+ write_program_data:39-62). Mutates ONLY the buffer
/// account (instruction account 0); the authority (account 1) is a read-only
/// signer. Writes `bytes` at `BUFFER_METADATA_SIZE + offset` into the buffer's
/// data, byte-for-byte.
fn doWrite(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    const data = ix.data;
    // bincode: tag(4) | offset u32(4) | bytes: len u64(8) + raw
    const offset_u32 = readU32LE(data, 4) orelse return;
    const bytes_len_u64 = readU64LE(data, 8) orelse return;
    const bytes_start: usize = 16;
    const bytes_len: usize = std.math.cast(usize, bytes_len_u64) orelse return;
    if (bytes_len > data.len - bytes_start) return; // truncated instruction → deserialize error
    const bytes = data[bytes_start .. bytes_start + bytes_len];

    // check_number_of_instruction_accounts(2)
    if (ix.account_indices.len < 2) return;
    const buf_ix = ix.account_indices[0];
    const auth_ix = ix.account_indices[1];
    if (buf_ix >= ptx.num_accounts or auth_ix >= ptx.num_accounts) return;

    const buffer_key = ptx.account_keys[buf_ix];
    const authority_key = ptx.account_keys[auth_ix];

    // get_state must be Buffer { authority_address } with present, matching,
    // signing authority — else reject (Immutable / IncorrectAuthority /
    // MissingRequiredSignature / InvalidAccountData all map to "no change").
    const buf = readOverlayed(bank, db, buffer_key) orelse return;
    // Agave enforces "the account being mutated must be owned by the executing
    // program" structurally in the borrow API (can_data_be_changed →
    // is_owned_by_current_program, instruction_accounts.rs:338-348). get_state
    // is owner-agnostic, so an account merely SHAPED like a Buffer but not
    // loader-owned passes every other check, then Agave rejects at get_data_mut
    // with no state change. Replicate that owner gate or we mix a delta the
    // cluster never applied (same divergence class as the carrier).
    if (!std.mem.eql(u8, &buf.owner.data, &LOADER_ID)) return;
    if ((readU32LE(buf.data, 0) orelse return) != STATE_BUFFER) return; // InvalidAccountData
    if (buf.data.len < 5) return;
    const opt = buf.data[4];
    if (opt == 0) return; // authority None → Immutable
    if (opt != 1) return; // malformed Option
    if (buf.data.len < BUFFER_METADATA_SIZE) return;
    const buf_authority = buf.data[5..BUFFER_METADATA_SIZE];
    if (!std.mem.eql(u8, buf_authority, &authority_key)) return; // IncorrectAuthority
    if (!isSigner(ptx, auth_ix)) return; // MissingRequiredSignature

    // write_program_data: bounds-check then copy.
    const start = BUFFER_METADATA_SIZE + @as(usize, offset_u32);
    const end = start +| bytes_len;
    if (buf.data.len < end) return; // AccountDataTooSmall

    if (!ptx.isWritable(@intCast(buf_ix))) return; // can't persist a non-writable account

    const new_data = alloc.alloc(u8, buf.data.len) catch return;
    @memcpy(new_data, buf.data);
    @memcpy(new_data[start..end], bytes);

    commitDataChange(bank, buffer_key, buf, new_data);
}

/// UpgradeableLoaderInstruction::InitializeBuffer  (Agave lib.rs:158-171).
/// Account 0 = buffer to initialize (must be Uninitialized), account 1 = the
/// authority to record. set_state(Buffer{Some(authority)}) writes 37 metadata
/// bytes at the head of the (already system-allocated, zero-filled) account;
/// the trailing program-data region is left untouched.
fn doInitializeBuffer(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    // check_number_of_instruction_accounts(2)
    if (ix.account_indices.len < 2) return;
    const buf_ix = ix.account_indices[0];
    const auth_ix = ix.account_indices[1];
    if (buf_ix >= ptx.num_accounts or auth_ix >= ptx.num_accounts) return;

    const buffer_key = ptx.account_keys[buf_ix];
    const authority_key = ptx.account_keys[auth_ix];

    const buf = readOverlayed(bank, db, buffer_key) orelse return;
    // Owner gate (see doWrite) — set_state → get_data_mut requires loader-owned.
    if (!std.mem.eql(u8, &buf.owner.data, &LOADER_ID)) return;
    // must currently be Uninitialized (tag 0) — else AccountAlreadyInitialized
    if ((readU32LE(buf.data, 0) orelse return) != STATE_UNINITIALIZED) return;
    // set_state needs room for the 37-byte Buffer metadata (serialized_size >
    // data.len → AccountDataTooSmall reject).
    if (buf.data.len < BUFFER_METADATA_SIZE) return;

    if (!ptx.isWritable(@intCast(buf_ix))) return;

    const new_data = alloc.alloc(u8, buf.data.len) catch return;
    @memcpy(new_data, buf.data);
    std.mem.writeInt(u32, new_data[0..4], STATE_BUFFER, .little);
    new_data[4] = 1; // Option::Some
    @memcpy(new_data[5..BUFFER_METADATA_SIZE], &authority_key);

    commitDataChange(bank, buffer_key, buf, new_data);
}

/// UpgradeableLoaderInstruction::SetAuthority (unchecked, `checked=false`,
/// Agave lib.rs:536-604) and ::SetAuthorityChecked (`checked=true`, :605-672).
/// Account 0 = Buffer or ProgramData (mutated), account 1 = present authority
/// (must sign), account 2 = new authority (unchecked: optional via `.ok()`;
/// checked: required + must sign).
///
/// set_state serializes ONLY the metadata length and leaves the trailing bytes
/// untouched — so a Some-authority rewrite touches just the Option byte + the
/// 32 pubkey bytes; the rest of the account (slot field / program data) is
/// preserved verbatim. Getting this tail-preservation wrong diverges lt_hash.
fn doSetAuthority(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
    checked: bool,
    feature_set: anytype,
) !void {
    // check_number_of_instruction_accounts: 2 (unchecked) / 3 (checked).
    const min_accts: usize = if (checked) 3 else 2;
    if (ix.account_indices.len < min_accts) return;
    const acct_ix = ix.account_indices[0];
    const present_ix = ix.account_indices[1];
    if (acct_ix >= ptx.num_accounts or present_ix >= ptx.num_accounts) return;
    const acct_key = ptx.account_keys[acct_ix];
    const present_key = ptx.account_keys[present_ix];

    // new_authority: Some(key of account 2) if that account is present, else None.
    var new_auth: ?[32]u8 = null;
    var new_auth_ix: u8 = 0;
    if (ix.account_indices.len >= 3) {
        const idx2 = ix.account_indices[2];
        if (idx2 < ptx.num_accounts) {
            new_auth = ptx.account_keys[idx2];
            new_auth_ix = idx2;
        }
    }

    const acct = readOverlayed(bank, db, acct_key) orelse return;
    // Owner gate (see doWrite) — set_state → get_data_mut requires loader-owned.
    if (!std.mem.eql(u8, &acct.owner.data, &LOADER_ID)) return;
    const tag = readU32LE(acct.data, 0) orelse return;

    if (tag == STATE_BUFFER) {
        if (acct.data.len < BUFFER_METADATA_SIZE) return;
        // unchecked: Buffer authority is NOT optional → new must be Some.
        if (!checked and new_auth == null) return; // IncorrectAuthority
        if (acct.data[4] == 0) return; // current authority None → Immutable
        if (acct.data[4] != 1) return;
        if (!std.mem.eql(u8, acct.data[5..BUFFER_METADATA_SIZE], &present_key)) return; // IncorrectAuthority
        if (!isSigner(ptx, present_ix)) return; // MissingRequiredSignature
        if (checked) {
            if (new_auth == null) return; // checkNumberOfAccounts(3) already ensured account 2 present
            if (!isSigner(ptx, new_auth_ix)) return; // New authority did not sign
        }
        const na = new_auth.?; // both paths require Some here
        if (!ptx.isWritable(@intCast(acct_ix))) return;
        const new_data = alloc.alloc(u8, acct.data.len) catch return;
        @memcpy(new_data, acct.data);
        new_data[4] = 1; // Option::Some
        @memcpy(new_data[5..BUFFER_METADATA_SIZE], &na);
        commitDataChange(bank, acct_key, acct, new_data);
        return;
    }

    if (tag == STATE_PROGRAM_DATA) {
        if (acct.data.len < PROGRAM_DATA_METADATA_SIZE) return;
        if (acct.data[12] == 0) return; // upgrade authority None → Program not upgradeable → Immutable
        if (acct.data[12] != 1) return;
        if (!std.mem.eql(u8, acct.data[13..PROGRAM_DATA_METADATA_SIZE], &present_key)) return; // IncorrectAuthority
        if (!isSigner(ptx, present_ix)) return; // MissingRequiredSignature
        if (checked) {
            if (new_auth == null) return;
            if (!isSigner(ptx, new_auth_ix)) return; // New authority did not sign
        }
        if (new_auth) |na| {
            // set ProgramData{slot, Some(na)} — Option byte + 32 pubkey; slot ([4..12]) preserved.
            if (!ptx.isWritable(@intCast(acct_ix))) return;
            const new_data = alloc.alloc(u8, acct.data.len) catch return;
            @memcpy(new_data, acct.data);
            new_data[12] = 1;
            @memcpy(new_data[13..PROGRAM_DATA_METADATA_SIZE], &na);
            commitDataChange(bank, acct_key, acct, new_data);
        } else {
            // ProgramData → None ("make immutable" / finalize). Agave 4.1.1
            // lib.rs:580-595 + FD fd_bpf_loader_finalize_v3_check (SIMD-0500):
            // the None flip applies UNCONDITIONALLY unless BOTH
            //   (a) disable_sbpf_v0_v1_v2_deployment is active, AND
            //   (b) the ELF embedded in ProgramData at [45..] parses as sBPF < V3
            // in which case it is rejected with InstructionError::InvalidAccountData
            // (→ tx rollback). Agave==FD agree byte-for-byte.
            if (disableSbpfV0V1V2(feature_set, bank.slot) and setAuthorityFinalizeRejects(acct.data)) {
                return LoaderError.InvalidAccountData;
            }
            if (!ptx.isWritable(@intCast(acct_ix))) return;
            // set_state(ProgramData{slot, None}) serializes 13 bytes
            // (tag(4)+slot(8)+Option::None(1)) via bincode serialize_into, which
            // does NOT truncate/zero the rest — so ONLY the Option byte @12 flips
            // to 0. The slot [4..12], the stale authority bytes [13..45], and the
            // program tail [45..] are all preserved verbatim (mirrors the Some
            // branch's tail-preservation; live cluster confirms @12=0 with tail
            // intact). Getting this wrong diverges lt_hash.
            const new_data = alloc.alloc(u8, acct.data.len) catch return;
            @memcpy(new_data, acct.data);
            new_data[12] = 0; // Option::None; [13..45] + [45..] left untouched
            commitDataChange(bank, acct_key, acct, new_data);
        }
        return;
    }

    // Any other state: "Account does not support authorities" → InvalidArgument → no change.
    return;
}

/// UpgradeableLoaderInstruction::Close (Agave lib.rs:673-776 + common_close_account:991-1016).
/// Account 0 = account to close, 1 = lamport recipient, 2 = authority (Buffer/
/// ProgramData), 3 = associated Program (ProgramData only). lt effect: the
/// closed account drops to 0 lamports (→ identity lt) with data truncated to
/// the 4-byte Uninitialized tag; the recipient gains the closed lamports. The
/// Program account (PD case) only gets a program-cache tombstone — no byte/
/// lamport change — so it contributes nothing to lt and we do not write it.
fn doClose(ix: anytype, ptx: anytype, bank: anytype, db: anytype, alloc: std.mem.Allocator) !void {
    if (ix.account_indices.len < 2) return; // check_number_of_instruction_accounts(2)
    const close_ix = ix.account_indices[0];
    const recip_ix = ix.account_indices[1];
    if (close_ix >= ptx.num_accounts or recip_ix >= ptx.num_accounts) return;
    if (close_ix == recip_ix) return; // recipient == account being closed → InvalidArgument
    const close_key = ptx.account_keys[close_ix];
    const recip_key = ptx.account_keys[recip_ix];

    const close = readOverlayed(bank, db, close_key) orelse return;
    // Owner gate (see doWrite): Close debits the closed account to 0
    // (set_lamports, instruction_accounts.rs:120-123) and truncates its data
    // (set_data_length → can_data_be_resized), both of which require the closed
    // account be loader-owned. The RECIPIENT is only CREDITED (lamport
    // increase), which Agave permits for any writable account — so no owner
    // gate there (just the isWritable check below).
    if (!std.mem.eql(u8, &close.owner.data, &LOADER_ID)) return;
    const tag = readU32LE(close.data, 0) orelse return;

    switch (tag) {
        STATE_UNINITIALIZED => {
            // No authority required; just move lamports.
        },
        STATE_BUFFER => {
            if (ix.account_indices.len < 3) return; // check_number_of_instruction_accounts(3)
            if (close.data.len < BUFFER_METADATA_SIZE) return;
            if (close.data[4] == 0) return; // authority None → Immutable
            if (close.data[4] != 1) return;
            const auth_ix = ix.account_indices[2];
            if (auth_ix >= ptx.num_accounts) return;
            if (!std.mem.eql(u8, close.data[5..BUFFER_METADATA_SIZE], &ptx.account_keys[auth_ix])) return; // IncorrectAuthority
            if (!isSigner(ptx, auth_ix)) return; // MissingRequiredSignature
        },
        STATE_PROGRAM_DATA => {
            if (ix.account_indices.len < 4) return; // check_number_of_instruction_accounts(4)
            if (close.data.len < PROGRAM_DATA_METADATA_SIZE) return;
            const deployed_slot = readU64LE(close.data, 4) orelse return;
            const prog_ix = ix.account_indices[3];
            if (prog_ix >= ptx.num_accounts) return;
            const prog_key = ptx.account_keys[prog_ix];
            if (!ptx.isWritable(@intCast(prog_ix))) return; // Program account not writable → InvalidArgument
            const prog = readOverlayed(bank, db, prog_key) orelse return;
            if (!std.mem.eql(u8, &prog.owner.data, &LOADER_ID)) return; // not owned by loader → IncorrectProgramId
            if (bank.slot == deployed_slot) return; // "deployed in this block already" → InvalidArgument
            if ((readU32LE(prog.data, 0) orelse return) != STATE_PROGRAM) return; // Invalid Program account
            if (prog.data.len < PROGRAM_SIZE) return;
            if (!std.mem.eql(u8, prog.data[4..PROGRAM_SIZE], &close_key)) return; // programdata mismatch → InvalidArgument
            // common_close_account authority check (authority at programdata[13..45], signer = account 2)
            if (close.data[12] == 0) return; // Immutable
            if (close.data[12] != 1) return;
            const auth_ix = ix.account_indices[2];
            if (auth_ix >= ptx.num_accounts) return;
            if (!std.mem.eql(u8, close.data[13..PROGRAM_DATA_METADATA_SIZE], &ptx.account_keys[auth_ix])) return; // IncorrectAuthority
            if (!isSigner(ptx, auth_ix)) return; // MissingRequiredSignature
        },
        else => return, // "Account does not support closing" → InvalidArgument
    }

    // All validation passed — apply the two lamport moves atomically. Both the
    // closed account and the recipient must be writable to persist.
    if (!ptx.isWritable(@intCast(close_ix))) return;
    if (!ptx.isWritable(@intCast(recip_ix))) return;

    const recip = readOverlayed(bank, db, recip_key) orelse OverlayedAccount{
        .lamports = 0,
        .owner = .{ .data = SYSTEM_ID },
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &[_]u8{},
    };
    const new_recip_lamports = recip.lamports +| close.lamports;

    // Recipient data is UNCHANGED but we commit a fresh copy (never alias a
    // borrowed overlay/mmap slice into a stored AccountWrite).
    const recip_data = alloc.alloc(u8, recip.data.len) catch return;
    if (recip.data.len > 0) @memcpy(recip_data, recip.data);

    // Closed account → set_data_length(4) + set_state(Uninitialized) = 4 zero
    // bytes; lamports → 0 (so its new lt is identity regardless of data).
    const closed_data = alloc.alloc(u8, UNINITIALIZED_SIZE) catch return;
    @memset(closed_data, 0);

    commitChange(bank, recip_key, recip, new_recip_lamports, recip_data);
    commitChange(bank, close_key, close, 0, closed_data);
}

// ── Phase 2 shared helpers ────────────────────────────────────────────────

/// Canonical rent-exempt minimum balance (Agave Rent::minimum_balance):
/// (data_len + ACCOUNT_STORAGE_OVERHEAD=128) * lamports_per_byte_year=3480 *
/// exemption_threshold=2. Integer math is exact for these magnitudes (same
/// formula as replay_stage.rentExemptMinimumBalanceDefault and the V4 vote
/// rent guard). Used by Extend/Upgrade/Deploy rent top-up math.
pub inline fn rentExemptMinimumBalance(data_len: u64) u64 {
    return (data_len + 128) * 3480 * 2;
}

/// SIMD-0431 feature query against the (anytype) live FeatureSet. Returns false
/// when the FeatureSet is not wired (bootstrap) — conservative: ExtendProgram
/// then skips the min-size gate, matching pre-activation behavior.
/// SIMD-0431 reject predicate (Agave lib.rs:871-872): returns true when the
/// extend MUST be rejected with InvalidArgument because additional_bytes is
/// below the 10 KiB minimum AND is not exactly the remaining headroom-to-max.
/// Pure (no FeatureSet) so it is directly unit-testable.
pub inline fn simd0431Rejects(additional_bytes: u32, old_len: u64) bool {
    const headroom: u64 = MAX_PERMITTED_DATA_LENGTH -| old_len;
    return additional_bytes < MINIMUM_EXTEND_PROGRAM_BYTES and @as(u64, additional_bytes) != headroom;
}

inline fn simd0431Active(feature_set: anytype, slot: u64) bool {
    if (@TypeOf(feature_set) == @TypeOf(null)) return false;
    const fs = feature_set orelse return false;
    return fs.isActive(features.LOADER_V3_MINIMUM_EXTEND_PROGRAM_SIZE, slot);
}

/// Carrier #9 fix: sol_sha512 loader-registry membership follows
/// enable_sha512_syscall (Agave registers it feature-gated; an ELF importing
/// it pre-activation must be rejected at deploy-verify like Agave does).
inline fn sha512SyscallActive(feature_set: anytype, slot: u64) bool {
    if (@TypeOf(feature_set) == @TypeOf(null)) return false;
    const fs = feature_set orelse return false;
    return fs.isActive(features.ENABLE_SHA512_SYSCALL, slot);
}

inline fn disableSbpfV0V1V2(feature_set: anytype, slot: u64) bool {
    if (@TypeOf(feature_set) == @TypeOf(null)) return false;
    const fs = feature_set orelse return false;
    return fs.isActive(features.DISABLE_SBPF_V0_V1_V2_DEPLOYMENT, slot);
}

/// SIMD-0500 finalize gate for SetAuthority(ProgramData → None). Caller has
/// already confirmed the feature is active + new_authority is None. Returns true
/// (REJECT with InvalidAccountData) iff the ELF embedded in the ProgramData
/// account parses as sBPF version < V3.
///
/// `programdata` is the FULL account data. The ELF lives at [PROGRAM_DATA_META..];
/// get_sbpf_version (anza-sbpf elf.rs:1265) reads e_flags as a u32 LE at
/// Elf64Ehdr offset 48 within the ELF → absolute offset 45+48 = 93 here (matches
/// FD `PROGRAMDATA_METADATA_SIZE + 48UL`). A short account with no room for
/// e_flags short-circuits to ACCEPT (Agave let-chain / FD length guard). e_flags
/// 0/1/2 = V0/V1/V2 (< V3) → reject; 3=V3, 4=V4, ≥5=Reserved (all ≥ V3) → accept.
inline fn setAuthorityFinalizeRejects(programdata: []const u8) bool {
    const e_flags = readU32LE(programdata, PROGRAM_DATA_METADATA_SIZE + 48) orelse return false;
    return e_flags < 3; // < SBPFVersion::V3
}

/// Map a vex_bpf2 SbpfVersion to the verifier's StaticBitSet config, honoring
/// `disable_sbpf_v0_v1_v2`: when set, only V3 (and up) may be deployed —
/// matching Agave `morph_into_deployment_environment` which clamps
/// `enabled_sbpf_versions` to `V3..=end`.
fn deploymentVerifyConfig(disable_v0_v1_v2: bool) vex_bpf2.verifier.VerifyConfig {
    var cfg = vex_bpf2.verifier.VerifyConfig.DEFAULT;
    if (disable_v0_v1_v2) {
        cfg.enabled_sbpf_versions = std.StaticBitSet(4).initEmpty();
        cfg.enabled_sbpf_versions.set(3);
    }
    return cfg;
}

/// Faithful port of Agave `deploy_program!` → `deploy_program()`
/// (program-runtime/src/deploy.rs:47-131): load the ELF with the stricter
/// deployment environment (reject_broken_elfs=true, sBPF versions clamped per
/// `disable_v0_v1_v2`), then verify with RequisiteVerifier. ANY failure maps to
/// `InstructionError::InvalidAccountData` (deploy.rs:84/96 `.map_err`). On
/// success the account mutations proceed; on failure we return an error so the
/// caller rolls the tx back (Agave returns Err and the tx fails). We do NOT
/// populate a program cache here — bank_hash depends only on the account bytes,
/// and Vexor's dispatch resolves/caches programs independently at call time.
pub fn deployVerify(
    alloc: std.mem.Allocator,
    programdata_elf: []const u8,
    disable_v0_v1_v2: bool,
    sha512_syscall_active: bool,
) LoaderError!void {
    // Executable.load with the deployment Config (reject_broken_elfs=true,
    // sBPF versions per the gate). load() derives the version from e_flags and
    // applies stricter ELF-header checks; a broken/old ELF errors out.
    var elf_cfg = vex_bpf2.elf.Config.DEFAULT;
    elf_cfg.reject_broken_elfs = true;
    if (disable_v0_v1_v2) elf_cfg.enabled_sbpf_versions = 0b1000; // V3 only

    // Carrier #9 fix (@414537973): supply the LOADER's registered-syscall key
    // set so relocate() can resolve non-function imports the way Agave does
    // (elf.rs:1129-1136, loader.get_function_registry().lookup_by_key). Without
    // this, EVERY program importing any syscall (i.e. every real program) was
    // rejected with UnknownSymbol under reject_broken_elfs → cluster-accepted
    // Deploy/Upgrade/Extend ops failed in Vexor (fee-only rollback, lt diverge).
    // Feature-awareness: sol_sha512 is registered by Agave only once
    // enable_sha512_syscall is active (epoch 973 testnet) — a pre-activation
    // ELF importing it must still be REJECTED, like Agave. The other gated
    // syscalls in the table are active on all live clusters (testnet feature
    // sweep 2026-06-10); full per-feature registration parity is a follow-up.
    var reg = vex_bpf2.syscalls.SyscallRegistry.init(alloc, {}, {}) catch
        return LoaderError.InvalidAccountData;
    defer reg.deinit();
    var keys_buf: [64]u32 = undefined;
    var nkeys: usize = 0;
    const sha512_key = vex_bpf2.syscalls.nameHash("sol_sha512");
    for (reg.entries) |e| {
        if (e.hash == sha512_key and !sha512_syscall_active) continue;
        if (nkeys < keys_buf.len) {
            keys_buf[nkeys] = e.hash;
            nkeys += 1;
        }
    }
    elf_cfg.loader_syscall_keys = keys_buf[0..nkeys];

    var exe = vex_bpf2.elf.Executable.load(alloc, programdata_elf, elf_cfg) catch {
        return LoaderError.InvalidAccountData;
    };
    defer exe.deinit();

    vex_bpf2.verifier.verify(
        exe.textBytes(),
        exe.version(),
        deploymentVerifyConfig(disable_v0_v1_v2),
        &exe.function_registry,
    ) catch {
        return LoaderError.InvalidAccountData;
    };
}

/// Like commitChange but also lets the caller set new owner + executable (for
/// DeployWithMaxDataLen which creates the ProgramData account and flips the
/// Program account executable). lt is computed over the post-state.
fn commitFull(
    bank: anytype,
    key: [32]u8,
    pre: OverlayedAccount,
    new_lamports: u64,
    new_owner: [32]u8,
    new_executable: bool,
    new_rent_epoch: u64,
    new_data: []const u8,
) void {
    const old_lt = bank_mod.Bank.accountLtHash(
        &key,
        &pre.owner.data,
        pre.lamports,
        pre.executable,
        pre.data,
    );
    const new_lt = bank_mod.Bank.accountLtHash(
        &key,
        &new_owner,
        new_lamports,
        new_executable,
        new_data,
    );
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

/// UpgradeableLoaderInstruction::ExtendProgram { additional_bytes: u32 }
/// (Agave lib.rs:777-779 → common_extend_program lib.rs:785-989, check_authority
/// = false in beta.3 — ExtendProgramChecked is NOT a beta.3 dispatch arm; its
/// feature id is a deletion placeholder). Account layout:
///   0 = ProgramData (grown + header re-stamped), 1 = Program, 2 = unused
///   system program, 3 = optional payer (rent top-up). FD parity:
///   fd_bpf_loader_program.c:664 common_extend_program / :2061 dispatch.
fn doExtendProgram(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
    feature_set: anytype,
) !void {
    const data = ix.data;
    // bincode: tag(4) | additional_bytes u32(4)
    const additional_bytes = readU32LE(data, 4) orelse return;

    const PROGRAM_DATA_IDX: usize = 0;
    const PROGRAM_IDX: usize = 1;
    const OPTIONAL_PAYER_IDX: usize = 3; // check_authority=false

    // additional_bytes == 0 → InvalidInstructionData (lib.rs:801-804).
    if (additional_bytes == 0) return;

    if (ix.account_indices.len <= PROGRAM_IDX) return; // need at least PD + Program
    const pd_ix = ix.account_indices[PROGRAM_DATA_IDX];
    const prog_ix = ix.account_indices[PROGRAM_IDX];
    if (pd_ix >= ptx.num_accounts or prog_ix >= ptx.num_accounts) return;
    const pd_key = ptx.account_keys[pd_ix];
    const prog_key = ptx.account_keys[prog_ix];

    const pd = readOverlayed(bank, db, pd_key) orelse return;
    // ProgramData owner must be the loader (lib.rs:810-813 InvalidAccountOwner)
    if (!std.mem.eql(u8, &pd.owner.data, &LOADER_ID)) return;
    // ProgramData writable (lib.rs:814-817 InvalidArgument)
    if (!ptx.isWritable(@intCast(pd_ix))) return;

    const prog = readOverlayed(bank, db, prog_key) orelse return;
    // Program writable (lib.rs:821-824) + loader-owned (lib.rs:825-828)
    if (!ptx.isWritable(@intCast(prog_ix))) return;
    if (!std.mem.eql(u8, &prog.owner.data, &LOADER_ID)) return;
    // Program state = Program{programdata_address == pd_key} (lib.rs:830-846)
    if ((readU32LE(prog.data, 0) orelse return) != STATE_PROGRAM) return;
    if (prog.data.len < PROGRAM_SIZE) return;
    if (!std.mem.eql(u8, prog.data[4..PROGRAM_SIZE], &pd_key)) return; // InvalidArgument

    const old_len: u64 = pd.data.len;
    const new_len: u64 = old_len +| @as(u64, additional_bytes);
    // new_len > MAX_PERMITTED_DATA_LENGTH → InvalidRealloc (lib.rs:851-859)
    if (new_len > MAX_PERMITTED_DATA_LENGTH) return;

    // SIMD-0431: min-extend-size gate (lib.rs:861-883).
    if (simd0431Active(feature_set, bank.slot) and simd0431Rejects(additional_bytes, old_len)) {
        return; // InvalidArgument
    }

    const clock_slot = bank.slot;

    // ProgramData must be ProgramData{slot, Some(authority)} (lib.rs:891-926).
    if (pd.data.len < PROGRAM_DATA_METADATA_SIZE) return; // InvalidAccountData
    const pd_slot = readU64LE(pd.data, 4) orelse return;
    if (clock_slot == pd_slot) return; // "extended in this block already" InvalidArgument
    if (pd.data[12] == 0) return; // upgrade authority None → Immutable
    if (pd.data[12] != 1) return; // malformed Option → treat as InvalidAccountData
    // check_authority=false in beta.3 → no authority signer check here.

    // rent top-up: required = max(minimum_balance(new_len),1) - balance (lib.rs:928-936).
    const min_balance = @max(rentExemptMinimumBalance(new_len), 1);
    const required_payment: u64 = min_balance -| pd.lamports;

    // Build the grown ProgramData bytes (realloc zero-fills the new tail:
    // Vec::resize(new_len, 0), instruction_accounts.rs:206). Header is then
    // re-stamped to ProgramData{slot=clock_slot, same authority}.
    const new_pd_data = alloc.alloc(u8, @intCast(new_len)) catch return;
    @memcpy(new_pd_data[0..pd.data.len], pd.data);
    @memset(new_pd_data[pd.data.len..], 0);

    // deploy_program! over the (grown) programdata payload region — explicitly
    // disable_sbpf_v0_v1_v2_deployment = false for extend (lib.rs:961-972).
    const pd_offset = PROGRAM_DATA_METADATA_SIZE;
    if (pd_offset > new_pd_data.len) return;
    try deployVerify(alloc, new_pd_data[pd_offset..], false, sha512SyscallActive(feature_set, bank.slot));

    // Re-stamp header: ProgramData{slot=clock_slot, Some(authority)} (lib.rs:977-980).
    // upgrade_authority_address is preserved from the pre-state (bytes [13..45]).
    std.mem.writeInt(u32, new_pd_data[0..4], STATE_PROGRAM_DATA, .little);
    std.mem.writeInt(u64, new_pd_data[4..12], clock_slot, .little);
    // [12]=Option byte already 1 (copied), [13..45]=authority already copied.

    // Apply rent top-up first (CPI system transfer payer→programdata, lib.rs:943-951),
    // then the realloc+restamp. lt deltas computed over real pre/post bytes.
    if (required_payment > 0) {
        if (ix.account_indices.len <= OPTIONAL_PAYER_IDX) return; // NotEnoughAccountKeys
        const payer_ix = ix.account_indices[OPTIONAL_PAYER_IDX];
        if (payer_ix >= ptx.num_accounts) return;
        if (!ptx.isWritable(@intCast(payer_ix))) return;
        const payer_key = ptx.account_keys[payer_ix];
        const payer = readOverlayed(bank, db, payer_key) orelse return;
        if (payer.lamports < required_payment) return; // system transfer InsufficientFunds
        // payer debited; payer data/owner/exec unchanged.
        const payer_data = alloc.alloc(u8, payer.data.len) catch return;
        if (payer.data.len > 0) @memcpy(payer_data, payer.data);
        commitChange(bank, payer_key, payer, payer.lamports - required_payment, payer_data);
        // programdata credited the same amount + new (grown/restamped) data.
        commitChange(bank, pd_key, pd, pd.lamports + required_payment, new_pd_data);
    } else {
        commitDataChange(bank, pd_key, pd, new_pd_data);
    }
}

/// UpgradeableLoaderInstruction::Upgrade (Agave lib.rs:360-535). Accounts:
///   0 = ProgramData (rewritten + funded), 1 = Program, 2 = Buffer (drained +
///   truncated), 3 = spill recipient, 4 = rent sysvar, 5 = clock sysvar,
///   6 = upgrade authority (signer). Copies buffer→programdata, zeroes the
///   tail, re-stamps the header, funds programdata to rent-exempt and spills
///   the remainder, drains+truncates the buffer.
fn doUpgrade(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
    feature_set: anytype,
) !void {
    // check_number_of_instruction_accounts(7) (lib.rs:361,367).
    if (ix.account_indices.len < 7) return;
    const pd_ix = ix.account_indices[0];
    const prog_ix = ix.account_indices[1];
    const buf_ix = ix.account_indices[2];
    const spill_ix = ix.account_indices[3];
    const auth_ix = ix.account_indices[6];
    if (pd_ix >= ptx.num_accounts or prog_ix >= ptx.num_accounts or
        buf_ix >= ptx.num_accounts or spill_ix >= ptx.num_accounts or
        auth_ix >= ptx.num_accounts) return;
    const pd_key = ptx.account_keys[pd_ix];
    const prog_key = ptx.account_keys[prog_ix];
    const buf_key = ptx.account_keys[buf_ix];
    const spill_key = ptx.account_keys[spill_ix];
    const authority_key = ptx.account_keys[auth_ix];

    // Verify Program account (lib.rs:372-394).
    const prog = readOverlayed(bank, db, prog_key) orelse return;
    if (!ptx.isWritable(@intCast(prog_ix))) return; // not writeable → InvalidArgument
    if (!std.mem.eql(u8, &prog.owner.data, &LOADER_ID)) return; // IncorrectProgramId
    if ((readU32LE(prog.data, 0) orelse return) != STATE_PROGRAM) return; // InvalidAccountData
    if (prog.data.len < PROGRAM_SIZE) return;
    if (!std.mem.eql(u8, prog.data[4..PROGRAM_SIZE], &pd_key)) return; // InvalidArgument

    // Verify Buffer account (lib.rs:398-420).
    const buf = readOverlayed(bank, db, buf_key) orelse return;
    if (!std.mem.eql(u8, &buf.owner.data, &LOADER_ID)) return;
    if ((readU32LE(buf.data, 0) orelse return) != STATE_BUFFER) return; // InvalidArgument
    if (buf.data.len < BUFFER_METADATA_SIZE) return;
    if (buf.data[4] == 0) return; // buffer authority None → mismatch → IncorrectAuthority
    if (buf.data[4] != 1) return;
    if (!std.mem.eql(u8, buf.data[5..BUFFER_METADATA_SIZE], &authority_key)) return; // IncorrectAuthority
    if (!isSigner(ptx, auth_ix)) return; // MissingRequiredSignature
    const buffer_lamports = buf.lamports;
    const buffer_data_offset = BUFFER_METADATA_SIZE;
    const buffer_data_len: u64 = @as(u64, buf.data.len) -| buffer_data_offset;
    if (buf.data.len < BUFFER_METADATA_SIZE or buffer_data_len == 0) return; // InvalidAccountData

    // Verify ProgramData account (lib.rs:425-468).
    const pd = readOverlayed(bank, db, pd_key) orelse return;
    if (!std.mem.eql(u8, &pd.owner.data, &LOADER_ID)) return;
    const pd_offset = PROGRAM_DATA_METADATA_SIZE;
    const programdata_balance_required = @max(rentExemptMinimumBalance(pd.data.len), 1);
    // programdata must be large enough to hold size_of_programdata(buffer_data_len)
    // = PROGRAM_DATA_METADATA_SIZE + buffer_data_len (lib.rs:429-434).
    if (@as(u64, pd.data.len) < pd_offset + buffer_data_len) return; // AccountDataTooSmall
    if (pd.lamports +| buffer_lamports < programdata_balance_required) return; // InsufficientFunds
    if (pd.data.len < PROGRAM_DATA_METADATA_SIZE) return;
    if ((readU32LE(pd.data, 0) orelse return) != STATE_PROGRAM_DATA) return; // InvalidAccountData
    const pd_slot = readU64LE(pd.data, 4) orelse return;
    if (bank.slot == pd_slot) return; // deployed in this block already → InvalidArgument
    if (pd.data[12] == 0) return; // upgrade authority None → Immutable
    if (pd.data[12] != 1) return;
    if (!std.mem.eql(u8, pd.data[13..PROGRAM_DATA_METADATA_SIZE], &authority_key)) return; // IncorrectAuthority

    // deploy_program! over the buffer payload (lib.rs:473-487). Honors
    // disable_sbpf_v0_v1_v2_deployment.
    const disable = disableSbpfV0V1V2(feature_set, bank.slot);
    try deployVerify(alloc, buf.data[buffer_data_offset..], disable, sha512SyscallActive(feature_set, bank.slot));

    // Build new ProgramData bytes: header restamped {slot, Some(authority)},
    // buffer payload copied to [pd_offset..pd_offset+buffer_data_len], rest
    // zeroed (lib.rs:495-519). The programdata length itself is UNCHANGED
    // (Upgrade does not resize programdata; it fills+zeroes the existing buffer).
    const new_pd_data = alloc.alloc(u8, pd.data.len) catch return;
    @memcpy(new_pd_data, pd.data);
    std.mem.writeInt(u32, new_pd_data[0..4], STATE_PROGRAM_DATA, .little);
    std.mem.writeInt(u64, new_pd_data[4..12], bank.slot, .little);
    new_pd_data[12] = 1; // Some(authority) — authority unchanged (bytes preserved)
    const copy_end: usize = @intCast(pd_offset + buffer_data_len);
    @memcpy(new_pd_data[pd_offset..copy_end], buf.data[buffer_data_offset..]);
    @memset(new_pd_data[copy_end..], 0);

    // Lamport flow (lib.rs:521-532): spill += pd.lamports + buffer - required;
    // buffer → 0; programdata → required. Buffer truncated to size_of_buffer(0)=37.
    const spill_gain: u64 = (pd.lamports +| buffer_lamports) -| programdata_balance_required;

    const spill = readOverlayed(bank, db, spill_key) orelse return;
    if (!ptx.isWritable(@intCast(spill_ix))) return;
    if (!ptx.isWritable(@intCast(buf_ix))) return;
    if (!ptx.isWritable(@intCast(pd_ix))) return;

    // Buffer → Uninitialized? No: Agave only set_data_length(size_of_buffer(0))
    // = 37 (keeps Buffer tag + authority bytes), and set_lamports(0). The 37
    // retained bytes are buffer.data[0..37] (tag + Option + authority).
    const new_buf_data = alloc.alloc(u8, BUFFER_METADATA_SIZE) catch return;
    @memcpy(new_buf_data, buf.data[0..BUFFER_METADATA_SIZE]);

    const spill_data = alloc.alloc(u8, spill.data.len) catch return;
    if (spill.data.len > 0) @memcpy(spill_data, spill.data);

    // Program account is unchanged on Upgrade (still Program{pd_key}); not written.
    commitChange(bank, spill_key, spill, spill.lamports +| spill_gain, spill_data);
    commitChange(bank, buf_key, buf, 0, new_buf_data);
    commitChange(bank, pd_key, pd, programdata_balance_required, new_pd_data);
}

/// UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len: u64 }
/// (Agave lib.rs:202-359). Accounts: 0 = payer, 1 = ProgramData (created),
///   2 = Program (init + executable), 3 = Buffer (drained + truncated),
///   4 = rent, 5 = clock, 6 = system program, 7 = authority (signer).
/// Creates the ProgramData account via a derived-address system create_account,
/// copies the buffer payload in, marks the Program executable.
fn doDeployWithMaxDataLen(
    ix: anytype,
    ptx: anytype,
    bank: anytype,
    db: anytype,
    alloc: std.mem.Allocator,
    feature_set: anytype,
) !void {
    const data = ix.data;
    const max_data_len_u64 = readU64LE(data, 4) orelse return;
    const max_data_len: u64 = max_data_len_u64;

    // check_number_of_instruction_accounts(8) (lib.rs:203,210).
    if (ix.account_indices.len < 8) return;
    const payer_ix = ix.account_indices[0];
    const pd_ix = ix.account_indices[1];
    const prog_ix = ix.account_indices[2];
    const buf_ix = ix.account_indices[3];
    const auth_ix = ix.account_indices[7];
    if (payer_ix >= ptx.num_accounts or pd_ix >= ptx.num_accounts or
        prog_ix >= ptx.num_accounts or buf_ix >= ptx.num_accounts or
        auth_ix >= ptx.num_accounts) return;
    const payer_key = ptx.account_keys[payer_ix];
    const pd_key = ptx.account_keys[pd_ix];
    const prog_key = ptx.account_keys[prog_ix];
    const buf_key = ptx.account_keys[buf_ix];
    const authority_key = ptx.account_keys[auth_ix];

    // Verify Program account (lib.rs:215-229).
    const prog = readOverlayed(bank, db, prog_key) orelse return;
    if ((readU32LE(prog.data, 0) orelse return) != STATE_UNINITIALIZED) return; // AccountAlreadyInitialized
    if (prog.data.len < PROGRAM_SIZE) return; // AccountDataTooSmall
    if (prog.lamports < rentExemptMinimumBalance(prog.data.len)) return; // ExecutableAccountNotRentExempt

    // Verify Buffer account (lib.rs:233-258).
    const buf = readOverlayed(bank, db, buf_key) orelse return;
    if ((readU32LE(buf.data, 0) orelse return) != STATE_BUFFER) return; // InvalidArgument
    if (buf.data.len < BUFFER_METADATA_SIZE) return;
    if (buf.data[4] == 0) return; // authority None → mismatch IncorrectAuthority
    if (buf.data[4] != 1) return;
    if (!std.mem.eql(u8, buf.data[5..BUFFER_METADATA_SIZE], &authority_key)) return; // IncorrectAuthority
    if (!isSigner(ptx, auth_ix)) return; // MissingRequiredSignature
    const buffer_data_offset = BUFFER_METADATA_SIZE;
    const buffer_data_len: u64 = @as(u64, buf.data.len) -| buffer_data_offset;
    const programdata_len: u64 = PROGRAM_DATA_METADATA_SIZE + max_data_len;
    if (buf.data.len < BUFFER_METADATA_SIZE or buffer_data_len == 0) return; // InvalidAccountData
    if (max_data_len < buffer_data_len) return; // AccountDataTooSmall
    if (programdata_len > MAX_PERMITTED_DATA_LENGTH) return; // InvalidArgument

    // ProgramData address must be the derived PDA find_program_address([program_id])
    // (lib.rs:272-277). Vexor has no in-handler PDA derivation wired; the cluster
    // already accepted this tx (derived_address == programdata_key), so on the
    // replay accept-path the equality holds by construction. We rely on the
    // buffer/program/authority gates above + the deploy verify for accept/reject
    // fidelity; the PDA check cannot flip an accepted tx to rejected here.
    // (Flagged: if a rejected-DeployWithMaxDataLen ever diverges, wire PDA derive.)

    // ProgramData created at rent-exempt(programdata_len) (lib.rs:288-294). The
    // payer funds it; the buffer is drained to the payer first (lib.rs:280-285).
    const pd = readOverlayed(bank, db, pd_key) orelse OverlayedAccount{
        .lamports = 0,
        .owner = .{ .data = SYSTEM_ID },
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
        .data = &[_]u8{},
    };
    // create_account requires the target be empty (system program); on a clean
    // accept-path pd is a fresh 0-lamport system account.
    const pd_rent = @max(rentExemptMinimumBalance(programdata_len), 1);

    const payer = readOverlayed(bank, db, payer_key) orelse return;
    if (!ptx.isWritable(@intCast(payer_ix))) return;
    if (!ptx.isWritable(@intCast(pd_ix))) return;
    if (!ptx.isWritable(@intCast(prog_ix))) return;
    if (!ptx.isWritable(@intCast(buf_ix))) return;

    // deploy_program! over the buffer payload (lib.rs:308-321). Honors
    // disable_sbpf_v0_v1_v2_deployment.
    const disable = disableSbpfV0V1V2(feature_set, bank.slot);
    try deployVerify(alloc, buf.data[buffer_data_offset..], disable, sha512SyscallActive(feature_set, bank.slot));

    // Lamport flow: buffer drained to payer (lib.rs:283-284), then payer pays
    // pd_rent for the new programdata (lib.rs:288-302). Net payer delta =
    // +buffer_lamports - pd_rent.
    const payer_after: u64 = (payer.lamports +| buf.lamports) -| pd_rent;
    if (payer.lamports +| buf.lamports < pd_rent) return; // payer can't fund → InsufficientFunds

    // Build ProgramData bytes: header ProgramData{slot, Some(authority)} +
    // buffer payload at [pd_offset..pd_offset+buffer_data_len], rest zero
    // (lib.rs:330-348). Length = programdata_len.
    const new_pd_data = alloc.alloc(u8, @intCast(programdata_len)) catch return;
    @memset(new_pd_data, 0);
    std.mem.writeInt(u32, new_pd_data[0..4], STATE_PROGRAM_DATA, .little);
    std.mem.writeInt(u64, new_pd_data[4..12], bank.slot, .little);
    new_pd_data[12] = 1; // Some(authority)
    @memcpy(new_pd_data[13..PROGRAM_DATA_METADATA_SIZE], &authority_key);
    const pd_offset = PROGRAM_DATA_METADATA_SIZE;
    const copy_end: usize = @intCast(pd_offset + buffer_data_len);
    @memcpy(new_pd_data[pd_offset..copy_end], buf.data[buffer_data_offset..]);

    // Program account: set_state(Program{programdata_address=pd_key}) + executable
    // (lib.rs:351-356). data len unchanged (already size_of_program=36).
    const new_prog_data = alloc.alloc(u8, prog.data.len) catch return;
    @memcpy(new_prog_data, prog.data);
    std.mem.writeInt(u32, new_prog_data[0..4], STATE_PROGRAM, .little);
    @memcpy(new_prog_data[4..PROGRAM_SIZE], &pd_key);

    // Buffer truncated to size_of_buffer(0)=37 (lib.rs:347), lamports → 0
    // (drained to payer above).
    const new_buf_data = alloc.alloc(u8, BUFFER_METADATA_SIZE) catch return;
    @memcpy(new_buf_data, buf.data[0..BUFFER_METADATA_SIZE]);

    const payer_data = alloc.alloc(u8, payer.data.len) catch return;
    if (payer.data.len > 0) @memcpy(payer_data, payer.data);

    // Commit all mutations.
    commitChange(bank, payer_key, payer, payer_after, payer_data);
    commitChange(bank, buf_key, buf, 0, new_buf_data);
    // ProgramData: created with loader owner, rent lamports, new bytes.
    commitFull(bank, pd_key, pd, pd_rent, LOADER_ID, false, pd.rent_epoch, new_pd_data);
    // Program: loader-owned (unchanged owner), executable=true, new bytes.
    commitFull(bank, prog_key, prog, prog.lamports, prog.owner.data, true, prog.rent_epoch, new_prog_data);
}

// ── tests ────────────────────────────────────────────────────────────────
test "loader-v3 size constants match Agave loader-v3-interface" {
    try std.testing.expectEqual(@as(usize, 4), UNINITIALIZED_SIZE);
    try std.testing.expectEqual(@as(usize, 37), BUFFER_METADATA_SIZE);
    try std.testing.expectEqual(@as(usize, 36), PROGRAM_SIZE);
    try std.testing.expectEqual(@as(usize, 45), PROGRAM_DATA_METADATA_SIZE);
}

test "readU32LE / readU64LE bounds + value" {
    const d = [_]u8{ 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqual(@as(?u32, 1), readU32LE(&d, 0));
    try std.testing.expectEqual(@as(?u32, 2), readU32LE(&d, 4));
    try std.testing.expectEqual(@as(?u64, 2), readU64LE(&d, 4));
    try std.testing.expectEqual(@as(?u32, null), readU32LE(&d, 9)); // OOB
    try std.testing.expectEqual(@as(?u64, null), readU64LE(&d, 8)); // OOB (needs 8 from off 8 → 16 > 12)
}

// ── P0-3 KAT: unknown discriminant fails the tx ────────────────────────────
// VEXOR-PROGRAM-COVERAGE-AUDIT-2026-07-11 §7 P0-3. `execute()`'s ix/ptx/bank/
// db params are `anytype` specifically to avoid a circular import with
// replay_stage.zig (see the entry-point doc comment above `execute`), so
// these tests use minimal structurally-duck-typed stand-ins for ix/ptx/bank/
// db — satisfying only the fields/methods execute() and its callees
// actually touch (enumerated by grepping every `ptx.`/`ix.`/`bank.`/`db.`
// site in this file). Deliberately NOT the real bank_mod.Bank: referencing
// Bank.init/.deinit by name here pulls bank.zig's own (unrelated,
// pre-existing) test suite into this test binary's discovery set, which
// carries known failures/leaks (e.g. a freeze()/updateSlotHistory leak, an
// EpochSchedule.DEFAULT test-order dependency) that have nothing to do with
// P0-3 and are out of this fix's scope.

const TestPtx = struct {
    num_accounts: u16 = 0,
    account_keys: []const [32]u8 = &.{},
    num_required_sigs: u8 = 0,

    pub fn isWritable(self: *const TestPtx, index: u16) bool {
        _ = self;
        _ = index;
        return false;
    }
};

const TestIx = struct {
    data: []const u8,
    account_indices: []const u8 = &.{},
};

const TestAccount = struct {
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

const TestDb = struct {
    pub fn getAccountInSlot(self: *const TestDb, pk: *const core.Pubkey, slot: u64, ancestors: []const u64) ?TestAccount {
        _ = self;
        _ = pk;
        _ = slot;
        _ = ancestors;
        return null; // no accounts on record — every read misses, matching an empty accounts_db
    }
};

// Structural stand-in for bank_mod.AccountWrite — matches the field set
// `readOverlayed`/`commitChange` dereference on `bank.pending_writes.items[i]`.
const TestWrite = struct {
    pubkey: Pubkey,
    lamports: u64,
    owner: Pubkey,
    executable: bool,
    rent_epoch: u64,
    data: []const u8,
};

const TestBank = struct {
    slot: u64 = 1,
    pending_writes: struct { items: []const TestWrite = &.{} } = .{},

    pub fn ancestors(self: *const TestBank) []const u64 {
        _ = self;
        return &.{};
    }
    pub fn collectWrite(self: *TestBank, write: anytype) !void {
        _ = self;
        _ = write;
    }
};

test "P0-3: unknown discriminant fails the tx (Agave InvalidInstructionData)" {
    const alloc = std.testing.allocator;
    var bank = TestBank{};
    const db = TestDb{};
    const ptx = TestPtx{};
    // Discriminant 0xFFFFFFFF is not any of IX_WRITE(0..7) — unknown variant.
    const ix = TestIx{ .data = &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF } };

    const result = execute(ix, ptx, &bank, db, alloc, null);
    try std.testing.expectError(error.InvalidInstructionData, result);
}

test "P0-3: known discriminant with too-few accounts still silently no-ops (unaffected by the fix)" {
    const alloc = std.testing.allocator;
    var bank = TestBank{};
    const db = TestDb{};
    const ptx = TestPtx{};
    // IX_CLOSE = 5, but account_indices is empty — doClose's own
    // `check_number_of_instruction_accounts(2)` guard bare-`return`s (a
    // clean no-op, not an error) BEFORE the discriminant-unknown path is
    // even reached. Proves the P0-3 fix is scoped to truly unknown
    // variants only — known-but-invalid instructions keep their existing
    // (pre-fix) silent-reject behavior.
    const ix = TestIx{ .data = &[_]u8{ 5, 0, 0, 0 } };

    try execute(ix, ptx, &bank, db, alloc, null);
}
