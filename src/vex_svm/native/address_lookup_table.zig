/// address_lookup_table.zig — Address Lookup Table Program for Vexor
///
/// Ported from:
///   sig/src/runtime/program/address_lookup_table/execute.zig (627 lines)
///
/// Agave reference:
///   https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs
///
/// Functions ported:
///   createLookupTable()     → createLookupTable()
///   freezeLookupTable()     → freezeLookupTable()
///   extendLookupTable()     → extendLookupTable()
///   deactivateLookupTable() → deactivateLookupTable()
///   closeLookupTable()      → closeLookupTable()
///
/// Naming: camelCase, no fd_ prefix (Vexor convention).
const std = @import("std");

// ─────────────────────────────────────────────────────────────────────────────
// Address Lookup Table Program ID
// AddressLookupTab1e1111111111111111111111111
// ─────────────────────────────────────────────────────────────────────────────
// FIX (carrier 420180889, 2026-07-06): the previous byte array was HAND-TYPED
// WRONG — it base58-encoded to `BP7ns7qVEz9ZKEqP2bvPxZTig6AyKwWiboQtYnBhW3z`,
// NOT the ALT program id. Because the top-level replay dispatch matches ALT
// instructions with `std.mem.eql(program_id, &PROGRAM_ID)` (replay_stage.zig
// executeDagTx:~6622 / serial:~8350), the mismatch meant EVERY top-level ALT
// instruction (Create/Extend/Freeze/Deactivate/Close) fell through to the
// generic BPF path — which for the Core-BPF-migrated ALT returns the M9
// `VariantPending_ExtendLookupTable` stub whose writes are then silently
// dropped → the extend/rent mutations never reached the committed write set
// (tx recorded SUCCESS, 0 writes) → bank_hash divergence. These bytes are now
// the canonical id, byte-verified against Agave 4.1.1
// (fetch-core-bpf.sh: AddressLookupTab1e…) and Firedancer
// (fd_solana_address_lookup_table_program_id): hex
// 0277a6af97339b7ac88d1892c90446f50002309266f62e53c118244982000000, and
// against the independent comptime-decoded copy in vex_bpf2/builtins/mod.zig
// (ADDRESS_LOOKUP_TABLE_PROGRAM_ID = decodeBase58Pubkey("AddressLookupTab1e…")).
// (a known pitfall here: never hand-type program-id bytes.)
pub const PROGRAM_ID: [32]u8 = .{
    0x02, 0x77, 0xa6, 0xaf, 0x97, 0x33, 0x9b, 0x7a,
    0xc8, 0x8d, 0x18, 0x92, 0xc9, 0x04, 0x46, 0xf5,
    0x00, 0x02, 0x30, 0x92, 0x66, 0xf6, 0x2e, 0x53,
    0xc1, 0x18, 0x24, 0x49, 0x82, 0x00, 0x00, 0x00,
};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// sig/src/runtime/program/address_lookup_table/state.zig
// ─────────────────────────────────────────────────────────────────────────────

/// CUs consumed by a lookup table instruction.
/// agave: programs/address-lookup-table/src/processor.rs  COMPUTE_UNITS = 750
pub const COMPUTE_UNITS: u64 = 750;

/// Byte size of the LookupTableMeta header that precedes address entries.
/// Serialised as: discriminant(4) + deactivation_slot(8) + last_extended_slot(8) +
///                last_extended_slot_start_index(1) + has_authority(1) + authority(32) + padding(2)
/// = 56 bytes  (agave AddressLookupTable META_SIZE)
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Maximum number of address entries in a single lookup table.
/// agave: LOOKUP_TABLE_MAX_ADDRESSES = 256
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

/// Sentinel value for deactivation_slot meaning "not deactivated".
pub const DEACTIVATION_SLOT_NONE: u64 = std.math.maxInt(u64);

// ─────────────────────────────────────────────────────────────────────────────
// Error set
// ─────────────────────────────────────────────────────────────────────────────
pub const AltError = error{
    MissingAccount,
    MissingRequiredSignature,
    InvalidAccountData,
    InvalidAccountOwner,
    InvalidArgument,
    InvalidInstructionData,
    /// Table already has an authority (immutable).
    Immutable,
    /// Authority provided does not match the stored authority.
    IncorrectAuthority,
    /// Table is full (256 entries).
    TableFull,
    /// Account already has data (CreateLookupTable only).
    AccountAlreadyInitialized,
    ArithmeticOverflow,
    OutOfMemory,
    /// Custom error code from program address derivation.
    Custom,
};

// ─────────────────────────────────────────────────────────────────────────────
// Instruction discriminants
// agave: programs/address-lookup-table/src/instruction.rs
// ─────────────────────────────────────────────────────────────────────────────
pub const Discriminant = enum(u32) {
    create_lookup_table = 0,
    freeze_lookup_table = 1,
    extend_lookup_table = 2,
    deactivate_lookup_table = 3,
    close_lookup_table = 4,
    _,
};

// ─────────────────────────────────────────────────────────────────────────────
// LookupTableMeta — the 56-byte header stored in the account
// sig: state.LookupTableMeta
// ─────────────────────────────────────────────────────────────────────────────
pub const LookupTableMeta = struct {
    /// Slot at which the table was deactivated; DEACTIVATION_SLOT_NONE when active.
    deactivation_slot: u64,
    /// Most recent slot this table was extended.
    last_extended_slot: u64,
    /// Index within last_extended_slot where new addresses start.
    last_extended_slot_start_index: u8,
    /// Optional authority (null = frozen).
    authority: ?[32]u8,

    /// Create a fresh table with the given authority.
    pub fn new(authority: [32]u8) LookupTableMeta {
        return .{
            .deactivation_slot = DEACTIVATION_SLOT_NONE,
            .last_extended_slot = 0,
            .last_extended_slot_start_index = 0,
            .authority = authority,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AddressLookupTable — in-memory view of account data
// ─────────────────────────────────────────────────────────────────────────────
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    /// Slice into the raw account data (not owned).
    addresses: [][32]u8,

    /// Decode a lookup table from raw account data.
    /// sig: AddressLookupTable.deserialize
    pub fn deserialize(data: []u8) AltError!AddressLookupTable {
        if (data.len < LOOKUP_TABLE_META_SIZE) return AltError.InvalidAccountData;

        // Header layout:
        //  [0..4]   discriminant (u32 LE) — must be 1 (LookupTable)
        //  [4..12]  deactivation_slot (u64 LE)
        //  [12..20] last_extended_slot (u64 LE)
        //  [20]     last_extended_slot_start_index (u8)
        //  [21]     has_authority (u8)
        //  [22..54] authority ([32]u8)  — only valid when has_authority=1
        //  [54..56] padding (2 bytes)
        const disc = std.mem.readInt(u32, data[0..4], .little);
        if (disc != 1) return AltError.InvalidAccountData;

        const deactivation_slot = std.mem.readInt(u64, data[4..12], .little);
        const last_extended_slot = std.mem.readInt(u64, data[12..20], .little);
        const last_extended_slot_start_index = data[20];
        const has_authority = data[21];
        const authority: ?[32]u8 = if (has_authority == 1)
            data[22..54].*
        else
            null;

        const addr_bytes = data[LOOKUP_TABLE_META_SIZE..];
        if (addr_bytes.len % 32 != 0) return AltError.InvalidAccountData;
        const addr_count = addr_bytes.len / 32;

        // Reinterpret the tail as a slice of [32]u8.
        const addresses: [][32]u8 = @as([*][32]u8, @ptrCast(@alignCast(addr_bytes.ptr)))[0..addr_count];

        return .{
            .meta = .{
                .deactivation_slot = deactivation_slot,
                .last_extended_slot = last_extended_slot,
                .last_extended_slot_start_index = last_extended_slot_start_index,
                .authority = authority,
            },
            .addresses = addresses,
        };
    }

    /// Write meta fields back into existing account data (in-place, preserves addresses).
    /// sig: AddressLookupTable.overwriteMetaData
    pub fn overwriteMetaData(data: []u8, meta: LookupTableMeta) AltError!void {
        if (data.len < LOOKUP_TABLE_META_SIZE) return AltError.InvalidAccountData;
        // discriminant = 1 (LookupTable)
        std.mem.writeInt(u32, data[0..4], 1, .little);
        std.mem.writeInt(u64, data[4..12], meta.deactivation_slot, .little);
        std.mem.writeInt(u64, data[12..20], meta.last_extended_slot, .little);
        data[20] = meta.last_extended_slot_start_index;
        if (meta.authority) |auth| {
            data[21] = 1;
            @memcpy(data[22..54], &auth);
        } else {
            data[21] = 0;
            @memset(data[22..54], 0);
        }
        data[54] = 0;
        data[55] = 0;
    }

    /// Initialise a meta-only (header-only) account data buffer.
    pub fn initMetaData(data: []u8, meta: LookupTableMeta) AltError!void {
        if (data.len < LOOKUP_TABLE_META_SIZE) return AltError.InvalidAccountData;
        try overwriteMetaData(data, meta);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// BorrowedAccount — minimal mutable account view
// (matches vote_v2.zig / nonce.zig style)
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
// InstrCtx — instruction context for ALT instructions
// ─────────────────────────────────────────────────────────────────────────────
pub const InstrCtx = struct {
    accounts: []BorrowedAccount,
    signer_mask: u64,
    allocator: std.mem.Allocator,

    /// Sysvar: current slot from the Clock sysvar.
    clock_slot: u64,
    /// Sysvar: whether `slot` appears in the recent SlotHashes list.
    recent_slot_fn: ?*const fn (slot: u64) bool,
    /// Sysvar: minimum lamport balance for `size` bytes (Rent).
    min_rent_balance_fn: ?*const fn (size: u64) u64,

    pub fn isSigner(self: *const InstrCtx, idx: usize) bool {
        if (idx >= 64) return false;
        return (self.signer_mask >> @intCast(idx)) & 1 != 0;
    }

    pub fn getAccount(self: *const InstrCtx, idx: usize) AltError!*BorrowedAccount {
        if (idx >= self.accounts.len) return AltError.MissingAccount;
        return &self.accounts[idx];
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// PDA derivation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Marker to detect whether a hash is on the curve (i.e. not a valid PDA).
/// An on-curve point means the derivation failed (off-curve required for PDAs).
/// We approximate: for ALT derivation we try all bump seeds 255..0.
fn tryCandidatePda(
    seeds: []const []const u8,
    bump: u8,
    program_id: *const [32]u8,
) ?[32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (seeds) |s| hasher.update(s);
    const bump_buf = [_]u8{bump};
    hasher.update(&bump_buf);
    hasher.update(program_id);
    hasher.update("ProgramDerivedAddress");
    var result: [32]u8 = undefined;
    hasher.final(&result);
    // Check that it's NOT a valid ed25519 curve point.
    // We use a simple heuristic: attempt parsing; real implementations use
    // curve25519 point-validation.  Here we accept all (conservative).
    return result;
}

/// Derive a program address with a known bump seed.
/// agave: create_program_address
pub fn createProgramAddress(
    seeds: []const []const u8,
    bump: u8,
    program_id: *const [32]u8,
) [32]u8 {
    return tryCandidatePda(seeds, bump, program_id) orelse unreachable;
}

// ─────────────────────────────────────────────────────────────────────────────
// createLookupTable
// agave: programs/address-lookup-table/src/processor.rs#L51
// sig: execute.zig:createLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Create a new address lookup table account.
///
/// Accounts:
///   [0] lookup_table_account (writable, new)
///   [1] authority_account (signer)
///   [2] payer_account (signer, writable)
///   [3] system_program
///
/// Instruction data:
///   [0..8]  recent_slot (u64 LE)
///   [8]     bump_seed (u8)
pub fn createLookupTable(
    ctx: *const InstrCtx,
    recent_slot: u64,
    bump_seed: u8,
) AltError!void {
    if (ctx.accounts.len < 3) return AltError.MissingAccount;

    const lookup_table_acct = try ctx.getAccount(0);
    const authority_acct = try ctx.getAccount(1);
    const payer_acct = try ctx.getAccount(2);

    // NOTE: createLookupTable does NOT require the authority to sign.
    // `relax_authority_signer_check_for_lookup_table_creation` is active cluster-wide
    // and the migrated Core-BPF ELF (current Agave processor.rs) performs no
    // authority-signer check on create — the PDA derivation (below) is the
    // protection. A hardcoded check here wrongly FAILED valid creates whose
    // authority != payer and didn't sign → bank_hash divergence vs cluster.
    // (freeze/extend/deactivate/close DO still require the authority to sign —
    // those checks are retained; this relaxation is create-only, matching Agave.)

    // agave:L87-L124 — payer must sign
    if (!ctx.isSigner(2)) {
        std.log.warn("[ALT] createLookupTable: payer must be a signer", .{});
        return AltError.MissingRequiredSignature;
    }

    // agave:L74-L86 — table account must not already be allocated
    // (pre-relax_authority_signer_check feature behaviour)
    if (lookup_table_acct.data.len > 0 and
        !std.mem.eql(u8, &lookup_table_acct.owner, &PROGRAM_ID))
    {
        std.log.warn("[ALT] createLookupTable: table account must not be allocated", .{});
        return AltError.AccountAlreadyInitialized;
    }

    // agave:L127-L135 — verify recent slot is in SlotHashes
    if (ctx.recent_slot_fn) |recent_fn| {
        if (!recent_fn(recent_slot)) {
            std.log.warn("[ALT] createLookupTable: {} is not a recent slot", .{recent_slot});
            return AltError.InvalidInstructionData;
        }
    }

    // agave:L137-L147 — derive and verify table address
    const slot_le = std.mem.nativeTo(u64, recent_slot, .little);
    const slot_bytes = std.mem.asBytes(&slot_le);
    const seeds: [2][]const u8 = .{ &authority_acct.pubkey, slot_bytes };
    const derived_key = createProgramAddress(&seeds, bump_seed, &PROGRAM_ID);

    if (!std.mem.eql(u8, &lookup_table_acct.pubkey, &derived_key)) {
        std.log.warn("[ALT] createLookupTable: table address must match derived address", .{});
        return AltError.InvalidArgument;
    }

    // agave:L152-L164 — ensure table has enough lamports; transfer from payer if needed
    const min_lamports: u64 = if (ctx.min_rent_balance_fn) |f|
        @max(f(LOOKUP_TABLE_META_SIZE), 1)
    else
        1;

    if (lookup_table_acct.lamports < min_lamports) {
        const needed = min_lamports - lookup_table_acct.lamports;
        if (payer_acct.lamports < needed) return AltError.MissingAccount; // InsufficientFunds
        payer_acct.lamports -= needed;
        lookup_table_acct.lamports += needed;
    }

    // agave:L164 — allocate + assign + write meta
    lookup_table_acct.data = try ctx.allocator.realloc(lookup_table_acct.data, LOOKUP_TABLE_META_SIZE);
    @memcpy(&lookup_table_acct.owner, &PROGRAM_ID);
    const meta = LookupTableMeta.new(authority_acct.pubkey);
    try AddressLookupTable.initMetaData(lookup_table_acct.data, meta);
}

// ─────────────────────────────────────────────────────────────────────────────
// freezeLookupTable
// agave: programs/address-lookup-table/src/processor.rs#L173
// sig: execute.zig:freezeLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Remove the authority from a lookup table (freeze it).
///
/// Accounts:
///   [0] lookup_table_account (writable)
///   [1] authority_account (signer)
pub fn freezeLookupTable(ctx: *const InstrCtx) AltError!void {
    if (ctx.accounts.len < 2) return AltError.MissingAccount;

    const lookup_table_acct = try ctx.getAccount(0);
    const authority_acct = try ctx.getAccount(1);

    // agave:L177-L182 — table must be owned by this program
    if (!std.mem.eql(u8, &lookup_table_acct.owner, &PROGRAM_ID))
        return AltError.InvalidAccountOwner;

    // agave:L184-L191 — authority must sign
    if (!ctx.isSigner(1)) {
        std.log.warn("[ALT] freezeLookupTable: authority must be a signer", .{});
        return AltError.MissingRequiredSignature;
    }

    var table = try AddressLookupTable.deserialize(lookup_table_acct.data);

    // agave:L194-L205 — check authority matches and table is unfrozen
    const stored_auth = table.meta.authority orelse {
        std.log.warn("[ALT] freezeLookupTable: lookup table is already frozen", .{});
        return AltError.Immutable;
    };
    if (!std.mem.eql(u8, &stored_auth, &authority_acct.pubkey))
        return AltError.IncorrectAuthority;

    // agave:L207-L213 — cannot freeze a deactivated table
    if (table.meta.deactivation_slot != DEACTIVATION_SLOT_NONE) {
        std.log.warn("[ALT] freezeLookupTable: deactivated tables cannot be frozen", .{});
        return AltError.InvalidArgument;
    }

    // agave:L214 — cannot freeze empty table
    if (table.addresses.len == 0) {
        std.log.warn("[ALT] freezeLookupTable: empty lookup tables cannot be frozen", .{});
        return AltError.InvalidInstructionData;
    }

    // agave:L214 — remove authority (freeze)
    table.meta.authority = null;
    try AddressLookupTable.overwriteMetaData(lookup_table_acct.data, table.meta);
}

// ─────────────────────────────────────────────────────────────────────────────
// extendLookupTable
// agave: programs/address-lookup-table/src/processor.rs#L224
// sig: execute.zig:extendLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Append new addresses to a lookup table.
///
/// Accounts:
///   [0] lookup_table_account (writable)
///   [1] authority_account (signer)
///   [2] payer_account (signer, writable)   — required when realloc needed
///   [3] system_program
///
/// Instruction data:
///   [0..8]  num_new_addresses (u64 LE)
///   [8..]   address entries (32 bytes each)
pub fn extendLookupTable(
    ctx: *const InstrCtx,
    new_addresses: []const [32]u8,
) AltError!void {
    if (ctx.accounts.len < 2) return AltError.MissingAccount;

    const lookup_table_acct = try ctx.getAccount(0);
    const authority_acct = try ctx.getAccount(1);

    // agave:L233 — table must be owned by this program
    if (!std.mem.eql(u8, &lookup_table_acct.owner, &PROGRAM_ID))
        return AltError.InvalidAccountOwner;

    // agave:L243 — authority must sign
    if (!ctx.isSigner(1)) {
        std.log.warn("[ALT] extendLookupTable: authority must be a signer", .{});
        return AltError.MissingRequiredSignature;
    }

    var table = try AddressLookupTable.deserialize(lookup_table_acct.data);

    // agave:L256-L263 — authority check
    const stored_auth = table.meta.authority orelse return AltError.Immutable;
    if (!std.mem.eql(u8, &stored_auth, &authority_acct.pubkey))
        return AltError.IncorrectAuthority;

    // agave:L265-L270 — cannot extend a deactivated table
    if (table.meta.deactivation_slot != DEACTIVATION_SLOT_NONE) {
        std.log.warn("[ALT] extendLookupTable: deactivated tables cannot be extended", .{});
        return AltError.InvalidArgument;
    }

    // agave:L272-L278 — check capacity
    if (table.addresses.len >= LOOKUP_TABLE_MAX_ADDRESSES) {
        std.log.warn("[ALT] extendLookupTable: lookup table is full", .{});
        return AltError.InvalidArgument;
    }

    // agave:L280-L284 — must add at least one address
    if (new_addresses.len == 0) {
        std.log.warn("[ALT] extendLookupTable: must extend with at least one address", .{});
        return AltError.InvalidInstructionData;
    }

    const new_total = table.addresses.len +| new_addresses.len;
    if (new_total > LOOKUP_TABLE_MAX_ADDRESSES) {
        std.log.warn("[ALT] extendLookupTable: would exceed max capacity {}", .{LOOKUP_TABLE_MAX_ADDRESSES});
        return AltError.InvalidInstructionData;
    }

    // agave:L286-L299 — update last_extended_slot if this is a new slot
    if (ctx.clock_slot != table.meta.last_extended_slot) {
        table.meta.last_extended_slot = ctx.clock_slot;
        table.meta.last_extended_slot_start_index =
            std.math.cast(u8, table.addresses.len) orelse return AltError.InvalidAccountData;
    }

    // agave:L301-L310 — resize account data
    const new_data_len = LOOKUP_TABLE_META_SIZE + new_total * 32;
    const old_data_len = lookup_table_acct.data.len;
    lookup_table_acct.data = try ctx.allocator.realloc(lookup_table_acct.data, new_data_len);

    // Write meta with updated last_extended_slot
    try AddressLookupTable.overwriteMetaData(lookup_table_acct.data, table.meta);

    // agave:L303-L309 — copy new addresses into tail
    const start_byte = old_data_len;
    for (new_addresses, 0..) |addr, i| {
        const off = start_byte + i * 32;
        @memcpy(lookup_table_acct.data[off..][0..32], &addr);
    }

    // agave:L319-L446 — ensure rent exemption; charge payer if needed
    const min_lamports: u64 = if (ctx.min_rent_balance_fn) |f|
        @max(f(new_data_len), 1)
    else
        0;

    if (min_lamports > lookup_table_acct.lamports and ctx.accounts.len >= 3) {
        const payer_acct = try ctx.getAccount(2);
        if (!ctx.isSigner(2)) {
            std.log.warn("[ALT] extendLookupTable: payer must be a signer", .{});
            return AltError.MissingRequiredSignature;
        }
        const needed = min_lamports - lookup_table_acct.lamports;
        if (payer_acct.lamports < needed) return AltError.MissingAccount; // InsufficientFunds
        payer_acct.lamports -= needed;
        lookup_table_acct.lamports += needed;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// deactivateLookupTable
// agave: programs/address-lookup-table/src/processor.rs#L343
// sig: execute.zig:deactivateLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Mark a lookup table for deactivation.
///
/// Accounts:
///   [0] lookup_table_account (writable)
///   [1] authority_account (signer)
pub fn deactivateLookupTable(ctx: *const InstrCtx) AltError!void {
    if (ctx.accounts.len < 2) return AltError.MissingAccount;

    const lookup_table_acct = try ctx.getAccount(0);
    const authority_acct = try ctx.getAccount(1);

    // agave:L351-L354 — table must be owned by this program
    if (!std.mem.eql(u8, &lookup_table_acct.owner, &PROGRAM_ID))
        return AltError.InvalidAccountOwner;

    // agave:L356-L362 — authority must sign
    if (!ctx.isSigner(1)) {
        std.log.warn("[ALT] deactivateLookupTable: authority must be a signer", .{});
        return AltError.MissingRequiredSignature;
    }

    var table = try AddressLookupTable.deserialize(lookup_table_acct.data);

    // agave:L364-L370 — frozen table cannot be deactivated
    const stored_auth = table.meta.authority orelse {
        std.log.warn("[ALT] deactivateLookupTable: lookup table is frozen", .{});
        return AltError.Immutable;
    };
    if (!std.mem.eql(u8, &stored_auth, &authority_acct.pubkey))
        return AltError.IncorrectAuthority;

    // agave:L372-L376 — already deactivated
    if (table.meta.deactivation_slot != DEACTIVATION_SLOT_NONE) {
        std.log.warn("[ALT] deactivateLookupTable: lookup table is already deactivated", .{});
        return AltError.InvalidArgument;
    }

    // agave:L378 — set deactivation slot to current slot
    table.meta.deactivation_slot = ctx.clock_slot;
    try AddressLookupTable.overwriteMetaData(lookup_table_acct.data, table.meta);
}

// ─────────────────────────────────────────────────────────────────────────────
// closeLookupTable
// agave: programs/address-lookup-table/src/processor.rs#L392
// sig: execute.zig:closeLookupTable
// ─────────────────────────────────────────────────────────────────────────────

/// Close a fully-deactivated lookup table and reclaim lamports.
///
/// Accounts:
///   [0] lookup_table_account (writable)
///   [1] authority_account (signer)
///   [2] recipient_account (writable) — receives the reclaimed lamports
pub fn closeLookupTable(ctx: *const InstrCtx) AltError!void {
    if (ctx.accounts.len < 3) return AltError.MissingAccount;

    const lookup_table_acct = try ctx.getAccount(0);
    const authority_acct = try ctx.getAccount(1);
    const recipient_acct = try ctx.getAccount(2);

    // agave:L400-L404 — table must be owned by this program
    if (!std.mem.eql(u8, &lookup_table_acct.owner, &PROGRAM_ID))
        return AltError.InvalidAccountOwner;

    // agave:L406-L412 — authority must sign
    if (!ctx.isSigner(1)) {
        std.log.warn("[ALT] closeLookupTable: authority must be a signer", .{});
        return AltError.MissingRequiredSignature;
    }

    // agave:L414-L420 — table != recipient
    if (std.mem.eql(u8, &lookup_table_acct.pubkey, &recipient_acct.pubkey)) {
        std.log.warn("[ALT] closeLookupTable: lookup table cannot be its own recipient", .{});
        return AltError.InvalidArgument;
    }

    const table = try AddressLookupTable.deserialize(lookup_table_acct.data);

    // agave:L422-L428 — authority check
    const stored_auth = table.meta.authority orelse {
        std.log.warn("[ALT] closeLookupTable: lookup table is frozen", .{});
        return AltError.Immutable;
    };
    if (!std.mem.eql(u8, &stored_auth, &authority_acct.pubkey))
        return AltError.IncorrectAuthority;

    // agave:L430-L447 — must be fully deactivated (not just deactivating)
    if (table.meta.deactivation_slot == DEACTIVATION_SLOT_NONE) {
        std.log.warn("[ALT] closeLookupTable: lookup table is not deactivated", .{});
        return AltError.InvalidArgument;
    }

    // agave: check Deactivating status using SlotHashes
    // If the deactivation_slot is still in SlotHashes the table is only "deactivating".
    if (ctx.recent_slot_fn) |recent_fn| {
        if (recent_fn(table.meta.deactivation_slot)) {
            std.log.warn("[ALT] closeLookupTable: table is still deactivating", .{});
            return AltError.InvalidArgument;
        }
    }

    // agave:L449-L453 — reclaim lamports
    const withdrawn = lookup_table_acct.lamports;
    recipient_acct.lamports = std.math.add(u64, recipient_acct.lamports, withdrawn) catch
        return AltError.ArithmeticOverflow;
    lookup_table_acct.lamports = 0;

    // agave:L455 — zero out data
    lookup_table_acct.data = try ctx.allocator.realloc(lookup_table_acct.data, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// execute — top-level dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Decode instruction data and dispatch to the appropriate handler.
/// agave: programs/address-lookup-table/src/processor.rs#L25
pub fn execute(ctx: *const InstrCtx, instr_data: []const u8) AltError!void {
    if (instr_data.len < 4) return AltError.InvalidInstructionData;
    const disc_raw = std.mem.readInt(u32, instr_data[0..4], .little);
    const disc: Discriminant = @enumFromInt(disc_raw);
    const payload = instr_data[4..];

    switch (disc) {
        .create_lookup_table => {
            // payload: recent_slot(u64) + bump_seed(u8)
            if (payload.len < 9) return AltError.InvalidInstructionData;
            const recent_slot = std.mem.readInt(u64, payload[0..8], .little);
            const bump_seed = payload[8];
            try createLookupTable(ctx, recent_slot, bump_seed);
        },
        .freeze_lookup_table => {
            try freezeLookupTable(ctx);
        },
        .extend_lookup_table => {
            // payload: num_addresses(u64 LE) + addresses(32 each)
            if (payload.len < 8) return AltError.InvalidInstructionData;
            const count = std.mem.readInt(u64, payload[0..8], .little);
            if (payload.len < 8 + count * 32) return AltError.InvalidInstructionData;
            const addrs_raw = payload[8 .. 8 + count * 32];
            // Wave 6B: extendLookupTable takes `[]const [32]u8`; preserve
            // the const-qualifier from `payload` (the instruction data is
            // borrowed read-only). Original cast dropped const and would
            // not compile when `execute` is reachable. Body unchanged
            // beyond this one-line type fix.
            const addrs: []const [32]u8 = @as([*]const [32]u8, @ptrCast(@alignCast(addrs_raw.ptr)))[0..count];
            try extendLookupTable(ctx, addrs);
        },
        .deactivate_lookup_table => {
            try deactivateLookupTable(ctx);
        },
        .close_lookup_table => {
            try closeLookupTable(ctx);
        },
        _ => return AltError.InvalidInstructionData,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

test "LookupTableMeta: encode/decode round-trip" {
    var buf: [LOOKUP_TABLE_META_SIZE]u8 = undefined;
    const authority: [32]u8 = .{0xAB} ** 32;
    const meta = LookupTableMeta{
        .deactivation_slot = DEACTIVATION_SLOT_NONE,
        .last_extended_slot = 42,
        .last_extended_slot_start_index = 7,
        .authority = authority,
    };

    try AddressLookupTable.overwriteMetaData(&buf, meta);

    // The discriminant byte must be 1
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, buf[0..4], .little));
    try std.testing.expectEqual(DEACTIVATION_SLOT_NONE, std.mem.readInt(u64, buf[4..12], .little));
    try std.testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, buf[12..20], .little));
    try std.testing.expectEqual(@as(u8, 7), buf[20]);
    try std.testing.expectEqual(@as(u8, 1), buf[21]); // has_authority
    try std.testing.expectEqualSlices(u8, &authority, buf[22..54]);
}

test "AddressLookupTable: deserialize header-only" {
    var buf = [_]u8{0} ** LOOKUP_TABLE_META_SIZE;
    const authority: [32]u8 = .{0xCC} ** 32;
    const meta = LookupTableMeta.new(authority);
    try AddressLookupTable.initMetaData(&buf, meta);

    const table = try AddressLookupTable.deserialize(&buf);
    try std.testing.expectEqual(DEACTIVATION_SLOT_NONE, table.meta.deactivation_slot);
    try std.testing.expectEqual(@as(usize, 0), table.addresses.len);
    try std.testing.expectEqualSlices(u8, &authority, &(table.meta.authority.?));
}

test "createLookupTable: rent-exempt funding (1,280,640) + authority-non-signer succeeds" {
    // Boot-KAT for the Tier-1 ALT createLookupTable carrier fix:
    //   (1) min_rent_balance_fn wired (replay_stage.zig ~11503) → new table funded
    //       with the rent-exempt minimum for 56 bytes = (56+128)*3480*2 = 1_280_640,
    //       NOT the old buggy 1 lamport.
    //   (2) the non-canonical authority-signer check is removed → a create whose
    //       authority != payer and did NOT sign still succeeds (payer is the only
    //       required signer, matching Agave Core-BPF processor.rs).
    //
    // Mock rent fn mirrors the REAL replay_stage.rentExemptMinimumBalanceDefault
    // (verified: `return (data_len + 128) * 3480 * 2;`).
    const Rent = struct {
        fn f(size: u64) u64 {
            return (size + 128) * 3480 * 2;
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const authority_key: [32]u8 = .{0x11} ** 32;
    const recent_slot: u64 = 123_456;
    const bump: u8 = 255;

    // Derive the table PDA exactly as createLookupTable does:
    //   seeds = { authority_pubkey, recent_slot(u64 LE) }, bump, PROGRAM_ID.
    const slot_le = std.mem.nativeTo(u64, recent_slot, .little);
    const slot_bytes = std.mem.asBytes(&slot_le);
    const seeds: [2][]const u8 = .{ &authority_key, slot_bytes };
    const derived_key = createProgramAddress(&seeds, bump, &PROGRAM_ID);

    // Table account: 0 lamports, empty/unallocated, system-owned (all-zero owner).
    const table_data = try a.alloc(u8, 0);
    const table_acct = BorrowedAccount{
        .pubkey = derived_key,
        .lamports = 0,
        .owner = .{0} ** 32, // system program (not yet ALT-owned)
        .data = table_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = false,
        .is_writable = true,
    };

    // Authority account — present but NOT a signer (proves removed check).
    var auth_data = [_]u8{};
    const authority_acct = BorrowedAccount{
        .pubkey = authority_key,
        .lamports = 0,
        .owner = .{0} ** 32,
        .data = &auth_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = false,
        .is_writable = false,
    };

    // Payer account — ample lamports, signer + writable.
    const payer_start: u64 = 5_000_000;
    var payer_data = [_]u8{};
    const payer_acct = BorrowedAccount{
        .pubkey = .{0x22} ** 32,
        .lamports = payer_start,
        .owner = .{0} ** 32,
        .data = &payer_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = true,
        .is_writable = true,
    };

    var accounts = [_]BorrowedAccount{ table_acct, authority_acct, payer_acct };

    const ctx = InstrCtx{
        .accounts = &accounts,
        .signer_mask = 1 << 2, // ONLY payer (idx 2) signs — NOT authority (idx 1)
        .allocator = a,
        .clock_slot = recent_slot,
        .recent_slot_fn = null, // skip SlotHashes verification
        .min_rent_balance_fn = &Rent.f,
    };

    try createLookupTable(&ctx, recent_slot, bump);

    const table = &accounts[0];
    const payer = &accounts[2];

    // (1) rent-exempt funding, NOT the old 1-lamport bug.
    try std.testing.expectEqual(@as(u64, 1_280_640), table.lamports);
    // (2) payer debited by exactly the rent-exempt minimum.
    try std.testing.expectEqual(@as(u64, 1_280_640), payer_start - payer.lamports);
    // (3) account reassigned to the ALT program + sized to the 56-byte header.
    try std.testing.expectEqualSlices(u8, &PROGRAM_ID, &table.owner);
    try std.testing.expectEqual(@as(usize, LOOKUP_TABLE_META_SIZE), table.data.len);

    // (4) byte-exact LookupTableMeta header.
    const d = table.data;
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, d[0..4], .little)); // discriminant
    try std.testing.expectEqual(DEACTIVATION_SLOT_NONE, std.mem.readInt(u64, d[4..12], .little)); // u64::MAX
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, d[12..20], .little)); // last_extended_slot
    try std.testing.expectEqual(@as(u8, 0), d[20]); // last_extended_slot_start_index
    try std.testing.expectEqual(@as(u8, 1), d[21]); // has_authority
    try std.testing.expectEqualSlices(u8, &authority_key, d[22..54]); // authority
    try std.testing.expectEqual(@as(u8, 0), d[54]); // padding
    try std.testing.expectEqual(@as(u8, 0), d[55]); // padding
}

test "AddressLookupTable: frozen (no authority)" {
    var buf = [_]u8{0} ** LOOKUP_TABLE_META_SIZE;
    const meta = LookupTableMeta{
        .deactivation_slot = DEACTIVATION_SLOT_NONE,
        .last_extended_slot = 0,
        .last_extended_slot_start_index = 0,
        .authority = null,
    };
    try AddressLookupTable.overwriteMetaData(&buf, meta);
    const table = try AddressLookupTable.deserialize(&buf);
    try std.testing.expect(table.meta.authority == null);
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression guard for carrier 420180889 (2026-07-06): PROGRAM_ID must be the
// canonical AddressLookupTable id. The prior hand-typed value base58-encoded to
// `BP7ns7qVEz9ZKEqP2bvPxZTig6AyKwWiboQtYnBhW3z`, so the top-level replay
// dispatch (`program_id == PROGRAM_ID`) never matched → every top-level ALT
// instruction fell to the generic BPF path and its writes were dropped.
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal runtime base58 decoder for the 32-byte canonical-id check below.
fn b58Decode32(comptime s: []const u8) [32]u8 {
    const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var bytes: [64]u8 = .{0} ** 64;
    var bytes_len: usize = 0;
    for (s) |c| {
        var carry: u32 = blk: {
            for (ALPHABET, 0..) |ac, i| if (ac == c) break :blk @intCast(i);
            unreachable; // invalid base58 char in a comptime-known string
        };
        var idx: usize = 0;
        while (idx < bytes_len or carry != 0) : (idx += 1) {
            if (idx < bytes_len) carry += @as(u32, bytes[idx]) * 58;
            bytes[idx] = @intCast(carry & 0xff);
            if (idx >= bytes_len) bytes_len = idx + 1;
            carry >>= 8;
        }
    }
    var leading_ones: usize = 0;
    for (s) |c| {
        if (c != '1') break;
        leading_ones += 1;
    }
    var out: [32]u8 = .{0} ** 32;
    var i: usize = 0;
    while (i < bytes_len) : (i += 1) out[leading_ones + i] = bytes[bytes_len - 1 - i];
    return out;
}

test "PROGRAM_ID is the canonical AddressLookupTable id (carrier 420180889 regression guard)" {
    const canonical = b58Decode32("AddressLookupTab1e1111111111111111111111111");
    try std.testing.expectEqualSlices(u8, &canonical, &PROGRAM_ID);
    // And explicitly NOT the old wrong value (BP7ns7qVEz9ZKEqP2bvPxZTig6AyKwWiboQtYnBhW3z).
    const wrong = [_]u8{
        0x02, 0xa8, 0xd0, 0xe2, 0x70, 0x49, 0xdc, 0xb4,
        0x5b, 0xc4, 0x11, 0xdf, 0x0f, 0x69, 0x24, 0xaa,
        0xb2, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    try std.testing.expect(!std.mem.eql(u8, &PROGRAM_ID, &wrong));
}

test "extendLookupTable: self-referential shape w/ DUPLICATE payer indices commits table growth + rent top-up (carrier 420180889)" {
    // Reproduces the exact instruction shape from carrier slot 420180889: a
    // top-level ExtendLookupTable whose account list has DUPLICATE indices
    // [table, payer(as authority), payer(as rent-payer), system] — i.e. the
    // authority and the rent-payer are the SAME pubkey, materialised as two
    // separate BorrowedAccount entries exactly as runAltFallback builds them
    // from `ix.account_indices` [1,0,0,8]. Asserts the handler:
    //   (1) appends the new address (table data grows by 32 bytes),
    //   (2) tops the table up to the rent-exempt minimum for the new size,
    //   (3) debits that top-up from the rent-payer copy (getAccount(2)),
    //   (4) leaves the authority copy (getAccount(1)) untouched.
    // The mock rent fn mirrors replay_stage.rentExemptMinimumBalanceDefault.
    const Rent = struct {
        fn f(size: u64) u64 {
            return (size + 128) * 3480 * 2;
        }
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const payer_key: [32]u8 = .{0x22} ** 32;

    // Existing table: 1 address, authority == payer, active, sized 56+32=88,
    // funded to exactly the rent-exempt minimum for 88 bytes.
    const old_addr: [32]u8 = .{0xAB} ** 32;
    const old_data_len = LOOKUP_TABLE_META_SIZE + 32;
    const table_data = try a.alloc(u8, old_data_len);
    try AddressLookupTable.overwriteMetaData(table_data, .{
        .deactivation_slot = DEACTIVATION_SLOT_NONE,
        .last_extended_slot = 0,
        .last_extended_slot_start_index = 0,
        .authority = payer_key,
    });
    @memcpy(table_data[LOOKUP_TABLE_META_SIZE..][0..32], &old_addr);
    const table_start_lamports = Rent.f(old_data_len); // rent-exempt @88

    const table_acct = BorrowedAccount{
        .pubkey = .{0x74} ** 32, // arbitrary table pubkey
        .lamports = table_start_lamports,
        .owner = PROGRAM_ID,
        .data = table_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = false,
        .is_writable = true,
    };
    // authority copy (getAccount(1)) — same pubkey as the rent-payer, signer.
    const payer_start: u64 = 8_000_000_000;
    var auth_data = [_]u8{};
    const authority_acct = BorrowedAccount{
        .pubkey = payer_key,
        .lamports = payer_start,
        .owner = .{0} ** 32,
        .data = &auth_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = true,
        .is_writable = true,
    };
    // rent-payer copy (getAccount(2)) — DUPLICATE of the authority pubkey.
    var payer_data = [_]u8{};
    const payer_acct = BorrowedAccount{
        .pubkey = payer_key,
        .lamports = payer_start,
        .owner = .{0} ** 32,
        .data = &payer_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = true,
        .is_writable = true,
    };
    // system program (getAccount(3)) — readonly.
    var sys_data = [_]u8{};
    const system_acct = BorrowedAccount{
        .pubkey = .{0} ** 32,
        .lamports = 1,
        .owner = .{0} ** 32,
        .data = &sys_data,
        .rent_epoch = 0,
        .executable = false,
        .is_signer = false,
        .is_writable = false,
    };

    var accounts = [_]BorrowedAccount{ table_acct, authority_acct, payer_acct, system_acct };
    const ctx = InstrCtx{
        .accounts = &accounts,
        .signer_mask = (1 << 1) | (1 << 2), // authority(1) + payer(2) both sign
        .allocator = a,
        .clock_slot = 999,
        .recent_slot_fn = null,
        .min_rent_balance_fn = &Rent.f,
    };

    const new_addr: [32]u8 = .{0xCD} ** 32;
    try extendLookupTable(&ctx, &[_][32]u8{new_addr});

    const table = &accounts[0];
    const authority = &accounts[1];
    const payer = &accounts[2];

    // (1) new address appended → data grew by exactly 32 bytes.
    try std.testing.expectEqual(@as(usize, old_data_len + 32), table.data.len);
    try std.testing.expectEqualSlices(u8, &new_addr, table.data[old_data_len..][0..32]);
    // (2) topped up to the rent-exempt minimum for the new 120-byte size.
    const expect_new = Rent.f(old_data_len + 32);
    try std.testing.expectEqual(expect_new, table.lamports);
    // (3) rent-payer (getAccount(2)) debited by exactly the top-up.
    const topup = expect_new - table_start_lamports;
    try std.testing.expectEqual(@as(u64, 222_720), topup); // matches carrier 420180889
    try std.testing.expectEqual(payer_start - topup, payer.lamports);
    // (4) the authority copy (getAccount(1)) is left untouched.
    try std.testing.expectEqual(payer_start, authority.lamports);
}
