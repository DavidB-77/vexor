//! voteforge, stage 2 — account-I/O layer: borrow-only-what's-touched (as in Firedancer)
//! account model over Vexor's flat `[]u8 + lamports + owner` account world
//! (VEXOR-VOTE-REWRITE-SCOPE-2026-07-10.md §E Stage 2, §F.1 layer 2, executive
//! summary lever #2).
//!
//! @prov:voteforge.borrowed-account-derivation — derived DIRECTLY from
//! Agave 4.2.0-beta.0's `BorrowCounter` (transaction_accounts.rs) and
//! `BorrowedAccount` (transaction_context.rs) semantics; full upstream line
//! citations in PROVENANCE.md. `BorrowCounter` below is a line-for-line Zig
//! port: `is_writing`/`is_reading`/`try_borrow`/`try_borrow_mut`/
//! `release_borrow`/`release_borrow_mut`, incl. the "shared borrows stack,
//! exclusive borrow is alone" semantics proven by that file's own `#[test]`
//! cases. `BorrowedAccount` was also carried almost verbatim into the (since
//! removed, vote-rewrite Stage 8) transplant's `borrowed_account.zig`, itself
//! cited per-method against the same Agave lines: `check_data_is_mutable`,
//! `check_can_set_data_length`, `set_lamports`/`add_lamports`/
//! `subtract_lamports`, `set_data_length`/`set_data_from_slice`,
//! `set_owner`, `set_executable`.
//! Shaped like Firedancer's `fd_borrowed_account_t` (acquire-by-instruction-
//! account-index, only the accounts a given instruction names — see scope doc
//! §C.2) rather than Sig's shim, which borrows into a `TransactionContext`
//! pre-populated with EVERY transaction account (the seam's current
//! `instruction_dispatch.zig:3316-3410`, lever #2's target).
//!
//! **Lever #2 is expressed in the API shape itself**: `AccountTable` is
//! constructed directly from the vote instruction's own `AccountMeta` list —
//! there is no constructor that takes a whole transaction's accounts, so a
//! caller physically cannot materialize more than the instruction touches.
//! Whichever future layer resolves pubkeys to storage (Stage 3/4's dispatch,
//! today's `executeVoteViaSig`'s `chainLookup`) supplies exactly the K
//! `AccountRecord`s (K = a vote ix's account count, typically 2-4) the
//! instruction's `account_metas` name — never the full `ptx.num_accounts`.
//!
//! NOT derived from Sig: this file has ZERO import of `sigvote` — voteforge/
//! is independent of the Sig transplant it replaced (deleted 2026-07-12,
//! vote-rewrite Stage 8). `kat_account_io.zig` no longer carries a `sigvote`
//! differential leg. (Historically the transplant served as a
//! regression oracle, per the scope doc's "Sig = differential oracle during
//! migration, not what the rewrite derives from" methodology note.)
//!
//! Design as Stage 3 will consume it (§F.1 layer 3 = pure state-transition
//! functions operating on borrowed accounts): a state-transition function
//! takes `*Borrow` handles, never raw `[]u8` — every read/write goes through
//! a checked accessor, exactly mirroring how `vote_state/mod.rs`'s functions
//! are written against Agave's own `BorrowedAccount`, not raw bytes.

const std = @import("std");

/// @prov:voteforge.max-permitted-data-length — carried into the
/// transplant's shim at `runtime/lib.zig` `program.system.*`. Vote accounts
/// never approach either bound (fixed 3762B, Stage 1 codec's stale-tail
/// contract never resizes in practice) — kept for parity with Agave's own
/// `BorrowedAccount::set_data_length` gate, in case a future instruction ever
/// needs it.
pub const MAX_PERMITTED_DATA_LENGTH: usize = 10 * 1024 * 1024;
pub const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 = 10 * 1024 * 1024 * 2;

/// Account-I/O-layer error taxonomy — a self-contained subset of Agave's
/// `InstructionError` (mod.rs), independent of `sigvote`'s own copy. Callers
/// one layer up (Stage 4 dispatch) map these 1:1 onto whatever error type the
/// dispatch layer ultimately returns to the runtime.
/// @prov:voteforge.account-io-errors — each variant below mirrors a specific
/// Agave check; full per-variant upstream file:line citations in
/// PROVENANCE.md.
pub const AccountIoError = error{
    /// double-borrow (mutable vs. mutable, mutable vs. shared, or i8 counter
    /// overflow).
    AccountBorrowFailed,
    /// missing/out-of-range account-meta index.
    MissingAccount,
    /// vote_processor.rs's per-handler `instruction_context.check_required_signer`-
    /// class checks (via `InstructionInfo::is_pubkey_signer` in the transplant
    /// shim) — surfaced here as a borrow-level convenience since the signer
    /// flag is bound into the same `AccountMeta` the borrow already carries.
    MissingRequiredSignature,
    /// check_data_is_mutable (not writable)
    ReadonlyDataModified,
    /// check_data_is_mutable (not owned)
    ExternalAccountDataModified,
    /// set_lamports (spend on non-owned)
    ExternalAccountLamportSpend,
    /// set_lamports (not writable)
    ReadonlyLamportChange,
    /// set_lamports/add/subtract overflow
    ProgramArithmeticOverflow,
    /// check_can_set_data_length (size changed, not owned)
    AccountDataSizeChanged,
    /// check_can_set_data_length (over MAX_PERMITTED_DATA_LENGTH)
    InvalidRealloc,
    /// check_can_set_data_length (tx-wide realloc budget)
    MaxAccountsDataAllocationsExceeded,
    /// set_owner (not writable / not owned / not zeroed)
    ModifiedProgramId,
    /// set_executable (rent)
    ExecutableAccountNotRentExempt,
    /// set_executable (not owned / not writable)
    ExecutableModified,
    /// serializeIntoAccountData (buffer too small)
    AccountDataTooSmall,
    /// InstructionContext::get_sysvar_with_account_check (pubkey mismatch)
    InvalidArgument,
};

/// One entry of a vote instruction's `account_metas` (mirrors the seam's
/// `sv.InstructionInfo.AccountMeta` / Agave's `InstructionAccount`) — pubkey +
/// signer/writable flags AS SEEN BY THIS INSTRUCTION, not the account's
/// intrinsic state.
pub const AccountMeta = struct {
    pubkey: [32]u8,
    is_signer: bool,
    is_writable: bool,
};

/// @prov:voteforge.borrow-counter — a line-for-line port of the i8-counter
/// RefCell-equivalent: positive = N concurrent shared (read) borrows,
/// negative (always exactly -1) = one exclusive (write) borrow, zero = free.
/// Shared borrows may stack; an exclusive borrow may not coexist with ANY
/// other borrow, shared or exclusive.
pub const BorrowCounter = struct {
    counter: i8 = 0,

    pub fn isWriting(self: BorrowCounter) bool {
        return self.counter < 0;
    }
    pub fn isReading(self: BorrowCounter) bool {
        return self.counter > 0;
    }

    /// @prov:voteforge.borrow-counter try_borrow
    pub fn tryBorrow(self: *BorrowCounter) AccountIoError!void {
        if (self.isWriting()) return error.AccountBorrowFailed;
        self.counter = std.math.add(i8, self.counter, 1) catch return error.AccountBorrowFailed;
    }

    /// @prov:voteforge.borrow-counter try_borrow_mut
    pub fn tryBorrowMut(self: *BorrowCounter) AccountIoError!void {
        if (self.isWriting() or self.isReading()) return error.AccountBorrowFailed;
        self.counter -|= 1; // known-zero here, so this always lands on -1
    }

    /// @prov:voteforge.borrow-counter release_borrow (saturating so a bug can't underflow)
    pub fn releaseBorrow(self: *BorrowCounter) void {
        self.counter -|= 1;
    }

    /// @prov:voteforge.borrow-counter release_borrow_mut
    pub fn releaseBorrowMut(self: *BorrowCounter) void {
        self.counter +|= 1;
    }
};

/// The mutable backing storage a borrow resolves against. CALLER-OWNED: a
/// future Stage 3/4 dispatch layer allocates/looks these up (e.g. via the
/// seam's own `chainLookup` pattern) and hands `AccountTable` only the
/// records the current instruction actually names — this is where lever #2's
/// "borrow only what's touched" is realized (no per-tx materialization here).
///
/// `data` is a caller-owned mutable slice. For the dominant vote-account case
/// this is the account's FULL FIXED-SIZE buffer (3762B) — Stage 1's codec
/// contract (`vote_codec.zig` header) already guarantees `serialize()` only
/// ever writes the serialized prefix, so mutating THIS SAME buffer in place
/// via a `Borrow.dataMut()` + `codec.serialize()` call is a genuine zero-copy
/// mutation, not a full-account duplicate the way the current seam's
/// `alloc.dupe` (`instruction_dispatch.zig:3382-3387`) is.
pub const AccountRecord = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    executable: bool,
    rent_epoch: u64,
    data: []u8,
    borrow: BorrowCounter = .{},

    pub fn initEmpty(pubkey: [32]u8) AccountRecord {
        return .{
            .pubkey = pubkey,
            .lamports = 0,
            .owner = [_]u8{0} ** 32,
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = &[_]u8{},
        };
    }
};

const BorrowKind = enum { shared, exclusive };

/// A checked handle onto one `AccountRecord`, scoped to the instruction that
/// borrowed it (`meta.is_signer`/`meta.is_writable` + the table's
/// `program_id`) — the Zig-idiom equivalent of Agave's `AccountRef`/
/// `AccountRefMut` (transaction_accounts.rs:550-589) fused into one type
/// (Zig has no borrow checker to enforce the Rust split at compile time, so
/// `kind` gates write-methods at runtime instead — see `checkDataIsMutable`/
/// `setLamports`, which additionally reject a `.shared` borrow attempting a
/// mutation even where the account itself would otherwise permit it).
///
/// MUST be released exactly once (`release()`) — mirrors Rust's `Drop`;
/// Zig has no destructor, so callers use `defer borrow.release()` at the
/// call site, exactly like the transplant's own `BorrowedAccount.release()`
/// convention (`borrowed_account.zig:52-54`).
pub const Borrow = struct {
    table: *AccountTable,
    index: usize,
    kind: BorrowKind,
    released: bool = false,

    fn rec(self: *const Borrow) *AccountRecord {
        return &self.table.records[self.index];
    }
    fn meta(self: *const Borrow) AccountMeta {
        return self.table.metas[self.index];
    }

    pub fn release(self: *Borrow) void {
        if (self.released) return;
        switch (self.kind) {
            .shared => self.rec().borrow.releaseBorrow(),
            .exclusive => self.rec().borrow.releaseBorrowMut(),
        }
        self.released = true;
    }

    pub fn pubkey(self: *const Borrow) [32]u8 {
        return self.rec().pubkey;
    }
    pub fn lamports(self: *const Borrow) u64 {
        return self.rec().lamports;
    }
    pub fn owner(self: *const Borrow) [32]u8 {
        return self.rec().owner;
    }
    pub fn executable(self: *const Borrow) bool {
        return self.rec().executable;
    }
    /// Rent-epoch handling: exposed read-only and left UNTOUCHED by every
    /// mutation helper below (lamports/data/owner/executable setters never
    /// write `rent_epoch`) — matching Agave, where `rent_epoch` is
    /// runtime-managed at commit time, never a program-writable field via
    /// `BorrowedAccount`. `kat_account_io.zig` pins this invariant directly
    /// (rent_epoch survives a lamports + data mutation byte-for-byte).
    pub fn rentEpoch(self: *const Borrow) u64 {
        return self.rec().rent_epoch;
    }
    pub fn isSigner(self: *const Borrow) bool {
        return self.meta().is_signer;
    }
    pub fn isWritable(self: *const Borrow) bool {
        return self.meta().is_writable;
    }
    pub fn dataConst(self: *const Borrow) []const u8 {
        return self.rec().data;
    }

    /// @prov:voteforge.borrowed-account-methods is_owned_by_current_program
    pub fn isOwnedByCurrentProgram(self: *const Borrow) bool {
        return std.mem.eql(u8, &self.rec().owner, &self.table.program_id);
    }

    /// Convenience gate on `AccountMeta.is_signer` — see `AccountIoError.MissingRequiredSignature` doc.
    pub fn requireSigner(self: *const Borrow) AccountIoError!void {
        if (!self.isSigner()) return error.MissingRequiredSignature;
    }

    /// @prov:voteforge.borrowed-account-methods check_data_is_mutable
    pub fn checkDataIsMutable(self: *const Borrow) ?AccountIoError {
        if (self.kind != .exclusive) return error.ReadonlyDataModified;
        if (!self.isWritable()) return error.ReadonlyDataModified;
        if (!self.isOwnedByCurrentProgram()) return error.ExternalAccountDataModified;
        return null;
    }

    /// @prov:voteforge.borrowed-account-methods mutable_account_data
    pub fn dataMut(self: *Borrow) AccountIoError![]u8 {
        if (self.checkDataIsMutable()) |e| return e;
        return self.rec().data;
    }

    /// @prov:voteforge.borrowed-account-methods set_lamports
    pub fn setLamports(self: *Borrow, new_lamports: u64) AccountIoError!void {
        const r = self.rec();
        if (new_lamports < r.lamports and !self.isOwnedByCurrentProgram())
            return error.ExternalAccountLamportSpend;
        if (self.kind != .exclusive or !self.isWritable())
            return error.ReadonlyLamportChange;
        if (new_lamports == r.lamports) return;

        self.table.accounts_lamport_delta = std.math.add(
            i128,
            self.table.accounts_lamport_delta,
            @as(i128, new_lamports) - @as(i128, r.lamports),
        ) catch return error.ProgramArithmeticOverflow;
        r.lamports = new_lamports;
    }

    /// @prov:voteforge.borrowed-account-methods add_lamports
    pub fn addLamports(self: *Borrow, amount: u64) AccountIoError!void {
        const nl = std.math.add(u64, self.rec().lamports, amount) catch return error.ProgramArithmeticOverflow;
        try self.setLamports(nl);
    }

    /// @prov:voteforge.borrowed-account-methods subtract_lamports
    pub fn subtractLamports(self: *Borrow, amount: u64) AccountIoError!void {
        const nl = std.math.sub(u64, self.rec().lamports, amount) catch return error.ProgramArithmeticOverflow;
        try self.setLamports(nl);
    }

    /// @prov:voteforge.borrowed-account-methods check_can_set_data_length
    pub fn checkCanSetDataLength(self: *const Borrow, new_length: usize) ?AccountIoError {
        const old_length = self.rec().data.len;
        if (new_length != old_length and !self.isOwnedByCurrentProgram())
            return error.AccountDataSizeChanged;
        if (new_length > MAX_PERMITTED_DATA_LENGTH)
            return error.InvalidRealloc;

        const length_signed: i64 = @intCast(new_length);
        const old_length_signed: i64 = @intCast(old_length);
        const new_delta = self.table.accounts_resize_delta +| (length_signed -| old_length_signed);
        if (new_delta > MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION)
            return error.MaxAccountsDataAllocationsExceeded;

        return self.checkDataIsMutable();
    }

    /// @prov:voteforge.borrowed-account-methods set_data_length. NOTE: vote
    /// accounts never exercise this path in practice (Stage 1 codec's
    /// fixed-buffer, stale-tail contract) — kept for API parity / future
    /// instruction needs, allocator-based exactly like `AccountSharedData.resize`
    /// (`native/sigvote/runtime/AccountSharedData.zig:73-89`).
    pub fn setDataLength(
        self: *Borrow,
        allocator: std.mem.Allocator,
        new_length: usize,
    ) (std.mem.Allocator.Error || AccountIoError)!void {
        if (self.checkCanSetDataLength(new_length)) |e| return e;
        const r = self.rec();
        if (r.data.len == new_length) return;

        const old_length_signed: i64 = @intCast(r.data.len);
        const new_length_signed: i64 = @intCast(new_length);
        self.table.accounts_resize_delta +|= new_length_signed -| old_length_signed;
        try resizeInPlace(allocator, &r.data, new_length);
    }

    /// @prov:voteforge.borrowed-account-methods set_data_from_slice
    pub fn setDataFromSlice(
        self: *Borrow,
        allocator: std.mem.Allocator,
        data: []const u8,
    ) (std.mem.Allocator.Error || AccountIoError)!void {
        if (self.checkCanSetDataLength(data.len)) |e| return e;
        const r = self.rec();
        const old_length_signed: i64 = @intCast(r.data.len);
        const new_length_signed: i64 = @intCast(data.len);
        self.table.accounts_resize_delta +|= new_length_signed -| old_length_signed;
        try resizeInPlace(allocator, &r.data, data.len);
        @memcpy(r.data[0..data.len], data);
    }

    /// @prov:voteforge.borrowed-account-methods set_owner
    pub fn setOwner(self: *Borrow, new_owner: [32]u8) AccountIoError!void {
        const r = self.rec();
        if (self.kind != .exclusive or
            !self.isWritable() or
            !self.isOwnedByCurrentProgram() or
            !std.mem.allEqual(u8, r.data, 0))
        {
            return error.ModifiedProgramId;
        }
        r.owner = new_owner;
    }

    /// @prov:voteforge.borrowed-account-methods set_executable. `is_rent_exempt` is
    /// supplied by the caller (account_io stays Rent-sysvar-agnostic per
    /// §F.1's "version- and instruction-agnostic" layer-2 design — the Rent
    /// check itself belongs to whichever sysvar/state layer is live at call
    /// time, TowerBFT today, potentially something else post-Alpenglow).
    pub fn setExecutable(self: *Borrow, want_executable: bool, is_rent_exempt: bool) AccountIoError!void {
        if (!is_rent_exempt) return error.ExecutableAccountNotRentExempt;
        if (self.kind != .exclusive or !self.isOwnedByCurrentProgram() or !self.isWritable())
            return error.ExecutableModified;
        self.rec().executable = want_executable;
    }
};

fn resizeInPlace(allocator: std.mem.Allocator, data: *[]u8, new_size: usize) std.mem.Allocator.Error!void {
    if (allocator.resize(data.*, new_size)) {
        const old_len = data.len;
        data.len = new_size;
        @memset(data.*[@min(old_len, data.len)..], 0);
    } else {
        const new_memory = try allocator.alloc(u8, new_size);
        @memset(new_memory, 0);
        @memcpy(new_memory[0..@min(data.len, new_size)], data.*[0..@min(data.len, new_size)]);
        allocator.free(data.*);
        data.* = new_memory;
    }
}

/// Borrow-only-the-instruction's-accounts table (lever #2's realization —
/// see file header). `metas`/`records` are PARALLEL, caller-owned slices,
/// one entry per instruction account-meta — never per transaction account.
/// Transaction-scoped deltas (`accounts_resize_delta`/`accounts_lamport_delta`)
/// mirror Agave's `TransactionContext` fields of the same name.
/// @prov:voteforge.account-table-borrow — at the SAME scope: one
/// `AccountTable` should back exactly one instruction's execution, matching
/// how the seam constructs one `TransactionContext` per `executeVoteViaSig`
/// call today.
pub const AccountTable = struct {
    program_id: [32]u8,
    metas: []const AccountMeta,
    records: []AccountRecord,
    accounts_resize_delta: i64 = 0,
    accounts_lamport_delta: i128 = 0,

    pub fn init(program_id: [32]u8, metas: []const AccountMeta, records: []AccountRecord) AccountIoError!AccountTable {
        if (metas.len != records.len) return error.MissingAccount;
        return .{ .program_id = program_id, .metas = metas, .records = records };
    }

    fn checkIndex(self: *const AccountTable, index: usize) AccountIoError!void {
        if (index >= self.records.len) return error.MissingAccount;
    }

    /// @prov:voteforge.account-table-borrow try_borrow (shared/read)
    pub fn borrowConst(self: *AccountTable, index: usize) AccountIoError!Borrow {
        try self.checkIndex(index);
        try self.records[index].borrow.tryBorrow();
        return .{ .table = self, .index = index, .kind = .shared };
    }

    /// @prov:voteforge.account-table-borrow try_borrow_mut (exclusive/write)
    pub fn borrowMut(self: *AccountTable, index: usize) AccountIoError!Borrow {
        try self.checkIndex(index);
        try self.records[index].borrow.tryBorrowMut();
        return .{ .table = self, .index = index, .kind = .exclusive };
    }

    /// Resolve an instruction account-meta by pubkey (linear scan — vote ixs
    /// never carry more than a handful of accounts, matching FD's
    /// `fd_borrowed_account_t` acquire-by-name pattern rather than a hash
    /// lookup built for hundreds of accounts).
    pub fn findByPubkey(self: *const AccountTable, key: [32]u8) ?usize {
        for (self.metas, 0..) |m, i| {
            if (std.mem.eql(u8, &m.pubkey, &key)) return i;
        }
        return null;
    }

    /// @prov:voteforge.account-table-borrow get_sysvar_with_account_check — the
    /// ACCOUNT-CHECK half only (does the account at this instruction index
    /// carry the expected sysvar pubkey). Deliberately does NOT deserialize a
    /// sysvar value: per §F.1, sysvar semantics belong to the dispatch/sysvar-
    /// cache layer, not account-I/O; this layer only certifies "the caller
    /// named the right account at the right slot," matching the account-level
    /// half of Agave's own check before it hands off to `sysvar_cache.get`.
    pub fn checkSysvarId(self: *const AccountTable, index: usize, expected_id: [32]u8) AccountIoError!void {
        try self.checkIndex(index);
        if (!std.mem.eql(u8, &self.metas[index].pubkey, &expected_id))
            return error.InvalidArgument;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Self-tests — borrow/lamport/data-mutability semantics independent of any
// fixture (the composition KAT lives in kat_account_io.zig). These pin the
// BorrowCounter port itself.
// ─────────────────────────────────────────────────────────────────────────────

const test_program_id: [32]u8 = [_]u8{9} ** 32;

fn testRecord(owner: [32]u8, lamports: u64, data: []u8) AccountRecord {
    return .{
        .pubkey = [_]u8{1} ** 32,
        .lamports = lamports,
        .owner = owner,
        .executable = false,
        .rent_epoch = 7,
        .data = data,
    };
}

test "BorrowCounter: shared borrows stack, exclusive is alone (agave transaction_accounts.rs:620-740 shape)" {
    var bc = BorrowCounter{};
    try bc.tryBorrow();
    try bc.tryBorrow();
    try std.testing.expectError(error.AccountBorrowFailed, bc.tryBorrowMut());
    bc.releaseBorrow();
    try std.testing.expectError(error.AccountBorrowFailed, bc.tryBorrowMut());
    bc.releaseBorrow();
    try bc.tryBorrowMut();
    try std.testing.expectError(error.AccountBorrowFailed, bc.tryBorrow());
    try std.testing.expectError(error.AccountBorrowFailed, bc.tryBorrowMut());
    bc.releaseBorrowMut();
    try bc.tryBorrow();
}

test "AccountTable.borrowMut: double-borrow of the same index rejected" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b1 = try table.borrowMut(0);
    try std.testing.expectError(error.AccountBorrowFailed, table.borrowMut(0));
    try std.testing.expectError(error.AccountBorrowFailed, table.borrowConst(0));
    b1.release();
    var b2 = try table.borrowMut(0);
    b2.release();
}

test "AccountTable.borrowConst: concurrent shared borrows of the same index allowed" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = false, .is_writable = false }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b1 = try table.borrowConst(0);
    var b2 = try table.borrowConst(0);
    b1.release();
    b2.release();
}

test "Borrow.checkDataIsMutable: readonly-write rejected" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = false }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectEqual(@as(?AccountIoError, error.ReadonlyDataModified), b.checkDataIsMutable());
    try std.testing.expectError(error.ReadonlyDataModified, b.dataMut());
}

test "Borrow.checkDataIsMutable: shared (const) borrow can never mutate, even if writable+owned" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowConst(0);
    defer b.release();
    try std.testing.expectError(error.ReadonlyDataModified, b.dataMut());
}

test "Borrow.checkDataIsMutable: externally-owned account rejected even when writable" {
    var data = [_]u8{0} ** 8;
    const other_owner: [32]u8 = [_]u8{2} ** 32;
    var records = [_]AccountRecord{testRecord(other_owner, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.ExternalAccountDataModified, b.dataMut());
}

test "Borrow.requireSigner: missing-signer rejected" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = false, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.MissingRequiredSignature, b.requireSigner());
}

test "Borrow.setLamports/addLamports/subtractLamports: overflow and underflow rejected" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.ProgramArithmeticOverflow, b.addLamports(std.math.maxInt(u64)));
    try std.testing.expectError(error.ProgramArithmeticOverflow, b.subtractLamports(200));
    try b.setLamports(250);
    try std.testing.expectEqual(@as(u64, 250), b.lamports());
    try std.testing.expectEqual(@as(i128, 150), table.accounts_lamport_delta);
}

test "Borrow.setLamports: external-owner spend-down rejected, top-up allowed" {
    var data = [_]u8{0} ** 8;
    const other_owner: [32]u8 = [_]u8{2} ** 32;
    var records = [_]AccountRecord{testRecord(other_owner, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = false, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.ExternalAccountLamportSpend, b.setLamports(50));
    try b.setLamports(150); // top-up is fine even on an externally-owned account
    try std.testing.expectEqual(@as(u64, 150), b.lamports());
}

test "Borrow.rentEpoch: unchanged across lamport + data mutation" {
    var data = [_]u8{0xAB} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectEqual(@as(u64, 7), b.rentEpoch());
    try b.setLamports(500);
    const d = try b.dataMut();
    d[0] = 0xFF;
    try std.testing.expectEqual(@as(u64, 7), b.rentEpoch());
}

test "AccountTable.checkSysvarId: match accepted, mismatch rejected" {
    var data = [_]u8{0} ** 8;
    const clock_id: [32]u8 = [_]u8{0xC1} ** 32;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = clock_id, .is_signer = false, .is_writable = false }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    try table.checkSysvarId(0, clock_id);
    try std.testing.expectError(error.InvalidArgument, table.checkSysvarId(0, [_]u8{0xC2} ** 32));
    try std.testing.expectError(error.MissingAccount, table.checkSysvarId(1, clock_id));
}

test "AccountTable.findByPubkey: resolves instruction account index by key" {
    var data = [_]u8{0} ** 8;
    var data2 = [_]u8{0} ** 8;
    var records = [_]AccountRecord{ testRecord(test_program_id, 100, &data), testRecord(test_program_id, 200, &data2) };
    const key0: [32]u8 = [_]u8{1} ** 32;
    const key1: [32]u8 = [_]u8{2} ** 32;
    const metas = [_]AccountMeta{
        .{ .pubkey = key0, .is_signer = true, .is_writable = true },
        .{ .pubkey = key1, .is_signer = false, .is_writable = false },
    };
    var table = try AccountTable.init(test_program_id, &metas, &records);
    try std.testing.expectEqual(@as(?usize, 1), table.findByPubkey(key1));
    try std.testing.expectEqual(@as(?usize, null), table.findByPubkey([_]u8{9} ** 32));
}

test "Borrow.setOwner: rejects unless writable+owned+zeroed data; accepts on zeroed" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    const new_owner: [32]u8 = [_]u8{5} ** 32;
    try b.setOwner(new_owner);
    try std.testing.expectEqualSlices(u8, &new_owner, &b.owner());
}

test "Borrow.setOwner: non-zeroed data rejected" {
    var data = [_]u8{0xFF} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.ModifiedProgramId, b.setOwner([_]u8{5} ** 32));
}

test "Borrow.setExecutable: not-rent-exempt rejected" {
    var data = [_]u8{0} ** 8;
    var records = [_]AccountRecord{testRecord(test_program_id, 100, &data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    defer b.release();
    try std.testing.expectError(error.ExecutableAccountNotRentExempt, b.setExecutable(true, false));
    try b.setExecutable(true, true);
    try std.testing.expect(b.executable());
}

test "Borrow.setDataLength: grows in place, preserves prefix, zero-fills tail" {
    const alloc = std.testing.allocator;
    const data = try alloc.dupe(u8, &[_]u8{ 1, 2, 3, 4 });
    var records = [_]AccountRecord{testRecord(test_program_id, 100, data)};
    const metas = [_]AccountMeta{.{ .pubkey = [_]u8{1} ** 32, .is_signer = true, .is_writable = true }};
    var table = try AccountTable.init(test_program_id, &metas, &records);

    var b = try table.borrowMut(0);
    try b.setDataLength(alloc, 8);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 0, 0, 0, 0 }, b.dataConst());
    try std.testing.expectEqual(@as(i64, 4), table.accounts_resize_delta);
    b.release();
    alloc.free(records[0].data);
}
