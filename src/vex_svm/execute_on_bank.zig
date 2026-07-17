//! SB-1 (parity backlog, shared blocker — execute half): canonical `executeOnBank`.
//!
//! RPC simulateTransaction + the block producer share ONE engine: load a tx's accounts, execute every
//! instruction against the existing per-instruction dispatch, collect {err, logs, units_consumed,
//! return_data, post_accounts}, and either DISCARD the writes (simulate) or COMMIT them (produce).
//! `simulate == produce minus the final commit`. Design is RULE#15-canonical vs Agave
//! `Bank::simulate_transaction` (runtime/src/bank.rs:3378-3536) — see
//! SB1-EXECUTE-HALF-INTEGRATION-PLAN-2026-06-13.md and memory
//! sb1-executeonbank-canonical-spec-2026-06-13.
//!
//! This file lands the FOUNDATION: the canonical result/option types + the local account OVERLAY (the
//! discard primitive). The tx-loop that drives the per-instruction engine (v2_dispatch) + the CU meter
//! + the LogCollector + return_data read-back are the next increments, all reusing existing code.
//!
//! WHY AN OVERLAY (not bank.pending_writes / worker_writes_override): reads must see intra-tx writes
//! (ix N+1 sees ix N), and simulate must NOT touch live bank state (worker_writes_override is write-only
//! and races replay — bank.zig:206,576). The overlay is a private pubkey→post-state map, seeded
//! read-only from the bank on first touch, folded with each instruction's mutations (which carry FULL
//! post-state, sbpf_executor AccountMutation — a direct overwrite, not a delta merge). simulate drops
//! it (bank untouched); produce flushes it through the existing commit path.

const std = @import("std");

/// simulate = discard the overlay; produce = commit it to the bank.
pub const ExecMode = enum { simulate, produce };

/// Options mirroring Agave's RPC simulate config (rpc/src/rpc.rs:3989-4054).
pub const ExecOpts = struct {
    /// ed25519-verify the tx signatures first (RPC default false for simulate). Mutually exclusive
    /// with replace_recent_blockhash (Agave rpc.rs:4020-4023).
    sig_verify: bool = false,
    /// Overwrite the tx's recent blockhash with the bank's latest (so an old tx simulates at tip).
    replace_recent_blockhash: bool = false,
    /// Record inner (CPI) instructions (Agave enable_cpi_recording). Default off.
    enable_cpi_recording: bool = false,
    /// Wire the LogCollector (so SimResult.logs is populated). Gated so replay's hot path is byte-
    /// unchanged when off.
    record_logs: bool = true,
    /// Read back return_data from the InvokeContext.
    record_return_data: bool = true,
};

/// A transaction-level error: the first failing instruction's error (Agave result = Err). null = Ok.
pub const TxError = struct {
    /// Agave TransactionError / InstructionError discriminant.
    code: u32,
    /// The failing instruction index (for the InstructionError variant).
    instruction_index: ?u8 = null,
};

/// One account's post-execution state (overlay entry / post_simulation_accounts element). Owns `data`.
pub const AccountState = struct {
    pubkey: [32]u8,
    lamports: u64,
    owner: [32]u8,
    data: []u8,
    executable: bool,
    rent_epoch: u64,
};

/// A read-only seed account fetched from the bank (data is borrowed from the bank, copied on seed).
pub const SeedAccount = struct {
    lamports: u64,
    owner: [32]u8,
    data: []const u8,
    executable: bool,
    rent_epoch: u64,
};

/// Read-only account source = the bank. In production this wraps bank.getAccountInSlot(pk, slot,
/// ancestors); in tests, a mock map. Type-erased so the overlay needn't depend on Bank.
pub const SeedReader = struct {
    ctx: *anyopaque,
    readFn: *const fn (ctx: *anyopaque, pubkey: *const [32]u8) ?SeedAccount,

    fn read(self: SeedReader, pubkey: *const [32]u8) ?SeedAccount {
        return self.readFn(self.ctx, pubkey);
    }
};

/// The result of executeOnBank — mirrors Agave TransactionSimulationResult (bank.rs:350-364). Fields
/// the foundation cannot yet populate (logs/units/return_data) come online with the tx-loop increment.
pub const SimResult = struct {
    err: ?TxError = null,
    logs: std.ArrayListUnmanaged([]u8) = .{},
    units_consumed: u64 = 0,
    return_data: ?[]u8 = null,
    post_accounts: []AccountState = &.{},
    loaded_accounts_data_size: u32 = 0,
    fee: ?u64 = null,

    pub fn deinit(self: *SimResult, allocator: std.mem.Allocator) void {
        for (self.logs.items) |l| allocator.free(l);
        self.logs.deinit(allocator);
        if (self.return_data) |rd| allocator.free(rd);
        for (self.post_accounts) |a| allocator.free(a.data);
        allocator.free(self.post_accounts);
        self.* = undefined;
    }
};

/// The local account overlay — the simulate/produce discard primitive. Seeded lazily read-only from
/// the bank; folded with each instruction's post-state; snapshot for post_simulation_accounts; dropped
/// (simulate) or committed (produce).
pub const Overlay = struct {
    allocator: std.mem.Allocator,
    entries: std.AutoHashMapUnmanaged([32]u8, AccountState) = .{},
    reader: SeedReader,

    pub fn init(allocator: std.mem.Allocator, reader: SeedReader) Overlay {
        return .{ .allocator = allocator, .reader = reader };
    }

    pub fn deinit(self: *Overlay) void {
        var it = self.entries.valueIterator();
        while (it.next()) |a| self.allocator.free(a.data);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Current state of `pubkey`: the overlay entry if present, else seed it read-only from the bank
    /// (caching an owned copy so later reads + the snapshot are stable), else null (account not found).
    /// Returns a pointer into the overlay valid until the next fold of the same key.
    pub fn get(self: *Overlay, pubkey: *const [32]u8) !?*const AccountState {
        if (self.entries.getPtr(pubkey.*)) |e| return e;
        const seed = self.reader.read(pubkey) orelse return null;
        const data = try self.allocator.dupe(u8, seed.data);
        errdefer self.allocator.free(data);
        const st = AccountState{
            .pubkey = pubkey.*,
            .lamports = seed.lamports,
            .owner = seed.owner,
            .data = data,
            .executable = seed.executable,
            .rent_epoch = seed.rent_epoch,
        };
        try self.entries.put(self.allocator, pubkey.*, st);
        return self.entries.getPtr(pubkey.*).?;
    }

    /// Fold an instruction's post-state for `pubkey` into the overlay (direct overwrite — AccountMutation
    /// carries the FULL post-state, not a delta). Frees the prior owned data.
    pub fn fold(self: *Overlay, pubkey: *const [32]u8, lamports: u64, owner: [32]u8, data: []const u8, executable: bool, rent_epoch: u64) !void {
        const new_data = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(new_data);
        const gop = try self.entries.getOrPut(self.allocator, pubkey.*);
        if (gop.found_existing) self.allocator.free(gop.value_ptr.data);
        gop.value_ptr.* = .{
            .pubkey = pubkey.*,
            .lamports = lamports,
            .owner = owner,
            .data = new_data,
            .executable = executable,
            .rent_epoch = rent_epoch,
        };
    }

    /// Snapshot the current state of `keys` (the tx's first-N account keys, in order) as owned copies —
    /// this is Agave's `post_simulation_accounts` (bank.rs:3452-3457). Caller owns the returned slice
    /// (free each .data + the slice; SimResult.deinit does this). Keys not in the overlay AND not in
    /// the bank are skipped.
    pub fn snapshot(self: *Overlay, keys: []const [32]u8) ![]AccountState {
        var out = std.ArrayListUnmanaged(AccountState){};
        errdefer {
            for (out.items) |a| self.allocator.free(a.data);
            out.deinit(self.allocator);
        }
        for (keys) |k| {
            const st = (try self.get(&k)) orelse continue;
            try out.append(self.allocator, .{
                .pubkey = st.pubkey,
                .lamports = st.lamports,
                .owner = st.owner,
                .data = try self.allocator.dupe(u8, st.data),
                .executable = st.executable,
                .rent_epoch = st.rent_epoch,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }
};

// ─────────────────────────────── KATs ───────────────────────────────

const testing = std.testing;

const MockBank = struct {
    map: std.AutoHashMapUnmanaged([32]u8, SeedAccount) = .{},
    allocator: std.mem.Allocator,

    fn put(self: *MockBank, key: [32]u8, a: SeedAccount) !void {
        try self.map.put(self.allocator, key, a);
    }
    fn reader(self: *MockBank) SeedReader {
        return .{ .ctx = self, .readFn = readImpl };
    }
    fn readImpl(ctx: *anyopaque, pubkey: *const [32]u8) ?SeedAccount {
        const self: *MockBank = @ptrCast(@alignCast(ctx));
        return self.map.get(pubkey.*);
    }
    fn deinit(self: *MockBank) void {
        self.map.deinit(self.allocator);
    }
};

test "Overlay: seed read-only, fold post-state, snapshot, simulate-discard isolation" {
    const a = testing.allocator;
    var bank = MockBank{ .allocator = a };
    defer bank.deinit();
    const FROM = [_]u8{0xAA} ** 32;
    const TO = [_]u8{0xBB} ** 32;
    const SYS = [_]u8{0} ** 32;
    try bank.put(FROM, .{ .lamports = 10_000_000, .owner = SYS, .data = "", .executable = false, .rent_epoch = 0 });
    try bank.put(TO, .{ .lamports = 0, .owner = SYS, .data = "", .executable = false, .rent_epoch = 0 });

    var ov = Overlay.init(a, bank.reader());
    defer ov.deinit();

    // seed read
    try testing.expectEqual(@as(u64, 10_000_000), (try ov.get(&FROM)).?.lamports);
    try testing.expect((try ov.get(&[_]u8{0xCC} ** 32)) == null); // not found

    // fold a transfer (from -1M, to +1M)
    try ov.fold(&FROM, 9_000_000, SYS, "", false, 0);
    try ov.fold(&TO, 1_000_000, SYS, "", false, 0);
    try testing.expectEqual(@as(u64, 9_000_000), (try ov.get(&FROM)).?.lamports);
    try testing.expectEqual(@as(u64, 1_000_000), (try ov.get(&TO)).?.lamports);

    // fold can change data (and frees the old buffer — no leak under the testing allocator)
    try ov.fold(&FROM, 9_000_000, SYS, "hello", false, 0);
    try testing.expectEqualStrings("hello", (try ov.get(&FROM)).?.data);

    // snapshot = post_simulation_accounts for [FROM, TO]
    const post = try ov.snapshot(&[_][32]u8{ FROM, TO });
    defer {
        for (post) |p| a.free(p.data);
        a.free(post);
    }
    try testing.expectEqual(@as(usize, 2), post.len);
    try testing.expectEqual(@as(u64, 9_000_000), post[0].lamports);
    try testing.expectEqual(@as(u64, 1_000_000), post[1].lamports);

    // SIMULATE DISCARD: the bank (seed source) is UNCHANGED — the overlay never wrote back.
    try testing.expectEqual(@as(u64, 10_000_000), bank.map.get(FROM).?.lamports);
    try testing.expectEqual(@as(u64, 0), bank.map.get(TO).?.lamports);
}

test "SimResult.deinit frees owned buffers (no leak)" {
    const a = testing.allocator;
    var r = SimResult{};
    try r.logs.append(a, try a.dupe(u8, "Program 111 invoke [1]"));
    try r.logs.append(a, try a.dupe(u8, "Program log: hi"));
    r.return_data = try a.dupe(u8, &[_]u8{ 1, 2, 3 });
    var posts = try a.alloc(AccountState, 1);
    posts[0] = .{ .pubkey = [_]u8{1} ** 32, .lamports = 5, .owner = [_]u8{0} ** 32, .data = try a.dupe(u8, "x"), .executable = false, .rent_epoch = 0 };
    r.post_accounts = posts;
    r.deinit(a); // must free logs + return_data + post_accounts[*].data + the slice
}
