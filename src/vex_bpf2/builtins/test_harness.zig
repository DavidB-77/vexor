//! Vexor BPF2 — M9: shared Stage-A test harness.
//!
//! Builds a minimal `InvokeContext + TransactionContext + SysvarCache`
//! tuple per test. Eliminates the freshCtx/freeCtx boilerplate that would
//! otherwise live in each `<program>_test.zig` file.

const std = @import("std");
const ic = @import("../invoke_ctx.zig");
const sysvar_cache = @import("../sysvar_cache.zig");

const InvokeContext = ic.InvokeContext;
const TransactionContext = ic.TransactionContext;
const AccountView = ic.AccountView;
const SysvarCache = sysvar_cache.SysvarCache;
const Pubkey32 = ic.Pubkey32;

pub const AccountSpec = struct {
    pubkey: Pubkey32 = std.mem.zeroes(Pubkey32),
    lamports: u64 = 0,
    /// Allocator-backed data buffer of exactly this length.
    data_len: usize = 0,
    owner: Pubkey32 = std.mem.zeroes(Pubkey32),
    executable: bool = false,
    rent_epoch: u64 = 0,
    is_writable: bool = false,
    is_signer: bool = false,
};

pub const Harness = struct {
    allocator: std.mem.Allocator,
    ctx: *InvokeContext,
    tc: *TransactionContext,
    cache: *SysvarCache,
    accounts: []AccountView,
    /// Owned data buffers to free on deinit.
    data_bufs: [][]u8,

    pub fn init(allocator: std.mem.Allocator, compute_units: u64, specs: []const AccountSpec) !Harness {
        const accounts = try allocator.alloc(AccountView, specs.len);
        errdefer allocator.free(accounts);
        const data_bufs = try allocator.alloc([]u8, specs.len);
        errdefer allocator.free(data_bufs);

        for (specs, 0..) |s, i| {
            const buf = try allocator.alloc(u8, s.data_len);
            @memset(buf, 0);
            data_bufs[i] = buf;
            accounts[i] = .{
                .pubkey = s.pubkey,
                .lamports = s.lamports,
                .owner = s.owner,
                .executable = s.executable,
                .rent_epoch = s.rent_epoch,
                .data = buf,
                .is_writable = s.is_writable,
                .is_signer = s.is_signer,
            };
        }

        const tc = try allocator.create(TransactionContext);
        errdefer allocator.destroy(tc);
        tc.* = TransactionContext.init(allocator, accounts, &.{});

        const cache = try allocator.create(SysvarCache);
        errdefer allocator.destroy(cache);
        cache.* = SysvarCache.init(allocator);

        const ctx = try allocator.create(InvokeContext);
        errdefer allocator.destroy(ctx);
        ctx.* = InvokeContext.init(allocator, tc, cache, compute_units);

        return .{
            .allocator = allocator,
            .ctx = ctx,
            .tc = tc,
            .cache = cache,
            .accounts = accounts,
            .data_bufs = data_bufs,
        };
    }

    pub fn deinit(self: *Harness) void {
        // Pop any leftover frames so InstructionStack can free its snaps.
        while (self.ctx.currentFrame() != null) self.ctx.pop();
        self.ctx.deinit();
        self.tc.deinit();
        self.cache.deinit();
        self.allocator.destroy(self.ctx);
        self.allocator.destroy(self.tc);
        self.allocator.destroy(self.cache);
        for (self.data_bufs) |b| self.allocator.free(b);
        self.allocator.free(self.data_bufs);
        self.allocator.free(self.accounts);
    }

    /// Push an instruction frame using `program_idx` and a borrow-set of
    /// account indices. Convenience wrapper around `ctx.push`.
    ///
    /// If the harness was initialised with zero accounts, this method
    /// auto-grows `tx.accounts` to include a single zero AccountView to
    /// satisfy `ctx.push`'s `program_idx >= tx.accounts.len` guard. This
    /// is purely a test convenience; production code paths always pass a
    /// real account list.
    pub fn pushFrame(self: *Harness, program_idx: u16, account_indices: []const u16) !void {
        if (self.accounts.len == 0 and program_idx == 0) {
            // Grow accounts to length 1 so push() validates.
            const grown = try self.allocator.alloc(AccountView, 1);
            const buf = try self.allocator.alloc(u8, 0);
            grown[0] = .{
                .pubkey = std.mem.zeroes(Pubkey32),
                .lamports = 0,
                .owner = std.mem.zeroes(Pubkey32),
                .executable = false,
                .rent_epoch = 0,
                .data = buf,
                .is_writable = false,
                .is_signer = false,
            };
            // Free old (empty) buffers + pointer.
            self.allocator.free(self.accounts);
            const new_data_bufs = try self.allocator.alloc([]u8, 1);
            new_data_bufs[0] = buf;
            self.allocator.free(self.data_bufs);
            self.accounts = grown;
            self.data_bufs = new_data_bufs;
            self.tc.accounts = grown;
        }
        try self.ctx.push(program_idx, account_indices);
    }

    pub fn popFrame(self: *Harness) void {
        self.ctx.pop();
    }
};

pub const init = Harness.init;

test "Harness sanity: empty init/deinit" {
    var h = try Harness.init(std.testing.allocator, 1_000, &.{});
    defer h.deinit();
}

test "Harness sanity: single-account push/pop" {
    var h = try Harness.init(std.testing.allocator, 1_000, &.{
        .{ .lamports = 100, .data_len = 8, .is_writable = true },
    });
    defer h.deinit();
    try h.pushFrame(0, &.{0});
    h.popFrame();
}
