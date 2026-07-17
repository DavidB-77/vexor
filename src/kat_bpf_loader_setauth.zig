//! KAT: BPFLoaderUpgradeable SetAuthority(ProgramData → None) — the "make
//! immutable" / finalize path (carrier 420349520, task fix/bpfloader-
//! setauthority-none-2026-07-07).
//!
//! Locks the byte-exact None-flip + the SIMD-0500 finalize gate against the
//! three-way canonical (Agave 4.1.1 lib.rs:564-596 == FD
//! fd_bpf_loader_program.c:1751-1787 / fd_bpf_loader_finalize_v3_check:237-245):
//!   - None applies UNCONDITIONALLY unless (disable_sbpf_v0_v1_v2_deployment
//!     active AND the embedded ELF parses as sBPF < V3), in which case the tx is
//!     rejected with InstructionError::InvalidAccountData.
//!   - set_state(ProgramData{slot, None}) serializes 13 bytes → ONLY the Option
//!     byte @12 flips to 0; slot [4..12], stale authority [13..45] and program
//!     tail [45..] are preserved verbatim (bincode serialize_into no truncate).
//!
//! FAIL-PRE / PASS-POST: on the pre-fix code the None arm was a logged no-op
//! (0 writes) → test 1 & 3 (which assert exactly 1 write with @12=0) FAIL; the
//! fix makes them PASS. Test 2 asserts the gate REJECTS.
//!
//! Same anytype duck-typed doubles as kat_bpf_loader_extend.zig.

const std = @import("std");
const vex_svm = @import("vex_svm");
const core = @import("core");
const bpf = vex_svm.bpf_loader_program;
const features = vex_svm.features;
const Pubkey = core.Pubkey;

const LOADER_ID = [_]u8{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
    0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
    0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
};
const SYSTEM_ID = [_]u8{0} ** 32;

const STATE_PROGRAM_DATA: u32 = 3;
const IX_SET_AUTHORITY: u32 = 4;
const PROGRAM_DATA_METADATA_SIZE: usize = 45;

// ─── test doubles (identical shape to kat_bpf_loader_extend.zig) ─────────────
const Ix = struct {
    data: []const u8,
    account_indices: []const u8,
};

const Acct = struct {
    key: [32]u8,
    lamports: u64,
    owner: [32]u8 = SYSTEM_ID,
    executable: bool = false,
    rent_epoch: u64 = std.math.maxInt(u64),
    data: []const u8,
};

const Ptx = struct {
    account_keys: [][32]u8,
    num_accounts: u8,
    num_required_sigs: u8,
    writable_mask: u64,

    pub fn isWritable(self: *const Ptx, idx: u16) bool {
        return (self.writable_mask >> @intCast(idx)) & 1 == 1;
    }
};

const Db = struct {
    accts: []const Acct,
    const Found = struct {
        lamports: u64,
        owner: Pubkey,
        executable: bool,
        rent_epoch: u64,
        data: []const u8,
    };
    pub fn getAccountInSlot(self: *Db, pk: *const Pubkey, slot: u64, ancestors: anytype) ?Found {
        _ = slot;
        _ = ancestors;
        for (self.accts) |a| {
            if (std.mem.eql(u8, &a.key, &pk.data)) {
                return .{
                    .lamports = a.lamports,
                    .owner = .{ .data = a.owner },
                    .executable = a.executable,
                    .rent_epoch = a.rent_epoch,
                    .data = a.data,
                };
            }
        }
        return null;
    }
};

const Bank = struct {
    slot: u64,
    pending_writes: std.ArrayListUnmanaged(WriteEntry) = .{},
    alloc: std.mem.Allocator,

    const WriteEntry = struct {
        pubkey: Pubkey,
        lamports: u64,
        owner: Pubkey,
        executable: bool,
        rent_epoch: u64,
        data: []const u8,
    };

    pub fn ancestors(self: *Bank) []const u64 {
        _ = self;
        return &[_]u64{};
    }

    pub fn collectWrite(self: *Bank, w: anytype) !void {
        try self.pending_writes.append(self.alloc, .{
            .pubkey = Pubkey{ .data = w.pubkey.data },
            .lamports = w.lamports,
            .owner = Pubkey{ .data = w.owner.data },
            .executable = w.executable,
            .rent_epoch = w.rent_epoch,
            .data = w.data,
        });
    }

    fn find(self: *Bank, key: [32]u8) ?*WriteEntry {
        for (self.pending_writes.items) |*e| {
            if (std.mem.eql(u8, &e.pubkey.data, &key)) return e;
        }
        return null;
    }
};

fn run(ix: Ix, ptx: *Ptx, bank: *Bank, db: *Db, fs: ?*const features.FeatureSet) !void {
    try bpf.execute(ix, ptx, bank, db, bank.alloc, fs);
}

// ProgramData body: [tag u32][slot u64][opt=1 u8][auth 32][elf payload].
fn makeProgramData(alloc: std.mem.Allocator, slot: u64, authority: [32]u8, payload: []const u8) ![]u8 {
    const d = try alloc.alloc(u8, PROGRAM_DATA_METADATA_SIZE + payload.len);
    @memset(d, 0);
    std.mem.writeInt(u32, d[0..4], STATE_PROGRAM_DATA, .little);
    std.mem.writeInt(u64, d[4..12], slot, .little);
    d[12] = 1; // Option::Some
    @memcpy(d[13..PROGRAM_DATA_METADATA_SIZE], &authority);
    @memcpy(d[PROGRAM_DATA_METADATA_SIZE..], payload);
    return d;
}

// Minimal ELF-shaped payload: only e_flags @48 (ELF64 header) is read by the
// finalize gate (get_sbpf_version — anza-sbpf elf.rs:1265 / FD raw e_flags load).
fn makeElfPayload(alloc: std.mem.Allocator, e_flags: u32) ![]u8 {
    const d = try alloc.alloc(u8, 64);
    @memset(d, 0);
    @memcpy(d[0..4], &[_]u8{ 0x7F, 'E', 'L', 'F' });
    std.mem.writeInt(u32, d[48..52], e_flags, .little);
    return d;
}

// Drive one SetAuthority(ProgramData, new_authority=None) and return the bank
// so callers inspect the emitted write (or its absence).
const SetAuthNoneFixture = struct {
    pd_key: [32]u8,
    authority: [32]u8,
    pd_data: []u8,
    slot: u64,
};

fn setup(arena: std.mem.Allocator, e_flags: u32) !SetAuthNoneFixture {
    const pd_key = [_]u8{0x11} ** 32;
    const authority = [_]u8{0x33} ** 32;
    const payload = try makeElfPayload(arena, e_flags);
    const pd_data = try makeProgramData(arena, 100, authority, payload);
    return .{ .pd_key = pd_key, .authority = authority, .pd_data = pd_data, .slot = 200 };
}

fn drive(arena: std.mem.Allocator, fx: SetAuthNoneFixture, fs: ?*const features.FeatureSet, bank: *Bank) !void {
    var accts = [_]Acct{
        .{ .key = fx.pd_key, .lamports = 5_000_000, .owner = LOADER_ID, .data = fx.pd_data },
        .{ .key = fx.authority, .lamports = 1, .owner = SYSTEM_ID, .data = &[_]u8{} },
    };
    var db = Db{ .accts = &accts };
    // keys[0]=ProgramData (writable, index 0), keys[1]=present authority (signer).
    var keys = [_][32]u8{ fx.pd_key, fx.authority };
    var ptx = Ptx{
        .account_keys = &keys,
        .num_accounts = 2,
        .num_required_sigs = 2, // both keys sign → present authority (idx1) is signer
        .writable_mask = 0b01, // ProgramData (idx0) writable
    };
    // instruction: tag(4)=SetAuthority(4). account_indices {0,1} → new_authority
    // is ABSENT (len==2) → None.
    var ix_data: [4]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], IX_SET_AUTHORITY, .little);
    const ix = Ix{ .data = &ix_data, .account_indices = &[_]u8{ 0, 1 } };
    _ = arena;
    try run(ix, &ptx, bank, &db, fs);
}

// ─── tests ──────────────────────────────────────────────────────────────────

test "SetAuthority(ProgramData->None): feature INACTIVE (carrier 420349520) — clears @12, preserves tail" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const fx = try setup(arena, 0); // V0 ELF — irrelevant when feature inactive
    const orig = try arena.dupe(u8, fx.pd_data); // snapshot pre-state bytes

    var bank = Bank{ .slot = fx.slot, .alloc = arena };
    try drive(arena, fx, null, &bank); // fs = null → feature inactive → UNCONDITIONAL apply

    // Exactly one write (the ProgramData account). FAILS on the pre-fix no-op (0 writes).
    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    const w = bank.find(fx.pd_key) orelse return error.MissingProgramDataWrite;

    // Same length (tail preserved), Option byte @12 flipped to 0/None.
    try std.testing.expectEqual(orig.len, w.data.len);
    try std.testing.expectEqual(@as(u8, 0), w.data[12]);
    // tag + slot preserved.
    try std.testing.expectEqual(STATE_PROGRAM_DATA, std.mem.readInt(u32, w.data[0..4], .little));
    try std.testing.expectEqual(@as(u64, 100), std.mem.readInt(u64, w.data[4..12], .little));
    // Stale authority bytes [13..45] preserved verbatim (bincode None writes 13 bytes only).
    try std.testing.expect(std.mem.eql(u8, w.data[13..PROGRAM_DATA_METADATA_SIZE], &fx.authority));
    // Program tail [45..] preserved verbatim.
    try std.testing.expect(std.mem.eql(u8, w.data[PROGRAM_DATA_METADATA_SIZE..], orig[PROGRAM_DATA_METADATA_SIZE..]));
    // Everything except byte @12 is byte-identical to the pre-state.
    try std.testing.expectEqual(orig[0..12].*, w.data[0..12].*);
    try std.testing.expect(std.mem.eql(u8, w.data[13..], orig[13..]));
    // owner unchanged (loader).
    try std.testing.expect(std.mem.eql(u8, &w.owner.data, &LOADER_ID));
}

test "SetAuthority(ProgramData->None): feature ACTIVE + sBPF<V3 (V0) — REJECT, no write" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const fx = try setup(arena, 0); // e_flags=0 → SBPFVersion::V0 (< V3)

    var fs = features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, features.DISABLE_SBPF_V0_V1_V2_DEPLOYMENT, 0); // active at any slot

    var bank = Bank{ .slot = fx.slot, .alloc = arena };
    // SIMD-0500 gate → InstructionError::InvalidAccountData (tx rollback).
    try std.testing.expectError(error.InvalidAccountData, drive(arena, fx, &fs, &bank));
    try std.testing.expectEqual(@as(usize, 0), bank.pending_writes.items.len);
}

test "SetAuthority(ProgramData->None): feature ACTIVE + sBPF V3 — apply (clears @12)" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const fx = try setup(arena, 3); // e_flags=3 → SBPFVersion::V3 (>= V3 → not gated)

    var fs = features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, features.DISABLE_SBPF_V0_V1_V2_DEPLOYMENT, 0);

    var bank = Bank{ .slot = fx.slot, .alloc = arena };
    try drive(arena, fx, &fs, &bank); // V3 → gate passes → apply

    try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
    const w = bank.find(fx.pd_key) orelse return error.MissingProgramDataWrite;
    try std.testing.expectEqual(@as(u8, 0), w.data[12]); // None applied
}

test "SetAuthority(ProgramData->None): feature ACTIVE + sBPF V4/Reserved — apply (not gated)" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // e_flags=4 (V4) and e_flags=7 (Reserved) both parse >= V3 → NOT rejected.
    for ([_]u32{ 4, 7 }) |ef| {
        const fx = try setup(arena, ef);
        var fs = features.FeatureSet.init();
        defer fs.deinit(alloc);
        try fs.activate(alloc, features.DISABLE_SBPF_V0_V1_V2_DEPLOYMENT, 0);
        var bank = Bank{ .slot = fx.slot, .alloc = arena };
        try drive(arena, fx, &fs, &bank);
        try std.testing.expectEqual(@as(usize, 1), bank.pending_writes.items.len);
        const w = bank.find(fx.pd_key) orelse return error.MissingProgramDataWrite;
        try std.testing.expectEqual(@as(u8, 0), w.data[12]);
    }
}
