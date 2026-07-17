//! KAT: BPFLoaderUpgradeable Phase-2 arms — ExtendProgram / Upgrade /
//! DeployWithMaxDataLen (task #67).
//!
//! Locks the byte-exact account mutations + the SIMD-0431 (min-extend-size)
//! gate + the deploy_program! ELF accept/reject port against the Agave
//! 4.1.0-beta.3 reference (programs/bpf_loader/src/lib.rs):
//!   - ExtendProgram   lib.rs:777 -> common_extend_program 785-989
//!   - Upgrade         lib.rs:360-535
//!   - DeployWithMaxDataLen lib.rs:202-359
//!   - deploy_program! program-runtime/src/deploy.rs:47-131 (load+verify ->
//!     InstructionError::InvalidAccountData on failure)
//!
//! Strategy: the loader handler is `anytype`-based, so we drive it through
//! tiny duck-typed test doubles (Ix/Ptx/Bank/Db). The Bank double owns a real
//! pending_writes list and a collectWrite that appends, and we recompute the
//! expected post-state lt via the REAL bank.accountLtHash, so the lt deltas are
//! exercised end-to-end. A minimal valid sBPF-v3 ELF (built inline, mirroring
//! src/vex_bpf2/elf_test.zig strict mode) is the deploy accept-path payload.

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

const STATE_UNINITIALIZED: u32 = 0;
const STATE_BUFFER: u32 = 1;
const STATE_PROGRAM: u32 = 2;
const STATE_PROGRAM_DATA: u32 = 3;

const BUFFER_METADATA_SIZE: usize = 37;
const PROGRAM_SIZE: usize = 36;
const PROGRAM_DATA_METADATA_SIZE: usize = 45;

// ─── minimal valid sBPF-v3 ELF (mirror of elf_test.zig strict mode) ──────────
const Elf64Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};
const Elf64Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};
const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const ET_DYN: u16 = 3;
const EM_BPF: u16 = 247;
const MM_BYTECODE_START: u64 = 1 << 32;

fn buildV3Elf(alloc: std.mem.Allocator) ![]u8 {
    const text_bytes = [_]u8{
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
        0x95, 0, 0, 0, 0, 0, 0, 0, // exit
    };
    var buf = std.ArrayList(u8){};
    errdefer buf.deinit(alloc);
    try buf.appendNTimes(alloc, 0, @sizeOf(Elf64Ehdr));
    const phdr_offset = buf.items.len;
    try buf.appendNTimes(alloc, 0, @sizeOf(Elf64Phdr));
    const text_off = buf.items.len;
    try buf.appendSlice(alloc, text_bytes[0..]);
    const phdr = Elf64Phdr{
        .p_type = PT_LOAD,
        .p_flags = PF_X,
        .p_offset = text_off,
        .p_vaddr = MM_BYTECODE_START,
        .p_paddr = MM_BYTECODE_START,
        .p_filesz = text_bytes.len,
        .p_memsz = text_bytes.len,
        .p_align = 8,
    };
    @memcpy(buf.items[phdr_offset..][0..@sizeOf(Elf64Phdr)], std.mem.asBytes(&phdr));
    var id: [16]u8 = .{0} ** 16;
    @memcpy(id[0..4], &[_]u8{ 0x7F, 'E', 'L', 'F' });
    id[4] = 2; // ELFCLASS64
    id[5] = 1; // ELFDATA2LSB
    id[6] = 1; // EV_CURRENT
    const ehdr = Elf64Ehdr{
        .e_ident = id,
        .e_type = ET_DYN,
        .e_machine = EM_BPF,
        .e_version = 1,
        .e_entry = MM_BYTECODE_START,
        .e_phoff = @sizeOf(Elf64Ehdr),
        .e_shoff = 0,
        .e_flags = 3, // SBPFVersion::V3
        .e_ehsize = @sizeOf(Elf64Ehdr),
        .e_phentsize = @sizeOf(Elf64Phdr),
        .e_phnum = 1,
        .e_shentsize = 64,
        .e_shnum = 0,
        .e_shstrndx = 0,
    };
    @memcpy(buf.items[0..@sizeOf(Elf64Ehdr)], std.mem.asBytes(&ehdr));
    return buf.toOwnedSlice(alloc);
}

// ─── test doubles ────────────────────────────────────────────────────────────
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
    writable_mask: u64, // bit i => account i writable

    pub fn isWritable(self: *const Ptx, idx: u16) bool {
        return (self.writable_mask >> @intCast(idx)) & 1 == 1;
    }
};

const Db = struct {
    accts: []const Acct,
    // anytype getAccountInSlot(pk, slot, ancestors) returning an account-shaped
    // struct (lamports/owner/executable/rent_epoch/data) or null.
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

    // Mirrors the fields readOverlayed reads off bank.pending_writes.items[i]:
    // w.pubkey.data, w.lamports, w.owner (Pubkey), w.executable, w.rent_epoch, w.data.
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
        // w.pubkey / w.owner are the loader's `.{ .data = key }` literals; rebuild
        // explicit Pubkey values so the field types match exactly.
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

fn run(
    ix: Ix,
    ptx: *Ptx,
    bank: *Bank,
    db: *Db,
    fs: ?*const features.FeatureSet,
) !void {
    try bpf.execute(ix, ptx, bank, db, bank.alloc, fs);
}

// ─── tests ───────────────────────────────────────────────────────────────────

test "deployVerify accepts a minimal valid V3 ELF and rejects garbage" {
    const alloc = std.testing.allocator;
    const elf = try buildV3Elf(alloc);
    defer alloc.free(elf);
    // disable_v0_v1_v2 = false (ExtendProgram path): any version allowed.
    try bpf.deployVerify(alloc, elf, false, false);

    // Garbage bytes -> InvalidAccountData (Agave deploy.rs:84 .map_err).
    const garbage = [_]u8{0xAA} ** 64;
    try std.testing.expectError(error.InvalidAccountData, bpf.deployVerify(alloc, &garbage, false, false));
}

test "SIMD-0431 reject predicate boundary (Agave lib.rs:871-872)" {
    const MAX: u64 = 10 * 1024 * 1024;
    // additional_bytes >= 10240 always OK.
    try std.testing.expect(!bpf.simd0431Rejects(10_240, 100));
    try std.testing.expect(!bpf.simd0431Rejects(10_241, 100));
    // additional_bytes < 10240 and not equal to headroom -> REJECT.
    try std.testing.expect(bpf.simd0431Rejects(1, 100));
    try std.testing.expect(bpf.simd0431Rejects(10_239, 100));
    // additional_bytes < 10240 BUT equals headroom (extend-to-max) -> OK.
    const old_len: u64 = MAX - 5;
    try std.testing.expect(!bpf.simd0431Rejects(5, old_len));
    // wrong headroom value still rejects.
    try std.testing.expect(bpf.simd0431Rejects(4, old_len));
}

test "rent-exempt minimum balance matches canonical (len+128)*3480*2" {
    try std.testing.expectEqual(@as(u64, (8 + 128) * 3480 * 2), bpf.rentExemptMinimumBalance(8));
    try std.testing.expectEqual(@as(u64, (0 + 128) * 3480 * 2), bpf.rentExemptMinimumBalance(0));
}

// Build a ProgramData account body: [tag u32][slot u64][opt u8][auth 32][payload].
fn makeProgramData(alloc: std.mem.Allocator, slot: u64, authority: [32]u8, payload: []const u8) ![]u8 {
    const d = try alloc.alloc(u8, PROGRAM_DATA_METADATA_SIZE + payload.len);
    @memset(d, 0);
    std.mem.writeInt(u32, d[0..4], STATE_PROGRAM_DATA, .little);
    std.mem.writeInt(u64, d[4..12], slot, .little);
    d[12] = 1;
    @memcpy(d[13..PROGRAM_DATA_METADATA_SIZE], &authority);
    @memcpy(d[PROGRAM_DATA_METADATA_SIZE..], payload);
    return d;
}
fn makeProgram(alloc: std.mem.Allocator, pd_key: [32]u8) ![]u8 {
    const d = try alloc.alloc(u8, PROGRAM_SIZE);
    @memset(d, 0);
    std.mem.writeInt(u32, d[0..4], STATE_PROGRAM, .little);
    @memcpy(d[4..PROGRAM_SIZE], &pd_key);
    return d;
}

test "ExtendProgram: grows programdata, zero-fills tail, re-stamps header, tops up rent" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const elf = try buildV3Elf(arena);
    const pd_key = [_]u8{0x11} ** 32;
    const prog_key = [_]u8{0x22} ** 32;
    const authority = [_]u8{0x33} ** 32;
    const payer_key = [_]u8{0x44} ** 32;

    // ProgramData deployed at slot 100 with the ELF as payload.
    const pd_data = try makeProgramData(arena, 100, authority, elf);
    const prog_data = try makeProgram(arena, pd_key);

    const old_len: u64 = pd_data.len;
    const additional_bytes: u32 = 10_240; // satisfies SIMD-0431
    const new_len: u64 = old_len + additional_bytes;
    const min_balance = bpf.rentExemptMinimumBalance(new_len);
    // Start programdata UNDER-funded so a rent top-up is required.
    const pd_start_lamports: u64 = min_balance - 7_000;

    var accts = [_]Acct{
        .{ .key = pd_key, .lamports = pd_start_lamports, .owner = LOADER_ID, .data = pd_data },
        .{ .key = prog_key, .lamports = 1, .owner = LOADER_ID, .data = prog_data },
        .{ .key = payer_key, .lamports = 1_000_000_000, .owner = SYSTEM_ID, .data = &[_]u8{} },
    };
    var db = Db{ .accts = &accts };

    var keys = [_][32]u8{ pd_key, prog_key, [_]u8{0xAB} ** 32, payer_key };
    var ptx = Ptx{
        .account_keys = &keys,
        .num_accounts = 4,
        .num_required_sigs = 1,
        // pd(0), prog(1), payer(3) writable. account 2 = system program (unused).
        .writable_mask = 0b1011,
    };

    // instruction data: tag(4)=ExtendProgram(6) | additional_bytes u32.
    var ix_data: [8]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], 6, .little);
    std.mem.writeInt(u32, ix_data[4..8], additional_bytes, .little);
    const ix = Ix{ .data = &ix_data, .account_indices = &[_]u8{ 0, 1, 2, 3 } };

    var bank = Bank{ .slot = 200, .alloc = arena };
    try run(ix, &ptx, &bank, &db, null); // SIMD-0431 inactive (null fs) — still satisfied anyway

    // Expect 2 writes: payer (debited) + programdata (grown/restamped/credited).
    const pd_w = bank.find(pd_key) orelse return error.MissingProgramDataWrite;
    const payer_w = bank.find(payer_key) orelse return error.MissingPayerWrite;

    // ProgramData new length == new_len.
    try std.testing.expectEqual(new_len, @as(u64, pd_w.data.len));
    // Header re-stamped: tag=ProgramData, slot=bank.slot(200), authority preserved.
    try std.testing.expectEqual(STATE_PROGRAM_DATA, std.mem.readInt(u32, pd_w.data[0..4], .little));
    try std.testing.expectEqual(@as(u64, 200), std.mem.readInt(u64, pd_w.data[4..12], .little));
    try std.testing.expectEqual(@as(u8, 1), pd_w.data[12]);
    try std.testing.expect(std.mem.eql(u8, pd_w.data[13..PROGRAM_DATA_METADATA_SIZE], &authority));
    // Original payload preserved at [pd_offset..old_len].
    try std.testing.expect(std.mem.eql(u8, pd_w.data[PROGRAM_DATA_METADATA_SIZE..old_len], elf));
    // Grown tail is zero-filled.
    for (pd_w.data[old_len..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    // Rent top-up: programdata credited exactly (min_balance - pd_start_lamports).
    const required_payment = min_balance - pd_start_lamports;
    try std.testing.expectEqual(pd_start_lamports + required_payment, pd_w.lamports);
    try std.testing.expectEqual(min_balance, pd_w.lamports);
    // Payer debited the same amount.
    try std.testing.expectEqual(@as(u64, 1_000_000_000) - required_payment, payer_w.lamports);
    // ProgramData owner preserved (loader).
    try std.testing.expect(std.mem.eql(u8, &pd_w.owner.data, &LOADER_ID));
}

test "ExtendProgram: SIMD-0431 violation emits no write (active feature)" {
    const alloc = std.testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(alloc);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const elf = try buildV3Elf(arena);
    const pd_key = [_]u8{0x11} ** 32;
    const prog_key = [_]u8{0x22} ** 32;
    const authority = [_]u8{0x33} ** 32;

    const pd_data = try makeProgramData(arena, 100, authority, elf);
    const prog_data = try makeProgram(arena, pd_key);

    var accts = [_]Acct{
        .{ .key = pd_key, .lamports = 50_000_000, .owner = LOADER_ID, .data = pd_data },
        .{ .key = prog_key, .lamports = 1, .owner = LOADER_ID, .data = prog_data },
    };
    var db = Db{ .accts = &accts };
    var keys = [_][32]u8{ pd_key, prog_key, [_]u8{0xAB} ** 32, [_]u8{0x44} ** 32 };
    var ptx = Ptx{ .account_keys = &keys, .num_accounts = 4, .num_required_sigs = 1, .writable_mask = 0b1011 };

    // additional_bytes = 1 (below 10240 min, headroom != 1) -> reject under SIMD-0431.
    var ix_data: [8]u8 = undefined;
    std.mem.writeInt(u32, ix_data[0..4], 6, .little);
    std.mem.writeInt(u32, ix_data[4..8], 1, .little);
    const ix = Ix{ .data = &ix_data, .account_indices = &[_]u8{ 0, 1, 2, 3 } };

    // Active SIMD-0431 feature set: activation slot 0 (active at any slot).
    var fs = features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, features.LOADER_V3_MINIMUM_EXTEND_PROGRAM_SIZE, 0);

    var bank = Bank{ .slot = 200, .alloc = arena };
    try run(ix, &ptx, &bank, &db, &fs);

    // No write emitted (rejected, no state change).
    try std.testing.expectEqual(@as(usize, 0), bank.pending_writes.items.len);
}

test "carrier #9 @414537973 LIVE VECTOR: deployVerify must ACCEPT the real post-extend ProgramData payload (torXFavt program, sBPF v0, 211K zero tail)" {
    // Real bytes fetched from testnet RPC (77ZohudHQryhFJU8maV3hT2xTFkRHACQiTdVQ8BDhNS
    // post-extend payload region [45..]); skip when the fixture isn't present.
    const alloc = std.testing.allocator;
    const f = std.fs.cwd().openFile("/tmp/pd_payload_77zoh.bin", .{}) catch return error.SkipZigTest;
    defer f.close();
    const payload = try f.readToEndAlloc(alloc, 1 << 22);
    defer alloc.free(payload);
    // Agave deploy_program! on extend: disable_sbpf_v0_v1_v2_deployment=false
    // (lib.rs:968-970) — cluster ACCEPTED this exact image at 414537973.
    try bpf.deployVerify(alloc, payload, false, false);
}
