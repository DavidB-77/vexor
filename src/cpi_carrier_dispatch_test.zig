//! cpi_carrier_dispatch_test.zig — FAITHFUL carrier repro through the REAL seam.
//!
//! SESSION-5 (2026-05-31): the old_lt hypothesis was refuted; the carrier is a
//! DROP of CPI-created-account mutations in the per-instruction commit path. The
//! SESSION-4 fixture (`cpi_carrier_create.fix`) ran the ATA `createIdempotent`
//! through `v2DispatchBpfProgram` DIRECTLY (single program, pre-built views) and
//! the ATA WAS collected — so that layer is correct. The carrier lives ONE layer
//! up: `dispatchBpfExecution` → `v2DispatchInternal` (rebuilds the per-instruction
//! `TxCtxOwned` from db + the `pending_writes` overlay) → `commitV2Mutations`.
//!
//! This harness drives the SAME real ATA program + accounts through
//! `dispatchBpfExecution` (the loop entry) against a real AccountsDb + Bank, and
//! checks whether the CPI-created ATA (`9xBMuA6V…`, absent in pre-state) lands in
//! `bank.pending_writes` with owner=Token + rent(165)=2_039_280, and whether the
//! funder (`CRnkKQTx…`) is debited that rent. Ground truth = the fixture's
//! `accounts_post` (== Agave canonical bhd-412214921 for these accounts).
//!
//! Rooted OUTSIDE vex_svm (imports it as one opaque module, like main.zig) to
//! dodge the module cycle. Run: `zig build test-cpi-carrier-dispatch`.

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_store = @import("vex_store");
const vex_crypto = @import("vex_crypto");
const vex_bpf2 = @import("vex_bpf2");
const core = @import("core");

const AccountsDb = vex_store.accounts.AccountsDb;
const Account = vex_store.accounts.Account;
const Bank = vex_svm.Bank;
const Hash = vex_svm.Hash;
const replay = vex_svm.replay_stage;
const Pubkey = core.Pubkey;

// ── base58 decode (tiny; avoids a dependency) ──────────────────────────────
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
fn b58(comptime s: []const u8) [32]u8 {
    @setEvalBranchQuota(100000);
    var bytes: [64]u8 = [_]u8{0} ** 64;
    var len: usize = 0;
    for (s) |c| {
        const di = std.mem.indexOfScalar(u8, B58, c) orelse @compileError("bad b58");
        var carry: usize = di;
        var i: usize = 0;
        while (i < len or carry != 0) : (i += 1) {
            if (i < len) carry += @as(usize, bytes[i]) * 58;
            bytes[i] = @intCast(carry & 0xff);
            carry >>= 8;
            if (i + 1 > len) len = i + 1;
        }
    }
    // leading '1's → leading zero bytes
    var zeros: usize = 0;
    for (s) |c| {
        if (c == '1') zeros += 1 else break;
    }
    var out: [32]u8 = [_]u8{0} ** 32;
    // bytes[] is little-endian; the decoded number is big-endian → reverse
    var j: usize = 0;
    while (j < len) : (j += 1) out[zeros + (len - 1 - j)] = bytes[j];
    return out;
}

// ── the 7 carrier accounts (cpi_carrier_create.fix accounts_pre) ───────────
const ATA_PROG = b58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"); // [0] program
const FUNDER = b58("CRnkKQTxctQ7LHVN3yssdgJyEksBJeBrDdwZAxBtsJoZ"); // [1] payer (signer, writable)
const ATA = b58("9xBMuA6Vty6WVeZHqSr6rmGULYPk3vexn8y7dDUFUrLP"); // [2] ATA to CREATE (lam=0 pre)
const WALLET = b58("AkFvcJXjoKYYUNBJd66gGL6bCos6x5KUWZTZdmXQyks6"); // [3] wallet (ATA owner)
const MINT = b58("J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn"); // [4] mint
const SYS_PROG = b58("11111111111111111111111111111111"); // [5] system
const TOKEN_PROG = b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"); // [6] token

const OWN_SYSTEM = b58("11111111111111111111111111111111");
const OWN_BPF2 = b58("BPFLoader2111111111111111111111111111111111");
const OWN_NATIVE = b58("NativeLoader1111111111111111111111111111111");
const OWN_BPF_UP = b58("BPFLoaderUpgradeab1e11111111111111111111111");
const OWN_RESTAKE = b58("RestkWeAVL8fRGgzhfeoqFhsqKRchg6aa1XrcH96z4Q");
const OWN_TOKEN = b58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const NEWACCT = [_]u8{0x77} ** 32; // ix0 createAccount target (absent pre-state)
const SYSVAR_RENT = b58("SysvarRent111111111111111111111111111111111");
const OWN_SYSVAR = b58("Sysvar1111111111111111111111111111111111111");
// Rent sysvar bytes: lamports_per_byte_year=3480 (u64 LE), exemption_threshold=2.0
// (f64 LE), burn_percent=50 (u8). (128 + 165) * 3480 * 2 = 2_039_280 = rent(165).
const RENT_DATA = [_]u8{ 0x98, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x32 };

const FUNDER_PRE: u64 = 4944017565900;
const RENT_165: u64 = 2039280; // expected ATA rent + funder debit (accounts_post)

const SEED_SLOT: core.Slot = 0;
const BANK_SLOT: core.Slot = 1;

// ── UnbalancedInstruction KAT fixtures (fix 9c94af4, carrier 419369596) ────
// Synthetic programs/accounts — NOT real base58 pubkeys (arbitrary 32-byte
// markers, distinct from every ATA-test constant above so the shared
// process-global V2ProgramCache never collides).
const PROG_UNBAL: [32]u8 = [_]u8{0xA1} ** 32; // "unbalanced" program id
const ACCT_UNBAL_A: [32]u8 = [_]u8{0xA2} ** 32; // sole writable account it touches

const PROG_BAL: [32]u8 = [_]u8{0xB1} ** 32; // "balanced control" program id
const ACCT_BAL_A: [32]u8 = [_]u8{0xB2} ** 32; // debited N
const ACCT_BAL_B: [32]u8 = [_]u8{0xB3} ** 32; // credited N (conserves Σ)

fn loadElf(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(alloc, path, 4 * 1024 * 1024);
}

fn putCache(cache: *vex_bpf2.v2_program_cache.V2ProgramCache, pid: [32]u8, elf: []const u8) !void {
    const exe_heap = try cache.allocator.create(vex_bpf2.elf.Executable);
    exe_heap.* = vex_bpf2.elf.Executable.load(cache.allocator, elf, vex_bpf2.elf.Config.DEFAULT) catch |e| {
        cache.allocator.destroy(exe_heap);
        return e;
    };
    vex_bpf2.verifier.verify(
        exe_heap.textBytes(),
        exe_heap.version(),
        vex_bpf2.verifier.VerifyConfig.DEFAULT,
        &exe_heap.function_registry,
    ) catch |e| {
        exe_heap.deinit();
        cache.allocator.destroy(exe_heap);
        return e;
    };
    try cache.put(pid, exe_heap, 1, 0);
}

// ── Minimal hand-stitched sBPF v3 ELF builder (strict program-header-only
// layout — elf.zig's loadStrict, mirrored from elf_test.zig's proven
// `buildStrictElf` "happy: V3 strict loads" pattern) ────────────────────────
//
// Produces the SMALLEST byte blob `elf2.Executable.load` + `verifier2.verify`
// accept: one ELF64 header + one PT_LOAD/PF_X program header (no rodata
// header, no section headers) + the caller's raw instruction bytes placed at
// vaddr `MM_BYTECODE_START` with `e_entry == MM_BYTECODE_START` (entry_pc=0,
// i.e. the FIRST instruction the caller supplies runs first). `e_flags=3`
// (sBPF v3) — resolveProgramSbpfVersion sniffs this byte and routes v3 ELFs
// through the V2 producer unconditionally (dispatchBpfExecution routing:
// `v == .v3 or v == .v0` always routes), and Vexor's verifier only retires
// the classic 0x79/0x7b LD/ST_DW_REG opcodes + LDDW under v2
// (`moveMemoryInstructionClasses`/`disableLddw` == `v==.v2` — see
// verifier.zig:157-158/verifier_test asserting `!disableLddw(.v3)`), so v3
// keeps the ordinary eBPF encoding this builder emits.
fn buildV3Elf(alloc: std.mem.Allocator, text_bytes: []const u8) ![]u8 {
    const ELFMAG: [4]u8 = .{ 0x7F, 'E', 'L', 'F' };
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ELFOSABI_NONE: u8 = 0;
    const EV_CURRENT: u32 = 1;
    const EM_BPF: u16 = 247;
    const ET_DYN: u16 = 3;
    const PT_LOAD: u32 = 1;
    const PF_X: u32 = 0x1;
    const MM_BYTECODE_START: u64 = 1 << 32;

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

    var buf = std.ArrayList(u8){};
    defer buf.deinit(alloc);
    try buf.appendNTimes(alloc, 0, @sizeOf(Elf64Ehdr));

    const phdr_offset = buf.items.len;
    const phdr_count: u16 = 1; // single PF_X bytecode header (skip_rodata path)
    try buf.appendNTimes(alloc, 0, phdr_count * @sizeOf(Elf64Phdr));

    const text_off = buf.items.len;
    try buf.appendSlice(alloc, text_bytes);

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

    var ident: [16]u8 = [_]u8{0} ** 16;
    @memcpy(ident[0..4], ELFMAG[0..]);
    ident[4] = ELFCLASS64;
    ident[5] = ELFDATA2LSB;
    ident[6] = @intCast(EV_CURRENT);
    ident[7] = ELFOSABI_NONE;

    const ehdr = Elf64Ehdr{
        .e_ident = ident,
        .e_type = ET_DYN,
        .e_machine = EM_BPF,
        .e_version = EV_CURRENT,
        .e_entry = MM_BYTECODE_START,
        .e_phoff = @sizeOf(Elf64Ehdr),
        .e_shoff = 0,
        .e_flags = 3, // sBPF v3
        .e_ehsize = @sizeOf(Elf64Ehdr),
        .e_phentsize = @sizeOf(Elf64Phdr),
        .e_phnum = phdr_count,
        .e_shentsize = 0,
        .e_shnum = 0,
        .e_shstrndx = 0,
    };
    @memcpy(buf.items[0..@sizeOf(Elf64Ehdr)], std.mem.asBytes(&ehdr));

    return try buf.toOwnedSlice(alloc);
}

fn seed(db: *AccountsDb, pk: [32]u8, owner: [32]u8, lamports: u64, executable: bool, data: []const u8) !void {
    const acct = Account{
        .lamports = lamports,
        .owner = Pubkey{ .data = owner },
        .executable = executable,
        .rent_epoch = std.math.maxInt(u64),
        .data = data,
    };
    const key = Pubkey{ .data = pk };
    try db.storeAccount(&key, &acct, SEED_SLOT);
}

test "FIX#95-cpi: ATA createIdempotent through dispatchBpfExecution — does the CPI-created account land?" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(path);

    const db = try AccountsDb.init(alloc, path, null);
    defer db.deinit();

    // Load the two real ELFs (dumped to cpi_programs/).
    const ata_elf = try loadElf(alloc, "tests/bpf_fixtures/cpi_programs/ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL.so");
    defer alloc.free(ata_elf);
    const token_elf = try loadElf(alloc, "tests/bpf_fixtures/cpi_programs/TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA.so");
    defer alloc.free(token_elf);
    // Real account data (from cpi_carrier_create.fix accounts_pre data_hex). The
    // mint MUST be a valid 82-byte SPL Mint or the ATA program returns "Invalid
    // Mint" (r0=2) before ever reaching the inner createAccount.
    const mint_data = try loadElf(alloc, "tests/bpf_fixtures/cpi_programs/acct4.bin"); // 82B SPL Mint
    defer alloc.free(mint_data);
    const wallet_data = try loadElf(alloc, "tests/bpf_fixtures/cpi_programs/acct3.bin"); // 520B Restake
    defer alloc.free(wallet_data);
    const sys_data = try loadElf(alloc, "tests/bpf_fixtures/cpi_programs/acct5.bin"); // 21B system marker

    // Seed the 7 accounts. Program accounts carry their ELF as data (so
    // resolveProgramSbpfVersion can read e_flags → V3). ATA absent (lam=0).
    try seed(db, ATA_PROG, OWN_BPF2, 2731913600, true, ata_elf);
    try seed(db, FUNDER, OWN_SYSTEM, FUNDER_PRE, false, &[_]u8{});
    try seed(db, ATA, OWN_SYSTEM, 0, false, &[_]u8{});
    try seed(db, WALLET, OWN_RESTAKE, 4510080, false, wallet_data);
    // NB: the MINT is intentionally NOT seeded to rooted db — it is written into
    // pending_writes below (collectWrite), modeling "created+initialized THIS
    // slot" (the live ix1/ix2), the untested axis (advisor's decisive test).
    try seed(db, SYS_PROG, OWN_NATIVE, 1, true, sys_data);
    try seed(db, TOKEN_PROG, OWN_BPF_UP, 11141440, true, token_elf);
    try seed(db, SYSVAR_RENT, OWN_SYSVAR, 1009200, false, &RENT_DATA);

    // Pre-warm the process-global V2 program cache (live replay's warm cache;
    // the inner Token CPI resolves via cache-get, no load-on-miss).
    const cache = replay.getOrInitV2ProgramCache(alloc);
    try putCache(cache, ATA_PROG, ata_elf);
    try putCache(cache, TOKEN_PROG, token_elf);

    vex_bpf2.dispatch_mode.setMode(.v2);

    const bank = try Bank.init(alloc, BANK_SLOT, SEED_SLOT, Hash{ .data = [_]u8{0} ** 32 }, vex_crypto.LtHash.init(), Hash{ .data = [_]u8{0} ** 32 });
    defer bank.deinit();

    // Build the ParsedTx. Canonical account order so isWritable() is correct:
    //   [0]=funder (writable signer), [1]=ata, [2]=wallet, [3]=mint (writable
    //   non-signers), [4]=ata_program, [5]=system, [6]=token (readonly).
    // Account order: writable signers [funder, newacct], writable non-signers
    // [ata, wallet, mint], readonly [ata_program, system, token].
    var account_keys = [_][32]u8{ FUNDER, NEWACCT, ATA, WALLET, MINT, ATA_PROG, SYS_PROG, TOKEN_PROG };
    // ix0 = System CreateAccount (funder creates a NEW account) — models the live
    // ix1 mint-create: a freshly-CREATED account in pending_writes before the
    // ATA-CPI. The 2-ix Transfer variant (modifying EXISTING accts) did NOT
    // reproduce; this tests whether a *created* account is the trigger.
    const CREATE_LAMP: u64 = 2_000_000;
    var create_accts = [_]u8{ 0, 1 }; // from=funder, to=newacct (both signers)
    var create_data: [52]u8 = [_]u8{0} ** 52; // CreateAccount(0) + lamports + space=0 + owner=System(zeros)
    std.mem.writeInt(u64, create_data[4..12], CREATE_LAMP, .little);
    // ix1 = ATA createIdempotent (payer, ata, wallet, mint, system, token).
    var ata_accts = [_]u8{ 0, 2, 3, 4, 6, 7 };
    var ata_data = [_]u8{0x01};
    var instrs = [_]replay.ParsedInstruction{
        .{ .program_id_index = 6, .account_indices = &create_accts, .data = &create_data }, // System
        .{ .program_id_index = 5, .account_indices = &ata_accts, .data = &ata_data }, // ATA program
    };
    const blockhash = [_]u8{0} ** 32;
    const ptx = replay.ParsedTx{
        .num_sigs = 2,
        .num_required_sigs = 2,
        .num_readonly_signed = 0,
        .num_readonly_unsigned = 3, // ata_program, system, token
        .account_keys = &account_keys,
        .num_accounts = 8,
        .blockhash = &blockhash,
        .instructions = &instrs,
        .num_instructions = 2,
        .fee_payer = FUNDER,
        .static_key_count = 8,
        .alt_writable_count = 0,
    };

    // Model the tx-level FEE debit on the fee payer (funder) — happens BEFORE the
    // instruction loop (replay_stage.zig:4405-4428: collectWrite funder-=fee).
    // fee = 2 sigs * 5000 = 10000, matching the recorder (funder's surviving
    // write = fee + rent(82)). This is the ONE condition the 3 passing synthetics
    // lacked: a tx-level fee write to the funder before the instruction loop.
    const FEE: u64 = 10_000;
    {
        const f_old = Bank.accountLtHash(&FUNDER, &OWN_SYSTEM, FUNDER_PRE, false, &[_]u8{});
        const f_new = Bank.accountLtHash(&FUNDER, &OWN_SYSTEM, FUNDER_PRE - FEE, false, &[_]u8{});
        bank.collectWrite(.{
            .pubkey = .{ .data = FUNDER },
            .lamports = FUNDER_PRE - FEE,
            .owner = .{ .data = OWN_SYSTEM },
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = &[_]u8{},
            .old_lt = f_old,
            .new_lt = f_new,
        }) catch {};
    }
    // ADVISOR DECISIVE TEST (the real axis): the MINT lives in pending_writes
    // (created+initialized THIS slot via ix1/ix2 live), NOT rooted db. If
    // v2DispatchInternal's snaps-building threads the pending_writes DATA to the
    // ATA's mint read → ATA lands. If it reads rooted (miss/empty) → "Invalid
    // Mint" → ZERO muts (M4_RunFailed → return &[_]AccountMutation{}, err=0) →
    // ATA dropped + funder under-debited = the EXACT live footprint.
    {
        const m_old = Bank.accountLtHash(&MINT, &OWN_SYSTEM, 0, false, &[_]u8{}); // pre: absent
        const m_new = Bank.accountLtHash(&MINT, &OWN_TOKEN, 1461600, false, mint_data);
        bank.collectWrite(.{
            .pubkey = .{ .data = MINT },
            .lamports = 1461600,
            .owner = .{ .data = OWN_TOKEN },
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = mint_data,
            .old_lt = m_old,
            .new_lt = m_new,
        }) catch {};
    }
    // ── Force MODE-3 (vasa + direct_mapping) — the LIVE path. ──────────────────
    // At feature_set=null this ran MODE-1 (vasa=false): Loop-1 copies the data and
    // the carrier NEVER fires (vacuous green). Production PR5AF-MODE-PROBE shows
    // vasa=true ddm=true. advisor 2026-06-01: vasa=false→ATA lands; vasa=true→ATA
    // DROPS = production. Force MODE-3 so this test drives the real seam.
    var fs = vex_svm.features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, vex_svm.features.VIRTUAL_ADDRESS_SPACE_ADJUSTMENTS, 0);
    try fs.activate(alloc, vex_svm.features.ACCOUNT_DATA_DIRECT_MAPPING, 0);
    const fs_ptr: *const vex_svm.features.FeatureSet = &fs;

    // ix0: native System createAccount — 2nd funder write (models the live ix1).
    try replay.executeSystemInstruction(instrs[0], &ptx, bank, db, alloc, &[_]u64{});
    // ix1: the ATA create (the carrier) through the REAL dispatch+commit seam —
    // does the CPI-created account STILL land now a prior funder write exists?
    try replay.dispatchBpfExecution(instrs[1], &ptx, bank, db, alloc, fs_ptr);

    // Inspect pending_writes: did the CPI-created ATA land? funder debited?
    var ata_found = false;
    var ata_lamports: u64 = 0;
    var ata_owner: [32]u8 = undefined;
    var funder_final: ?u64 = null;
    for (bank.pending_writes.items) |w| {
        if (std.mem.eql(u8, &w.pubkey.data, &ATA)) {
            ata_found = true;
            ata_lamports = w.lamports;
            ata_owner = w.owner.data;
        }
        if (std.mem.eql(u8, &w.pubkey.data, &FUNDER)) funder_final = w.lamports;
    }

    std.debug.print(
        "\n[CPI-CARRIER-DISPATCH] pending_writes={d}\n  ATA landed={} lamports={d} (expect {d}) owner_is_token={}\n  funder_final={?d} (expect {d} = pre-{d})\n",
        .{
            bank.pending_writes.items.len,
            ata_found,
            ata_lamports,
            RENT_165,
            std.mem.eql(u8, &ata_owner, &OWN_TOKEN),
            funder_final,
            FUNDER_PRE - FEE - CREATE_LAMP - RENT_165,
            RENT_165,
        },
    );

    // Ground-truth assertions (accounts_post == Agave canonical). If these FAIL,
    // the carrier is reproduced in the dispatchBpfExecution seam.
    try std.testing.expect(ata_found); // ATA must be CREATED (live: 0 writes)
    try std.testing.expectEqual(RENT_165, ata_lamports);
    try std.testing.expect(std.mem.eql(u8, &ata_owner, &OWN_TOKEN));
    try std.testing.expectEqual(@as(?u64, FUNDER_PRE - FEE - CREATE_LAMP - RENT_165), funder_final);
}

// ─────────────────────────────────────────────────────────────────────────
// UnbalancedInstruction KAT (fix 9c94af4, carrier slot 419369596)
// ─────────────────────────────────────────────────────────────────────────
//
// Real-world carrier: Jito ChangeTipReceiverV1 directly rewrote two accounts'
// lamports to a NET-DESTRUCTIVE total (+150000000 / -300000000) with ZERO
// CPI — a raw in-VM memory write to the input region's lamports field,
// exactly like a hand-written eBPF program would. The cluster rejected it
// (InstructionError::UnbalancedInstruction); pre-fix Vexor committed it.
//
// These two tests drive REAL hand-stitched sBPF v3 programs (built by
// `buildV3Elf` above) through the ACTUAL production path
// (`replay.dispatchBpfExecution` → `dispatchV3ViaV2Producer` →
// `v2_dispatch.v2DispatchBpfProgram`) — not a unit-test of the invariant
// math in isolation. Each program does a RAW `stxdw [lamports_addr], r]`
// write straight into the serialized input region's lamports field (no
// syscall, no CPI), mirroring the Jito carrier's own mechanism.
//
// HOW THE UNBALANCED CASE IS CONSTRUCTED (for audit):
//   `v2DispatchBpfProgram` maps the VM's input region at the FIXED vaddr
//   `serialize.INPUT_START` (0x400000000) from the exact `serialized.bytes`
//   buffer `serialize2.serializeParametersAligned` produces. Each non-dup
//   declared account's lamports field sits at a vaddr computable via the
//   SAME serializer function: header(8) + marker/flags/pad(8) + pubkey(32)
//   + owner(32) = +80 bytes for the first (only) account in a 1-account
//   instruction. Rather than hand-derive that formula, the test calls
//   `serialize2.serializeParametersAligned` ITSELF, with the identical
//   `AccountInput` values (order, lamports, data length, vasa+dm cfg) the
//   real dispatch will use, and reads `account_layouts[i].vm_lamports_addr`
//   straight out of the result. That address is then embedded as an `lddw`
//   immediate in the hand-stitched program, so the program's raw store lands
//   exactly on the real dispatch's lamports field — no guessing, no
//   approximation.
//
//   Unbalanced program (single writable account, no CPI):
//     r1 = lddw ADDR_A                  ; ADDR_A = precomputed vm_lamports_addr
//     r2 = ldxdw [r1+0]                 ; read current lamports
//     r2 = r2 + DELTA                   ; DELTA = +500000 — no offsetting debit
//     stxdw [r1+0], r2                  ; write back — Σ changed by +DELTA
//     r0 = 0 ; exit
//   The instruction declares EXACTLY ONE writable account (A). The fix's
//   post-loop check sums `s.lamports` (pre) vs `post_lamports` (post) over
//   writable non-dup declared accounts — here that set is {A} alone, so
//   Σpre=A_LAMPORTS, Σpost=A_LAMPORTS+DELTA, Σpre≠Σpost ⇒ UnbalancedInstruction
//   ⇒ `v2DispatchBpfProgram` returns `error.M4_RunFailed`, which propagates
//   unchanged through `dispatchV3ViaV2Producer`/`dispatchBpfExecution`
//   (PROVEN propagation path per the 9c94af4 commit message).
//
//   Balanced CONTROL program (two writable accounts, conserving move):
//     r1 = lddw ADDR_A ; r2 = ldxdw[r1] ; r2 -= N ; stxdw[r1], r2
//     r3 = lddw ADDR_B ; r4 = ldxdw[r3] ; r4 += N ; stxdw[r3], r4
//     r0 = 0 ; exit
//   Σ over {A,B} is invariant (−N then +N cancel) — models the ~946 benign
//   dm-splits seen live. Dispatch must NOT return M4_RunFailed here; this is
//   the false-positive guard (the #1 risk of the 9c94af4 fix).

fn lddwImmParts(addr: u64) struct { lo: i32, hi: i32 } {
    return .{
        .lo = @bitCast(@as(u32, @truncate(addr))),
        .hi = @bitCast(@as(u32, @truncate(addr >> 32))),
    };
}

test "UnbalancedInstruction KAT: single writable account bumps lamports with no offsetting debit -> M4_RunFailed" {
    const alloc = std.testing.allocator;
    const enc = vex_bpf2.interpreter.encode;
    const opc = vex_bpf2.interpreter.opc;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(path);

    const db = try AccountsDb.init(alloc, path, null);
    defer db.deinit();

    const ACCT_A_LAMPORTS: u64 = 5_000_000;
    const DELTA: i32 = 500_000; // net lamports MANUFACTURED out of nowhere

    // ── Precompute the REAL vm_lamports_addr the production serializer will
    // assign to ACCT_UNBAL_A, using the identical AccountInput shape (order,
    // lamports, empty data, vasa+dm cfg) the live dispatch will feed it. See
    // the file-level comment above for why this replaces hand-derivation.
    const addr_a: u64 = blk: {
        const precompute_inputs = [_]vex_bpf2.serialize.AccountInput{.{
            .pubkey = ACCT_UNBAL_A,
            .owner = OWN_SYSTEM,
            .lamports = ACCT_A_LAMPORTS,
            .data = &[_]u8{},
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .is_signer = false,
            .is_writable = true,
        }};
        const precomp = try vex_bpf2.serialize.serializeParametersAligned(
            alloc,
            PROG_UNBAL,
            &[_]u8{},
            &precompute_inputs,
            .{ .virtual_address_space_adjustments = true, .account_data_direct_mapping = true },
        );
        defer alloc.free(precomp.bytes);
        defer alloc.free(precomp.account_layouts);
        defer if (precomp.input_regions.len > 0) alloc.free(precomp.input_regions);
        defer if (precomp.acc_region_metas.len > 0) alloc.free(precomp.acc_region_metas);
        break :blk precomp.account_layouts[0].vm_lamports_addr;
    };
    const addr_parts = lddwImmParts(addr_a);

    // ── Build the raw sBPF v3 program: r2 = *(u64*)(r1) + DELTA; store back.
    var prog = std.ArrayList(u8){};
    defer prog.deinit(alloc);
    try prog.appendSlice(alloc, &enc(opc.ld_dw_imm, 1, 0, 0, addr_parts.lo));
    try prog.appendSlice(alloc, &enc(0, 0, 0, 0, addr_parts.hi));
    try prog.appendSlice(alloc, &enc(opc.ld_dw_reg, 2, 1, 0, 0)); // r2 = [r1+0]
    try prog.appendSlice(alloc, &enc(opc.add64_imm, 2, 0, 0, DELTA)); // r2 += DELTA
    try prog.appendSlice(alloc, &enc(opc.st_dw_reg, 1, 2, 0, 0)); // [r1+0] = r2
    try prog.appendSlice(alloc, &enc(opc.mov64_imm, 0, 0, 0, 0)); // r0 = 0
    try prog.appendSlice(alloc, &enc(opc.exit, 0, 0, 0, 0));

    const elf_bytes = try buildV3Elf(alloc, prog.items);
    defer alloc.free(elf_bytes);

    try seed(db, ACCT_UNBAL_A, OWN_SYSTEM, ACCT_A_LAMPORTS, false, &[_]u8{});
    try seed(db, PROG_UNBAL, OWN_BPF2, 2_000_000, true, elf_bytes);

    const cache = replay.getOrInitV2ProgramCache(alloc);
    try putCache(cache, PROG_UNBAL, elf_bytes);

    vex_bpf2.dispatch_mode.setMode(.v2);

    const bank = try Bank.init(alloc, BANK_SLOT, SEED_SLOT, Hash{ .data = [_]u8{0} ** 32 }, vex_crypto.LtHash.init(), Hash{ .data = [_]u8{0} ** 32 });
    defer bank.deinit();

    // account_keys = [ACCT_UNBAL_A (writable, non-signer), PROG_UNBAL (readonly)].
    var account_keys = [_][32]u8{ ACCT_UNBAL_A, PROG_UNBAL };
    var account_indices = [_]u8{0}; // ONLY ACCT_UNBAL_A is declared to the instruction
    var ix_data = [_]u8{};
    var instrs = [_]replay.ParsedInstruction{
        .{ .program_id_index = 1, .account_indices = &account_indices, .data = &ix_data },
    };
    const blockhash = [_]u8{0} ** 32;
    const ptx = replay.ParsedTx{
        .num_sigs = 0,
        .num_required_sigs = 0,
        .num_readonly_signed = 0,
        .num_readonly_unsigned = 1, // PROG_UNBAL is readonly
        .account_keys = &account_keys,
        .num_accounts = 2,
        .blockhash = &blockhash,
        .instructions = &instrs,
        .num_instructions = 1,
        .fee_payer = ACCT_UNBAL_A,
        .static_key_count = 2,
        .alt_writable_count = 0,
    };

    // Force MODE-3 (vasa + direct_mapping) — the LIVE testnet regime, same as
    // the FIX#95 test above and the same cfg used in the address precompute.
    var fs = vex_svm.features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, vex_svm.features.VIRTUAL_ADDRESS_SPACE_ADJUSTMENTS, 0);
    try fs.activate(alloc, vex_svm.features.ACCOUNT_DATA_DIRECT_MAPPING, 0);
    const fs_ptr: *const vex_svm.features.FeatureSet = &fs;

    const result = replay.dispatchBpfExecution(instrs[0], &ptx, bank, db, alloc, fs_ptr);

    std.debug.print(
        "\n[UNBALANCED-KAT] result={any} pending_writes={d} (expect error.M4_RunFailed, 0 writes)\n",
        .{ result, bank.pending_writes.items.len },
    );

    // The fix must reject this instruction exactly as the cluster did
    // (InstructionError::UnbalancedInstruction ≈ M4_RunFailed, fee-only
    // rollback) — NOT commit the manufactured +DELTA lamports.
    try std.testing.expectError(error.M4_RunFailed, result);
    // Belt-and-suspenders: the unbalanced write must not have landed in
    // pending_writes (v2DispatchBpfProgram's errdefer frees `list` on this
    // return path — commitV2Mutations is never reached).
    try std.testing.expectEqual(@as(usize, 0), bank.pending_writes.items.len);
}

test "UnbalancedInstruction KAT (control): conserving A-to-B lamport move does NOT trip M4_RunFailed" {
    const alloc = std.testing.allocator;
    const enc = vex_bpf2.interpreter.encode;
    const opc = vex_bpf2.interpreter.opc;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(path);

    const db = try AccountsDb.init(alloc, path, null);
    defer db.deinit();

    const ACCT_A_LAMPORTS: u64 = 5_000_000;
    const ACCT_B_LAMPORTS: u64 = 1_000_000;
    const N: i32 = 250_000; // conserving move: A -= N, B += N (Σ invariant)

    // Precompute BOTH accounts' vm_lamports_addr in ONE call, in the SAME
    // order the instruction declares them (A then B) — mirrors exactly what
    // the real dispatch's serializer will produce.
    const addrs: struct { a: u64, b: u64 } = blk: {
        const precompute_inputs = [_]vex_bpf2.serialize.AccountInput{
            .{
                .pubkey = ACCT_BAL_A,
                .owner = OWN_SYSTEM,
                .lamports = ACCT_A_LAMPORTS,
                .data = &[_]u8{},
                .executable = false,
                .rent_epoch = std.math.maxInt(u64),
                .is_signer = false,
                .is_writable = true,
            },
            .{
                .pubkey = ACCT_BAL_B,
                .owner = OWN_SYSTEM,
                .lamports = ACCT_B_LAMPORTS,
                .data = &[_]u8{},
                .executable = false,
                .rent_epoch = std.math.maxInt(u64),
                .is_signer = false,
                .is_writable = true,
            },
        };
        const precomp = try vex_bpf2.serialize.serializeParametersAligned(
            alloc,
            PROG_BAL,
            &[_]u8{},
            &precompute_inputs,
            .{ .virtual_address_space_adjustments = true, .account_data_direct_mapping = true },
        );
        defer alloc.free(precomp.bytes);
        defer alloc.free(precomp.account_layouts);
        defer if (precomp.input_regions.len > 0) alloc.free(precomp.input_regions);
        defer if (precomp.acc_region_metas.len > 0) alloc.free(precomp.acc_region_metas);
        break :blk .{
            .a = precomp.account_layouts[0].vm_lamports_addr,
            .b = precomp.account_layouts[1].vm_lamports_addr,
        };
    };
    const parts_a = lddwImmParts(addrs.a);
    const parts_b = lddwImmParts(addrs.b);

    var prog = std.ArrayList(u8){};
    defer prog.deinit(alloc);
    try prog.appendSlice(alloc, &enc(opc.ld_dw_imm, 1, 0, 0, parts_a.lo));
    try prog.appendSlice(alloc, &enc(0, 0, 0, 0, parts_a.hi));
    try prog.appendSlice(alloc, &enc(opc.ld_dw_reg, 2, 1, 0, 0)); // r2 = lamports[A]
    try prog.appendSlice(alloc, &enc(opc.add64_imm, 2, 0, 0, -N)); // r2 -= N
    try prog.appendSlice(alloc, &enc(opc.st_dw_reg, 1, 2, 0, 0)); // lamports[A] = r2
    try prog.appendSlice(alloc, &enc(opc.ld_dw_imm, 3, 0, 0, parts_b.lo));
    try prog.appendSlice(alloc, &enc(0, 0, 0, 0, parts_b.hi));
    try prog.appendSlice(alloc, &enc(opc.ld_dw_reg, 4, 3, 0, 0)); // r4 = lamports[B]
    try prog.appendSlice(alloc, &enc(opc.add64_imm, 4, 0, 0, N)); // r4 += N
    try prog.appendSlice(alloc, &enc(opc.st_dw_reg, 3, 4, 0, 0)); // lamports[B] = r4
    try prog.appendSlice(alloc, &enc(opc.mov64_imm, 0, 0, 0, 0)); // r0 = 0
    try prog.appendSlice(alloc, &enc(opc.exit, 0, 0, 0, 0));

    const elf_bytes = try buildV3Elf(alloc, prog.items);
    defer alloc.free(elf_bytes);

    try seed(db, ACCT_BAL_A, OWN_SYSTEM, ACCT_A_LAMPORTS, false, &[_]u8{});
    try seed(db, ACCT_BAL_B, OWN_SYSTEM, ACCT_B_LAMPORTS, false, &[_]u8{});
    try seed(db, PROG_BAL, OWN_BPF2, 2_000_000, true, elf_bytes);

    const cache = replay.getOrInitV2ProgramCache(alloc);
    try putCache(cache, PROG_BAL, elf_bytes);

    vex_bpf2.dispatch_mode.setMode(.v2);

    const bank = try Bank.init(alloc, BANK_SLOT, SEED_SLOT, Hash{ .data = [_]u8{0} ** 32 }, vex_crypto.LtHash.init(), Hash{ .data = [_]u8{0} ** 32 });
    defer bank.deinit();

    // account_keys = [ACCT_BAL_A (writable), ACCT_BAL_B (writable), PROG_BAL (readonly)].
    var account_keys = [_][32]u8{ ACCT_BAL_A, ACCT_BAL_B, PROG_BAL };
    var account_indices = [_]u8{ 0, 1 };
    var ix_data = [_]u8{};
    var instrs = [_]replay.ParsedInstruction{
        .{ .program_id_index = 2, .account_indices = &account_indices, .data = &ix_data },
    };
    const blockhash = [_]u8{0} ** 32;
    const ptx = replay.ParsedTx{
        .num_sigs = 0,
        .num_required_sigs = 0,
        .num_readonly_signed = 0,
        .num_readonly_unsigned = 1, // PROG_BAL is readonly
        .account_keys = &account_keys,
        .num_accounts = 3,
        .blockhash = &blockhash,
        .instructions = &instrs,
        .num_instructions = 1,
        .fee_payer = ACCT_BAL_A,
        .static_key_count = 3,
        .alt_writable_count = 0,
    };

    var fs = vex_svm.features.FeatureSet.init();
    defer fs.deinit(alloc);
    try fs.activate(alloc, vex_svm.features.VIRTUAL_ADDRESS_SPACE_ADJUSTMENTS, 0);
    try fs.activate(alloc, vex_svm.features.ACCOUNT_DATA_DIRECT_MAPPING, 0);
    const fs_ptr: *const vex_svm.features.FeatureSet = &fs;

    // MUST NOT return M4_RunFailed (or any error) — this is the false-positive guard.
    try replay.dispatchBpfExecution(instrs[0], &ptx, bank, db, alloc, fs_ptr);

    var a_final: ?u64 = null;
    var b_final: ?u64 = null;
    for (bank.pending_writes.items) |w| {
        if (std.mem.eql(u8, &w.pubkey.data, &ACCT_BAL_A)) a_final = w.lamports;
        if (std.mem.eql(u8, &w.pubkey.data, &ACCT_BAL_B)) b_final = w.lamports;
    }

    std.debug.print(
        "\n[BALANCED-CONTROL-KAT] a_final={?d} (expect {d}) b_final={?d} (expect {d})\n",
        .{ a_final, ACCT_A_LAMPORTS - N, b_final, ACCT_B_LAMPORTS + N },
    );

    try std.testing.expectEqual(@as(?u64, ACCT_A_LAMPORTS - @as(u64, @intCast(N))), a_final);
    try std.testing.expectEqual(@as(?u64, ACCT_B_LAMPORTS + @as(u64, @intCast(N))), b_final);
}
