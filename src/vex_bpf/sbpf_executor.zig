//! Vexor SBPF Executor
//!
//! Drives the native Zig SBPF VM against a serialised Solana instruction context.
//!
//! Execution pipeline:
//!   1. Serialise accounts into the Solana BPF v1 input format
//!   2. Initialise VmContext with 4 memory regions
//!   3. Register all syscalls
//!   4. Execute via BpfVm.execute()
//!   5. Deserialise mutated account state from the (now-modified) input buffer
//!   6. Return only accounts whose state changed
//!
//! CPI fallback: if the program calls sol_invoke_signed the VM surfaces
//! VmError.CpiRequired. The executor returns an empty mutation list and the
//! caller (bank.executeBpfProgram) uses the RPC shadow path for that slot.
//!
//! Future: when we have a full CPI stack, remove the CpiRequired path.

const std = @import("std");
const core = @import("core");
const storage = @import("vex_store");
const bpf = @import("root.zig");
const interp = @import("interpreter.zig");
const syscalls = @import("syscalls.zig");

const BpfVm = interp.BpfVm;
const VmContext = interp.VmContext;
const VmError = interp.VmError;

// Max account data realloc allowed inside VM (10 KiB, matches Agave)
const MAX_REALLOC: usize = 10 * 1024;

// ── Public types ──────────────────────────────────────────────────────────────

pub const AccountEntry = struct {
    pubkey: core.Pubkey,
    owner: core.Pubkey,
    lamports: u64,
    data: []const u8,
    executable: bool,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
};

pub const AccountMutation = struct {
    pubkey: core.Pubkey,
    new_lamports: u64,
    /// vex-039 / core-r10-bpf-owner restored 2026-05-22: post-mutation owner
    /// bytes read by deserialise() from the BPF input region at the
    /// (lamports_offset - 32) window. V1's commit path in
    /// `replay_stage.executeBpfProgram` MUST use these bytes for new_lt + the
    /// pending AccountWrite.owner — otherwise owner-mutating BPF txs (CPI
    /// to system_program::Assign, owner-transfer ix, PDA creation) silently
    /// drop the owner change, desyncing the bank LtHash accumulator from
    /// Agave for every such slot.
    owner: [32]u8,
    data: []u8, // caller owns
    /// Wave 5: optional owner-change (V2 path only). `null` ⇒ V2 didn't
    /// report a change. V2 dispatch sets this from M5 `AccountOutput.owner`
    /// when it differs from pre-state. V1 path reads `.owner` above, not
    /// this field (preserves vex-079 / vex-039 invariants).
    new_owner: ?[32]u8 = null,
};

// ── Executor ──────────────────────────────────────────────────────────────────

/// fix/proactive-trio FIX-1a (2026-06-10, task #65 — sibling of carrier #6
/// @414386920): classification of the TOP-LEVEL (cpi_depth==0) program run.
/// Pre-fix, executeInner converted EVERY failure into an empty-mutation
/// SUCCESS, so a multi-instruction tx whose V1-ELF instruction genuinely
/// aborted after an earlier writing instruction LEAKED the earlier writes
/// (Agave message_processor.rs stops at the first InstructionError and
/// account_saver.rs keeps only rollback accounts). The executor still
/// RETURNS an empty slice on failure (signature unchanged for all callers,
/// incl. recursive CPI), but now records WHY, so executeBpfProgramCore can
/// propagate genuine program failures to the tx-rollback loops.
///
/// Taxonomy (per-variant, see the FIX-1a commit message table):
///   .program_error     — program ran to completion and returned r0 != 0
///                        (incl. abort()/sol_panic_, which now force r0=1,
///                        matching Agave: SyscallError::Abort/Panic ALWAYS
///                        fails the instruction) → GENUINE tx failure.
///   .vm_fault          — interpreter fault (AccessViolation, bad insn, …).
///                        Agave would also fail here IF the fault were real,
///                        but Vexor's V1 interpreter has KNOWN spurious
///                        faults (r75-bug-class-b pc=43931 wild-pointer
///                        class) → UNKNOWN: kept non-fatal + loud counter.
///   .compute_exceeded  — V1 insn-count limit hit. Vexor V1 meters raw
///                        instructions, NOT Agave compute-units (no syscall
///                        costs, no requested-CU budget) → the signal is not
///                        faithful → UNKNOWN: kept non-fatal + loud counter.
///   .plumbing          — Vexor infrastructure didn't run the program to a
///                        verdict (CPI deferral, VM init, syscall registry,
///                        OOM) → NEVER fails the tx.
pub const TopLevelRunOutcome = enum {
    ok,
    program_error,
    vm_fault,
    compute_exceeded,
    plumbing,
};

pub const SbpfExecutor = struct {
    allocator: std.mem.Allocator,

    /// Outcome of the most recent TOP-LEVEL run (cpi_depth==0 only; nested
    /// CPI runs never touch this). Read by replay_stage.executeBpfProgramCore
    /// immediately after execute() returns. Single-threaded per executor
    /// instance (one executor per instruction dispatch).
    last_top_outcome: TopLevelRunOutcome = .ok,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Execute a BPF program.
    ///
    /// Returns a slice of AccountMutation for writable accounts whose state
    /// changed. Caller must free each mutation.data and the slice itself.
    ///
    /// Returns an empty slice (not an error) when:
    ///   - The program reverted (non-zero r0 exit)
    ///   - The program used CPI (sol_invoke_signed) — caller should use RPC shadow
    ///   - Any other benign execution failure
    pub fn execute(
        self: *Self,
        program: *const bpf.LoadedProgram,
        accounts: []const AccountEntry,
        ix_data: []const u8,
        program_id: *const core.Pubkey,
    ) ![]AccountMutation {
        // PR-S4 Phase 2c-A: no bank context (fixture/test path) → bank_slot=0,
        // ancestors=&.{} causes getAccountInSlot to fall through to `_getRooted`,
        // preserving the legacy flat-rooted-read behavior byte-for-byte.
        return self.executeInner(program, accounts, ix_data, program_id, null, null, 0, 0, &[_]u64{});
    }

    /// Execute with CPI support. accounts_db is used to resolve accounts
    /// not present in the parent instruction's account list.
    /// PR-S4 Phase 2c-A: bank_slot + ancestors are threaded into CpiState so
    /// nested CPI loads in cpiHandler use ancestor-aware reads (closes the
    /// last facade leak in the production tx-replay path).
    pub fn executeWithAccounts(
        self: *Self,
        program: *const bpf.LoadedProgram,
        accounts: []const AccountEntry,
        ix_data: []const u8,
        program_id: *const core.Pubkey,
        accounts_db: ?*storage.AccountsDb,
        program_cache: ?*bpf_program_cache.BpfProgramCache,
        bank_slot: u64,
        ancestors: []const u64,
    ) ![]AccountMutation {
        return self.executeInner(program, accounts, ix_data, program_id, accounts_db, program_cache, 0, bank_slot, ancestors);
    }

    fn executeInner(
        self: *Self,
        program: *const bpf.LoadedProgram,
        accounts: []const AccountEntry,
        ix_data: []const u8,
        program_id: *const core.Pubkey,
        accounts_db: ?*storage.AccountsDb,
        program_cache: ?*bpf_program_cache.BpfProgramCache,
        cpi_depth: u8,
        bank_slot: u64,
        ancestors: []const u64,
    ) ![]AccountMutation {
        // r75-bug-class-b-2026-05-06: disable runtime safety at the PARENT
        // function level so the flag propagates to all inlined callees in the
        // call chain (deserialise, vm step, mutations.append, etc.). Function-
        // local @setRuntimeSafety on deserialise alone did NOT catch the panic
        // because Zig's safety scope is local — inlined code retains its own.
        // BPF spec semantics are wrapping arithmetic anyway; disabling Zig's
        // overflow checks here matches Solana behavior. After R_BPF_64_RELATIVE
        // relocations are applied (eba13d45-class), programs run their bodies
        // and may write degenerate values that trigger overflow in deeper code.
        @setRuntimeSafety(false);

        // FIX-1a: reset the top-level outcome at entry; every swallow point
        // below overrides it. Nested CPI runs (cpi_depth > 0) never touch it.
        if (cpi_depth == 0) self.last_top_outcome = .ok;

        const pid4 = .{
            program_id.data[0],  program_id.data[1],
            program_id.data[30], program_id.data[31],
        };

        // 1. Serialise accounts + ix data into the BPF v1 input buffer
        var input_buf = std.ArrayListUnmanaged(u8){};
        defer input_buf.deinit(self.allocator);

        var meta_list = try std.ArrayListUnmanaged(AccountMeta).initCapacity(self.allocator, accounts.len);
        defer meta_list.deinit(self.allocator);

        try serialise(self.allocator, &input_buf, &meta_list, accounts, ix_data, program_id);

        // r75-bug-class-b-2026-05-06: hex-dump first 256 bytes of input region
        // when GJHtFqM9 (Jito tip-payment, pid4=e34d3f98) is invoked. Provides
        // ground-truth bytes for byte-level diff against Agave abiv1 reference.
        // Capped at 32 dumps to prevent log flood.
        if (pid4[0] == 0xe3 and pid4[1] == 0x4d and pid4[2] == 0x3f and pid4[3] == 0x98) {
            const HexDumpC = struct {
                var n: u32 = 0;
            };
            if (HexDumpC.n < 1) {
                const dump_len = @min(input_buf.items.len, 256);
                var hex_buf: [512 + 1]u8 = undefined;
                const hex_chars = "0123456789abcdef";
                for (input_buf.items[0..dump_len], 0..) |b, idx| {
                    hex_buf[idx * 2] = hex_chars[b >> 4];
                    hex_buf[idx * 2 + 1] = hex_chars[b & 0xf];
                }
                hex_buf[dump_len * 2] = 0;
                std.log.warn("[BPF-INPUT-DUMP] prog=GJHt total_len={d} accts={d} first_{d}={s}", .{
                    input_buf.items.len, accounts.len, dump_len, hex_buf[0 .. dump_len * 2],
                });
                // Also dump per-account meta
                for (meta_list.items, 0..) |m, mi| {
                    std.log.warn("[BPF-INPUT-META] acct[{d}] lam_off={d} dat_off={d} dat_len={d} pubkey_idx={d}", .{
                        mi, m.lamports_offset, m.data_offset, m.data_len, m.pubkey_idx,
                    });
                }
                HexDumpC.n += 1;
            }
        }

        // 2. Build VmContext (VmState in Zig 0.15.2).
        // r48-A-rev2 (2026-04-27): use program.sbpf_version (parsed from ELF e_flags
        // in elf_loader.zig:parseSbpfVersionFromEflags) instead of hardcoded .v1.
        // V3 programs require this so vm.MemoryMap.init's enableLowerBytecodeVaddr()
        // predicate maps bytecode at vaddr 0 (not RODATA_START), preventing
        // AccessViolation at first instruction fetch.
        var ctx = VmContext.init(
            self.allocator,
            program.rodata_combined,
            program.rodata_vaddr,
            input_buf.items,
            program.sbpf_version,
            program.entry_pc,
        ) catch {
            if (cpi_depth == 0) self.last_top_outcome = .plumbing;
            return &[_]AccountMutation{};
        };
        defer ctx.deinit();

        // r75-bug-class-b-2026-05-06: SIMD-0321 — when active, r2 holds the
        // instruction_data_offset (raw byte offset from input region start),
        // NOT zero. Active on testnet since slot 388028256 (per Agave vm.rs).
        // V1 left r2=0 → Anchor's BPF entrypoint computed wrong ix_data ptr →
        // discriminator decoded as garbage → wrong handler dispatch → wild
        // pointer in pc=43931 LDX_64. Port from vex_bpf2 commit 21298a3.
        // Layout at end of serialise: [...acct_records] u64 ix_data_len
        // ix_data[ix_data_len] program_id[32]. So ix_data starts at:
        //   input_buf_len - 32 (program_id) - ix_data.len
        const ix_data_offset: u64 = input_buf.items.len -| 32 -| ix_data.len;
        ctx.regs[2] = ix_data_offset;

        // 3. Register syscalls
        syscalls.registerAll(&ctx) catch {
            if (cpi_depth == 0) self.last_top_outcome = .plumbing;
            return &[_]AccountMutation{};
        };

        // 4. Wire CPI handler so sol_invoke_signed works natively
        var cpi_state = CpiState{
            .executor = self,
            .accounts = accounts,
            .accounts_db = accounts_db,
            .program_cache = program_cache,
            .depth = cpi_depth,
            .bank_slot = bank_slot,
            .ancestors = ancestors,
        };
        ctx.cpi_ctx = @ptrCast(&cpi_state);
        ctx.cpi_handler = cpiHandler;

        // r71-fix-7e: thread the program's function registry into the VM so
        // JMP_CALL imm can resolve local function calls (murmur3 → PC). The
        // registry is owned by `program` (LoadedProgram); ctx only borrows.
        ctx.function_registry = &program.function_registry;

        // 5. Run the program
        const text = program.rodata_combined[program.text_offset..][0..program.text_size];

        const exit_code: u64 = BpfVm.execute(&ctx, text, program.entry_pc) catch |err| blk: {
            switch (err) {
                error.Halted => break :blk ctx.regs[0],
                error.CpiRequired => {
                    std.log.debug("[SBPF] CPI fallback — deferring to RPC shadow", .{});
                    // FIX-1a: Vexor deferral, the program reached no verdict
                    // → plumbing, must NOT fail the tx.
                    if (cpi_depth == 0) self.last_top_outcome = .plumbing;
                    return &[_]AccountMutation{};
                },
                error.InstructionLimitExceeded => {
                    std.log.debug("[SBPF] compute limit exceeded", .{});
                    // FIX-1a: V1 meters raw insns, not Agave CUs → signal not
                    // faithful → UNKNOWN class (non-fatal + loud counter at
                    // the executeBpfProgramCore boundary).
                    if (cpi_depth == 0) self.last_top_outcome = .compute_exceeded;
                    return &[_]AccountMutation{};
                },
                else => {
                    // [VMFAULT] env-gated diagnostic (observability only, no consensus
                    // effect): capture the EXACT faulting instruction + registers to
                    // localize the carrier (2026-06-18 PayEntry slot 416083630).
                    if (std.posix.getenv("VEX_VMFAULT_DEBUG") != null and cpi_depth == 0) {
                        const fpc = ctx.pc; // instruction index
                        const byte_off = fpc *% 8; // text is []u8; insn is 8 bytes at pc*8
                        if (byte_off + 8 <= text.len) {
                            const raw = std.mem.readInt(u64, text[byte_off..][0..8], .little);
                            const op: u8 = @truncate(raw);
                            const dstsrc: u8 = @truncate(raw >> 8);
                            const off: i16 = @bitCast(@as(u16, @truncate(raw >> 16)));
                            const imm: u32 = @truncate(raw >> 32);
                            std.log.warn("[VMFAULT] err={s} pc={d} ninsn={d} op=0x{x:0>2} dst=r{d} src=r{d} off={d} imm=0x{x} raw=0x{x:0>16} | r0=0x{x} r1=0x{x} r2=0x{x} r3=0x{x} r4=0x{x} r6=0x{x} r7=0x{x} r8=0x{x} r9=0x{x} r10=0x{x}", .{ @errorName(err), fpc, text.len / 8, op, dstsrc & 0x0f, (dstsrc >> 4) & 0x0f, off, imm, raw, ctx.regs[0], ctx.regs[1], ctx.regs[2], ctx.regs[3], ctx.regs[4], ctx.regs[6], ctx.regs[7], ctx.regs[8], ctx.regs[9], ctx.regs[10] });
                        } else {
                            std.log.warn("[VMFAULT] err={s} pc={d} byte_off={d} >= text.len {d} | r0=0x{x} r1=0x{x} r6=0x{x} r10=0x{x}", .{ @errorName(err), fpc, byte_off, text.len, ctx.regs[0], ctx.regs[1], ctx.regs[6], ctx.regs[10] });
                        }
                    }
                    // FIX-1a: interpreter fault. Would be genuine on Agave,
                    // but V1 has known spurious faults (pc=43931 class) →
                    // UNKNOWN class (non-fatal + loud counter).
                    if (cpi_depth == 0) self.last_top_outcome = .vm_fault;
                    return &[_]AccountMutation{};
                },
            }
        };

        if (exit_code != 0) {
            // FIX-1a: the program ran to completion and returned an error
            // (r0 != 0, incl. forced r0=1 from abort()/sol_panic_). Agave
            // records InstructionError::Custom(r0)/ProgramFailedToComplete
            // and FAILS the tx → genuine. Zero mutations for THIS instruction
            // (correct either way); the caller propagates the failure so the
            // tx-rollback loops can discard EARLIER instructions' writes.
            if (cpi_depth == 0) self.last_top_outcome = .program_error;
            if (std.posix.getenv("VEX_VMFAULT_DEBUG") != null and cpi_depth == 0) {
                std.log.warn("[VMEXIT] PROGRAM_ERROR exit_code(r0)=0x{x} depth={d} → 0 muts", .{ exit_code, cpi_depth });
            }
            return &[_]AccountMutation{};
        }

        // 6. Deserialise mutations
        const muts = try deserialise(self.allocator, input_buf.items, meta_list.items, accounts);
        if (std.posix.getenv("VEX_VMFAULT_DEBUG") != null and cpi_depth == 0) {
            std.log.warn("[VMEXIT] SUCCESS r0=0 depth={d} n_muts={d}", .{ cpi_depth, muts.len });
        }
        return muts;
    }
};

// ── CPI (Cross-Program Invocation) ────────────────────────────────────────────
//
// When a BPF program calls sol_invoke_signed, the syscall handler calls
// cpiHandler (registered via ctx.cpi_handler). This function:
//   1. Reads the SolInstruction from VM memory (r1 = VM ptr)
//   2. Reads the SolAccountInfo array from VM memory (r2 = VM ptr, r3 = len)
//   3. Resolves account state — first from the parent accounts list, then
//      from accounts_db for accounts not already loaded
//   4. Loads the invoked program's ELF from accounts_db
//   5. Recursively calls executeInner() with depth+1
//   6. Applies inner mutations back to the parent VM input buffer
//
// Solana C ABI structs (little-endian, 64-bit pointers):
//
//   SolInstruction (40 bytes):
//     +0  u64  program_id_ptr  → [32]u8 pubkey
//     +8  u64  accounts_ptr    → SolAccountMeta[]
//     +16 u64  accounts_len
//     +24 u64  data_ptr        → u8[]
//     +32 u64  data_len
//
//   SolAccountMeta (16 bytes):
//     +0  u64  pubkey_ptr      → [32]u8 pubkey
//     +8  u8   is_writable
//     +9  u8   is_signer
//     (6 bytes padding)
//
//   SolAccountInfo (64 bytes, passed in r2 for sol_invoke_signed):
//     +0  u64  key_ptr         → [32]u8 pubkey
//     +8  u64  lamports_ptr    → u64
//     +16 u64  data_len
//     +24 u64  data_ptr        → u8[]
//     +32 u64  owner_ptr       → [32]u8 pubkey
//     +40 u64  rent_epoch
//     +48 u8   is_signer
//     +49 u8   is_writable
//     +50 u8   executable
//     (13 bytes padding)

const CpiState = struct {
    executor: *SbpfExecutor,
    accounts: []const AccountEntry,
    accounts_db: ?*storage.AccountsDb,
    program_cache: ?*bpf_program_cache.BpfProgramCache,
    depth: u8,
    // PR-S4 Phase 2c-A (2026-05-15): fork-isolation context. When the BPF
    // execution comes from replay (`executeWithAccounts`), bank_slot is the
    // reading bank's slot and ancestors is the bank's ancestor chain. When
    // the entry is `execute()` (test/fixture), bank_slot=0 and ancestors=&.{}
    // — getAccountInSlot falls through to `_getRooted` (legacy behavior).
    // The `ancestors` slice points into `bank.ancestors_buf` which lives
    // for the bank's full lifetime, exceeding any BPF execution.
    bank_slot: u64,
    ancestors: []const u64,
};

const bpf_program_cache = @import("bpf_program_cache.zig");
const elf_loader = @import("elf_loader.zig");
const system_cpi = @import("system_cpi.zig");

// r71-fix-6: SolAccountInfo C ABI stride (executor doc: 64-byte stride).
const SOL_ACCT_INFO_STRIDE: u64 = 64;
const MAX_REALLOC_BUDGET_FOR_CPI: usize = 10 * 1024;

/// r71-fix-6: dispatch a System-program CPI without recursing into a nested
/// VM. Mirrors vex-152-W3's dispatchSystemCpi but lives in sbpf_executor
/// (the production path) instead of vm_syscalls (the dormant path). Reads
/// SolAccountInfo entries from the outer VM, builds AccountSlice (write-
/// through pointers into the input region), dispatches by u32 discriminator.
fn dispatchSystemCpiInner(
    vm_ctx: *VmContext,
    ix_data: []const u8,
    accts_vm: u64,
    accts_n: u64,
) VmError!u64 {
    // Read instruction discriminator (first 4 bytes, little-endian u32).
    if (ix_data.len < 4) return system_cpi.ERR_INVALID_INSTRUCTION;
    const disc = std.mem.readInt(u32, ix_data[0..4], .little);

    const parse = struct {
        fn one(vm: *VmContext, base: u64, idx: u64) ?system_cpi.AccountSlice {
            const off = base + idx * SOL_ACCT_INFO_STRIDE;
            const info_raw = vm.translateR(off, SOL_ACCT_INFO_STRIDE) catch return null;
            const key_vm = std.mem.readInt(u64, info_raw[0..8], .little);
            const lam_vm = std.mem.readInt(u64, info_raw[8..16], .little);
            const dlen = std.mem.readInt(u64, info_raw[16..24], .little);
            const data_vm = std.mem.readInt(u64, info_raw[24..32], .little);
            const owner_vm = std.mem.readInt(u64, info_raw[32..40], .little);
            const is_writable = info_raw[49] != 0;

            const lam_slice = vm.translate(lam_vm, 8, true) catch return null;
            const data_slice: []u8 = if (dlen > 0)
                (vm.translate(data_vm, dlen, true) catch return null)
            else
                lam_slice[0..0];
            const owner_slice = vm.translate(owner_vm, 32, true) catch return null;
            const dlen_hdr_slice: []u8 = if (data_vm >= 8)
                (vm.translate(data_vm - 8, 8, true) catch return null)
            else
                lam_slice[0..0];

            var pk: [32]u8 = .{0} ** 32;
            if (vm.translateR(key_vm, 32)) |k| {
                @memcpy(&pk, k[0..32]);
            } else |_| {}

            return .{
                .lamports_ptr = lam_slice,
                .data = data_slice,
                .data_len_hdr = dlen_hdr_slice,
                .owner_ptr = owner_slice,
                .realloc_capacity = MAX_REALLOC_BUDGET_FOR_CPI,
                .pubkey = pk,
                .is_writable = is_writable,
            };
        }
    }.one;

    const SystemCpiLog = struct {
        var n: u64 = 0;
    };
    const log_n_max: u64 = 32;

    switch (disc) {
        system_cpi.IX_TRANSFER => {
            if (accts_n < 2 or ix_data.len < 12) return system_cpi.ERR_INVALID_INSTRUCTION;
            const lamports = std.mem.readInt(u64, ix_data[4..12], .little);
            const from = parse(vm_ctx, accts_vm, 0) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const to = parse(vm_ctx, accts_vm, 1) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const rc = system_cpi.execTransfer(from, to, lamports);
            if (SystemCpiLog.n < log_n_max) {
                SystemCpiLog.n += 1;
                std.log.debug("[CPI-SYSTEM-V1] kind=Transfer lamports={d} rc={d}\n", .{ lamports, rc });
            }
            return rc;
        },
        system_cpi.IX_CREATE_ACCOUNT => {
            if (accts_n < 2 or ix_data.len < 52) return system_cpi.ERR_INVALID_INSTRUCTION;
            const lamports = std.mem.readInt(u64, ix_data[4..12], .little);
            const space = std.mem.readInt(u64, ix_data[12..20], .little);
            var owner: [32]u8 = undefined;
            @memcpy(&owner, ix_data[20..52]);
            const from = parse(vm_ctx, accts_vm, 0) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const to = parse(vm_ctx, accts_vm, 1) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const rc = system_cpi.execCreateAccount(from, to, lamports, space, owner);
            if (SystemCpiLog.n < log_n_max) {
                SystemCpiLog.n += 1;
                std.log.debug("[CPI-SYSTEM-V1] kind=CreateAccount lamports={d} space={d} rc={d}\n", .{ lamports, space, rc });
            }
            return rc;
        },
        system_cpi.IX_ALLOCATE => {
            if (accts_n < 1 or ix_data.len < 12) return system_cpi.ERR_INVALID_INSTRUCTION;
            const space = std.mem.readInt(u64, ix_data[4..12], .little);
            const tgt = parse(vm_ctx, accts_vm, 0) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const rc = system_cpi.execAllocate(tgt, space);
            if (SystemCpiLog.n < log_n_max) {
                SystemCpiLog.n += 1;
                std.log.debug("[CPI-SYSTEM-V1] kind=Allocate space={d} rc={d}\n", .{ space, rc });
            }
            return rc;
        },
        system_cpi.IX_ASSIGN => {
            if (accts_n < 1 or ix_data.len < 36) return system_cpi.ERR_INVALID_INSTRUCTION;
            var new_owner: [32]u8 = undefined;
            @memcpy(&new_owner, ix_data[4..36]);
            const tgt = parse(vm_ctx, accts_vm, 0) orelse return system_cpi.ERR_INVALID_INSTRUCTION;
            const rc = system_cpi.execAssign(tgt, new_owner);
            if (SystemCpiLog.n < log_n_max) {
                SystemCpiLog.n += 1;
                std.log.debug("[CPI-SYSTEM-V1] kind=Assign rc={d}\n", .{rc});
            }
            return rc;
        },
        else => return system_cpi.ERR_NOT_SUPPORTED,
    }
}

fn cpiHandler(
    raw_cpi_ctx: *anyopaque,
    vm_ctx: *VmContext,
    r1: u64, // VM ptr → SolInstruction (40 bytes)
    r2: u64, // VM ptr → SolAccountInfo array
    _: u64, // account_infos_len
    _: u64, // signers_seeds_ptr  (PDA verification — TODO)
    _: u64, // signers_seeds_len
) VmError!u64 {
    const cpi = @as(*CpiState, @ptrCast(@alignCast(raw_cpi_ctx)));

    // Depth guard — Solana allows max 4 levels of CPI nesting
    if (cpi.depth >= 4) {
        std.log.warn("[CPI] Max recursion depth reached", .{});
        return 1;
    }

    // ── Step 1: Deserialise SolInstruction ───────────────────────────────────
    const ix_raw = vm_ctx.translateR(r1, 40) catch return 1;
    const prog_id_ptr = std.mem.readInt(u64, ix_raw[0..8], .little);
    _ = std.mem.readInt(u64, ix_raw[8..16], .little);
    const accts_len = std.mem.readInt(u64, ix_raw[16..24], .little);
    const data_ptr = std.mem.readInt(u64, ix_raw[24..32], .little);
    const data_len = std.mem.readInt(u64, ix_raw[32..40], .little);

    if (accts_len > 64 or data_len > 10 * 1024) return 1; // sanity bounds

    const prog_id_bytes = vm_ctx.translateR(prog_id_ptr, 32) catch return 1;
    var program_id: core.Pubkey = undefined;
    @memcpy(&program_id.data, prog_id_bytes);

    const ix_data_bytes = if (data_len > 0)
        (vm_ctx.translateR(data_ptr, data_len) catch return 1)
    else
        &[_]u8{};

    // r71-fix-6 (2026-04-28): System program inline CPI dispatch (vex-152-W3
    // ported into the production cpiHandler path). When inner program_id is
    // the all-zero System program ID, dispatch to system_cpi.zig handlers
    // (execTransfer / execCreateAccount / execAllocate / execAssign) which
    // write through the VM input region pointers (lamports_ptr/data_ptr/
    // owner_ptr) so the outer BPF caller sees post-CPI state without any
    // merge step. Pre-fix: cpiHandler tried to load System program account
    // as a BPF ELF (line 363-407 below), failed, returned 1 → BPF program
    // saw CPI failure → mutations=0 → 12 PDAs at slot 484 never created.
    var sys_is_zeros: bool = true;
    for (program_id.data) |b| if (b != 0) {
        sys_is_zeros = false;
        break;
    };
    const cpi_dbg = std.posix.getenv("VEX_VMFAULT_DEBUG") != null;
    if (cpi_dbg) {
        std.log.warn("[CPI-IN] depth={d} sys={} prog={x:0>2}{x:0>2}..{x:0>2}{x:0>2} accts={d} data_len={d}", .{
            cpi.depth, sys_is_zeros, program_id.data[0], program_id.data[1], program_id.data[30], program_id.data[31], accts_len, data_len,
        });
    }
    if (sys_is_zeros) {
        const rc = dispatchSystemCpiInner(vm_ctx, ix_data_bytes, r2, accts_len);
        if (cpi_dbg) std.log.warn("[CPI-SYS] dispatchSystemCpiInner rc={any}", .{rc});
        return rc;
    }

    // ── Step 2: Deserialise SolAccountInfo array ─────────────────────────────
    // SolAccountInfo = 64 bytes each
    const acct_infos_raw = vm_ctx.translateR(r2, accts_len * 64) catch return 1;

    const alloc = cpi.executor.allocator;
    var inner_accounts = std.ArrayListUnmanaged(AccountEntry){};
    defer inner_accounts.deinit(alloc);

    for (0..accts_len) |i| {
        const base = i * 64;
        const key_ptr = std.mem.readInt(u64, acct_infos_raw[base..][0..8], .little);
        const lamports_ptr = std.mem.readInt(u64, acct_infos_raw[base + 8 ..][0..8], .little);
        const acct_data_len = std.mem.readInt(u64, acct_infos_raw[base + 16 ..][0..8], .little);
        const acct_data_ptr = std.mem.readInt(u64, acct_infos_raw[base + 24 ..][0..8], .little);
        const owner_ptr = std.mem.readInt(u64, acct_infos_raw[base + 32 ..][0..8], .little);
        const rent_epoch = std.mem.readInt(u64, acct_infos_raw[base + 40 ..][0..8], .little);
        const is_signer = acct_infos_raw[base + 48] != 0;
        const is_writable = acct_infos_raw[base + 49] != 0;
        const executable = acct_infos_raw[base + 50] != 0;

        const key_bytes = vm_ctx.translateR(key_ptr, 32) catch continue;
        const owner_bytes = vm_ctx.translateR(owner_ptr, 32) catch continue;
        const lam_bytes = vm_ctx.translateR(lamports_ptr, 8) catch continue;

        var pubkey: core.Pubkey = undefined;
        var owner: core.Pubkey = undefined;
        @memcpy(&pubkey.data, key_bytes);
        @memcpy(&owner.data, owner_bytes);

        const lamports = std.mem.readInt(u64, lam_bytes[0..8], .little);

        const acct_data = if (acct_data_len > 0)
            (vm_ctx.translateR(acct_data_ptr, acct_data_len) catch &[_]u8{})
        else
            &[_]u8{};

        inner_accounts.append(alloc, .{
            .pubkey = pubkey,
            .owner = owner,
            .lamports = lamports,
            .data = acct_data,
            .executable = executable,
            .rent_epoch = rent_epoch,
            .is_signer = is_signer,
            .is_writable = is_writable,
        }) catch continue;
    }

    // ── Step 3: Load inner program from accounts_db ───────────────────────────
    const adb = cpi.accounts_db orelse {
        std.log.debug("[CPI] No accounts_db — cannot load program {}", .{program_id});
        return 1;
    };

    // PR-S4 Phase 2c-A (2026-05-15): ancestor-aware read via CpiState's
    // bank_slot/ancestors plumbed by `executeWithAccounts`. When entry was
    // `execute()` (no bank), ancestors.len==0 → falls through to `_getRooted`
    // (legacy behavior preserved). When entry was replay, fork-iso enforced.
    const prog_account = adb.getAccountInSlot(&program_id, cpi.bank_slot, cpi.ancestors) orelse {
        std.log.debug("[CPI] Program account not found: {}", .{program_id});
        return 1;
    };

    // Resolve ELF through BPFLoaderUpgradeable indirection if needed
    // BPFLoaderUpgradeable: BPFLoaderUpgradeab1e11111111111111111111111
    const BPF_LOADER_UPGRADEABLE = [_]u8{
        0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
        0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
        0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
        0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
    };
    const elf_data: []const u8 = blk: {
        if (std.mem.eql(u8, &prog_account.owner.data, &BPF_LOADER_UPGRADEABLE)) {
            if (prog_account.data.len >= 36) {
                const state = std.mem.readInt(u32, prog_account.data[0..4], .little);
                if (state == 2) { // Program variant
                    var pd_key: core.Pubkey = undefined;
                    @memcpy(&pd_key.data, prog_account.data[4..36]);
                    // PR-S4 Phase 2c-A: ancestor-aware (see comment above).
                    const pd_account = adb.getAccountInSlot(&pd_key, cpi.bank_slot, cpi.ancestors) orelse break :blk prog_account.data;
                    if (pd_account.data.len >= 45) break :blk pd_account.data[45..];
                }
            }
        }
        break :blk prog_account.data;
    };

    // Load or compile the program from cache or inline
    var inline_loaded: elf_loader.LoadedProgram = undefined;
    var inline_loaded_valid = false;
    const loaded: *const bpf.LoadedProgram = if (cpi.program_cache) |pc|
        pc.getOrLoad(&program_id, elf_data) orelse return 1
    else blk: {
        // No cache — load inline (slightly slower per CPI, but correct)
        var loader = elf_loader.ElfLoader.init(alloc);
        inline_loaded = loader.load(elf_data) catch return 1;
        inline_loaded_valid = true;
        break :blk &inline_loaded;
    };
    defer if (inline_loaded_valid) alloc.free(inline_loaded.rodata_combined);

    // ── Step 4: Execute inner program ─────────────────────────────────────────
    const mutations = cpi.executor.executeInner(
        loaded,
        inner_accounts.items,
        ix_data_bytes,
        &program_id,
        cpi.accounts_db,
        cpi.program_cache,
        cpi.depth + 1,
        // PR-S4 Phase 2c-A: forward bank-slot context into nested CPI so
        // depth>0 reads also see the ancestor-aware path (the d28aa/d28ff
        // carrier class lived at depth>0).
        cpi.bank_slot,
        cpi.ancestors,
    ) catch return 1;
    defer {
        for (mutations) |*m| alloc.free(m.data);
        alloc.free(mutations);
    }

    // ── Step 5: Write mutations back into parent VM input buffer ──────────────
    // Find each mutated account in the parent input_region by scanning the
    // serialised account data and updating lamports + data in-place.
    for (mutations) |mut| {
        // Scan parent accounts list to find offset in input buffer
        for (cpi.accounts) |parent_acct| {
            if (!std.mem.eql(u8, &parent_acct.pubkey.data, &mut.pubkey.data)) continue;

            // Input region is index 3 in memory map (program=0, stack=1, heap=2, input=3)
            const input_region = vm_ctx.memory_map.regions[3];
            const input_len = input_region.vm_end - input_region.vm_start;
            const input = input_region.host_ptr[0..input_len];

            // Search for this account's pubkey in the serialised buffer.
            // Account layout: [1 dup][1 signer][1 writable][1 exec][4 pad][32 pubkey][32 owner][8 lam][8 dlen][data...]
            // The pubkey starts at byte 8 of each account record.
            var scan: usize = 0;
            while (scan + 8 + 32 <= input.len) {
                if (std.mem.eql(u8, input[scan + 8 .. scan + 40], &parent_acct.pubkey.data)) {
                    // Found! Update lamports at scan+8+32+32 = scan+72
                    if (scan + 72 + 8 <= input.len) {
                        std.mem.writeInt(u64, input[scan + 72 ..][0..8], mut.new_lamports, .little);
                    }
                    // Update data length and data at scan+72+8=scan+80
                    if (scan + 80 + 8 <= input.len) {
                        const new_dlen = @min(mut.data.len, parent_acct.data.len + MAX_REALLOC);
                        std.mem.writeInt(u64, input[scan + 80 ..][0..8], @intCast(new_dlen), .little);
                        if (scan + 88 + new_dlen <= input.len) {
                            @memcpy(input[scan + 88 .. scan + 88 + new_dlen], mut.data[0..new_dlen]);
                        }
                    }
                    break;
                }
                // Skip to next account: 8 header + 32 pubkey + 32 owner + 8 lam + 8 dlen + data + MAX_REALLOC + alignPad + 8 rent
                // alignPad mirrors the writer (vex-V1-ALIGN, round6-beam-t2: BPF_ALIGN_OF_U128 = 16);
                // without it this walk drifts by up to 15 bytes per account whenever data_len % 16 != 0.
                const dlen_off = scan + 72 + 8;
                if (dlen_off + 8 > input.len) break;
                const dlen = std.mem.readInt(u64, input[dlen_off..][0..8], .little);
                const dlen_clamped = @min(dlen, 10 * 1024 * 1024);
                const align_pad = (16 - (dlen_clamped % 16)) % 16;
                scan = scan +| 88 +| dlen_clamped +| MAX_REALLOC +| align_pad +| 8;
            }
            break;
        }
    }

    std.log.debug("[CPI] Invoked {} with {} accounts, {} mutations applied", .{ program_id, accts_len, mutations.len });
    return 0; // success
}

// ── Serialisation ─────────────────────────────────────────────────────────────
//
// Solana BPF v1 (non-direct-mapping) input format:
//   For each account:
//     [u8  dup_marker]         0xFF = unique, else = index of original
//     if unique:
//       [u8  is_signer]
//       [u8  is_writable]
//       [u8  executable]
//       [u32 padding]
//       [32  pubkey]
//       [32  owner]
//       [u64 lamports]         ← lamports_offset
//       [u64 data_len]
//       [N   data]             ← data_offset  (program may write here)
//       [10240 realloc pad]    (zero-padded, program may grow data up to 10 KiB)
//       [u64 rent_epoch]
//   Footer:
//     [u64 ix_data_len]
//     [N   ix_data]
//     [32  program_id]

const AccountMeta = struct {
    is_writable: bool,
    /// vex-039 / core-r10-bpf-owner restored 2026-05-22: byte offset of the
    /// owner field within the serialized BPF input region. Default 0 keeps
    /// the is_dup branch's meta-append shape compatible (is_dup entries are
    /// skipped in deserialise() before any offset math, vex-033 invariant #4).
    /// Contract for non-dup entries: owner_offset == lamports_offset - 32.
    owner_offset: usize = 0,
    lamports_offset: usize,
    data_offset: usize,
    data_len: usize,
    pubkey_idx: usize,
};

fn serialise(
    allocator: std.mem.Allocator,
    buf: *std.ArrayListUnmanaged(u8),
    meta: *std.ArrayListUnmanaged(AccountMeta),
    accounts: []const AccountEntry,
    ix_data: []const u8,
    prog_id: *const core.Pubkey,
) !void {
    const w = buf.writer(allocator);

    // Leading u64 num_accounts — Agave serialization.rs:539 / Firedancer
    // fd_bpf_loader_serialization.c:283. Without this, programs read the
    // first 8 bytes as num_accounts and get garbage (first account's marker
    // byte + sign/writ/exec/pad), causing them to walk a wrong number of
    // accounts and panic via abort_/sol_panic_.
    try w.writeInt(u64, @intCast(accounts.len), .little);

    for (accounts, 0..) |acct, i| {
        // Dup-detection: linear scan earlier accounts for matching pubkey.
        // Agave serialization.rs:564-568 / Firedancer fd_bpf_loader_serialization.c:292-303.
        // Solana txns sanitise to ≤256 accounts; linear O(n²) is fine here.
        var dup_pos: ?u8 = null;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (std.mem.eql(u8, &acct.pubkey.data, &accounts[j].pubkey.data)) {
                dup_pos = @intCast(j);
                break;
            }
        }

        if (dup_pos) |pos| {
            // Dup encoding: position byte + 7 padding zeros = 8 bytes total.
            // Mirrors Firedancer's `FD_STORE(ulong, ..., 0UL); FD_STORE(uchar, ..., pos);`.
            // No meta entry needed — original already scans the same offsets in deserialise().
            try w.writeByte(pos);
            try buf.appendNTimes(allocator, 0, 7);
        } else {
            // Non-dup: full account record.
            try w.writeByte(0xFF); // NON_DUP_MARKER
            try w.writeByte(if (acct.is_signer) 1 else 0);
            try w.writeByte(if (acct.is_writable) 1 else 0);
            try w.writeByte(if (acct.executable) 1 else 0);
            try w.writeInt(u32, 0, .little); // 4-byte pad (`original_data_len` placeholder)
            try w.writeAll(&acct.pubkey.data);
            // vex-039 / core-r10-bpf-owner restored 2026-05-22: capture owner
            // offset for deserialise() to read post-mutation owner bytes.
            // Contract: own_off == lam_off - 32 (32-byte pubkey, no pad between).
            const own_off = buf.items.len;
            try w.writeAll(&acct.owner.data);

            const lam_off = buf.items.len;
            try w.writeInt(u64, acct.lamports, .little);

            try w.writeInt(u64, acct.data.len, .little);
            const dat_off = buf.items.len;
            try w.writeAll(acct.data);
            try buf.appendNTimes(allocator, 0, MAX_REALLOC); // realloc gap
            // alignPad (BPF_ALIGN_OF_U128 = 16) — vex-079 + round6-beam-t2 (9baf82d).
            // Agave program-runtime/src/serialization.rs uses align_offset(BPF_ALIGN_OF_U128)
            // where BPF_ALIGN_OF_U128 = 16. data_len%8 was wrong; ANY data_len % 16 ∉ {0,8}
            // shifted the next account's header by up to 8 bytes vs Agave's layout, producing
            // uniform input-region AccessViolation on multi-account txs.
            const align_pad = (16 - (acct.data.len % 16)) % 16;
            try buf.appendNTimes(allocator, 0, align_pad);

            // rent_epoch masked to u64::MAX per Agave's
            // `mask_out_rent_epoch_in_vm_serialization`.
            try w.writeInt(u64, std.math.maxInt(u64), .little);

            try meta.append(allocator, .{
                .is_writable = acct.is_writable,
                .owner_offset = own_off,
                .lamports_offset = lam_off,
                .data_offset = dat_off,
                .data_len = acct.data.len,
                .pubkey_idx = i,
            });
        }
    }
    try w.writeInt(u64, ix_data.len, .little);
    try w.writeAll(ix_data);
    try w.writeAll(&prog_id.data);
}

// ── Deserialisation ───────────────────────────────────────────────────────────

fn deserialise(
    allocator: std.mem.Allocator,
    buf: []const u8,
    meta: []const AccountMeta,
    accounts: []const AccountEntry,
) ![]AccountMutation {
    // r75-bug-class-b-2026-05-06: BPF deserialise reads buffer values
    // that may contain wrapping/overflow-prone arithmetic. After the
    // R_BPF_64_RELATIVE relocations were applied, programs run their
    // bodies and write degenerate values that previously got silent-skip
    // (program-aborted-before-mutation). Saturating math at 6 sites caught
    // most but not all overflow-risk arithmetic. Disable runtime safety
    // here as a defensive belt — BPF spec semantics are wrapping-add anyway.
    @setRuntimeSafety(false);
    var mutations = std.ArrayListUnmanaged(AccountMutation){};
    errdefer {
        for (mutations.items) |*m| allocator.free(m.data);
        mutations.deinit(allocator);
    }

    // Always-on diagnostic; rate-limited at the call-site cap below.
    const probe_buf_diff = true;
    var probe_buf_diff_count: u32 = 0;

    for (meta) |m| {
        if (!m.is_writable) continue;
        if (m.lamports_offset +| 8 > buf.len) continue;

        // vex-039 / core-r10-bpf-owner restored 2026-05-22: read the
        // post-mutation owner bytes BPF programs may have written into the
        // 32-byte window at owner_offset (set by serialise() to lamports_offset-32).
        // Without this, owner-mutating BPF txs (system_program::Assign CPI,
        // PDA creation, ATA via System.CreateAccount CPI, owner-transfer ix)
        // silently drop the owner change; new_lt is computed with the
        // pre-mutation owner; bank LtHash accumulator desynchronizes from
        // Agave for every such slot. Default owner_offset=0 from is_dup
        // entries is skipped by `!m.is_writable continue` above.
        if (m.owner_offset +| 32 > buf.len) continue;
        const new_owner_bytes = buf[m.owner_offset..][0..32].*;

        const new_lam = std.mem.readInt(u64, buf[m.lamports_offset..][0..8], .little);

        // Read new data_len from the 8 bytes immediately before data_offset.
        // Guard against degenerate meta entries where data_offset < 8 (would underflow).
        if (m.data_offset < 8) continue;
        const dlen_off = m.data_offset - 8;
        if (dlen_off +| 8 > buf.len) continue;
        const new_dlen = std.mem.readInt(u64, buf[dlen_off..][0..8], .little);

        // Clamp to original len + realloc budget. Saturating add prevents
        // overflow panic on degenerate inputs (e.g. corrupt new_dlen).
        const safe_dlen = @min(new_dlen, m.data_len +| MAX_REALLOC);
        if (m.data_offset +| safe_dlen > buf.len) continue;

        // Saturating add — defensive against degenerate meta entries
        const data_end = m.data_offset +| safe_dlen;
        const new_data = buf[m.data_offset..data_end];
        const orig = &accounts[m.pubkey_idx];

        if (probe_buf_diff and probe_buf_diff_count < 24) {
            const lam_eq = new_lam == orig.lamports;
            const dlen_eq = new_dlen == m.data_len;
            const data_eq = std.mem.eql(u8, new_data, orig.data);
            const head_pre = if (orig.data.len >= 8) std.mem.readInt(u64, orig.data[0..8], .little) else 0;
            const head_post = if (new_data.len >= 8) std.mem.readInt(u64, new_data[0..8], .little) else 0;
            std.log.debug("[BPF-BUFDIFF] pk={x:0>2}{x:0>2}{x:0>2}{x:0>2} lam_off={d} lam_pre={d} lam_post={d} lam_eq={} dlen_pre={d} dlen_post={d} dlen_eq={} data_eq={} data_head_pre={x:0>16} data_head_post={x:0>16}\n", .{
                orig.pubkey.data[0], orig.pubkey.data[1], orig.pubkey.data[2], orig.pubkey.data[3],
                m.lamports_offset,   orig.lamports,       new_lam,             lam_eq,
                m.data_len,          new_dlen,            dlen_eq,             data_eq,
                head_pre,            head_post,
            });
            probe_buf_diff_count += 1;
        }

        // Skip if nothing changed (lamports + data + owner) — vex-039 expanded
        // the change-detect from just (lamports, data) to include owner.
        const owner_changed = !std.mem.eql(u8, &new_owner_bytes, &orig.owner.data);
        if (new_lam == orig.lamports and std.mem.eql(u8, new_data, orig.data) and !owner_changed) continue;

        const data_copy = try allocator.dupe(u8, new_data);
        try mutations.append(allocator, .{
            .pubkey = orig.pubkey,
            .new_lamports = new_lam,
            .owner = new_owner_bytes,
            .data = data_copy,
        });
    }

    return mutations.toOwnedSlice(allocator);
}
