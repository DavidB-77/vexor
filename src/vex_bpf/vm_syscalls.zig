//! sBPF syscall implementations — NOT wired into any live dispatch path.
//!
//! `registerAll` (below) has zero callers anywhere in this tree (verified by
//! grep at fix/small-parity-batch-2026-07-17): this file's `SyscallMap` is
//! never populated and none of these handlers execute on the live validator,
//! not even as a fallback. The live BPF dispatch chain is
//! `instruction_dispatch.dispatchBpfExecution` -> (resolvable ELF)
//! `dispatchV3ViaV2Producer` -> `vex_bpf2/syscalls.zig`'s registry, or
//! (ELF-resolution failure) `executeBpfProgram` -> `executeBpfProgramCore` ->
//! `SbpfExecutor.execute`, which registers syscalls from the sibling file
//! `src/vex_bpf/syscalls.zig` (a different, actually-consumed table — see
//! `sbpf_executor.zig:24`), not this one. `build.zig` labels this file part
//! of the "dormant-chain DELETE→KEEP verbatim-carry" set (module 67 comment)
//! pending a post-migration cleanup pass.
//!
//! Several handlers below are genuine stubs (poseidon/secp256k1-recover/
//! alt-bn128 group-op+compression return an unconditional placeholder value)
//! — those TODOs are accurate statements about THIS file's code, just moot
//! for live behavior since the file is never reached. `src/vex_bpf/
//! syscalls.zig`, the table actually used by the legacy V1 fallback path,
//! has a real (stub) secp256k1-recover but does not register poseidon or
//! alt-bn128 at all; the actual pure-Zig BN254/Poseidon implementations live
//! in `vex_crypto/bn254.zig` and are reachable only via the V2 dispatch path
//! (`vex_bpf2/syscalls.zig`).
//!
//! All syscall IDs are murmur3_32(name, seed=0).
//!
//! References:
//!   sig/src/vm/syscalls/lib.zig        (dispatch, logging, alloc, PDA, return data)
//!   sig/src/vm/syscalls/hash.zig       (sha256/keccak/blake3/poseidon)
//!   sig/src/vm/syscalls/ecc.zig        (secp256k1, curve25519, alt-bn128)
//!   sig/src/vm/syscalls/sysvar.zig     (getClock, getRent, getEpochSchedule)
//!   sig/src/vm/syscalls/memops.zig     (memcpy/memmove/memset/memcmp)
//!   sig/src/vm/syscalls/cpi.zig        (CPI — thin shim for now)
//!   fd_vm/syscall/fd_vm_syscall_*.c    (authoritative C implementations)

const std = @import("std");
const sbpf = @import("vm_sbpf.zig");
const mem = @import("vm_memory.zig");
const interp = @import("vm_interpreter.zig");
const sys_cpi = @import("system_cpi.zig");

const MemoryMap = mem.MemoryMap;
const SyscallContext = interp.SyscallContext;
const SyscallMap = interp.SyscallMap;
const SyscallFn = interp.SyscallFn;
const ExecutionError = sbpf.ExecutionError;
const ComputeBudget = sbpf.ComputeBudget;

// ── Syscall IDs: murmur3_32(name, 0) ─────────────────────────────────────────
// Verified against Agave rbpf source and sig/src/vm/syscalls/lib.zig:Syscall.

pub const ID_ABORT: u32 = 0xb6fc1a11;
pub const ID_SOL_PANIC: u32 = 0x686093bb;
pub const ID_SOL_LOG: u32 = 0x207559bd;
pub const ID_SOL_LOG_64: u32 = 0x5c2a3178;
pub const ID_SOL_LOG_PUBKEY: u32 = 0x7ef088ca;
pub const ID_SOL_LOG_COMPUTE_UNITS: u32 = 0x52ba5096;
pub const ID_SOL_LOG_DATA: u32 = 0x7317b434;
pub const ID_SOL_MEMCPY: u32 = 0x717cc4a3;
pub const ID_SOL_MEMMOVE: u32 = 0x434371f8;
pub const ID_SOL_MEMCMP: u32 = 0x5fdcde31;
pub const ID_SOL_MEMSET: u32 = 0x3770fb22;
pub const ID_SOL_SHA256: u32 = 0x11f49d86;
pub const ID_SOL_KECCAK256: u32 = 0xd7793abb;
pub const ID_SOL_BLAKE3: u32 = 0x174c5122;
pub const ID_SOL_POSEIDON: u32 = 0xc4947c21; // r74-vex-027: was 0xa5d8a0e6 (drifted); corrected to murmur3("sol_poseidon")
pub const ID_SOL_SECP256K1_RECOVER: u32 = 0x17e40350;
pub const ID_SOL_CURVE_VALIDATE: u32 = 0xaa2607ca;
pub const ID_SOL_CURVE_GROUP_OP: u32 = 0xdd1c41a6; // r74-vex-027: was 0xbf2b90e1 (drifted); corrected to murmur3("sol_curve_group_op")
pub const ID_SOL_CURVE_MSM: u32 = 0x60a40880; // r74-vex-027: was 0xcc6ada39 (drifted); corrected to murmur3("sol_curve_multiscalar_mul")
pub const ID_SOL_ALT_BN128: u32 = 0xae0c318b; // r74-vex-027: was 0x23a6e300 (drifted); corrected to murmur3("sol_alt_bn128_group_op")
pub const ID_SOL_ALT_BN128_COMPRESS: u32 = 0x334fd5ed; // r74-vex-027: was 0x9d4e2b9d (drifted); corrected to murmur3("sol_alt_bn128_compression")
pub const ID_SOL_CREATE_PDA: u32 = 0x9377323c; // r74-vex-027: was 0x96108919 (drifted, trailing-underscore variant); corrected to murmur3("sol_create_program_address")
pub const ID_SOL_TRY_FIND_PDA: u32 = 0x48504a38;
pub const ID_SOL_INVOKE_SIGNED_C: u32 = 0xa22b9c85;
pub const ID_SOL_INVOKE_SIGNED_R: u32 = 0xd7449092;
pub const ID_SOL_ALLOC_FREE: u32 = 0x83f00e8f;
pub const ID_SOL_GET_CLOCK: u32 = 0xd56b5fe9;
pub const ID_SOL_GET_EPOCH_SCHED: u32 = 0x23a29a61;
pub const ID_SOL_GET_FEES: u32 = 0x3b97b73c; // r74-vex-027: was 0xa5d20d1e (drifted); corrected to murmur3("sol_get_fees_sysvar")
pub const ID_SOL_GET_RENT: u32 = 0xbf7188f6;
pub const ID_SOL_GET_LAST_RESTART_SLOT: u32 = 0x188a0031; // r74-vex-027: corrected to murmur3("sol_get_last_restart_slot") — SIMD-0047
pub const ID_SOL_GET_EPOCH_REWARDS: u32 = 0xfdba2b3b; // r74-vex-027: was 0x91d0dd4c (drifted); corrected to murmur3("sol_get_epoch_rewards_sysvar")
pub const ID_SOL_SET_RETURN_DATA: u32 = 0xa226d3eb;
pub const ID_SOL_GET_RETURN_DATA: u32 = 0x5d2245e4;
pub const ID_SOL_GET_STACK_HEIGHT: u32 = 0x85532d94;
pub const ID_SOL_GET_SIBLING: u32 = 0xadb8efc8;
pub const ID_SOL_GET_SYSVAR: u32 = 0x13c1b505; // r74-vex-027: was 0x4caaee6e (drifted); corrected to murmur3("sol_get_sysvar") — SIMD-0127
pub const ID_SOL_REMAINING_CU: u32 = 0xedef5aee; // r74-vex-027: was 0x3e2b5b08 (drifted); corrected to murmur3("sol_remaining_compute_units")
pub const ID_SOL_GET_EPOCH_STAKE: u32 = 0x5be92f4a; // r74-vex-027: was 0x9b3ee6e2 (drifted); corrected to murmur3("sol_get_epoch_stake")

// ── CPI callback ─────────────────────────────────────────────────────────────
// When the Vm encounters sol_invoke_signed, it calls this if wired in.
pub const CpiHandlerFn = *const fn (
    cpi_ctx: *anyopaque,
    sc_ctx: *SyscallContext,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
) ExecutionError!u64;

pub const CpiHandler = struct {
    ctx: *anyopaque,
    func: CpiHandlerFn,
};

// Thread-local CPI handler; wired by the executor before each invocation.
var tls_cpi_handler: ?CpiHandler = null;

pub fn setCpiHandler(h: CpiHandler) void {
    tls_cpi_handler = h;
}
pub fn clearCpiHandler() void {
    tls_cpi_handler = null;
}

// ── vex-152 W3: inline System program CPI counters (observability) ──────────
pub const SystemCpiDiag = struct {
    pub var total: u64 = 0;
    pub var transfer: u64 = 0;
    pub var create_account: u64 = 0;
    pub var allocate: u64 = 0;
    pub var assign: u64 = 0;
    pub var with_seed_stub: u64 = 0;
    pub var nonce_stub: u64 = 0;
    pub var parse_fail: u64 = 0;
    pub var ok: u64 = 0;
    pub var err: u64 = 0;
};

pub fn snapshotSystemCpi() [9]u64 {
    return .{
        SystemCpiDiag.total,      SystemCpiDiag.transfer, SystemCpiDiag.create_account,
        SystemCpiDiag.allocate,   SystemCpiDiag.assign,   SystemCpiDiag.with_seed_stub,
        SystemCpiDiag.nonce_stub, SystemCpiDiag.ok,       SystemCpiDiag.err,
    };
}

// ── Registration ─────────────────────────────────────────────────────────────

/// Register all syscalls into the provided SyscallMap.
/// cf. sig/src/vm/syscalls/lib.zig:Syscall.Registry + sig Syscall.map
pub fn registerAll(smap: *SyscallMap, allocator: std.mem.Allocator) error{OutOfMemory}!void {
    const put = SyscallMap.put;
    try put(smap, allocator, ID_ABORT, abort_);
    try put(smap, allocator, ID_SOL_PANIC, solPanic);
    try put(smap, allocator, ID_SOL_LOG, solLog);
    try put(smap, allocator, ID_SOL_LOG_64, solLog64);
    try put(smap, allocator, ID_SOL_LOG_PUBKEY, solLogPubkey);
    try put(smap, allocator, ID_SOL_LOG_COMPUTE_UNITS, solLogComputeUnits);
    try put(smap, allocator, ID_SOL_LOG_DATA, solLogData);
    try put(smap, allocator, ID_SOL_MEMCPY, solMemcpy);
    try put(smap, allocator, ID_SOL_MEMMOVE, solMemmove);
    try put(smap, allocator, ID_SOL_MEMCMP, solMemcmp);
    try put(smap, allocator, ID_SOL_MEMSET, solMemset);
    try put(smap, allocator, ID_SOL_SHA256, solSha256);
    try put(smap, allocator, ID_SOL_KECCAK256, solKeccak256);
    try put(smap, allocator, ID_SOL_BLAKE3, solBlake3);
    try put(smap, allocator, ID_SOL_POSEIDON, solPoseidon);
    try put(smap, allocator, ID_SOL_SECP256K1_RECOVER, solSecp256k1Recover);
    try put(smap, allocator, ID_SOL_CURVE_VALIDATE, solCurveValidate);
    try put(smap, allocator, ID_SOL_CURVE_GROUP_OP, solCurveGroupOp);
    try put(smap, allocator, ID_SOL_CURVE_MSM, solCurveMsm);
    try put(smap, allocator, ID_SOL_ALT_BN128, solAltBn128GroupOp);
    try put(smap, allocator, ID_SOL_ALT_BN128_COMPRESS, solAltBn128Compress);
    try put(smap, allocator, ID_SOL_CREATE_PDA, solCreatePda);
    try put(smap, allocator, ID_SOL_TRY_FIND_PDA, solTryFindPda);
    try put(smap, allocator, ID_SOL_INVOKE_SIGNED_C, solInvokeSigned);
    try put(smap, allocator, ID_SOL_INVOKE_SIGNED_R, solInvokeSigned);
    try put(smap, allocator, ID_SOL_ALLOC_FREE, solAllocFree);
    try put(smap, allocator, ID_SOL_GET_CLOCK, solGetClock);
    try put(smap, allocator, ID_SOL_GET_EPOCH_SCHED, solGetEpochSchedule);
    try put(smap, allocator, ID_SOL_GET_FEES, solGetFees);
    try put(smap, allocator, ID_SOL_GET_RENT, solGetRent);
    try put(smap, allocator, ID_SOL_GET_LAST_RESTART_SLOT, solGetLastRestartSlot);
    try put(smap, allocator, ID_SOL_GET_EPOCH_REWARDS, solGetEpochRewards);
    try put(smap, allocator, ID_SOL_SET_RETURN_DATA, solSetReturnData);
    try put(smap, allocator, ID_SOL_GET_RETURN_DATA, solGetReturnData);
    try put(smap, allocator, ID_SOL_GET_STACK_HEIGHT, solGetStackHeight);
    try put(smap, allocator, ID_SOL_GET_SIBLING, solGetSibling);
    try put(smap, allocator, ID_SOL_GET_SYSVAR, solGetSysvar);
    try put(smap, allocator, ID_SOL_REMAINING_CU, solRemainingComputeUnits);
    try put(smap, allocator, ID_SOL_GET_EPOCH_STAKE, solGetEpochStake);
}

// ── Memory translation helpers ────────────────────────────────────────────────
// cf. sig/src/vm/syscalls/lib.zig:safeR / sig/src/vm/memory.zig:translateSlice

/// Memory map is passed as the second argument to syscalls via the context.
/// We thread it through SyscallContext instead of passing it explicitly,
/// because the SyscallFn signature is fixed.
/// Callers must fill sc.memory_map before calling registerAll.
///
/// NOTE: The current SyscallFn signature passes a *SyscallContext that does NOT
/// yet include a MemoryMap pointer.  We accept this limitation; full integration
/// requires extending SyscallContext.  For now, syscalls that need memory translation
/// receive the MemoryMap from the context extension below.
const MAX_LOG_LEN: u64 = 10_000;
const MAX_SLICE_LEN: u64 = 32 * 1024 * 1024; // 32 MiB absolute cap

// ── Per-syscall helpers that need MemoryMap ───────────────────────────────────
// We embed the MemoryMap reference in SyscallContext to keep the signature clean.
// This extension is set by SbpfExecutor before running the VM.
pub const FullSyscallContext = struct {
    base: SyscallContext,
    memory_map: *MemoryMap,
    // Call depth for sol_get_stack_height.
    call_depth: u64,
    // Epoch stake table (optional, for sol_get_epoch_stake).
    epoch_stake_fn: ?*const fn (vote_addr: [32]u8) u64,
};

fn sc(ctx: *SyscallContext) *FullSyscallContext {
    return @fieldParentPtr("base", ctx);
}

// ── abort / panic ─────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/lib.zig:abort + panic
// fd_vm/syscall/fd_vm_syscall_base.c:fd_vm_syscall_abort

fn abort_(_: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return ExecutionError.Exit;
}

fn solPanic(ctx: *SyscallContext, file_vm: u64, file_len: u64, line: u64, col: u64, _: u64) ExecutionError!u64 {
    const mm = sc(ctx).memory_map;
    const file: []const u8 = mm.vmap(.constant, file_vm, @min(file_len, 512)) catch "<?>";
    std.log.warn("[SBPF] panic at {s}:{}:{}", .{ file, line, col });
    return ExecutionError.Exit;
}

// ── Logging ───────────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/lib.zig:log/log64/logPubkey/logComputeUnits/logData
// fd_vm/syscall/fd_vm_syscall_base.c:fd_vm_syscall_sol_log_*

fn solLog(ctx: *SyscallContext, msg_vm: u64, msg_len: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, @max(ComputeBudget.SYSCALL_BASE_COST, msg_len));
    const mm = sc(ctx).memory_map;
    const msg = mm.vmap(.constant, msg_vm, @min(msg_len, MAX_LOG_LEN)) catch return 0;
    const b0 = interp.Bpf143.cur_prog_b0;
    if (b0 == 0x8c or b0 == 0xe3 or b0 == 0x06) {
        const rgn: []const u8 = if (msg_vm < 0x1_0000_0000) "lo" else if (msg_vm < 0x2_0000_0000) "PROG" else if (msg_vm < 0x3_0000_0000) "STACK" else if (msg_vm < 0x4_0000_0000) "HEAP" else if (msg_vm < 0x5_0000_0000) "INPUT" else "hi";
        std.log.err("[BPF-MSG] prog={x:0>2}{x:0>2} vm=0x{x} len={d} rgn={s} \"{s}\"", .{ b0, interp.Bpf143.cur_prog_b1, msg_vm, msg_len, rgn, msg });
    } else {
        std.log.debug("[Program] {s}", .{msg});
    }
    return 0;
}

fn solLog64(_: *SyscallContext, a: u64, b: u64, c: u64, d: u64, e: u64) ExecutionError!u64 {
    const b0 = interp.Bpf143.cur_prog_b0;
    if (b0 == 0x8c or b0 == 0xe3 or b0 == 0x06) {
        std.log.err("[BPF-MSG-64] prog={x:0>2}{x:0>2} 0x{x} 0x{x} 0x{x} 0x{x} 0x{x}", .{ b0, interp.Bpf143.cur_prog_b1, a, b, c, d, e });
    } else {
        std.log.debug("[Program] 0x{x} 0x{x} 0x{x} 0x{x} 0x{x}", .{ a, b, c, d, e });
    }
    return 0;
}

fn solLogPubkey(ctx: *SyscallContext, pk_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.LOG_PUBKEY_COST);
    const mm = sc(ctx).memory_map;
    const pk = mm.vmap(.constant, pk_vm, 32) catch return 0;
    const b0 = interp.Bpf143.cur_prog_b0;
    if (b0 == 0x8c or b0 == 0xe3 or b0 == 0x06) {
        const pk_hex = std.fmt.bytesToHex(pk[0..32].*, .upper);
        std.log.err("[BPF-MSG-PK] prog={x:0>2}{x:0>2} pk={s}", .{ b0, interp.Bpf143.cur_prog_b1, &pk_hex });
    }
    return 0;
}

fn solLogComputeUnits(ctx: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    std.log.debug("[Program] compute units remaining: {}", .{ctx.compute_remaining.*});
    return 0;
}

fn solLogData(ctx: *SyscallContext, slices_vm: u64, n: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    if (n > 64) return ExecutionError.AccessViolation;
    consumeCu(ctx, ComputeBudget.SYSCALL_BASE_COST *| n);
    const mm = sc(ctx).memory_map;
    // Each slice: {ptr: u64, len: u64}
    const hdrs = mm.vmap(.constant, slices_vm, n * 16) catch return ExecutionError.AccessViolation;
    var i: u64 = 0;
    const b0 = interp.Bpf143.cur_prog_b0;
    const panic_loop = b0 == 0x8c or b0 == 0xe3 or b0 == 0x06;
    while (i < n) : (i += 1) {
        const off = @as(usize, @intCast(i)) * 16;
        const ptr = std.mem.readInt(u64, hdrs[off..][0..8], .little);
        const len = std.mem.readInt(u64, hdrs[off + 8 ..][0..8], .little);
        consumeCu(ctx, len);
        const data = mm.vmap(.constant, ptr, @min(len, 1024)) catch continue;
        if (panic_loop) {
            std.log.err("[BPF-MSG-DATA] prog={x:0>2}{x:0>2} slice{d} len={d} bytes={x}", .{ b0, interp.Bpf143.cur_prog_b1, i, data.len, data });
        }
    }
    return 0;
}

// ── Memory operations ─────────────────────────────────────────────────────────
// sig/src/vm/syscalls/memops.zig / fd_vm/syscall/fd_vm_syscall_mem.c

fn solMemcpy(ctx: *SyscallContext, dst_vm: u64, src_vm: u64, n: u64, _: u64, _: u64) ExecutionError!u64 {
    if (n == 0) return 0;
    if (n > MAX_SLICE_LEN) return ExecutionError.AccessViolation;
    consumeCu(ctx, n / 1024 + ComputeBudget.MEM_OP_BASE_COST);
    const mm = sc(ctx).memory_map;
    const src = try mm.vmap(.constant, src_vm, n);
    const dst = try mm.vmap(.mutable, dst_vm, n);
    // Overlapping source/destination is UB for memcpy; we check.
    if (regionsOverlap(dst.ptr, src.ptr, n)) return ExecutionError.AccessViolation;
    @memcpy(dst, src);
    return 0;
}

fn solMemmove(ctx: *SyscallContext, dst_vm: u64, src_vm: u64, n: u64, _: u64, _: u64) ExecutionError!u64 {
    if (n == 0) return 0;
    if (n > MAX_SLICE_LEN) return ExecutionError.AccessViolation;
    consumeCu(ctx, n / 1024 + ComputeBudget.MEM_OP_BASE_COST);
    const mm = sc(ctx).memory_map;
    const src = try mm.vmap(.constant, src_vm, n);
    const dst = try mm.vmap(.mutable, dst_vm, n);
    std.mem.copyForwards(u8, dst, src);
    return 0;
}

fn solMemcmp(ctx: *SyscallContext, a_vm: u64, b_vm: u64, n: u64, out_vm: u64, _: u64) ExecutionError!u64 {
    if (n > MAX_SLICE_LEN) return ExecutionError.AccessViolation;
    consumeCu(ctx, n / 1024 + ComputeBudget.MEM_OP_BASE_COST);
    const mm = sc(ctx).memory_map;
    const a = try mm.vmap(.constant, a_vm, n);
    const b = try mm.vmap(.constant, b_vm, n);
    const out = try mm.vmap(.mutable, out_vm, 4);
    var cmp: i32 = 0;
    var mi: usize = 0;
    while (mi < @as(usize, @intCast(n))) : (mi += 1) {
        if (a[mi] != b[mi]) {
            cmp = @as(i32, a[mi]) - @as(i32, b[mi]);
            break;
        }
    }
    std.mem.writeInt(i32, out[0..4], cmp, .little);
    return 0;
}

fn solMemset(ctx: *SyscallContext, dst_vm: u64, val: u64, n: u64, _: u64, _: u64) ExecutionError!u64 {
    if (n == 0) return 0;
    if (n > MAX_SLICE_LEN) return ExecutionError.AccessViolation;
    consumeCu(ctx, n / 1024 + ComputeBudget.MEM_OP_BASE_COST);
    const mm = sc(ctx).memory_map;
    const dst = try mm.vmap(.mutable, dst_vm, n);
    @memset(dst, @truncate(val));
    return 0;
}

// ── Heap allocator ────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/lib.zig:allocFree
// fd_vm/syscall/fd_vm_syscall_sol_alloc_free.c

fn solAllocFree(ctx: *SyscallContext, size: u64, free_addr: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    if (free_addr != 0) return 0; // free is a no-op (bump allocator)
    if (size == 0) return 0;
    // Align to 16 bytes (u128 alignment, matching Agave's BPF_ALIGN_OF_U128).
    const align_to: u64 = 16;
    const bytes_to_align = (align_to - (ctx.bpf_alloc_pos % align_to)) % align_to;
    const start = ctx.bpf_alloc_pos + bytes_to_align;
    const end = start + size;
    if (end > sbpf.HEAP_SIZE) return 0; // OOM → null (not an error)
    ctx.bpf_alloc_pos = end;
    return sbpf.HEAP_START + start;
}

// ── Hash syscalls ─────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/hash.zig / fd_vm/syscall/fd_vm_syscall_hash.c

const SliceHdr = extern struct { ptr: u64, len: u64 };

/// Generic multi-slice hasher.  Reads n SliceHdr from slices_vm, hashes each slice.
fn hashSlices(
    comptime Hasher: type,
    ctx: *SyscallContext,
    slices_vm: u64,
    n: u64,
    out_vm: u64,
    comptime out_len: usize,
) ExecutionError!u64 {
    if (n > 1000) return ExecutionError.AccessViolation;
    consumeCu(ctx, ComputeBudget.SHA256_BASE_COST);
    const mm = sc(ctx).memory_map;
    const hdrs_mem = try mm.vmap(.constant, slices_vm, n * @sizeOf(SliceHdr));
    var hasher = Hasher.init(.{});
    var i: u64 = 0;
    while (i < n) : (i += 1) {
        const off = @as(usize, @intCast(i)) * @sizeOf(SliceHdr);
        const hdr: SliceHdr = @bitCast(hdrs_mem[off..][0..@sizeOf(SliceHdr)].*);
        if (hdr.len == 0) continue;
        consumeCu(ctx, hdr.len * ComputeBudget.SHA256_BYTE_COST);
        const data = try mm.vmap(.constant, hdr.ptr, hdr.len);
        hasher.update(data);
    }
    const out = try mm.vmap(.mutable, out_vm, out_len);
    var digest: [Hasher.digest_length]u8 = undefined;
    hasher.final(&digest);
    @memcpy(out[0..out_len], digest[0..out_len]);
    return 0;
}

fn solSha256(ctx: *SyscallContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) ExecutionError!u64 {
    return hashSlices(std.crypto.hash.sha2.Sha256, ctx, sl_vm, n, out_vm, 32);
}

fn solKeccak256(ctx: *SyscallContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) ExecutionError!u64 {
    return hashSlices(std.crypto.hash.sha3.Keccak256, ctx, sl_vm, n, out_vm, 32);
}

fn solBlake3(ctx: *SyscallContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) ExecutionError!u64 {
    return hashSlices(std.crypto.hash.Blake3, ctx, sl_vm, n, out_vm, 32);
}

/// Genuine stub — always returns 1 (unimplemented). Not registered by
/// `registerAll` (dead table, see file header) and not the syscall a live
/// `sol_poseidon` call reaches; the real pure-Zig implementation is
/// `vex_crypto.bn254.poseidonHash` via `vex_bpf2/syscalls.zig`.
fn solPoseidon(_: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return 1; // unimplemented in this dormant table (see file header)
}

// ── secp256k1 recover ─────────────────────────────────────────────────────────
// sig/src/vm/syscalls/ecc.zig:secp256k1Recover
// fd_vm/syscall/fd_vm_syscall_cryp.c:fd_vm_syscall_sol_secp256k1_recover

fn solSecp256k1Recover(
    ctx: *SyscallContext,
    hash_vm: u64,
    recovery_id_vm: u64,
    sig_vm: u64,
    result_vm: u64,
    _: u64,
) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SECP256K1_COST);
    const mm = sc(ctx).memory_map;

    // Validate input addresses are accessible — even if we can't recover yet.
    _ = try mm.vmap(.constant, hash_vm, 32); // 32-byte hash
    _ = try mm.vmap(.constant, sig_vm, 64); // 64-byte (r||s) signature
    const recovery_id_bytes = try mm.vmap(.constant, recovery_id_vm, 8);
    _ = try mm.vmap(.mutable, result_vm, 64); // output: uncompressed pubkey (x||y)

    const rec_id = std.mem.readInt(u64, recovery_id_bytes[0..8], .little);
    if (rec_id > 3) return 2; // invalid recovery id

    // Genuine stub — always returns 1 (invalid signature) regardless of
    // input. Not registered by `registerAll` (dead table, see file header);
    // the syscall a live secp256k1_recover call actually reaches is
    // `vex_crypto.secp256k1.recoverPublicKey` via `vex_bpf2/syscalls.zig`
    // (real pure-Zig ECDSA recovery — its failure-path error mapping is a
    // separate, already-tracked parity item, unrelated to this dead table).
    return 1; // 1 = invalid signature (programs handle gracefully)
}

// ── Curve25519 / Ed25519 group operations ─────────────────────────────────────
// sig/src/vm/syscalls/ecc.zig:curvePointValidation/curveGroupOp/curveMultiscalarMul

fn solCurveValidate(
    ctx: *SyscallContext,
    curve_id: u64,
    point_vm: u64,
    _: u64,
    _: u64,
    _: u64,
) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.CURVE25519_VALIDATE);
    const mm = sc(ctx).memory_map;

    switch (curve_id) {
        0 => { // Edwards25519
            const buf = try mm.vmap(.constant, point_vm, 32);
            var arr: [32]u8 = undefined;
            @memcpy(&arr, buf);
            const result = std.crypto.ecc.Edwards25519.fromBytes(arr);
            return @intFromBool(std.meta.isError(result));
        },
        1 => { // Ristretto255
            const buf = try mm.vmap(.constant, point_vm, 32);
            var arr: [32]u8 = undefined;
            @memcpy(&arr, buf);
            const result = std.crypto.ecc.Ristretto255.fromBytes(arr);
            return @intFromBool(std.meta.isError(result));
        },
        else => return 1, // unknown curve
    }
}

fn solCurveGroupOp(
    ctx: *SyscallContext,
    curve_id: u64,
    group_op: u64,
    left_vm: u64,
    right_vm: u64,
    result_vm: u64,
) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.CURVE25519_GROUP_OP);
    const mm = sc(ctx).memory_map;

    if (curve_id > 1) return 1; // only Edwards/Ristretto supported

    const left_buf = try mm.vmap(.constant, left_vm, 32);
    const right_buf = try mm.vmap(.constant, right_vm, 32);
    const out_buf = try mm.vmap(.mutable, result_vm, 32);

    var la: [32]u8 = undefined;
    @memcpy(&la, left_buf);
    var ra: [32]u8 = undefined;
    @memcpy(&ra, right_buf);

    if (curve_id == 0) {
        // Edwards25519
        const Edwards25519 = std.crypto.ecc.Edwards25519;
        const l = Edwards25519.fromBytes(la) catch return 1;
        const r = Edwards25519.fromBytes(ra) catch return 1;
        const res: Edwards25519 = switch (group_op) {
            0 => l.add(r),
            1 => l.sub(r),
            2 => blk: { // scalar multiply: left_buf = scalar, right_buf = point
                Edwards25519.scalar.rejectNonCanonical(la) catch return 1;
                const pt = Edwards25519.fromBytes(ra) catch return 1;
                break :blk pt.mul(la) catch return 1;
            },
            else => return 1,
        };
        @memcpy(out_buf, &res.toBytes());
    } else {
        // Ristretto255
        const Ristretto255 = std.crypto.ecc.Ristretto255;
        const l = Ristretto255.fromBytes(la) catch return 1;
        const r = Ristretto255.fromBytes(ra) catch return 1;
        const res: Ristretto255 = switch (group_op) {
            0 => .{ .p = l.p.add(r.p) },
            1 => .{ .p = l.p.sub(r.p) },
            2 => blk: {
                std.crypto.ecc.Edwards25519.scalar.rejectNonCanonical(la) catch return 1;
                const pt = Ristretto255.fromBytes(ra) catch return 1;
                break :blk pt.mul(la) catch return 1;
            },
            else => return 1,
        };
        @memcpy(out_buf, &res.toBytes());
    }
    return 0;
}

/// Multi-scalar multiplication (batch scalar × point).
/// sig/src/vm/syscalls/ecc.zig:curveMultiscalarMul
fn solCurveMsm(
    ctx: *SyscallContext,
    curve_id: u64,
    scalars_vm: u64,
    points_vm: u64,
    n: u64,
    result_vm: u64,
) ExecutionError!u64 {
    if (n > 512) return 1;
    consumeCu(ctx, ComputeBudget.CURVE25519_GROUP_OP *| n);
    const mm = sc(ctx).memory_map;

    if (curve_id > 1) return 1;

    const scalars_raw = try mm.vmap(.constant, scalars_vm, n * 32);
    const points_raw = try mm.vmap(.constant, points_vm, n * 32);
    const out_buf = try mm.vmap(.mutable, result_vm, 32);

    const Edwards25519 = std.crypto.ecc.Edwards25519;
    const Ristretto255 = std.crypto.ecc.Ristretto255;

    // Naive implementation: sum = sum + scalar_i * point_i
    if (curve_id == 0) {
        var acc = Edwards25519.identityElement;
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const off = @as(usize, @intCast(i)) * 32;
            var sc_bytes: [32]u8 = undefined;
            var pt_bytes: [32]u8 = undefined;
            @memcpy(&sc_bytes, scalars_raw[off..][0..32]);
            @memcpy(&pt_bytes, points_raw[off..][0..32]);
            Edwards25519.scalar.rejectNonCanonical(sc_bytes) catch return 1;
            const pt = Edwards25519.fromBytes(pt_bytes) catch return 1;
            const term = pt.mul(sc_bytes) catch return 1;
            acc = acc.add(term);
        }
        @memcpy(out_buf, &acc.toBytes());
    } else {
        // Ristretto255 identity: zero bytes decoded
        const ristretto_identity_bytes = [_]u8{0} ** 32;
        var acc = Ristretto255.fromBytes(ristretto_identity_bytes) catch
            Ristretto255{ .p = Edwards25519.identityElement };
        var i: u64 = 0;
        while (i < n) : (i += 1) {
            const off = @as(usize, @intCast(i)) * 32;
            var sc_bytes: [32]u8 = undefined;
            var pt_bytes: [32]u8 = undefined;
            @memcpy(&sc_bytes, scalars_raw[off..][0..32]);
            @memcpy(&pt_bytes, points_raw[off..][0..32]);
            Edwards25519.scalar.rejectNonCanonical(sc_bytes) catch return 1;
            const pt = Ristretto255.fromBytes(pt_bytes) catch return 1;
            const term = pt.mul(sc_bytes) catch return 1;
            acc = .{ .p = acc.p.add(term.p) };
        }
        @memcpy(out_buf, &acc.toBytes());
    }
    return 0;
}

/// alt-bn128 group operations (pairing-friendly curves, SIMD-0129).
/// Genuine stub — always returns 1 (unimplemented). Not registered by
/// `registerAll` (dead table, see file header) and not the syscall a live
/// `sol_alt_bn128_group_op` call reaches; the real pure-Zig implementation is
/// `vex_crypto.bn254.g1Add`/`g1Mul`/`g2Add`/`g2Mul`/`pairing` via
/// `vex_bpf2/syscalls.zig`.
fn solAltBn128GroupOp(_: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return 1; // unimplemented in this dormant table (see file header)
}

/// Genuine stub — always returns 1 (unimplemented). Not registered by
/// `registerAll` (dead table, see file header); the real pure-Zig
/// compress/decompress implementation is `vex_crypto.bn254.g1Compress`/
/// `g1Decompress`/`g2Compress`/`g2Decompress` via `vex_bpf2/syscalls.zig`.
fn solAltBn128Compress(_: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return 1; // unimplemented in this dormant table (see file header)
}

// ── PDA (Program Derived Addresses) ──────────────────────────────────────────
// sig/src/vm/syscalls/lib.zig:createProgramAddress + findProgramAddress
// fd_vm/syscall/fd_vm_syscall_pda.c

fn pdaHash(
    mm: MemoryMap,
    seeds_vm: u64,
    n_seeds: u64,
    program_id_vm: u64,
    bump: ?u8,
) mem.AccessError!?[32]u8 {
    if (n_seeds > 16) return null;
    const SeedHdr = extern struct { ptr: u64, len: u64 };
    const hdrs_raw = try mm.vmap(.constant, seeds_vm, n_seeds * @sizeOf(SeedHdr));
    const prog_id = try mm.vmap(.constant, program_id_vm, 32);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var i: u64 = 0;
    while (i < n_seeds) : (i += 1) {
        const off = @as(usize, @intCast(i)) * @sizeOf(SeedHdr);
        const hdr: SeedHdr = @bitCast(hdrs_raw[off..][0..@sizeOf(SeedHdr)].*);
        if (hdr.len > 32) return null; // seed too long
        if (hdr.len > 0) {
            const seed = mm.vmap(.constant, hdr.ptr, hdr.len) catch return null;
            hasher.update(seed);
        }
    }
    if (bump) |b| hasher.update(&[_]u8{b});
    hasher.update(prog_id);
    hasher.update("ProgramDerivedAddress");
    const digest = hasher.finalResult();

    // Valid PDA must NOT be a valid Ed25519 point.
    // We use the canonical check: try to decode; failure = off-curve = valid PDA.
    const result = std.crypto.ecc.Edwards25519.fromBytes(digest);
    if (!std.meta.isError(result)) return null; // on-curve → invalid PDA
    return digest;
}

fn solCreatePda(ctx: *SyscallContext, seeds_vm: u64, n: u64, prog_vm: u64, out_vm: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SHA256_BASE_COST * (n + 1));
    const mm: MemoryMap = sc(ctx).memory_map.*;
    const hash = pdaHash(mm, seeds_vm, n, prog_vm, null) catch return ExecutionError.AccessViolation;
    if (hash == null) return 1; // invalid PDA
    const out = try mm.vmap(.mutable, out_vm, 32);
    @memcpy(out, &hash.?);
    return 0;
}

fn solTryFindPda(ctx: *SyscallContext, seeds_vm: u64, n: u64, prog_vm: u64, out_vm: u64, bump_vm: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SHA256_BASE_COST * (n + 1) * 256);
    const mm: MemoryMap = sc(ctx).memory_map.*;
    var bump: u8 = 255;
    while (true) {
        const hash = pdaHash(mm, seeds_vm, n, prog_vm, bump) catch return ExecutionError.AccessViolation;
        if (hash) |h| {
            const out = try mm.vmap(.mutable, out_vm, 32);
            const bout = try mm.vmap(.mutable, bump_vm, 1);
            @memcpy(out, &h);
            bout[0] = bump;
            return 0;
        }
        if (bump == 0) break;
        bump -= 1;
    }
    return 1; // no valid bump found
}

// ── CPI ───────────────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/cpi.zig:invokeSigned
// fd_vm/syscall/fd_vm_syscall_cpi.c

fn solInvokeSigned(ctx: *SyscallContext, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) ExecutionError!u64 {
    // Phase-1 inline CPI: dispatch System program calls natively without
    // recursing into a nested VM. This is what unblocks ATA / Router / and
    // panic-loop programs that previously got Exit→empty-mutations because
    // every CPI to System came back as "no handler wired".
    //
    // r1 → SolInstruction (40-byte C ABI):
    //   +0  u64 program_id_addr   → VM ptr to [32]u8
    //   +8  u64 accounts_addr     → VM ptr to SolAccountMeta[]
    //   +16 u64 accounts_len
    //   +24 u64 data_addr         → VM ptr to u8[]
    //   +32 u64 data_len
    //
    // r2 → SolAccountInfo[] (C ABI, 64-byte stride per executor docs):
    //   +0  u64 key_addr        → VM ptr to [32]u8
    //   +8  u64 lamports_addr   → VM ptr to u64       (write-through)
    //   +16 u64 data_len
    //   +24 u64 data_addr       → VM ptr to u8[]      (write-through)
    //   +32 u64 owner_addr      → VM ptr to [32]u8    (write-through)
    //   +40 u64 rent_epoch
    //   +48 u8 is_signer
    //   +49 u8 is_writable
    //   +50 u8 executable
    //   (13 bytes pad → 64 total)
    //
    // r3 → account info count (typically same as accounts_len)
    // r4/r5 → signers_seeds_ptr / signers_seeds_len (PDA validation; ignored
    //         in Phase 1 — see system_cpi.zig docstring).

    // ── Try inline System dispatch first ────────────────────────────────────
    const mm = sc(ctx).memory_map;

    // Read SolInstruction (40 bytes).
    if (mm.vmap(.constant, r1, 40)) |ix_raw| {
        const pid_ptr = std.mem.readInt(u64, ix_raw[0..8], .little);
        if (mm.vmap(.constant, pid_ptr, 32)) |pid_bytes| {
            // Match against System program ID (all-zero pubkey).
            var is_system = true;
            for (pid_bytes[0..32]) |b| if (b != 0) {
                is_system = false;
                break;
            };
            if (is_system) {
                const data_addr = std.mem.readInt(u64, ix_raw[24..32], .little);
                const data_len = std.mem.readInt(u64, ix_raw[32..40], .little);
                return dispatchSystemCpi(ctx, mm, data_addr, data_len, r2, r3, r4, r5);
            }
        } else |_| {}
    } else |_| {}

    // ── Existing escape hatch: external CPI handler (legacy / future Rust ABI) ─
    if (tls_cpi_handler) |h| {
        return h.func(h.ctx, ctx, r1, r2, r3, r4, r5);
    }
    // Unhandled CPI target — RPC shadow fallback. Caller maps Exit→empty
    // mutations + cpi_required diag.
    return ExecutionError.Exit;
}

/// SolAccountInfo C ABI stride. The executor's CPI docs document 64 bytes
/// (with 13-byte trailing pad). vex-022's SPL handler used 56 bytes (no
/// trailing executable+pad). Solana's program SDK rust definition pads to
/// 64. Use 64 to match the program-runtime canonical.
const SOL_ACCT_INFO_STRIDE: u64 = 64;

/// Maximum reallocation slack the serialiser leaves after each account's
/// data region. MUST stay in sync with sbpf_executor.zig:MAX_REALLOC.
const MAX_REALLOC_BUDGET: usize = 10 * 1024;

fn dispatchSystemCpi(
    _: *SyscallContext,
    mm: *mem.MemoryMap,
    data_addr: u64,
    data_len: u64,
    accts_vm: u64,
    accts_n: u64,
    _: u64, // signers_seeds_ptr — Phase 1 ignores
    _: u64, // signers_seeds_len — Phase 1 ignores
) ExecutionError!u64 {
    SystemCpiDiag.total += 1;
    _ = &SystemCpiDiag.parse_fail;

    // Read instruction discriminator (first 4 bytes, little-endian u32).
    if (data_len < 4) {
        SystemCpiDiag.parse_fail += 1;
        SystemCpiDiag.err += 1;
        return sys_cpi.ERR_INVALID_INSTRUCTION;
    }
    const ix_data = mm.vmap(.constant, data_addr, data_len) catch {
        SystemCpiDiag.parse_fail += 1;
        SystemCpiDiag.err += 1;
        return sys_cpi.ERR_INVALID_INSTRUCTION;
    };
    const disc = std.mem.readInt(u32, ix_data[0..4], .little);

    // Helper: parse a SolAccountInfo at index i into an AccountSlice.
    const parse = struct {
        fn one(m: *mem.MemoryMap, base: u64, idx: u64) ?sys_cpi.AccountSlice {
            const off = base + idx * SOL_ACCT_INFO_STRIDE;
            const info_raw = m.vmap(.constant, off, SOL_ACCT_INFO_STRIDE) catch return null;
            const key_vm = std.mem.readInt(u64, info_raw[0..8], .little);
            const lam_vm = std.mem.readInt(u64, info_raw[8..16], .little);
            const dlen = std.mem.readInt(u64, info_raw[16..24], .little);
            const data_vm = std.mem.readInt(u64, info_raw[24..32], .little);
            const owner_vm = std.mem.readInt(u64, info_raw[32..40], .little);
            const is_writable = info_raw[49] != 0;

            const lam_slice = m.vmap(.mutable, lam_vm, 8) catch return null;
            const data_slice: []u8 = if (dlen > 0)
                (m.vmap(.mutable, data_vm, dlen) catch return null)
            else
                lam_slice[0..0];
            const owner_slice = m.vmap(.mutable, owner_vm, 32) catch return null;

            // The data_len header sits 8 bytes BEFORE data_addr in the input
            // region. The serializer wrote it (sbpf_executor.zig:720). It's
            // mutable too (input region is .mutable).
            const dlen_hdr_slice: []u8 = if (data_vm >= 8)
                (m.vmap(.mutable, data_vm - 8, 8) catch return null)
            else
                lam_slice[0..0];

            var pk: [32]u8 = .{0} ** 32;
            if (m.vmap(.constant, key_vm, 32)) |k| {
                @memcpy(&pk, k[0..32]);
            } else |_| {}

            return .{
                .lamports_ptr = lam_slice,
                .data = data_slice,
                .data_len_hdr = dlen_hdr_slice,
                .owner_ptr = owner_slice,
                // The serialiser reserves MAX_REALLOC bytes after each
                // account's data, plus alignment padding. Allocating up to
                // realloc_capacity is safe.
                .realloc_capacity = MAX_REALLOC_BUDGET,
                .pubkey = pk,
                .is_writable = is_writable,
            };
        }
    }.one;

    const log_n_max: u64 = 32;
    const SystemCpiLogState = struct {
        var n: u64 = 0;
    };

    switch (disc) {
        sys_cpi.IX_TRANSFER => {
            SystemCpiDiag.transfer += 1;
            if (accts_n < 2 or data_len < 12) {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            }
            const lamports = std.mem.readInt(u64, ix_data[4..12], .little);
            const from = parse(mm, accts_vm, 0) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const to = parse(mm, accts_vm, 1) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const rc = sys_cpi.execTransfer(from, to, lamports);
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=Transfer from={x:0>2}{x:0>2}..{x:0>2}{x:0>2} to={x:0>2}{x:0>2}..{x:0>2}{x:0>2} lamports={d} rc={d}\n", .{
                    from.pubkey[0], from.pubkey[1], from.pubkey[30], from.pubkey[31],
                    to.pubkey[0],   to.pubkey[1],   to.pubkey[30],   to.pubkey[31],
                    lamports,       rc,
                });
            }
            if (rc == 0) SystemCpiDiag.ok += 1 else SystemCpiDiag.err += 1;
            return rc;
        },
        sys_cpi.IX_CREATE_ACCOUNT => {
            SystemCpiDiag.create_account += 1;
            // Layout: u32 disc, u64 lamports, u64 space, [32]u8 owner = 52 bytes.
            if (accts_n < 2 or data_len < 52) {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            }
            const lamports = std.mem.readInt(u64, ix_data[4..12], .little);
            const space = std.mem.readInt(u64, ix_data[12..20], .little);
            var owner: [32]u8 = undefined;
            @memcpy(&owner, ix_data[20..52]);
            const from = parse(mm, accts_vm, 0) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const to = parse(mm, accts_vm, 1) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const rc = sys_cpi.execCreateAccount(from, to, lamports, space, owner);
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=CreateAccount fee_payer={x:0>2}{x:0>2}..{x:0>2}{x:0>2} new={x:0>2}{x:0>2}..{x:0>2}{x:0>2} lamports={d} space={d} owner={x:0>2}{x:0>2}..{x:0>2}{x:0>2} rc={d}\n", .{
                    from.pubkey[0], from.pubkey[1], from.pubkey[30], from.pubkey[31],
                    to.pubkey[0],   to.pubkey[1],   to.pubkey[30],   to.pubkey[31],
                    lamports,       space,          owner[0],        owner[1],
                    owner[30],      owner[31],      rc,
                });
            }
            if (rc == 0) SystemCpiDiag.ok += 1 else SystemCpiDiag.err += 1;
            return rc;
        },
        sys_cpi.IX_ALLOCATE => {
            SystemCpiDiag.allocate += 1;
            if (accts_n < 1 or data_len < 12) {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            }
            const space = std.mem.readInt(u64, ix_data[4..12], .little);
            const tgt = parse(mm, accts_vm, 0) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const rc = sys_cpi.execAllocate(tgt, space);
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=Allocate target={x:0>2}{x:0>2}..{x:0>2}{x:0>2} space={d} rc={d}\n", .{
                    tgt.pubkey[0], tgt.pubkey[1], tgt.pubkey[30], tgt.pubkey[31], space, rc,
                });
            }
            if (rc == 0) SystemCpiDiag.ok += 1 else SystemCpiDiag.err += 1;
            return rc;
        },
        sys_cpi.IX_ASSIGN => {
            SystemCpiDiag.assign += 1;
            if (accts_n < 1 or data_len < 36) {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            }
            var owner: [32]u8 = undefined;
            @memcpy(&owner, ix_data[4..36]);
            const tgt = parse(mm, accts_vm, 0) orelse {
                SystemCpiDiag.err += 1;
                return sys_cpi.ERR_INVALID_INSTRUCTION;
            };
            const rc = sys_cpi.execAssign(tgt, owner);
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=Assign target={x:0>2}{x:0>2}..{x:0>2}{x:0>2} owner={x:0>2}{x:0>2}..{x:0>2}{x:0>2} rc={d}\n", .{
                    tgt.pubkey[0], tgt.pubkey[1], tgt.pubkey[30], tgt.pubkey[31],
                    owner[0],      owner[1],      owner[30],      owner[31],
                    rc,
                });
            }
            if (rc == 0) SystemCpiDiag.ok += 1 else SystemCpiDiag.err += 1;
            return rc;
        },
        sys_cpi.IX_CREATE_ACCOUNT_WITH_SEED, sys_cpi.IX_ALLOCATE_WITH_SEED, sys_cpi.IX_ASSIGN_WITH_SEED, sys_cpi.IX_TRANSFER_WITH_SEED => {
            // Phase 1: WithSeed variants need create_with_seed PDA derivation
            // (sha256(base || seed || owner)). Stub returns InstructionError
            // — NOT silent Exit — so the BPF caller's `?` propagates Err.
            SystemCpiDiag.with_seed_stub += 1;
            SystemCpiDiag.err += 1;
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=WithSeed disc={d} STUB rc={d}\n", .{ disc, sys_cpi.ERR_NOT_SUPPORTED });
            }
            return sys_cpi.ERR_NOT_SUPPORTED;
        },
        sys_cpi.IX_ADVANCE_NONCE, sys_cpi.IX_WITHDRAW_NONCE, sys_cpi.IX_INITIALIZE_NONCE, sys_cpi.IX_AUTHORIZE_NONCE, sys_cpi.IX_UPGRADE_NONCE => {
            SystemCpiDiag.nonce_stub += 1;
            SystemCpiDiag.err += 1;
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=Nonce disc={d} STUB rc={d}\n", .{ disc, sys_cpi.ERR_NOT_SUPPORTED });
            }
            return sys_cpi.ERR_NOT_SUPPORTED;
        },
        else => {
            SystemCpiDiag.err += 1;
            if (SystemCpiLogState.n < log_n_max) {
                SystemCpiLogState.n += 1;
                std.log.debug("[CPI-SYSTEM] kind=Unknown disc={d} rc={d}\n", .{ disc, sys_cpi.ERR_INVALID_INSTRUCTION });
            }
            return sys_cpi.ERR_INVALID_INSTRUCTION;
        },
    }
}

// ── Sysvars ───────────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/sysvar.zig:getClock/getEpochSchedule/getRent/etc.
// fd_vm/syscall/fd_vm_syscall_sysvar.c

/// Generic sysvar getter: copies ctx.{sysvar}_data into the VM destination.
fn writeSysvar(ctx: *SyscallContext, out_vm: u64, data: []const u8) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SYSVAR_BASE_COST + @as(u64, data.len));
    const mm = sc(ctx).memory_map;
    const out = try mm.vmap(.mutable, out_vm, @as(u64, data.len));
    @memcpy(out, data);
    return 0;
}

fn solGetClock(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return writeSysvar(ctx, out_vm, &ctx.clock_data);
}

fn solGetEpochSchedule(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return writeSysvar(ctx, out_vm, &ctx.epoch_sched_data);
}

fn solGetFees(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    // Fees sysvar: 8-byte lamports_per_signature.
    var fees: [8]u8 = [_]u8{0} ** 8;
    std.mem.writeInt(u64, &fees, 5000, .little); // default: 5000 lamports/sig
    return writeSysvar(ctx, out_vm, &fees);
}

fn solGetRent(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return writeSysvar(ctx, out_vm, &ctx.rent_data);
}

fn solGetLastRestartSlot(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    var last: [8]u8 = [_]u8{0} ** 8; // 0 = no restart yet
    return writeSysvar(ctx, out_vm, &last);
}

fn solGetEpochRewards(ctx: *SyscallContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    // EpochRewards sysvar: 33 bytes (active + distribution_starting_block_height + total + distributed)
    // Return zeroed for now (no epoch rewards active).
    var rew: [33]u8 = [_]u8{0} ** 33;
    return writeSysvar(ctx, out_vm, &rew);
}

/// Generic sol_get_sysvar (SIMD-0127): lookup by pubkey → copy slice.
fn solGetSysvar(ctx: *SyscallContext, id_vm: u64, out_vm: u64, offset: u64, length: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SYSVAR_BASE_COST + length / ComputeBudget.CPI_BYTES_PER_UNIT);
    const mm = sc(ctx).memory_map;
    const id_bytes = mm.vmap(.constant, id_vm, 32) catch return 2; // SYSVAR_NOT_FOUND
    // Match against known sysvar pubkeys.  For now return not-found for unknown sysvars.
    const clock_key = [_]u8{ 6, 167, 213, 23, 25, 44, 92, 81, 33, 140, 201, 76, 61, 74, 241, 127, 88, 218, 238, 8, 195, 255, 73, 219, 180, 52, 166, 248, 195, 206, 7, 181 };
    const rent_key = [_]u8{ 6, 167, 213, 23, 24, 199, 116, 201, 66, 86, 9, 97, 140, 226, 113, 131, 183, 125, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const epoch_sched_key = [_]u8{ 6, 167, 213, 23, 30, 5, 65, 103, 13, 140, 28, 206, 214, 174, 138, 62, 100, 197, 247, 242, 164, 99, 8, 22, 255, 119, 190, 253, 149, 13, 200, 119 };

    const data: []const u8 = if (std.mem.eql(u8, id_bytes, &clock_key))
        &ctx.clock_data
    else if (std.mem.eql(u8, id_bytes, &rent_key))
        &ctx.rent_data
    else if (std.mem.eql(u8, id_bytes, &epoch_sched_key))
        &ctx.epoch_sched_data
    else
        return 2; // SYSVAR_NOT_FOUND

    if (@as(u64, data.len) < offset + length) return 1; // OFFSET_LENGTH_EXCEEDS
    const out = try mm.vmap(.mutable, out_vm, length);
    @memcpy(out, data[@intCast(offset)..@intCast(offset + length)]);
    return 0;
}

// ── Return data ───────────────────────────────────────────────────────────────
// sig/src/vm/syscalls/lib.zig:setReturnData/getReturnData
// fd_vm/syscall/fd_vm_syscall_base.c

pub const MAX_RETURN_DATA: u64 = 1024;

fn solSetReturnData(ctx: *SyscallContext, addr: u64, len: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    if (len > MAX_RETURN_DATA) return 1; // ReturnDataTooLarge
    consumeCu(ctx, len / ComputeBudget.CPI_BYTES_PER_UNIT + ComputeBudget.SYSCALL_BASE_COST);
    const mm = sc(ctx).memory_map;
    if (len == 0) {
        ctx.return_data_len = 0;
        return 0;
    }
    const data = try mm.vmap(.constant, addr, len);
    @memcpy(ctx.return_data[0..@intCast(len)], data);
    ctx.return_data_len = len;
    return 0;
}

fn solGetReturnData(ctx: *SyscallContext, out_vm: u64, max_len: u64, prog_id_vm: u64, _: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SYSCALL_BASE_COST);
    const mm = sc(ctx).memory_map;
    const copy_len = @min(ctx.return_data_len, max_len);
    if (copy_len > 0) {
        const cost = (copy_len + 32) / ComputeBudget.CPI_BYTES_PER_UNIT;
        consumeCu(ctx, cost);
        const out = try mm.vmap(.mutable, out_vm, copy_len);
        @memcpy(out, ctx.return_data[0..@intCast(copy_len)]);
        const prog_id_out = try mm.vmap(.mutable, prog_id_vm, 32);
        @memcpy(prog_id_out, &ctx.return_program_id);
    }
    return ctx.return_data_len;
}

// ── Introspection ─────────────────────────────────────────────────────────────

fn solGetStackHeight(ctx: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return sc(ctx).call_depth + 1;
}

fn solGetSibling(_: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return 0; // not found — full impl requires InstructionTrace context
}

fn solRemainingComputeUnits(ctx: *SyscallContext, _: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    return ctx.compute_remaining.*;
}

fn solGetEpochStake(ctx: *SyscallContext, vote_addr_vm: u64, _: u64, _: u64, _: u64, _: u64) ExecutionError!u64 {
    consumeCu(ctx, ComputeBudget.SYSCALL_BASE_COST);
    if (vote_addr_vm == 0) return 0; // return total active stake (not tracked here)
    const f = sc(ctx).epoch_stake_fn orelse return 0;
    const mm = sc(ctx).memory_map;
    const addr_bytes = mm.vmap(.constant, vote_addr_vm, 32) catch return 0;
    var addr: [32]u8 = undefined;
    @memcpy(&addr, addr_bytes);
    return f(addr);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

inline fn consumeCu(ctx: *SyscallContext, cost: u64) void {
    ctx.compute_remaining.* -|= cost;
}

fn regionsOverlap(a: [*]const u8, b: [*]const u8, n: u64) bool {
    const ai = @intFromPtr(a);
    const bi = @intFromPtr(b);
    return !(ai + n <= bi or bi + n <= ai);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "syscall IDs: known murmur3 values" {
    const murmur3 = @import("vm_executable.zig").murmur3;
    try std.testing.expectEqual(ID_SOL_LOG, murmur3("sol_log_"));
    try std.testing.expectEqual(ID_SOL_SHA256, murmur3("sol_sha256"));
    try std.testing.expectEqual(ID_SOL_INVOKE_SIGNED_R, murmur3("sol_invoke_signed_rust"));
    try std.testing.expectEqual(ID_SOL_ALLOC_FREE, murmur3("sol_alloc_free_"));
    try std.testing.expectEqual(ID_SOL_GET_CLOCK, murmur3("sol_get_clock_sysvar"));
    try std.testing.expectEqual(ID_SOL_GET_RENT, murmur3("sol_get_rent_sysvar"));
}
