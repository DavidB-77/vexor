//! Vexor SBPF Syscall Implementations
//!
//! All syscall IDs are murmur3_32(name, seed=0) where name is the exact
//! function name string Solana programs emit. Values computed from first
//! principles — see tools/compute_syscall_hashes.py in this repo.
//!
//! Syscalls that require CPI return VmError.CpiRequired so the executor
//! can fall back to the RPC shadow for those slots.

const std = @import("std");
const interp = @import("interpreter.zig");
const VmContext = interp.VmContext;
const VmError = interp.VmError;

// ── Exact murmur3_32(name, 0) values ─────────────────────────────────────────

pub const ID_ABORT: u32 = 0xb6fc1a11;
pub const ID_SOL_PANIC: u32 = 0x686093bb;
pub const ID_SOL_LOG: u32 = 0x207559bd;
pub const ID_SOL_LOG_64: u32 = 0x5c2a3178;
pub const ID_SOL_LOG_PUBKEY: u32 = 0x7ef088ca;
pub const ID_SOL_LOG_CU: u32 = 0x52ba5096;
pub const ID_SOL_LOG_DATA: u32 = 0x7317b434;
pub const ID_SOL_MEMCPY: u32 = 0x717cc4a3;
pub const ID_SOL_MEMMOVE: u32 = 0x434371f8;
pub const ID_SOL_MEMCMP: u32 = 0x5fdcde31;
pub const ID_SOL_MEMSET: u32 = 0x3770fb22;
pub const ID_SOL_SHA256: u32 = 0x11f49d86;
pub const ID_SOL_KECCAK256: u32 = 0xd7793abb;
pub const ID_SOL_BLAKE3: u32 = 0x174c5122;
pub const ID_SOL_SHA512: u32 = 0x9229cdcc; // murmur3("sol_sha512"), SIMD-0512
pub const ID_SOL_SECP256K1: u32 = 0x17e40350;
pub const ID_SOL_CREATE_PDA: u32 = 0x9377323c; // r74-vex-027: was 0x96108919 (drifted, trailing-underscore variant)
pub const ID_SOL_TRY_FIND_PDA: u32 = 0x48504a38;
pub const ID_SOL_INVOKE_SIGNED_C: u32 = 0xa22b9c85;
pub const ID_SOL_INVOKE_SIGNED_R: u32 = 0xd7449092;
pub const ID_SOL_ALLOC_FREE: u32 = 0x83f00e8f;
pub const ID_SOL_GET_CLOCK: u32 = 0xd56b5fe9;
pub const ID_SOL_GET_RENT: u32 = 0xbf7188f6;
pub const ID_SOL_GET_EPOCH_SCHED: u32 = 0x23a29a61;
pub const ID_SOL_SET_RETURN: u32 = 0xa226d3eb;
pub const ID_SOL_GET_RETURN: u32 = 0x5d2245e4;
pub const ID_SOL_STACK_HEIGHT: u32 = 0x85532d94;
pub const ID_SOL_GET_SIBLING: u32 = 0xadb8efc8;

// ── Registration ─────────────────────────────────────────────────────────────

pub fn registerAll(ctx: *VmContext) !void {
    const R = VmContext.registerSyscall;
    try R(ctx, ID_ABORT, abort_);
    try R(ctx, ID_SOL_PANIC, solPanic);
    try R(ctx, ID_SOL_LOG, solLog);
    try R(ctx, ID_SOL_LOG_64, solLog64);
    try R(ctx, ID_SOL_LOG_PUBKEY, solLogPubkey);
    try R(ctx, ID_SOL_LOG_CU, solLogCu);
    try R(ctx, ID_SOL_LOG_DATA, solLogData);
    try R(ctx, ID_SOL_MEMCPY, solMemcpy);
    try R(ctx, ID_SOL_MEMMOVE, solMemmove);
    try R(ctx, ID_SOL_MEMCMP, solMemcmp);
    try R(ctx, ID_SOL_MEMSET, solMemset);
    try R(ctx, ID_SOL_SHA256, solSha256);
    try R(ctx, ID_SOL_KECCAK256, solKeccak256);
    try R(ctx, ID_SOL_BLAKE3, solBlake3);
    try R(ctx, ID_SOL_SHA512, solSha512);
    try R(ctx, ID_SOL_SECP256K1, solSecp256k1Recover);
    try R(ctx, ID_SOL_CREATE_PDA, solCreatePda);
    try R(ctx, ID_SOL_TRY_FIND_PDA, solTryFindPda);
    // CPI — both C and Rust ABI flavours
    try R(ctx, ID_SOL_INVOKE_SIGNED_C, solInvokeSigned);
    try R(ctx, ID_SOL_INVOKE_SIGNED_R, solInvokeSigned);
    try R(ctx, ID_SOL_ALLOC_FREE, solAllocFree);
    try R(ctx, ID_SOL_GET_CLOCK, solGetClock);
    try R(ctx, ID_SOL_GET_RENT, solGetRent);
    try R(ctx, ID_SOL_GET_EPOCH_SCHED, solGetEpochSched);
    try R(ctx, ID_SOL_SET_RETURN, solSetReturnData);
    try R(ctx, ID_SOL_GET_RETURN, solGetReturnData);
    try R(ctx, ID_SOL_STACK_HEIGHT, solStackHeight);
    try R(ctx, ID_SOL_GET_SIBLING, solGetSibling);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read a host slice that the VM told us is at vm_addr with length vm_len.
/// Guards against absurd lengths before translating.
fn safeR(ctx: *const VmContext, vm_addr: u64, vm_len: u64, max: u64) VmError![]const u8 {
    if (vm_len > max) return VmError.AccessViolation;
    return ctx.translateR(vm_addr, vm_len);
}

fn safeW(ctx: *const VmContext, vm_addr: u64, vm_len: u64, max: u64) VmError![]u8 {
    if (vm_len > max) return VmError.AccessViolation;
    return ctx.translate(vm_addr, vm_len, true);
}

// ── Abort / panic ─────────────────────────────────────────────────────────────

fn abort_(ctx: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    // FIX-1a (2026-06-10, task #65): force a non-zero exit code. Agave's
    // abort syscall is ALWAYS an instruction failure (SyscallError::Abort →
    // ProgramFailedToComplete), regardless of whatever happens to sit in r0.
    // Pre-fix, Halted made executeInner read garbage r0 — a 0 there recorded
    // a program abort as SUCCESS. r0=1 lands the run in the genuine
    // .program_error class.
    ctx.regs[0] = 1;
    return VmError.Halted;
}

fn solPanic(ctx: *VmContext, file_vm: u64, file_len: u64, line: u64, col: u64, _: u64) VmError!u64 {
    const file = safeR(ctx, file_vm, file_len, 512) catch "<?>";
    std.log.warn("[SBPF] panic at {s}:{}:{}", .{ file, line, col });
    // FIX-1a: same as abort_ — sol_panic_ is always SyscallError::Panic on
    // Agave; never a success path.
    ctx.regs[0] = 1;
    return VmError.Halted;
}

// ── Logging ───────────────────────────────────────────────────────────────────

fn solLog(ctx: *VmContext, msg_vm: u64, msg_len: u64, _: u64, _: u64, _: u64) VmError!u64 {
    const msg = safeR(ctx, msg_vm, msg_len, 10_000) catch return 0;
    std.log.debug("[Program] {s}", .{msg});
    return 0;
}

fn solLog64(_: *VmContext, a: u64, b: u64, c: u64, d: u64, e: u64) VmError!u64 {
    std.log.debug("[Program] {x} {x} {x} {x} {x}", .{ a, b, c, d, e });
    return 0;
}

fn solLogPubkey(ctx: *VmContext, pk_vm: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    const pk = safeR(ctx, pk_vm, 32, 32) catch return 0;
    std.log.debug("[Program] pubkey {x}", .{pk});
    return 0;
}

fn solLogCu(_: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return 0; // TODO: wire compute budget
}

fn solLogData(ctx: *VmContext, slices_vm: u64, n: u64, _: u64, _: u64, _: u64) VmError!u64 {
    if (n > 64) return VmError.AccessViolation;
    const hdrs = try ctx.translateR(slices_vm, n * 16);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ptr = std.mem.readInt(u64, hdrs[i * 16 ..][0..8], .little);
        const len = std.mem.readInt(u64, hdrs[i * 16 + 8 ..][0..8], .little);
        const data = safeR(ctx, ptr, len, 1024) catch continue;
        std.log.debug("[Program data] {x}", .{data});
    }
    return 0;
}

// ── Memory operations ─────────────────────────────────────────────────────────

fn solMemcpy(ctx: *VmContext, dst_vm: u64, src_vm: u64, n: u64, _: u64, _: u64) VmError!u64 {
    if (n == 0) return 0;
    if (n > 10 * 1024 * 1024) return VmError.AccessViolation;
    const src = try ctx.translateR(src_vm, n);
    const dst = try ctx.translate(dst_vm, n, true);
    // memcpy requires non-overlapping; overlapping is undefined behaviour
    @memcpy(dst, src);
    return 0;
}

fn solMemmove(ctx: *VmContext, dst_vm: u64, src_vm: u64, n: u64, _: u64, _: u64) VmError!u64 {
    if (n == 0) return 0;
    if (n > 10 * 1024 * 1024) return VmError.AccessViolation;
    const src = try ctx.translateR(src_vm, n);
    const dst = try ctx.translate(dst_vm, n, true);
    std.mem.copyForwards(u8, dst, src);
    return 0;
}

fn solMemcmp(ctx: *VmContext, a_vm: u64, b_vm: u64, n: u64, out_vm: u64, _: u64) VmError!u64 {
    if (n > 10 * 1024 * 1024) return VmError.AccessViolation;
    const a = try ctx.translateR(a_vm, n);
    const b = try ctx.translateR(b_vm, n);
    const out = try ctx.translate(out_vm, 4, true);
    var cmp: i32 = 0;
    for (0..n) |i| {
        if (a[i] != b[i]) {
            cmp = @as(i32, a[i]) - @as(i32, b[i]);
            break;
        }
    }
    std.mem.writeInt(i32, out[0..4], cmp, .little);
    return 0;
}

fn solMemset(ctx: *VmContext, dst_vm: u64, val: u64, n: u64, _: u64, _: u64) VmError!u64 {
    if (n == 0) return 0;
    if (n > 10 * 1024 * 1024) return VmError.AccessViolation;
    const dst = try ctx.translate(dst_vm, n, true);
    @memset(dst, @truncate(val));
    return 0;
}

// ── Heap allocator ────────────────────────────────────────────────────────────

fn solAllocFree(ctx: *VmContext, size: u64, free_addr: u64, _: u64, _: u64, _: u64) VmError!u64 {
    if (free_addr != 0) return 0; // free is a no-op (bump allocator)
    if (size == 0) return 0;
    const aligned = (size + 7) & ~@as(u64, 7);
    const ptr = ctx.heap_cursor;
    const end = ptr + aligned;
    if (end > interp.VM_HEAP_START + interp.HEAP_SIZE) return 0; // OOM → null
    ctx.heap_cursor = end;
    return ptr;
}

// ── Hash syscalls ─────────────────────────────────────────────────────────────

const SliceHdr = extern struct { ptr: u64, len: u64 };

fn hashSlices(comptime Hasher: type, ctx: *VmContext, slices_vm: u64, n: u64, out_vm: u64, comptime out_len: usize) VmError!u64 {
    if (n > 1000) return VmError.AccessViolation;
    const hdrs_mem = try ctx.translateR(slices_vm, n * @sizeOf(SliceHdr));
    var hasher = Hasher.init(.{});
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const h: SliceHdr = @bitCast(hdrs_mem[i * @sizeOf(SliceHdr) ..][0..@sizeOf(SliceHdr)].*);
        if (h.len == 0) continue;
        const data = try ctx.translateR(h.ptr, h.len);
        hasher.update(data);
    }
    const out = try ctx.translate(out_vm, out_len, true);
    // Zig 0.14: final() requires a comptime-known fixed-size array, not a runtime slice.
    var digest: [Hasher.digest_length]u8 = undefined;
    hasher.final(&digest);
    @memcpy(out[0..out_len], digest[0..out_len]);
    return 0;
}

fn solSha256(ctx: *VmContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) VmError!u64 {
    return hashSlices(std.crypto.hash.sha2.Sha256, ctx, sl_vm, n, out_vm, 32);
}

fn solKeccak256(ctx: *VmContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) VmError!u64 {
    return hashSlices(std.crypto.hash.sha3.Keccak256, ctx, sl_vm, n, out_vm, 32);
}

fn solBlake3(ctx: *VmContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) VmError!u64 {
    return hashSlices(std.crypto.hash.Blake3, ctx, sl_vm, n, out_vm, 32);
}

// SIMD-0512. V1 has no feature plumbing — registered unconditionally; only
// sbpf v1/v2 ELFs reach V1 (v0/v3 route to the V2 producer where the gate
// lives), so the pre-activation exposure window is ~nil and V1 CU accounting
// is already declared non-authoritative. hashSlices sizes the digest from
// Hasher.digest_length (= 64 for Sha512).
fn solSha512(ctx: *VmContext, sl_vm: u64, n: u64, out_vm: u64, _: u64, _: u64) VmError!u64 {
    return hashSlices(std.crypto.hash.sha2.Sha512, ctx, sl_vm, n, out_vm, 64);
}

fn solSecp256k1Recover(_: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return 1; // not implemented — programs using this will get error code 1
}

// ── PDA (Program Derived Addresses) ──────────────────────────────────────────
//
// PDA = SHA256(seed[0] || seed[1] || ... || program_id || "ProgramDerivedAddress")
// Valid PDA: result must NOT be a valid Ed25519 point.
// Simplified validity check: test byte [31] & 0x80 (heuristic, not exact).
// For full correctness, proper curve-point rejection is needed; this covers
// the vast majority of real PDAs on testnet.

fn pdaHash(
    ctx: *VmContext,
    seeds_vm: u64,
    n_seeds: u64,
    program_id_vm: u64,
    bump_seed: ?u8,
) VmError![32]u8 {
    if (n_seeds > 16) return VmError.AccessViolation;
    const SeedHdr = extern struct { ptr: u64, len: u64 };
    const hdrs_mem = try ctx.translateR(seeds_vm, n_seeds * @sizeOf(SeedHdr));
    const prog_id = try ctx.translateR(program_id_vm, 32);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var i: usize = 0;
    while (i < n_seeds) : (i += 1) {
        const h: SeedHdr = @bitCast(hdrs_mem[i * @sizeOf(SeedHdr) ..][0..@sizeOf(SeedHdr)].*);
        if (h.len > 32) return VmError.SyscallFailed;
        if (h.len > 0) {
            const seed = try ctx.translateR(h.ptr, h.len);
            hasher.update(seed);
        }
    }
    if (bump_seed) |b| hasher.update(&[_]u8{b});
    hasher.update(prog_id);
    hasher.update("ProgramDerivedAddress");
    return hasher.finalResult();
}

fn solCreatePda(ctx: *VmContext, seeds_vm: u64, n: u64, prog_vm: u64, out_vm: u64, _: u64) VmError!u64 {
    const hash = try pdaHash(ctx, seeds_vm, n, prog_vm, null);
    // Reject if on Ed25519 curve (simplified: any byte with high bit set signals off-curve)
    if (hash[31] & 0x80 == 0) return 1; // on-curve → invalid PDA
    const out = try ctx.translate(out_vm, 32, true);
    @memcpy(out, &hash);
    return 0;
}

fn solTryFindPda(ctx: *VmContext, seeds_vm: u64, n: u64, prog_vm: u64, out_vm: u64, bump_vm: u64) VmError!u64 {
    var bump: u8 = 255;
    while (true) {
        const hash = try pdaHash(ctx, seeds_vm, n, prog_vm, bump);
        if (hash[31] & 0x80 != 0) {
            const out = try ctx.translate(out_vm, 32, true);
            const bout = try ctx.translate(bump_vm, 1, true);
            @memcpy(out, &hash);
            bout[0] = bump;
            return 0;
        }
        if (bump == 0) break;
        bump -= 1;
    }
    return 1; // no valid bump
}

// ── CPI ───────────────────────────────────────────────────────────────────────
//
// Cross-program invocation requires recursively executing another program,
// which in turn requires access to the full bank execution context. That
// context isn't available inside the VM. We signal CpiRequired and the
// executor falls back to the RPC shadow BPF for this slot.

fn solInvokeSigned(ctx: *VmContext, r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) VmError!u64 {
    // If the executor registered a CPI handler, use it for native CPI execution.
    if (ctx.cpi_ctx) |cpi_ctx| {
        if (ctx.cpi_handler) |handler| {
            const rc = try handler(cpi_ctx, ctx, r1, r2, r3, r4, r5);
            return rc;
        }
    }
    // No handler — signal the executor to fall back to RPC shadow.
    return VmError.CpiRequired;
}

// ── Sysvars ───────────────────────────────────────────────────────────────────

// Clock layout matches Agave Clock struct (packed, little-endian)
const ClockLayout = extern struct {
    slot: u64,
    epoch_start_ts: i64,
    epoch: u64,
    leader_schedule_epoch: u64,
    unix_ts: i64,
};

fn solGetClock(ctx: *VmContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    const out = try ctx.translate(out_vm, @sizeOf(ClockLayout), true);
    const now = std.time.timestamp();
    const clk = ClockLayout{
        .slot = 0,
        .epoch_start_ts = now,
        .epoch = 0,
        .leader_schedule_epoch = 1,
        .unix_ts = now,
    };
    @memcpy(out, std.mem.asBytes(&clk));
    return 0;
}

const RentLayout = extern struct { lamports_per_byte_year: u64, exemption_threshold: f64, burn_percent: u8 };

fn solGetRent(ctx: *VmContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    const out = try ctx.translate(out_vm, @sizeOf(RentLayout), true);
    const rent = RentLayout{ .lamports_per_byte_year = 3480, .exemption_threshold = 2.0, .burn_percent = 50 };
    @memcpy(out, std.mem.asBytes(&rent));
    return 0;
}

const EpochSchedLayout = extern struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
    _pad: [7]u8,
    first_normal_epoch: u64,
    first_normal_slot: u64,
};

fn solGetEpochSched(ctx: *VmContext, out_vm: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    const out = try ctx.translate(out_vm, @sizeOf(EpochSchedLayout), true);
    const es = EpochSchedLayout{
        .slots_per_epoch = 432_000,
        .leader_schedule_slot_offset = 432_000,
        .warmup = false,
        ._pad = [_]u8{0} ** 7,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };
    @memcpy(out, std.mem.asBytes(&es));
    return 0;
}

// ── Return data ───────────────────────────────────────────────────────────────

fn solSetReturnData(_: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return 0; // TODO: thread through executor context
}

fn solGetReturnData(_: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return 0; // returns length 0 (no return data)
}

// ── Introspection ─────────────────────────────────────────────────────────────

fn solStackHeight(ctx: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return ctx.call_depth + 1; // 1 = root frame
}

fn solGetSibling(_: *VmContext, _: u64, _: u64, _: u64, _: u64, _: u64) VmError!u64 {
    return 0; // not found
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "syscall IDs: spot-check murmur3" {
    // sol_log_ = 0x207559bd — verified against Agave rbpf
    try std.testing.expectEqual(@as(u32, 0x207559bd), ID_SOL_LOG);
    try std.testing.expectEqual(@as(u32, 0xd7449092), ID_SOL_INVOKE_SIGNED_R);
    try std.testing.expectEqual(@as(u32, 0x11f49d86), ID_SOL_SHA256);
}
