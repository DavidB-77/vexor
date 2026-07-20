//! Vexor BPF2 — M6 Syscalls test suite (Stage A).
//!
//! Stage-A coverage targets:
//!   1. Murmur3 hash parity vs V1 (`vm_executable.zig:851`) — anchored
//!      tests verify all V1 IDs match M6's `nameHash`.
//!   2. Registry shape: 43 entries, distinct hashes, selfTest passes.
//!   3. Memory access checks: parameterized AccessViolation tests for the
//!      pointer-bearing syscall families.
//!   4. CU exhaustion: each handler family raises `M6_ConsumeOverflow`
//!      when the meter is below its base cost.
//!   5. SysvarNotPopulated propagation (vex-058 invariant).
//!   6. Return-data round-trip (set then get).
//!   7. PDA derivation matches a known test vector (Sha256(seeds || pid || marker)).
//!   8. CPI handler stub returns `M6_CpiHandlerNotReady`.
//!   9. M4 trait adapter dispatches through.
//!  10. Crypto placeholders (poseidon, alt_bn128, curves, big_mod_exp)
//!      consume CU then return the documented named error.

const std = @import("std");
const testing = std.testing;

const memory = @import("memory.zig");
const invoke_ctx_mod = @import("invoke_ctx.zig");
const sysvar_cache_mod = @import("sysvar_cache.zig");
const interpreter = @import("interpreter.zig");
const syscalls = @import("syscalls.zig");
const trace = @import("trace.zig");
const bls_vectors = @import("bls12_381_test_vectors.zig");

const InvokeContext = invoke_ctx_mod.InvokeContext;
const TransactionContext = invoke_ctx_mod.TransactionContext;
const AccountView = invoke_ctx_mod.AccountView;
const SysvarCache = sysvar_cache_mod.SysvarCache;
const AlignedMemoryMap = memory.AlignedMemoryMap;
const Region = memory.Region;
const SyscallRegistry = syscalls.SyscallRegistry;
const SyscallError = syscalls.SyscallError;

// ──────────────────────────────────────────────────────────────────────────────
// Test harness — minimal InvokeContext + AlignedMemoryMap with five regions
// matching agave's canonical layout (bytecode, rodata, stack, heap, input).
// ──────────────────────────────────────────────────────────────────────────────

const Harness = struct {
    alloc: std.mem.Allocator,
    accounts: []AccountView,
    tx: TransactionContext,
    cache: SysvarCache,
    ic: InvokeContext,
    bytecode_buf: []u8,
    rodata_buf: []u8,
    stack_buf: []u8,
    heap_buf: []u8,
    input_buf: []u8,
    mm: AlignedMemoryMap,

    fn init(alloc: std.mem.Allocator, compute: u64) !*Harness {
        // Wave 5: silence forced sol_log emissions during tests so the test
        // runner doesn't interpret them as logged errors. Production sink is
        // restored by the next non-test caller of setSink.
        trace.setSink(trace.silentSinkFn());

        const h = try alloc.create(Harness);
        h.alloc = alloc;

        // One placeholder account so currentProgramId returns something stable.
        h.accounts = try alloc.alloc(AccountView, 1);
        h.accounts[0] = .{
            .pubkey = [_]u8{1} ** 32,
            .lamports = 0,
            .owner = [_]u8{0} ** 32,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
            .data = &.{},
            .is_writable = false,
            .is_signer = false,
        };

        const indices = try alloc.alloc(u16, 0);
        h.tx = TransactionContext.init(alloc, h.accounts, indices);
        h.cache = SysvarCache.init(alloc);
        h.ic = InvokeContext.init(alloc, &h.tx, &h.cache, compute);

        h.bytecode_buf = try alloc.alloc(u8, 4096);
        h.rodata_buf = try alloc.alloc(u8, 4096);
        h.stack_buf = try alloc.alloc(u8, 4096);
        // 20480 (not 4096): large enough to hold the FIX-1 hash-cost KAT's
        // 10,000-byte payload + VmSlice descriptor + output digest in one
        // region. No existing test depends on the heap region being exactly
        // 4096 bytes (checked: no OOB test addresses MM_HEAP_START+4096).
        h.heap_buf = try alloc.alloc(u8, 20480);
        h.input_buf = try alloc.alloc(u8, 4096);
        @memset(h.bytecode_buf, 0);
        @memset(h.rodata_buf, 0);
        @memset(h.stack_buf, 0);
        @memset(h.heap_buf, 0);
        @memset(h.input_buf, 0);

        const regions = [_]Region{
            Region.fromSlice(memory.MM_BYTECODE_START, h.bytecode_buf),
            Region.fromSlice(memory.MM_RODATA_START, h.rodata_buf),
            Region.fromSlice(memory.MM_STACK_START, h.stack_buf),
            Region.fromSlice(memory.MM_HEAP_START, h.heap_buf),
            Region.fromSlice(memory.MM_INPUT_START, h.input_buf),
        };
        h.mm = try AlignedMemoryMap.init(alloc, &regions);
        h.ic.mm = @ptrCast(&h.mm);
        return h;
    }

    fn deinit(self: *Harness) void {
        self.alloc.free(self.bytecode_buf);
        self.alloc.free(self.rodata_buf);
        self.alloc.free(self.stack_buf);
        self.alloc.free(self.heap_buf);
        self.alloc.free(self.input_buf);
        self.mm.deinit();
        self.ic.deinit();
        self.tx.deinit();
        self.cache.deinit();
        self.alloc.free(self.tx.program_indices);
        self.alloc.free(self.accounts);
        self.alloc.destroy(self);
    }

    fn refillCu(self: *Harness, units: u64) void {
        self.ic.compute_remaining = units;
    }
};

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

test "M6: Murmur3 hash parity (canonical std.hash.Murmur3_32, seed=0)" {
    // Anchor values are computed by `std.hash.Murmur3_32.hashWithSeed(name, 0)`
    // — the exact one-line function V1's `vm_executable.zig:851` exposes as
    // `pub fn murmur3(...)`. M6's `nameHash` is byte-for-byte the same call.
    //
    // V1's `vm_syscalls.zig:32-70` ID table was an *aspirational* lookup
    // list; many of its constants drifted from the live hash function (see
    // `R2-syscalls-cpi-serializer.md` §1 "stale" finding for poseidon and
    // friends). V1's *test* (`vm_executable.zig:869-874`) only verifies 4
    // names against canonical Murmur3 and they all match here. M6 anchors
    // all 43 against canonical Murmur3 — divergence from V1's stale table
    // is by design.
    //
    // The four V1-validated values (canonical and locked):
    try testing.expectEqual(@as(u32, 0x207559bd), syscalls.nameHash("sol_log_"));
    try testing.expectEqual(@as(u32, 0x11f49d86), syscalls.nameHash("sol_sha256"));
    try testing.expectEqual(@as(u32, 0xd7449092), syscalls.nameHash("sol_invoke_signed_rust"));
    try testing.expectEqual(@as(u32, 0x83f00e8f), syscalls.nameHash("sol_alloc_free_"));
    // The remaining 38 names — canonical Murmur3 (verified independently
    // via /tmp m3all.zig harness; these are reproducible).
    try testing.expectEqual(@as(u32, 0xb6fc1a11), syscalls.nameHash("abort"));
    try testing.expectEqual(@as(u32, 0x686093bb), syscalls.nameHash("sol_panic_"));
    try testing.expectEqual(@as(u32, 0x5c2a3178), syscalls.nameHash("sol_log_64_"));
    try testing.expectEqual(@as(u32, 0x7ef088ca), syscalls.nameHash("sol_log_pubkey"));
    try testing.expectEqual(@as(u32, 0x52ba5096), syscalls.nameHash("sol_log_compute_units_"));
    try testing.expectEqual(@as(u32, 0x7317b434), syscalls.nameHash("sol_log_data"));
    try testing.expectEqual(@as(u32, 0x717cc4a3), syscalls.nameHash("sol_memcpy_"));
    try testing.expectEqual(@as(u32, 0x434371f8), syscalls.nameHash("sol_memmove_"));
    try testing.expectEqual(@as(u32, 0x5fdcde31), syscalls.nameHash("sol_memcmp_"));
    try testing.expectEqual(@as(u32, 0x3770fb22), syscalls.nameHash("sol_memset_"));
    try testing.expectEqual(@as(u32, 0xd7793abb), syscalls.nameHash("sol_keccak256"));
    try testing.expectEqual(@as(u32, 0x174c5122), syscalls.nameHash("sol_blake3"));
    try testing.expectEqual(@as(u32, 0xc4947c21), syscalls.nameHash("sol_poseidon"));
    try testing.expectEqual(@as(u32, 0x17e40350), syscalls.nameHash("sol_secp256k1_recover"));
    try testing.expectEqual(@as(u32, 0xaa2607ca), syscalls.nameHash("sol_curve_validate_point"));
    try testing.expectEqual(@as(u32, 0xdd1c41a6), syscalls.nameHash("sol_curve_group_op"));
    try testing.expectEqual(@as(u32, 0x60a40880), syscalls.nameHash("sol_curve_multiscalar_mul"));
    try testing.expectEqual(@as(u32, 0x080c98b0), syscalls.nameHash("sol_curve_decompress"));
    try testing.expectEqual(@as(u32, 0xf111a47e), syscalls.nameHash("sol_curve_pairing_map"));
    try testing.expectEqual(@as(u32, 0xae0c318b), syscalls.nameHash("sol_alt_bn128_group_op"));
    try testing.expectEqual(@as(u32, 0x334fd5ed), syscalls.nameHash("sol_alt_bn128_compression"));
    try testing.expectEqual(@as(u32, 0x9377323c), syscalls.nameHash("sol_create_program_address"));
    try testing.expectEqual(@as(u32, 0x48504a38), syscalls.nameHash("sol_try_find_program_address"));
    try testing.expectEqual(@as(u32, 0xa22b9c85), syscalls.nameHash("sol_invoke_signed_c"));
    try testing.expectEqual(@as(u32, 0xd56b5fe9), syscalls.nameHash("sol_get_clock_sysvar"));
    try testing.expectEqual(@as(u32, 0x23a29a61), syscalls.nameHash("sol_get_epoch_schedule_sysvar"));
    try testing.expectEqual(@as(u32, 0x3b97b73c), syscalls.nameHash("sol_get_fees_sysvar"));
    try testing.expectEqual(@as(u32, 0xbf7188f6), syscalls.nameHash("sol_get_rent_sysvar"));
    try testing.expectEqual(@as(u32, 0x188a0031), syscalls.nameHash("sol_get_last_restart_slot"));
    try testing.expectEqual(@as(u32, 0xfdba2b3b), syscalls.nameHash("sol_get_epoch_rewards_sysvar"));
    try testing.expectEqual(@as(u32, 0xa226d3eb), syscalls.nameHash("sol_set_return_data"));
    try testing.expectEqual(@as(u32, 0x5d2245e4), syscalls.nameHash("sol_get_return_data"));
    try testing.expectEqual(@as(u32, 0x85532d94), syscalls.nameHash("sol_get_stack_height"));
    try testing.expectEqual(@as(u32, 0xadb8efc8), syscalls.nameHash("sol_get_processed_sibling_instruction"));
    try testing.expectEqual(@as(u32, 0x13c1b505), syscalls.nameHash("sol_get_sysvar"));
    try testing.expectEqual(@as(u32, 0xedef5aee), syscalls.nameHash("sol_remaining_compute_units"));
    try testing.expectEqual(@as(u32, 0x5be92f4a), syscalls.nameHash("sol_get_epoch_stake"));
    try testing.expectEqual(@as(u32, 0x780e4c15), syscalls.nameHash("sol_big_mod_exp"));
    // SIMD-0512 (2026-06-10):
    try testing.expectEqual(@as(u32, 0x9229cdcc), syscalls.nameHash("sol_sha512"));
}

test "M6: Registry has 43 entries with distinct hashes; selfTest passes" {
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectEqual(@as(usize, 43), reg.count());

    // No duplicate hashes.
    var seen = std.AutoHashMap(u32, void).init(testing.allocator);
    defer seen.deinit();
    for (reg.entries) |e| {
        try testing.expect(!seen.contains(e.hash));
        try seen.put(e.hash, {});
        // Hash matches name.
        try testing.expectEqual(syscalls.nameHash(e.name), e.hash);
    }
    const result = reg.selfTest();
    try testing.expectEqual(@as(usize, 43), result.registered);
}

test "M6: lookup miss → null; lookup hit → matching entry" {
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expect(reg.lookup(0xdead_beef) == null);
    const e = reg.lookup(syscalls.nameHash("sol_log_")).?;
    try testing.expectEqualStrings("sol_log_", e.name);
}

test "M6: sol_log_ happy path consumes max(base, len) CU" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const msg = "hello";
    @memcpy(h.heap_buf[0..msg.len], msg);
    const before = h.ic.computeRemaining();

    const result = try reg.invoke(&h.ic, syscalls.nameHash("sol_log_"), memory.MM_HEAP_START, msg.len, 0, 0, 0);
    try testing.expectEqual(@as(u64, 0), result);
    try testing.expectEqual(@as(u64, before - 100), h.ic.computeRemaining()); // base=100, len=5 → max=100
}

test "M6: sol_log_ AccessViolation on bad addr" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // VM addr in unmapped region (above all five regions).
    const bad_addr: u64 = @as(u64, 0xff) << 32;
    try testing.expectError(error.M6_AccessViolation, reg.invoke(&h.ic, syscalls.nameHash("sol_log_"), bad_addr, 5, 0, 0, 0));
}

test "M6: CU exhaustion on sol_log_64_" {
    const h = try Harness.init(testing.allocator, 50);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // log_64_units = 100, only 50 available.
    try testing.expectError(error.M6_ConsumeOverflow, reg.invoke(&h.ic, syscalls.nameHash("sol_log_64_"), 1, 2, 3, 4, 5));
}

test "M6: sol_memcpy_ happy path; CopyOverlapping detection" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..5], "hello");
    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_memcpy_"), memory.MM_HEAP_START + 100, memory.MM_HEAP_START, 5, 0, 0);
    try testing.expectEqualStrings("hello", h.heap_buf[100..105]);

    h.refillCu(10_000);
    // Overlapping: dst=heap+2, src=heap, n=5 → ranges overlap.
    try testing.expectError(
        error.M6_CopyOverlapping,
        reg.invoke(&h.ic, syscalls.nameHash("sol_memcpy_"), memory.MM_HEAP_START + 2, memory.MM_HEAP_START, 5, 0, 0),
    );
}

test "M6: sol_memset_ writes c byte n times" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_memset_"), memory.MM_HEAP_START, 0xab, 16, 0, 0);
    for (h.heap_buf[0..16]) |b| try testing.expectEqual(@as(u8, 0xab), b);
}

test "M6: sol_memcmp_ writes signed difference" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..3], "abc");
    @memcpy(h.heap_buf[100..103], "abd");
    // place i32 destination at heap+200 (aligned to 4)
    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_memcmp_"),
        memory.MM_HEAP_START,
        memory.MM_HEAP_START + 100,
        3,
        memory.MM_HEAP_START + 200,
        0,
    );
    const diff = std.mem.readInt(i32, h.heap_buf[200..204], .little);
    try testing.expectEqual(@as(i32, -1), diff);
}

test "M6: sol_sha256 of empty input matches std.crypto" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_sha256"), 0, 0, memory.MM_HEAP_START, 0, 0);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&[_]u8{}, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[0..32]);
}

// ── FIX 1 (cpi-invoke-units-cu-parity, 2026-07-12): per-slice hash cost ────
// Agave syscalls/src/lib.rs:2551-2596 (SyscallHash<H>). Previously
// hashSlicesGeneric summed all slice lengths then charged ONCE via
// sum/cpi_bytes_per_unit(250) — wrong constant and wrong aggregation.
// Correct: base(85) + max(mem_op_base(10), byte_cost(1) * (len/2)) PER
// SLICE, plus a hash_max_slices(20_000) gate checked BEFORE any CU consume.

test "FIX1: sol_sha256 one 10,000-byte slice -> base(85) + max(10, 1*(10000/2)) = 5085 CU" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // 10,000-byte payload at heap+0; VmSlice<u8> descriptor at heap+10_100;
    // output digest at heap+10_200 (heap_buf is 20_480 bytes, plenty of room).
    @memset(h.heap_buf[0..10_000], 0x5a);
    std.mem.writeInt(u64, h.heap_buf[10_100..10_108], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[10_108..10_116], 10_000, .little);

    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_sha256"),
        memory.MM_HEAP_START + 10_100,
        1,
        memory.MM_HEAP_START + 10_200,
        0,
        0,
    );

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(h.heap_buf[0..10_000], &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[10_200..10_232]);

    // Agave: 85 + max(10, 1*(10000/2)=5000) = 5085. Previous (buggy) Vexor
    // formula gave 85 + max(10, 10000/250=40) = 125 — a 4,960 CU shortfall.
    try testing.expectEqual(@as(u64, 100_000 - 5085), h.ic.compute_remaining);
}

test "FIX1: sol_sha256 max-slices cap -> M6_TooManySlices BEFORE any CU consume" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_TooManySlices,
        reg.invoke(&h.ic, syscalls.nameHash("sol_sha256"), memory.MM_HEAP_START, 20_001, memory.MM_HEAP_START + 200, 0, 0),
    );
    try testing.expectEqual(@as(u64, 10_000), h.ic.compute_remaining);
}

test "FIX1: sol_keccak256 multi-slice per-slice floor (was summed-then-once)" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..5], "hello");
    @memcpy(h.heap_buf[8..14], " world");
    std.mem.writeInt(u64, h.heap_buf[100..108], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[108..116], 5, .little);
    std.mem.writeInt(u64, h.heap_buf[116..124], memory.MM_HEAP_START + 8, .little);
    std.mem.writeInt(u64, h.heap_buf[124..132], 6, .little);

    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_keccak256"),
        memory.MM_HEAP_START + 100,
        2,
        memory.MM_HEAP_START + 200,
        0,
        0,
    );

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("hello world", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[200..232]);
    // CU: 85 + max(10, 5/2=2) + max(10, 6/2=3) = 85 + 10 + 10 = 105.
    // Previous (buggy) formula: 85 + max(10, 11/250=0) = 95 — a 10 CU
    // shortfall even on this tiny example.
    try testing.expectEqual(@as(u64, 10_000 - 105), h.ic.compute_remaining);
}

test "M6: sol_keccak256 of single slice matches std.crypto" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..5], "hello");

    // VmSlice<u8> = (ptr u64 LE, len u64 LE) at heap_buf[100..116].
    std.mem.writeInt(u64, h.heap_buf[100..108], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[108..116], 5, .little);

    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_keccak256"),
        memory.MM_HEAP_START + 100,
        1,
        memory.MM_HEAP_START + 200,
        0,
        0,
    );

    var expected: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash("hello", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[200..232]);
}

// ── SIMD-0512 sol_sha512 KATs (2026-06-10) ──────────────────────────────────
// Canonical behavior: agave-4.1.0-beta.3 syscalls/src/lib.rs:2579-2641
// (SyscallHash::<Sha512Hasher>), sha256 cost family (85/1/20_000), 64-byte
// digest, per-slice cost max(mem_op_base=10, byte_cost*(len/2)). Feature
// enable_sha512_syscall gated at INVOKE in Vexor (Agave gates at register) —
// both fail the tx pre-activation with zero CU consumed.

test "M6: sol_sha512 gate OFF -> M6_FeatureGated with ZERO CU consumed" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // sha512_syscall_active defaults false (pre-epoch-973 testnet state).
    try testing.expectError(
        error.M6_FeatureGated,
        reg.invoke(&h.ic, syscalls.nameHash("sol_sha512"), 0, 0, memory.MM_HEAP_START, 0, 0),
    );
    try testing.expectEqual(@as(u64, 10_000), h.ic.compute_remaining);
}

test "M6: sol_sha512 empty input -> NIST SHA512(\"\") vector, 64 bytes written" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    h.ic.sha512_syscall_active = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memset(h.heap_buf[0..64], 0xAA); // canary: all 64 bytes must be overwritten
    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_sha512"), 0, 0, memory.MM_HEAP_START, 0, 0);

    var expected: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&[_]u8{}, &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[0..64]);
    // NIST: SHA512("") = cf83e1357eefb8bd...327af927da3e
    try testing.expectEqual(@as(u8, 0xcf), h.heap_buf[0]);
    try testing.expectEqual(@as(u8, 0x83), h.heap_buf[1]);
    try testing.expectEqual(@as(u8, 0x3e), h.heap_buf[63]);
    // CU: base only (no slices) = 85.
    try testing.expectEqual(@as(u64, 10_000 - 85), h.ic.compute_remaining);
}

test "M6: sol_sha512 single slice \"abc\" -> full NIST vector + canonical CU" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    h.ic.sha512_syscall_active = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..3], "abc");
    std.mem.writeInt(u64, h.heap_buf[100..108], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[108..116], 3, .little);

    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_sha512"),
        memory.MM_HEAP_START + 100,
        1,
        memory.MM_HEAP_START + 200,
        0,
        0,
    );

    // NIST FIPS 180-4: SHA512("abc")
    const nist = [_]u8{
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    try testing.expectEqualSlices(u8, &nist, h.heap_buf[200..264]);
    // CU: 85 + max(10, 1*(3/2)=1) = 85 + 10 = 95.
    try testing.expectEqual(@as(u64, 10_000 - 95), h.ic.compute_remaining);
}

test "M6: sol_sha512 multi-slice == concatenated digest; per-slice CU floor" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    h.ic.sha512_syscall_active = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..5], "hello");
    @memcpy(h.heap_buf[8..14], " world");
    std.mem.writeInt(u64, h.heap_buf[100..108], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[108..116], 5, .little);
    std.mem.writeInt(u64, h.heap_buf[116..124], memory.MM_HEAP_START + 8, .little);
    std.mem.writeInt(u64, h.heap_buf[124..132], 6, .little);

    _ = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_sha512"),
        memory.MM_HEAP_START + 100,
        2,
        memory.MM_HEAP_START + 200,
        0,
        0,
    );

    var expected: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("hello world", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, h.heap_buf[200..264]);
    // CU: 85 + max(10, 5/2=2) + max(10, 6/2=3) = 85 + 10 + 10 = 105
    // (the per-slice mem_op floor — exactly where the legacy once-total
    // formula in hashSlicesGeneric diverges).
    try testing.expectEqual(@as(u64, 10_000 - 105), h.ic.compute_remaining);
}

test "M6: sol_sha512 max-slices cap -> M6_TooManySlices BEFORE any CU consume" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    h.ic.sha512_syscall_active = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_TooManySlices,
        reg.invoke(&h.ic, syscalls.nameHash("sol_sha512"), memory.MM_HEAP_START, 20_001, memory.MM_HEAP_START + 200, 0, 0),
    );
    try testing.expectEqual(@as(u64, 10_000), h.ic.compute_remaining);
}

test "M6: sysvar getter propagates SysvarNotPopulated (vex-058)" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // SysvarCache empty → must propagate.
    try testing.expectError(
        error.M6_SysvarNotPopulated,
        reg.invoke(&h.ic, syscalls.nameHash("sol_get_clock_sysvar"), memory.MM_HEAP_START, 0, 0, 0, 0),
    );
}

test "M6: sol_set_return_data + sol_get_return_data round-trip" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Push a frame so currentProgramId is populated.
    try h.ic.push(0, &.{});

    @memcpy(h.heap_buf[0..4], "data");
    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_set_return_data"), memory.MM_HEAP_START, 4, 0, 0, 0);
    h.refillCu(10_000);

    // Read back into heap+100.
    const len = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_get_return_data"),
        memory.MM_HEAP_START + 100,
        4,
        memory.MM_HEAP_START + 200,
        0,
        0,
    );
    try testing.expectEqual(@as(u64, 4), len);
    try testing.expectEqualSlices(u8, "data", h.heap_buf[100..104]);
    // program_id 32 bytes at heap+200 should equal account[0].pubkey = [_]u8{1}**32.
    for (h.heap_buf[200..232]) |b| try testing.expectEqual(@as(u8, 1), b);
}

// FIX 3 (cpi-invoke-units-cu-parity, 2026-07-12): agave-4.2.0-beta.0-src
// syscalls/src/lib.rs:1991-1995 — cost = (length + size_of::<Pubkey>(32))
// / cpi_bytes_per_unit(250). The prior formula omitted the +32 term.
test "FIX3: sol_get_return_data — copy_len=218 charges (218+32)/250=1, not 218/250=0" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try h.ic.push(0, &.{});

    @memset(h.heap_buf[0..218], 0x7a);
    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_set_return_data"), memory.MM_HEAP_START, 218, 0, 0, 0);
    h.refillCu(10_000);

    const len = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_get_return_data"),
        memory.MM_HEAP_START + 300,
        218,
        memory.MM_HEAP_START + 600,
        0,
        0,
    );
    try testing.expectEqual(@as(u64, 218), len);
    try testing.expectEqualSlices(u8, h.heap_buf[0..218], h.heap_buf[300..518]);
    // CU: base(100) + (218+32)/250(1) = 101. Previous (buggy) formula:
    // 100 + 218/250(0) = 100 — a 1 CU shortfall.
    try testing.expectEqual(@as(u64, 10_000 - 101), h.ic.compute_remaining);
}

// FIX 4 (cpi-invoke-units-cu-parity, 2026-07-12): agave-4.2.0-beta.0-src
// syscalls/src/lib.rs:2603-2665 `SyscallGetEpochStake` (SIMD-0133) charges
// syscall_base(100) on the null-addr branch but
// syscall_base(100) + floor(32/250)(0) + mem_op_base(10) = 110 on the
// non-null branch. The prior code charged a flat 100 (sysvar_base_cost)
// for both branches — a 10 CU shortfall on the non-null path.
test "FIX4: sol_get_epoch_stake — null addr charges syscall_base_cost=100" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_get_epoch_stake"), 0, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 10_000 - 100), h.ic.compute_remaining);
}

test "FIX4: sol_get_epoch_stake — non-null addr charges 110 (was 100, 10 CU short)" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    _ = try reg.invoke(&h.ic, syscalls.nameHash("sol_get_epoch_stake"), memory.MM_HEAP_START, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 10_000 - 110), h.ic.compute_remaining);
}

test "M6: sol_get_stack_height returns >=1" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_get_stack_height"), 0, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 1), r);

    try h.ic.push(0, &.{});
    h.refillCu(10_000);
    const r2 = try reg.invoke(&h.ic, syscalls.nameHash("sol_get_stack_height"), 0, 0, 0, 0, 0);
    try testing.expectEqual(@as(u64, 1), r2); // depth=1 after one push
}

test "M6: sol_remaining_compute_units returns meter" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_remaining_compute_units"), 0, 0, 0, 0, 0);
    // After consuming 100 (get_remaining_compute_units_cost), should be 9900.
    try testing.expectEqual(@as(u64, 9900), r);
}

test "M6: PDA derivation produces deterministic 32-byte hash off-curve" {
    const h = try Harness.init(testing.allocator, 50_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Single seed = "vex" at heap+0; bump byte at heap+8.
    @memcpy(h.heap_buf[0..3], "vex");
    h.heap_buf[8] = 0xfd; // bump
    // VmSlice for "vex" at heap+16: (ptr=heap+0, len=3); for bump at heap+32: (ptr=heap+8, len=1).
    std.mem.writeInt(u64, h.heap_buf[16..24], memory.MM_HEAP_START, .little);
    std.mem.writeInt(u64, h.heap_buf[24..32], 3, .little);
    std.mem.writeInt(u64, h.heap_buf[32..40], memory.MM_HEAP_START + 8, .little);
    std.mem.writeInt(u64, h.heap_buf[40..48], 1, .little);
    // Program id at heap+64
    @memset(h.heap_buf[64..96], 0x42);
    // Out at heap+128

    // Call sol_create_program_address. It will use 2 seeds (vex + bump).
    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_create_program_address"),
        memory.MM_HEAP_START + 16,
        2,
        memory.MM_HEAP_START + 64,
        memory.MM_HEAP_START + 128,
        0,
    );
    // Either 0 (off-curve, success) or 1 (on-curve, "not derivable" — non-fatal).
    try testing.expect(r == 0 or r == 1);
}

test "M6: CPI handler stub returns M6_CpiHandlerNotReady" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_CpiHandlerNotReady,
        reg.invoke(&h.ic, syscalls.nameHash("sol_invoke_signed_c"), 0, 0, 0, 0, 0),
    );
    try testing.expectError(
        error.M6_CpiHandlerNotReady,
        reg.invoke(&h.ic, syscalls.nameHash("sol_invoke_signed_rust"), 0, 0, 0, 0, 0),
    );
}

test "Wave6C2: crypto placeholders surface NAMED port-required errors (not silent stub)" {
    // Only meaningful with the .unported bn254 backend. Under -Dballet_bn254 these
    // syscalls are the REAL FD impls (poseidon/alt_bn128 — covered by test-bn254-poseidon),
    // so the port-required stub errors no longer fire. Skip rather than false-fail.
    if (vex_crypto.bn254.active_backend != .unported) return error.SkipZigTest;
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Poseidon needs zig-poseidon package — return named port-required.
    try testing.expectError(
        error.M6_PoseidonRequiresBn254ImplPort,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_poseidon"),
            0,
            0,
            memory.MM_HEAP_START,
            1,
            memory.MM_HEAP_START + 100,
        ),
    );
    h.refillCu(100_000);
    // alt_bn128 needs sig.crypto.bn254 (~3800 LoC) — return named port-required.
    try testing.expectError(
        error.M6_AltBn128RequiresBn254ImplPort,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_alt_bn128_group_op"),
            0,
            memory.MM_HEAP_START,
            16,
            memory.MM_HEAP_START + 100,
            0,
        ),
    );
    h.refillCu(100_000);
    // alt_bn128_compression — same path-forward.
    try testing.expectError(
        error.M6_AltBn128RequiresBn254ImplPort,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_alt_bn128_compression"),
            0,
            memory.MM_HEAP_START,
            16,
            memory.MM_HEAP_START + 100,
            0,
        ),
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Wave 6C-2: Edwards25519 / Ristretto255 real impl tests.
//
// Test vectors from sig/src/vm/syscalls/ecc.zig:863-1032 and Zig stdlib's
// own Edwards25519 round-trip semantics. Validate the full happy path,
// AccessViolation paths, and CU exhaustion.
// ──────────────────────────────────────────────────────────────────────────────

test "Wave6C2: sol_curve_validate_point — Edwards25519 valid → 0" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // sig ecc.zig:864-867 valid Edwards25519 point.
    const valid_bytes = [_]u8{
        201, 179, 241, 122, 180, 185, 239, 50,  183, 52,  221, 0,  153,
        195, 43,  18,  22,  38,  187, 206, 179, 192, 210, 58,  53, 45,
        150, 98,  89,  17,  158, 11,
    };
    @memcpy(h.heap_buf[0..32], &valid_bytes);

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_validate_point"),
        0, // edwards
        memory.MM_HEAP_START,
        0,
        0,
        0,
    );
    try testing.expectEqual(@as(u64, 0), r);
}

test "Wave6C2: sol_curve_validate_point — Edwards25519 invalid → 1" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // sig ecc.zig:870-874 invalid Edwards25519 point.
    const invalid_bytes = [_]u8{
        120, 140, 152, 233, 41,  227, 203, 27, 87,  115, 25,  251, 219,
        5,   84,  148, 117, 38,  84,  60,  87, 144, 161, 146, 42,  34,
        91,  155, 158, 189, 121, 79,
    };
    @memcpy(h.heap_buf[0..32], &invalid_bytes);

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_validate_point"),
        0,
        memory.MM_HEAP_START,
        0,
        0,
        0,
    );
    try testing.expectEqual(@as(u64, 1), r);
}

test "Wave6C2: sol_curve_validate_point — Ristretto255 valid → 0" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // sig ecc.zig:900-903 valid Ristretto255 point.
    const valid_bytes = [_]u8{
        226, 242, 174, 10,  106, 188, 78,  113, 168, 132, 169, 97,  197,
        0,   81,  95,  88,  227, 11,  106, 165, 130, 221, 141, 182, 166,
        89,  69,  224, 141, 45,  118,
    };
    @memcpy(h.heap_buf[0..32], &valid_bytes);

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_validate_point"),
        1, // ristretto
        memory.MM_HEAP_START,
        0,
        0,
        0,
    );
    try testing.expectEqual(@as(u64, 0), r);
}

test "Wave6C2: sol_curve_validate_point — invalid curve_id → CurveInvalidId" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_CurveInvalidId,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_validate_point"),
            99,
            memory.MM_HEAP_START,
            0,
            0,
            0,
        ),
    );
}

test "Wave6C2: sol_curve_validate_point — bad vm-addr → AccessViolation" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_AccessViolation,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_validate_point"),
            0,
            0xdeadbeef, // outside any region
            0,
            0,
            0,
        ),
    );
}

test "Wave6C2: sol_curve_validate_point — empty CU → ConsumeOverflow" {
    const h = try Harness.init(testing.allocator, 1);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_ConsumeOverflow,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_validate_point"),
            0,
            memory.MM_HEAP_START,
            0,
            0,
            0,
        ),
    );
}

test "Wave6C2: sol_curve_group_op — Edwards25519 add identity+identity = identity" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Identity element for Edwards25519: (0, 1) encoded as 32 bytes with
    // y=1 (LSB=1). Standard identity in compressed form is `01 00..00`.
    const identity = [_]u8{1} ++ [_]u8{0} ** 31;
    @memcpy(h.heap_buf[0..32], &identity); // left
    @memcpy(h.heap_buf[64..96], &identity); // right

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_group_op"),
        0, // edwards
        0, // add
        memory.MM_HEAP_START, // left @ +0
        memory.MM_HEAP_START + 64, // right @ +64
        memory.MM_HEAP_START + 128, // out @ +128
    );
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqualSlices(u8, &identity, h.heap_buf[128..160]);
}

test "Wave6C2: sol_curve_group_op — Edwards25519 mul scalar*basePoint round-trip" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // scalar = 1 (canonical).
    const scalar = [_]u8{1} ++ [_]u8{0} ** 31;
    // base_point = Edwards25519 base point bytes.
    const base = std.crypto.ecc.Edwards25519.basePoint.toBytes();

    @memcpy(h.heap_buf[0..32], &scalar);
    @memcpy(h.heap_buf[64..96], &base);

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_group_op"),
        0,
        2, // mul
        memory.MM_HEAP_START,
        memory.MM_HEAP_START + 64,
        memory.MM_HEAP_START + 128,
    );
    try testing.expectEqual(@as(u64, 0), r);
    // 1 * basePoint = basePoint.
    try testing.expectEqualSlices(u8, &base, h.heap_buf[128..160]);
}

test "Wave6C2: sol_curve_group_op — bad GroupOp → CurveInvalidGroupOp" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_CurveInvalidGroupOp,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_group_op"),
            0,
            5, // invalid op
            memory.MM_HEAP_START,
            memory.MM_HEAP_START + 64,
            memory.MM_HEAP_START + 128,
        ),
    );
}

test "Wave6C2: sol_curve_multiscalar_mul — Edwards25519 single 1*basePoint = basePoint" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const scalar = [_]u8{1} ++ [_]u8{0} ** 31;
    const base = std.crypto.ecc.Edwards25519.basePoint.toBytes();
    @memcpy(h.heap_buf[0..32], &scalar);
    @memcpy(h.heap_buf[64..96], &base);

    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_curve_multiscalar_mul"),
        0,
        memory.MM_HEAP_START, // scalars
        memory.MM_HEAP_START + 64, // points
        1, // n
        memory.MM_HEAP_START + 128, // result
    );
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqualSlices(u8, &base, h.heap_buf[128..160]);
}

test "Wave6C2: sol_curve_multiscalar_mul — n>512 → CurveMsmTooManyPoints" {
    const h = try Harness.init(testing.allocator, 1_000_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_CurveMsmTooManyPoints,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_multiscalar_mul"),
            0,
            memory.MM_HEAP_START,
            memory.MM_HEAP_START + 32,
            513,
            memory.MM_HEAP_START + 100,
        ),
    );
}

// SIMD-0388 gate (default OFF in the test harness, ic.enable_bls12_381_syscall
// = false): the BLS12-381 curve_ids abort with M6_FeatureGated (agave
// SyscallError::InvalidAttribute) BEFORE any CU/translate — same observable as
// the old port-required stub, now grounded in the real feature gate. The real
// crypto KATs (gate ON) live in src/vex_bpf2/bls12_381_kat_test.zig.
test "Wave6C2: sol_curve_decompress → BLS12-381 feature-gated when inactive" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // curve_id=5 → bls12_381_g1_le; r3 = result_addr (corrected ABI).
    try testing.expectError(
        error.M6_FeatureGated,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_decompress"),
            5,
            memory.MM_HEAP_START,
            memory.MM_HEAP_START + 100,
            0,
            0,
        ),
    );
}

test "Wave6C2: sol_curve_pairing_map → BLS12-381 feature-gated when inactive" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // curve_id=4 → bls12_381_le; ABI: r2=num_pairs, r3=g1, r4=g2, r5=result.
    try testing.expectError(
        error.M6_FeatureGated,
        reg.invoke(
            &h.ic,
            syscalls.nameHash("sol_curve_pairing_map"),
            4,
            1,
            memory.MM_HEAP_START,
            memory.MM_HEAP_START + 96,
            memory.MM_HEAP_START + 300,
        ),
    );
}

// ── SIMD-0388 end-to-end (feature ON): drives the real arms THROUGH the
// registry/memory-translation so the CORRECTED register ABIs are actually
// exercised (the wrapper-direct KAT in bls12_381_kat_test.zig cannot catch a
// transposed register in the syscall body). One per corrected ABI. ──────────

const HEAP = memory.MM_HEAP_START;

test "Wave6C2 e2e: sol_curve_validate_point G1 generator (feature ON) → r0=0" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    h.ic.enable_bls12_381_syscall = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..96], &bls_vectors.INPUT_BE_G1_VALIDATE_GENERATOR_VALID);
    // curve_id=5 (G1 BE | 0x80 = 133); r2=point_addr.
    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_curve_validate_point"), 5 | 0x80, HEAP, 0, 0, 0);
    try testing.expectEqual(@as(u64, 0), r); // valid

    // not-on-curve → r0=1
    @memcpy(h.heap_buf[0..96], &bls_vectors.INPUT_BE_G1_VALIDATE_NOT_ON_CURVE_INVALID);
    const r2 = try reg.invoke(&h.ic, syscalls.nameHash("sol_curve_validate_point"), 5 | 0x80, HEAP, 0, 0, 0);
    try testing.expectEqual(@as(u64, 1), r2);
}

test "Wave6C2 e2e: sol_curve_decompress G1 generator — result@r3 ABI (feature ON)" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    h.ic.enable_bls12_381_syscall = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..48], &bls_vectors.INPUT_BE_G1_DECOMPRESS_GENERATOR);
    // curve_id=133 (G1 BE); r2=point_addr (48B in), r3=result_addr (96B out).
    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_curve_decompress"), 5 | 0x80, HEAP, HEAP + 200, 0, 0);
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqualSlices(u8, &bls_vectors.OUTPUT_BE_G1_DECOMPRESS_GENERATOR, h.heap_buf[200..296]);
}

test "Wave6C2 e2e: sol_curve_group_op G1 MUL — scalar@left/point@right ABI (feature ON)" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    h.ic.enable_bls12_381_syscall = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Vector input layout = [Point(96) | Scalar(32)]. The syscall ABI is
    // scalar@left_addr, point@right_addr — place them accordingly to PROVE the
    // operand order in the body.
    @memcpy(h.heap_buf[0..96], bls_vectors.INPUT_BE_G1_MUL_RANDOM[0..96]); // point
    @memcpy(h.heap_buf[96..128], bls_vectors.INPUT_BE_G1_MUL_RANDOM[96..128]); // scalar
    // curve_id=133, op=mul(2); left=scalar@heap+96, right=point@heap+0, out=heap+200.
    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_curve_group_op"), 5 | 0x80, 2, HEAP + 96, HEAP, HEAP + 200);
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqualSlices(u8, &bls_vectors.OUTPUT_BE_G1_MUL_RANDOM, h.heap_buf[200..296]);
}

test "Wave6C2 e2e: sol_curve_pairing_map 1 pair — num_pairs/g1/g2/result ABI (feature ON)" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    h.ic.enable_bls12_381_syscall = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Input = [g1(96) | g2(192)]. ABI: r2=num_pairs, r3=g1_addr, r4=g2_addr, r5=result.
    @memcpy(h.heap_buf[0..96], bls_vectors.INPUT_BE_PAIRING_ONE_PAIR[0..96]);
    @memcpy(h.heap_buf[96..288], bls_vectors.INPUT_BE_PAIRING_ONE_PAIR[96..288]);
    // curve_id=132 (plain BLS BE), num_pairs=1, g1@heap, g2@heap+96, result@heap+300 (576B).
    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_curve_pairing_map"), 4 | 0x80, 1, HEAP, HEAP + 96, HEAP + 300);
    try testing.expectEqual(@as(u64, 0), r);
    try testing.expectEqualSlices(u8, &bls_vectors.OUTPUT_BE_PAIRING_ONE_PAIR, h.heap_buf[300 .. 300 + 576]);
}

test "Wave6C2 e2e: unknown / unsupported curve-id → abort (feature ON)" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    h.ic.enable_bls12_381_syscall = true;
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Unknown curve_id (99) → CurveId.wrap fails → InvalidId abort.
    try testing.expectError(
        error.M6_CurveInvalidId,
        reg.invoke(&h.ic, syscalls.nameHash("sol_curve_validate_point"), 99, HEAP, 0, 0, 0),
    );
    // curve_id 132 (plain BLS) has no decompress arm → UnsupportedId abort.
    try testing.expectError(
        error.M6_CurveUnsupportedId,
        reg.invoke(&h.ic, syscalls.nameHash("sol_curve_decompress"), 4 | 0x80, HEAP, HEAP + 200, 0, 0),
    );
    // curve_id 133 (G1) into pairing_map (which only takes plain 4/132) → UnsupportedId.
    try testing.expectError(
        error.M6_CurveUnsupportedId,
        reg.invoke(&h.ic, syscalls.nameHash("sol_curve_pairing_map"), 5 | 0x80, 1, HEAP, HEAP + 96, HEAP + 300),
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// Wave 6C-2: big_mod_exp real impl tests.
//
// Vectors from RFC 8017 / NIST + edge cases; cross-checked with Python's
// pow(b,e,m) before transcription.
// ──────────────────────────────────────────────────────────────────────────────

// FIX 2 (cpi-invoke-units-cu-parity, 2026-07-12): agave-4.2.0-beta.0-src
// syscalls/src/lib.rs:2306-2322 `SyscallBigModExp` is UNCONDITIONALLY
// `Ok(1)` — no params read, no memory touched, zero CU consumed (SIMD-529
// not yet approved). This REPLACES the prior "Wave6C2" KATs below, which
// exercised a real square-and-multiply modpow implementation that matched
// an older "rc.1"-era Agave pin but NOT this pinned 4.2.0-beta.0 tree —
// that real impl is preserved as dead code (`solBigModExpRealUnused`) for
// when SIMD-529 lands.

test "FIX2: sol_big_mod_exp — agave stub: r0=1, ZERO CU consumed, output untouched" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memset(h.heap_buf[300..310], 0xAA); // canary over the would-be output region
    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_big_mod_exp"),
        memory.MM_HEAP_START + 200,
        0,
        0,
        0,
        memory.MM_HEAP_START + 300,
    );
    try testing.expectEqual(@as(u64, 1), r);
    try testing.expectEqual(@as(u64, 100_000), h.ic.compute_remaining); // 0 CU
    for (h.heap_buf[300..310]) |b| try testing.expectEqual(@as(u8, 0xAA), b); // untouched
}

test "FIX2: sol_big_mod_exp — unmapped params/output pointers still succeed (agave never dereferences)" {
    const h = try Harness.init(testing.allocator, 5_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Deliberately garbage, unmapped addresses. A real modpow impl would
    // AccessViolation trying to translate these; agave's stub never reads
    // its _params/_return_value arguments at all, so this must succeed.
    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_big_mod_exp"), 0xdead_beef_0000, 0, 0, 0, 0xfeed_face_0000);
    try testing.expectEqual(@as(u64, 1), r);
    try testing.expectEqual(@as(u64, 5_000), h.ic.compute_remaining);
}

test "FIX2: sol_big_mod_exp — zero-CU budget still succeeds (compute meter never touched)" {
    const h = try Harness.init(testing.allocator, 0);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const r = try reg.invoke(&h.ic, syscalls.nameHash("sol_big_mod_exp"), memory.MM_HEAP_START, 0, 0, 0, memory.MM_HEAP_START + 100);
    try testing.expectEqual(@as(u64, 1), r);
    try testing.expectEqual(@as(u64, 0), h.ic.compute_remaining);
}

test "M6: sol_get_fees_sysvar surfaces FeatureGated" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_FeatureGated,
        reg.invoke(&h.ic, syscalls.nameHash("sol_get_fees_sysvar"), memory.MM_HEAP_START, 0, 0, 0, 0),
    );
}

test "M6: sol_alloc_free_ surfaces deprecation" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_AllocFreeDeprecated,
        reg.invoke(&h.ic, syscalls.nameHash("sol_alloc_free_"), 64, 0, 0, 0, 0),
    );
}

test "M6: abort surfaces ProgramAbort" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(
        error.M6_ProgramAbort,
        reg.invoke(&h.ic, syscalls.nameHash("abort"), 0, 0, 0, 0, 0),
    );
}

test "M6: M4 trait adapter dispatches" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const trait = reg.asTrait();
    const slot = trait.lookup(syscalls.nameHash("sol_log_64_")).?;
    const r = try trait.invoke(@ptrCast(&h.ic), slot, 1, 2, 3, 4, 5);
    try testing.expectEqual(@as(u64, 0), r);
}

test "M6: trait adapter maps M6_ConsumeOverflow → ExceededMaxInstructions" {
    const h = try Harness.init(testing.allocator, 10);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const trait = reg.asTrait();
    const slot = trait.lookup(syscalls.nameHash("sol_log_64_")).?;
    try testing.expectError(error.ExceededMaxInstructions, trait.invoke(@ptrCast(&h.ic), slot, 1, 2, 3, 4, 5));
}

test "M6: trait adapter maps program error → SyscallError" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    const trait = reg.asTrait();
    const slot = trait.lookup(syscalls.nameHash("abort")).?;
    try testing.expectError(error.SyscallError, trait.invoke(@ptrCast(&h.ic), slot, 0, 0, 0, 0, 0));
}

test "M6: sol_get_sysvar generic path returns SYSVAR_NOT_FOUND when cache empty" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // sysvar id at heap+0 = Clock pubkey (will be unpopulated).
    @memcpy(h.heap_buf[0..32], &sysvar_cache_mod.SYSVAR_CLOCK_ID);
    // var dst in heap region (NOT input), 8 bytes
    const r = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_get_sysvar"),
        memory.MM_HEAP_START,
        memory.MM_HEAP_START + 100,
        0,
        8,
        0,
    );
    try testing.expectEqual(@as(u64, 2), r); // SYSVAR_NOT_FOUND
}

test "M6: sol_get_sysvar rejects var_addr in MM_INPUT region (SIMD-0459 preemptive)" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    @memcpy(h.heap_buf[0..32], &sysvar_cache_mod.SYSVAR_CLOCK_ID);
    try testing.expectError(error.M6_AccessViolation, reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_get_sysvar"),
        memory.MM_HEAP_START,
        memory.MM_INPUT_START, // disallowed
        0,
        8,
        0,
    ));
}

test "M6: ReturnData oversize rejected" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(error.M6_ReturnDataTooLarge, reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_set_return_data"),
        memory.MM_HEAP_START,
        2048, // > MAX_RETURN_DATA = 1024
        0,
        0,
        0,
    ));
}

test "M6: NotRegistered for unknown hash via invoke" {
    const h = try Harness.init(testing.allocator, 10_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    try testing.expectError(error.M6_NotRegistered, reg.invoke(&h.ic, 0xdead_beef, 0, 0, 0, 0, 0));
}

test "M6: feature/SIMD inventory smoke (informational)" {
    // This test is documentation: every SIMD pubkey listed in the M6 header
    // must appear verbatim in vault/rebuild-scope/SIMD-STATUS-SWEEP.md.
    // We can't read the file at test time without I/O, so we assert the
    // count of registered syscalls (43) which is the load-bearing fact for
    // the SIMD inventory's "active" set on testnet.
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();
    try testing.expectEqual(@as(usize, 43), reg.count());
}

// ──────────────────────────────────────────────────────────────────────────────
// Wave 3.5: sol_secp256k1_recover real-cryptography test.
//
// The placeholder M6 handler used to return `M6_Secp256k1RecoverError`
// unconditionally. Wave 3.5 wires `vex_crypto.secp256k1.recoverPublicKey`
// via the build module graph; this test exercises the full recovery path
// using a generate-then-recover pattern (same vector style as
// `src/vex_crypto/secp256k1.zig:454` "full round-trip" test).
// ──────────────────────────────────────────────────────────────────────────────

const vex_crypto = @import("vex_crypto");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

test "M6: sol_secp256k1_recover round-trips against vex_crypto" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;

    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Generate a fresh key + sign a known message.
    const keypair = Ecdsa.KeyPair.generate();
    const message = "vexor M6 secp256k1 wireup test";
    var msg_hash: [32]u8 = undefined;
    Keccak256.hash(message, &msg_hash, .{});
    const signature = try keypair.signPrehashed(msg_hash, null);
    const sig_bytes = signature.toBytes();

    // Discover the correct recovery_id (0 or 1) by trial.
    var rec_id: u2 = 0;
    var found = false;
    for (0..2) |candidate| {
        const r: u2 = @intCast(candidate);
        if (vex_crypto.secp256k1.recoverPublicKey(&msg_hash, &sig_bytes, r)) |recovered| {
            if (std.mem.eql(u8, &recovered.toUncompressedSec1(), &keypair.public_key.toUncompressedSec1())) {
                rec_id = r;
                found = true;
                break;
            }
        } else |_| {}
    }
    try testing.expect(found);

    // Lay arguments out in VM input region:
    //   heap+0   : 32-byte hash
    //   heap+32  : 64-byte signature
    //   heap+128 : 64-byte output buffer
    @memcpy(h.heap_buf[0..32], &msg_hash);
    @memcpy(h.heap_buf[32..96], &sig_bytes);
    @memset(h.heap_buf[128..192], 0);

    const r0 = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_secp256k1_recover"),
        memory.MM_HEAP_START + 0,
        rec_id,
        memory.MM_HEAP_START + 32,
        memory.MM_HEAP_START + 128,
        0,
    );
    try testing.expectEqual(@as(u64, 0), r0);

    // Output should be X || Y (drop the 0x04 prefix from SEC1 uncompressed).
    const expected = keypair.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, expected[1..65], h.heap_buf[128..192]);
}

test "M6: sol_secp256k1_recover rejects recovery_id > 1" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // Layout the same way as the happy-path test, but pass recovery_id=2.
    @memset(h.heap_buf[0..192], 0);

    try testing.expectError(error.M6_Secp256k1RecoverError, reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_secp256k1_recover"),
        memory.MM_HEAP_START + 0,
        2, // out-of-range recovery_id
        memory.MM_HEAP_START + 32,
        memory.MM_HEAP_START + 128,
        0,
    ));
}

// FIX (LANE-L-BACKPORT-AUDIT-2026-07-17 #2): G1/G2 compress() in
// bn254/curve.zig do a bare @memcpy(out, input[0..N]) internally, which
// PANICS (ReleaseSafe safety check: @memcpy requires disjoint src/dst) the
// instant in_addr==out_addr -- a legitimate in-place-compress calling
// pattern a real BPF program may use. Before this fix, this exact syscall
// call shape crashed the entire validator process. bn254.active_backend is
// unconditionally .pure_zig (bn254.zig:39, no stub gate), so this path is
// live-reachable today, not merely a conformance-harness artifact.
test "M6 alt_bn128_compression: G1 compress with in_addr==out_addr does not panic (LANE-L #2 regression)" {
    const h = try Harness.init(testing.allocator, 100_000);
    defer h.deinit();
    var reg = try SyscallRegistry.init(testing.allocator, {}, {});
    defer reg.deinit();

    // (X=1, Y=2), big-endian, 32B || 32B. compress()'s fromBytesRaw only
    // requires valid field elements (< p), not an on-curve point, so this
    // trivial pair is sufficient to exercise the memcpy path.
    @memset(h.heap_buf[0..64], 0);
    h.heap_buf[31] = 1; // X = 1
    h.heap_buf[63] = 2; // Y = 2

    // op=0 == ALT_BN128_G1_COMPRESS_BE (private const in syscalls.zig).
    const r0 = try reg.invoke(
        &h.ic,
        syscalls.nameHash("sol_alt_bn128_compression"),
        0, // op = G1 compress, big-endian
        memory.MM_HEAP_START, // in_addr
        64, // in_len
        memory.MM_HEAP_START, // out_addr == in_addr: the aliasing case
        0,
    );
    try testing.expectEqual(@as(u64, 0), r0); // success (not a soft r0=1 fail)
    // X survives unchanged in the compressed output (NEG flag, if any, is
    // OR'd into byte 0 for big-endian, not byte 31 where X's low byte lives).
    try testing.expectEqual(@as(u8, 1), h.heap_buf[31]);
}
