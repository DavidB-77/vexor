//! SIMD-accelerated GF(2^8) multiply-accumulate for Reed-Solomon FEC.
//!
//! Three tiers of hardware acceleration for the RS recovery hot loop:
//!   Tier 1: GFNI + AVX-512F — 64 bytes/instruction (AMD Zen 4, Intel Icelake+)
//!   Tier 2: AVX2 vpshufb    — 32 bytes/instruction (Intel Haswell+, AMD Zen+)
//!   Tier 3: Scalar log/exp  —  1 byte/instruction  (Universal fallback)
//!
//! Usage:
//!   const simd = GfSimd.init();
//!   // dst[i] ^= gfMul(coeff, src[i])  for all i
//!   simd.mulAccum(dst, src, coeff);
//!
//! Build with `-Dcpu=znver4` (or `-Dcpu=native` on Zen 4) to activate GFNI.
//! Build with `-Dcpu=x86_64_v3` for AVX2. Generic builds use scalar fallback.

const std = @import("std");
const builtin = @import("builtin");

// ═══════════════════════════════════════════════════════════════════════════
// Compile-Time Feature Detection
// ═══════════════════════════════════════════════════════════════════════════

const is_x86_64 = builtin.cpu.arch == .x86_64;

pub const has_gfni_avx512: bool = is_x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .gfni) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);

pub const has_avx2: bool = is_x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

// PERF #2 (2026-06-15, LANDED): Tier-1 GFNI is now a real hardware multiply — mulAccumGfni uses
// VEX.256 VGF2P8AFFINEQB (32 B/instr) with the row-functional matrix from buildGfniMatrix, proven
// byte-identical to scalar over all 256 coeffs × all tail alignments by the exhaustive test-gf-simd
// KAT. (Two bugs fixed along the way: the EVEX "v"/zmm asm constraint is rejected by Zig 0.15.2 → use
// "x"/ymm VEX.256; and buildGfniMatrix had the COLUMN layout — a transpose of what the instruction's
// output.bit[i]=parity(M.byte[7-i] & x) semantics need — now the row-functional layout.)
// The AVX2 vpshufb kernel (mulAccumAvx2) was documented-broken (lane-collapse) and never routed
// anywhere; REMOVED at the vexor-rebuild migration (2026-07-06, CLEAN per manifest §1.13) — see the
// deletion note above mulAccumGfni. avx2-only builds fall back to scalar.

/// Active tier (resolved at comptime — dead code is eliminated)
pub const active_tier: GfTier = if (has_gfni_avx512)
    .gfni_avx512
else if (has_avx2)
    .avx2
else
    .scalar;

pub const GfTier = enum {
    gfni_avx512, // 64 bytes/cycle
    avx2, // 32 bytes/cycle
    scalar, // 1 byte/cycle

    pub fn name(self: GfTier) []const u8 {
        return switch (self) {
            .gfni_avx512 => "GFNI VEX.256 affine (32B/instr)",
            .avx2 => "AVX2 vpshufb (32B/cycle)",
            .scalar => "Scalar log/exp (1B/cycle)",
        };
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// GF(2^8) Primitives (used for table construction — NOT in hot path)
// ═══════════════════════════════════════════════════════════════════════════

/// GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1
const POLY: u16 = 0x11D;

/// Scalar GF(2^8) multiply using peasant multiplication.
/// Only used during table/matrix construction at init time.
pub fn gfMulScalar(a: u8, b: u8) u8 {
    var r: u8 = 0;
    var aa: u16 = a;
    var bb: u8 = b;
    inline for (0..8) |_| {
        if (bb & 1 != 0) r ^= @truncate(aa);
        bb >>= 1;
        aa <<= 1;
        if (aa & 0x100 != 0) aa ^= POLY;
    }
    return r;
}

// ═══════════════════════════════════════════════════════════════════════════
// The GfSimd Engine
// ═══════════════════════════════════════════════════════════════════════════

pub const GfSimd = struct {
    /// Log/exp tables for scalar fallback path
    log_table: [256]u8,
    exp_table: [512]u8,

    /// Pre-computed GFNI matrices: gfni_matrices[c] = 8x8 bit matrix for mul-by-c
    /// Only populated when tier == .gfni_avx512
    gfni_matrices: [256]u64,

    tier: GfTier,

    pub fn init() GfSimd {
        var self: GfSimd = undefined;
        self.tier = active_tier;

        // Always build log/exp tables (needed for scalar path and table construction)
        var x: u16 = 1;
        for (0..255) |i| {
            self.exp_table[i] = @truncate(x);
            self.exp_table[i + 255] = @truncate(x);
            x <<= 1;
            if (x & 0x100 != 0) x ^= POLY;
        }
        self.exp_table[510] = self.exp_table[0];
        self.exp_table[511] = self.exp_table[1];
        self.log_table[0] = 0;
        for (0..255) |i| {
            self.log_table[self.exp_table[i]] = @truncate(i);
        }

        // Build tier-specific lookup structures
        if (comptime has_gfni_avx512) {
            for (0..256) |c| {
                self.gfni_matrices[c] = buildGfniMatrix(@truncate(c));
            }
        }

        std.log.info("[FEC-SIMD] GF(2^8) engine initialized: {s}", .{self.tier.name()});
        return self;
    }

    /// Scalar GF multiply using log/exp tables
    pub inline fn mul(self: *const GfSimd, a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return self.exp_table[@as(u16, self.log_table[a]) + @as(u16, self.log_table[b])];
    }

    // ═══════════════════════════════════════════════════════════════════
    // The Core Operation: Multiply-Accumulate
    //   dst[i] ^= gfMul(coeff, src[i])   for all i in 0..len
    //
    // This is the innermost loop of RS recovery. Each recovered byte is
    // the XOR-sum of (decode_matrix_coeff * available_shard_byte) across
    // all n available shards. Vectorizing this loop gives us 32-64x speedup.
    // ═══════════════════════════════════════════════════════════════════

    pub fn mulAccum(self: *const GfSimd, dst: []u8, src: []const u8, coeff: u8) void {
        std.debug.assert(dst.len == src.len);
        if (coeff == 0) return;
        if (coeff == 1) {
            // Multiply by 1 = identity → just XOR
            for (dst, src) |*d, s| d.* ^= s;
            return;
        }

        // GFNI = real hardware multiply (perf#2 landed). The AVX2 vpshufb kernel (Tier 2) was a
        // lane-collapse-broken dead branch never routed here — removed at the vexor-rebuild
        // migration (2026-07-06, CLEAN per manifest §1.13); avx2-only CPUs use the scalar path.
        if (comptime has_gfni_avx512) {
            self.mulAccumGfni(dst, src, coeff);
        } else {
            self.mulAccumScalar(dst, src, coeff);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Tier 3: Scalar Fallback (1 byte/cycle)
    // ═══════════════════════════════════════════════════════════════════

    fn mulAccumScalar(self: *const GfSimd, dst: []u8, src: []const u8, coeff: u8) void {
        const log_c = self.log_table[coeff];
        for (dst, src) |*d, s| {
            if (s != 0) {
                d.* ^= self.exp_table[@as(u16, self.log_table[s]) + @as(u16, log_c)];
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Tier 2 (AVX2 vpshufb split-table, 32 bytes/cycle) REMOVED at the
    // vexor-rebuild migration (2026-07-06): the fix105 `mulAccumAvx2` kernel
    // was a documented-broken (lane-collapse), never-routed dead branch — its
    // only callers were its own now-deleted `lo_tables`/`hi_tables` fields and
    // populating init() loop. `mulAccum` never dispatched to it (only
    // `mulAccumGfni`/`mulAccumScalar`, see above); confirmed zero external
    // callers repo-wide before deletion. CLEAN per manifest §1.13's own note
    // ("CLEAN = delete or fix+KAT the documented-broken mulAccumAvx2 dead
    // branch") — zero logic change to the live GFNI/scalar tiers.
    // ═══════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════
    // Tier 1: GFNI + AVX-512F (64 bytes/cycle)
    //
    // The GF2P8AFFINEQB instruction performs:
    //   for each byte b in src: output = M × b  (in GF(2))
    // where M is an 8×8 bit matrix packed in a u64 qword.
    //
    // To multiply by constant c in GF(2^8):
    //   Column j of M = bit representation of gfMul(c, 2^j)
    //   This works because multiplication is GF(2)-linear.
    //
    // One instruction processes 64 bytes (ZMM register) — 64x scalar speed.
    // ═══════════════════════════════════════════════════════════════════

    fn mulAccumGfni(self: *const GfSimd, dst: []u8, src: []const u8, coeff: u8) void {
        // GF(2^8) multiply-by-constant `coeff` as a GF(2)-linear map applied with one VEX.256
        // VGF2P8AFFINEQB per 32 bytes. The 8×8 bit-matrix gfni_matrices[coeff] (built by
        // buildGfniMatrix, KAT-verified) encodes mul-by-coeff INCLUDING the field reduction, so this is
        // field-agnostic — correct for our POLY=0x11D (the instruction's own hardwired 0x11B GF2P8MULB
        // does NOT apply; the affine form does). 256-bit ymm via the "x" constraint (Zig 0.15.2's asm
        // rejects the "v"/zmm AVX-512 constraint — the limitation the prior scalar stub noted); all
        // operands are registers (matrix broadcast into all 4 qwords + src loaded via @Vector). coeff
        // 0/1 are handled by the mulAccum guard, so here coeff >= 2.
        const mat_q = self.gfni_matrices[coeff];
        const mat_vec: @Vector(32, u8) = @bitCast(@as(@Vector(4, u64), @splat(mat_q)));

        var i: usize = 0;
        while (i + 32 <= src.len) : (i += 32) {
            const data_vec: @Vector(32, u8) = src[i..][0..32].*;
            // AT&T order: vgf2p8affineqb $imm8, src2(matrix), src1(data), dst.
            const prod: @Vector(32, u8) = asm (
                \\vgf2p8affineqb $0, %[mat], %[data], %[out]
                : [out] "=x" (-> @Vector(32, u8)),
                : [mat] "x" (mat_vec),
                  [data] "x" (data_vec),
            );
            const dst_vec: @Vector(32, u8) = dst[i..][0..32].*;
            dst[i..][0..32].* = dst_vec ^ prod;
        }

        // Scalar tail (< 64 bytes) — log/exp table multiply.
        const log_c = self.log_table[coeff];
        while (i < src.len) : (i += 1) {
            const s = src[i];
            if (s != 0) {
                dst[i] ^= self.exp_table[@as(u16, self.log_table[s]) + @as(u16, log_c)];
            }
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// GFNI Matrix Construction
// ═══════════════════════════════════════════════════════════════════════════

/// Build the 8×8 GF(2) matrix qword for multiplication by constant `c`, in the exact layout
/// VGF2P8AFFINEQB consumes. The instruction computes, for each data byte x and matrix qword M:
///   output.bit[i] = parity( M.byte[7-i] AND x )   (imm8 = 0)
/// i.e. M.byte[7-i] is the linear functional extracting output bit i. For GF(2^8) mul-by-c,
/// output.bit[i] = XOR over j of bit_i(c ⊗ 2^j) · x.bit[j], so:
///   M.byte[7-i].bit[j] = bit_i( gfMul(c, 2^j) )   →   M.byte[k].bit[j] = bit_(7-k)( gfMul(c, 2^j) )
/// (This is the row-functional layout; the earlier column layout gfMul(c,2^(7-k)) per byte was a
/// transpose of what the instruction wants — it produced wrong products and is fixed here. Validated
/// independently by affineApplyScalar in the KATs, and end-to-end by the perf#2 exhaustive KAT.)
pub fn buildGfniMatrix(c: u8) u64 {
    var matrix: u64 = 0;
    inline for (0..8) |k| {
        const out_bit: u3 = @intCast(7 - k); // byte k serves output bit i = 7-k
        var byte_val: u8 = 0;
        inline for (0..8) |j| {
            const cj = gfMulScalar(c, @as(u8, 1) << @intCast(j)); // c ⊗ 2^j
            const bit: u8 = (cj >> out_bit) & 1;
            byte_val |= bit << @intCast(j);
        }
        matrix |= @as(u64, byte_val) << @intCast(k * 8);
    }
    return matrix;
}

/// Scalar emulation of VGF2P8AFFINEQB (imm8=0) for ONE byte — used by KATs to validate buildGfniMatrix
/// independently of the hardware instruction: output.bit[i] = parity(matrix.byte[7-i] AND x).
fn affineApplyScalar(matrix: u64, x: u8) u8 {
    var out: u8 = 0;
    inline for (0..8) |i| {
        const row: u8 = @truncate(matrix >> @intCast((7 - i) * 8));
        const parity: u8 = @popCount(row & x) & 1;
        out |= parity << @intCast(i);
    }
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// Runtime CPU Feature Detection (for generic builds)
// ═══════════════════════════════════════════════════════════════════════════

/// Detect the best GF tier at runtime using CPUID.
/// Use this when the binary is built with generic x86_64 features
/// and you want to enable SIMD on capable hardware.
pub fn detectTierRuntime() GfTier {
    if (!is_x86_64) return .scalar;

    // CPUID leaf 7, subleaf 0
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    asm volatile ("cpuid"
        : [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
        : [eax] "{eax}" (@as(u32, 7)),
          [in_ecx] "{ecx}" (@as(u32, 0)),
        : .{ .edx = true });

    const cpu_avx2 = (ebx & (1 << 5)) != 0;
    const cpu_avx512f = (ebx & (1 << 16)) != 0;
    const cpu_gfni = (ecx & (1 << 8)) != 0;

    // Also verify OS has enabled AVX state saving via XGETBV (XCR0)
    var xcr0_lo: u32 = undefined;
    asm volatile ("xgetbv"
        : [eax] "={eax}" (xcr0_lo),
        : [in_ecx] "{ecx}" (@as(u32, 0)),
        : .{ .edx = true });
    const os_avx = (xcr0_lo & 0x06) == 0x06; // SSE + AVX state
    const os_avx512 = os_avx and (xcr0_lo & 0xE0) == 0xE0; // opmask + ZMM state

    if (cpu_gfni and cpu_avx512f and os_avx512) return .gfni_avx512;
    if (cpu_avx2 and os_avx) return .avx2;
    return .scalar;
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

test "gfMulScalar: identity and zero" {
    // a * 1 = a
    for (1..256) |i| {
        const a: u8 = @intCast(i);
        try std.testing.expectEqual(a, gfMulScalar(a, 1));
    }
    // a * 0 = 0
    for (0..256) |i| {
        try std.testing.expectEqual(@as(u8, 0), gfMulScalar(@intCast(i), 0));
    }
}

test "gfMulScalar: commutativity" {
    for (1..50) |i| {
        for (1..50) |j| {
            const a: u8 = @intCast(i);
            const b: u8 = @intCast(j);
            try std.testing.expectEqual(gfMulScalar(a, b), gfMulScalar(b, a));
        }
    }
}

test "gfMulScalar: inverse via division" {
    // (a * b) should be derivable: test a few known products
    // 2 * 2 in GF(2^8) with poly 0x11D
    try std.testing.expectEqual(@as(u8, 4), gfMulScalar(2, 2)); // x * x = x^2
    try std.testing.expectEqual(@as(u8, 0x1D), gfMulScalar(0x80, 2)); // x^7 * x = x^8 = x^4+x^3+x^2+1
}

test "buildGfniMatrix: identity (mul-by-1) emulated-affine == x for all x" {
    const matrix = buildGfniMatrix(1);
    for (0..256) |x| {
        try std.testing.expectEqual(@as(u8, @intCast(x)), affineApplyScalar(matrix, @intCast(x)));
    }
}

test "buildGfniMatrix: emulated-affine == gfMulScalar for ALL coeffs x ALL bytes" {
    // The matrix layout is correct iff applying it via the instruction's own semantics
    // (affineApplyScalar) reproduces the canonical scalar GF(2^8) product, for every (c, x).
    var c: usize = 0;
    while (c < 256) : (c += 1) {
        const matrix = buildGfniMatrix(@intCast(c));
        var x: usize = 0;
        while (x < 256) : (x += 1) {
            try std.testing.expectEqual(
                gfMulScalar(@intCast(c), @intCast(x)),
                affineApplyScalar(matrix, @intCast(x)),
            );
        }
    }
}

test "GfSimd scalar mulAccum correctness" {
    const simd = GfSimd.init();

    // Test: dst ^= coeff * src
    var dst = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    const src = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const coeff: u8 = 37;

    simd.mulAccum(&dst, &src, coeff);

    // Verify against reference scalar multiply
    for (0..8) |i| {
        try std.testing.expectEqual(gfMulScalar(coeff, src[i]), dst[i]);
    }
}

test "GfSimd mulAccum: XOR accumulation" {
    const simd = GfSimd.init();

    // Two rounds of mulAccum should XOR-accumulate
    var dst = [_]u8{0} ** 16;
    const src1 = [_]u8{0x42} ** 16;
    const src2 = [_]u8{0x7F} ** 16;

    simd.mulAccum(&dst, &src1, 5);
    simd.mulAccum(&dst, &src2, 11);

    // Verify: dst[i] = gfMul(5, 0x42) ^ gfMul(11, 0x7F)
    const expected = gfMulScalar(5, 0x42) ^ gfMulScalar(11, 0x7F);
    try std.testing.expectEqual(expected, dst[0]);
}

test "GfSimd mulAccum: coeff=0 is noop" {
    const simd = GfSimd.init();
    var dst = [_]u8{0xAA} ** 8;
    const src = [_]u8{0x55} ** 8;
    simd.mulAccum(&dst, &src, 0);
    // dst should be unchanged
    try std.testing.expectEqual(@as(u8, 0xAA), dst[0]);
}

test "GfSimd mulAccum: coeff=1 is XOR" {
    const simd = GfSimd.init();
    var dst = [_]u8{0xF0} ** 4;
    const src = [_]u8{0x0F} ** 4;
    simd.mulAccum(&dst, &src, 1);
    try std.testing.expectEqual(@as(u8, 0xFF), dst[0]);
}

test "detectTierRuntime: does not crash" {
    if (!is_x86_64) return;
    const tier = detectTierRuntime();
    // Just verify it returns a valid tier without crashing
    _ = tier.name();
}

test "mulAccum: 1084-byte shred (realistic tail handling)" {
    // Typical Turbine erasure portion: 1084 bytes
    // GFNI: 16 × 64 = 1024, then 32-byte YMM chunk, then 28-byte scalar tail
    const simd = GfSimd.init();
    const coeff: u8 = 0xAB;

    var src: [1084]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i ^ 0x37);

    // SIMD path
    var dst_simd = [_]u8{0} ** 1084;
    simd.mulAccum(&dst_simd, &src, coeff);

    // Reference: scalar one-at-a-time
    var dst_ref = [_]u8{0} ** 1084;
    for (&dst_ref, &src) |*d, s| d.* ^= gfMulScalar(coeff, s);

    // Every byte must match
    try std.testing.expectEqualSlices(u8, &dst_ref, &dst_simd);
}

test "mulAccum: 1-byte edge case (pure scalar tail)" {
    const simd = GfSimd.init();
    var dst = [_]u8{0};
    const src = [_]u8{0xFF};
    simd.mulAccum(&dst, &src, 42);
    try std.testing.expectEqual(gfMulScalar(42, 0xFF), dst[0]);
}

test "mulAccum: 63-byte edge case (no full SIMD chunk)" {
    const simd = GfSimd.init();
    const coeff: u8 = 200;
    var src: [63]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i + 1);

    var dst_simd = [_]u8{0} ** 63;
    simd.mulAccum(&dst_simd, &src, coeff);

    var dst_ref = [_]u8{0} ** 63;
    for (&dst_ref, &src) |*d, s| d.* ^= gfMulScalar(coeff, s);

    try std.testing.expectEqualSlices(u8, &dst_ref, &dst_simd);
}

// PERF #2 KAT (2026-06-15): EXHAUSTIVE proof that the active SIMD multiply path (GFNI VEX.256
// vgf2p8affineqb on znver4) is BYTE-IDENTICAL to the canonical scalar GF(2^8) definition, over ALL 256
// coefficients and many lengths incl. every tail alignment (the affine loop does 32B chunks + a scalar
// tail). Also verifies XOR-ACCUMULATE (non-zero initial dst) — mulAccum must xor into dst, not overwrite
// — since FEC recovery accumulates many shard contributions. If the SIMD kernel diverged from scalar by
// even one byte for any coeff/length, FEC recovery would corrupt → this fails loudly.
test "perf#2: GFNI mulAccum == scalar for all 256 coeffs x all tail alignments" {
    const simd = GfSimd.init();
    const lengths = [_]usize{ 1, 7, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 95, 96, 127, 128, 1024, 1084, 1280 };

    var buf_src: [1280]u8 = undefined;
    var buf_simd: [1280]u8 = undefined;
    var buf_ref: [1280]u8 = undefined;

    var coeff: usize = 0;
    while (coeff < 256) : (coeff += 1) {
        for (lengths) |len| {
            // Varied source + NON-ZERO accumulator seed (different per coeff/len).
            for (0..len) |i| {
                buf_src[i] = @truncate((i *% 31) ^ (coeff *% 7) ^ 0x5a);
                const acc: u8 = @truncate((i *% 13) ^ (len *% 3) ^ 0xa5);
                buf_simd[i] = acc;
                buf_ref[i] = acc;
            }
            // Production dispatch (GFNI VEX.256 affine on znver4).
            simd.mulAccum(buf_simd[0..len], buf_src[0..len], @truncate(coeff));
            // Canonical scalar reference (handles coeff 0/1 the same way mulAccum guards them).
            if (coeff == 0) {
                // no-op
            } else if (coeff == 1) {
                for (0..len) |i| buf_ref[i] ^= buf_src[i];
            } else {
                for (0..len) |i| buf_ref[i] ^= gfMulScalar(@truncate(coeff), buf_src[i]);
            }
            try std.testing.expectEqualSlices(u8, buf_ref[0..len], buf_simd[0..len]);
        }
    }
}
