//! Vexor pure-Zig BN254 (alt_bn128) syscall leaf.
//!
//! Public drop-in for the Firedancer Ballet `fd_bn254_*` FFI leaf: same byte
//! contract (already-translated host slices in/out, `big_endian` flag, bool
//! result where true = out written and false = soft failure → syscall `return 1`).
//! The syscall layer (vex_bpf2/syscalls.zig) owns CU/memory/feature-gate glue and
//! the abort-vs-return-1 mapping; this module is the crypto leaf only.
//!
//! Length handling mirrors the reference leaf: group-op inputs are zero-padded
//! into a fixed buffer (over-long ⇒ reject); the syscall layer above enforces the
//! endianness-specific exact/upper-bound length policy before calling. Pairing
//! consumes ⌊len/192⌋ elements and ignores any trailing remainder (matching the
//! Agave/Ballet leaf, which does NOT re-check len%192==0).

const std = @import("std");
const curve = @import("curve.zig");
const pairing = @import("pairing.zig");
const field = @import("field.zig");

const G1 = curve.G1;
const G2 = curve.G2;
const Fp12 = field.Fp12;
const Endian = std.builtin.Endian;

pub const field_mod = field;
pub const curve_mod = curve;
pub const pairing_mod = pairing;

fn endianOf(big_endian: bool) Endian {
    return if (big_endian) .big else .little;
}

/// Read a 32-byte scalar (unvalidated, may exceed r) as a u256. Big-endian wire
/// scalars are byte-swapped to the little-endian integer representation.
fn readScalar(bytes: *const [32]u8, big_endian: bool) u256 {
    if (big_endian) {
        var le: [32]u8 = undefined;
        for (0..32) |i| le[i] = bytes[31 - i];
        return @bitCast(le);
    }
    return @bitCast(bytes.*);
}

// ── Group ops ───────────────────────────────────────────────────────────────

pub fn g1Add(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len > 128 or out.len < 64) return false;
    var buf: [128]u8 = @splat(0);
    @memcpy(buf[0..in.len], in);
    const e = endianOf(big_endian);
    const a = G1.fromBytes(buf[0..64], e) catch return false;
    const b = G1.fromBytes(buf[64..128], e) catch return false;
    const r = curve.ops.affineAddG1(a, b);
    r.toBytes(out[0..64], e);
    return true;
}

pub fn g1Mul(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len > 128 or out.len < 64) return false;
    var buf: [128]u8 = @splat(0);
    @memcpy(buf[0..in.len], in);
    const e = endianOf(big_endian);
    const a = G1.fromBytes(buf[0..64], e) catch return false;
    const s = readScalar(buf[64..96], big_endian);
    const r = curve.ops.mulScalarG1(a, s);
    r.toBytes(out[0..64], e);
    return true;
}

pub fn g2Add(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len > 256 or out.len < 128) return false;
    var buf: [256]u8 = @splat(0);
    @memcpy(buf[0..in.len], in);
    const e = endianOf(big_endian);
    // G2 ADD: on-curve check ONLY (no subgroup) — SIMD-locked.
    const a = G2.fromBytesCheckCurve(buf[0..128], e) catch return false;
    const b = G2.fromBytesCheckCurve(buf[128..256], e) catch return false;
    const r = curve.ops.affineAddG2(a, b);
    r.toBytes(out[0..128], e);
    return true;
}

pub fn g2Mul(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len > 160 or out.len < 128) return false;
    var buf: [160]u8 = @splat(0);
    @memcpy(buf[0..in.len], in);
    const e = endianOf(big_endian);
    // G2 MUL: on-curve AND subgroup check — SIMD-locked.
    const a = G2.fromBytesCheckSubgroup(buf[0..128], e) catch return false;
    const s = readScalar(buf[128..160], big_endian);
    const r = curve.ops.mulScalarG2(a, s);
    r.toBytes(out[0..128], e);
    return true;
}

pub fn pairingIsOne(out: []u8, in: []const u8, big_endian: bool) bool {
    if (out.len < 32) return false;
    const e = endianOf(big_endian);
    const elements = in.len / 192;

    var ps: [pairing.BATCH_MAX]G1 = undefined;
    var qs: [pairing.BATCH_MAX]G2 = undefined;
    var acc: Fp12 = .one;
    var sz: usize = 0;

    var i: usize = 0;
    while (i < elements) : (i += 1) {
        const chunk = in[i * 192 ..][0..192];
        const p = G1.fromBytes(chunk[0..64], e) catch return false;
        const q = G2.fromBytesCheckSubgroup(chunk[64..192], e) catch return false;
        if (p.isZero() or q.isZero()) continue;
        ps[sz] = p;
        qs[sz] = q;
        sz += 1;
        if (sz == pairing.BATCH_MAX or i == elements - 1) {
            acc = acc.mul(pairing.millerLoop(ps[0..sz], qs[0..sz]));
            sz = 0;
        }
    }
    if (sz > 0) acc = acc.mul(pairing.millerLoop(ps[0..sz], qs[0..sz]));

    acc = pairing.finalExp(acc);
    @memset(out[0..32], 0);
    out[if (big_endian) 31 else 0] = if (acc.isOne()) 1 else 0;
    return true;
}

// ── Compression (fixed-size buffers; syscall layer size-checks before call) ──

pub fn g1Compress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len < 64 or out.len < 32) return false;
    G1.compress(out[0..32], in[0..64], endianOf(big_endian)) catch return false;
    return true;
}

pub fn g1Decompress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len < 32 or out.len < 64) return false;
    G1.decompress(out[0..64], in[0..32], endianOf(big_endian)) catch return false;
    return true;
}

pub fn g2Compress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len < 128 or out.len < 64) return false;
    G2.compress(out[0..64], in[0..128], endianOf(big_endian)) catch return false;
    return true;
}

pub fn g2Decompress(out: []u8, in: []const u8, big_endian: bool) bool {
    if (in.len < 64 or out.len < 128) return false;
    G2.decompress(out[0..128], in[0..64], endianOf(big_endian)) catch return false;
    return true;
}

test {
    std.testing.refAllDecls(@This());
}
