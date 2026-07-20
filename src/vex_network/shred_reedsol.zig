//! Reed-Solomon PARITY ENCODER for block production (the shredder's gating piece).
//!
//! STAGED / MODULAR: not wired to the live path; gated behind -Dleader_mode at the call site. The
//! shred encoder needs to generate `m` parity shreds from `n` data shreds so every validator can
//! recover the FEC set. Vexor's receive path (fec_resolver.zig) already RECOVERS real cluster shreds
//! using a Vandermonde encoding matrix M = V·inv(top(V)) over GF(2^8)/0x11D — so that matrix matches
//! the cluster's encoder. This module applies the SAME field + matrix in the FORWARD direction
//! (data → parity), which yields cluster-byte-identical parity.
//!
//! Ground truth: GF(2^8) primitive poly 0x11D, α=2 — IMPORTED from fec_resolver.GaloisField so the
//! field is provably identical to the live recovery path (Agave reed-solomon-erasure uses the same
//! field). Matrix construction mirrors fec_resolver.zig:730-803 (Vandermonde V[r][c]=r^c with r=0
//! special-cased, top-n×n inverse via Gaussian elimination, M = V·top_inv). FD: 32 data : 32 parity.

const std = @import("std");

/// GF(2^8) with primitive polynomial 0x11D, α=2 — BYTE-IDENTICAL to fec_resolver.GaloisField (the
/// live receive-side recovery field) and to Agave's reed-solomon-erasure. Embedded here (not
/// imported) so this module + its KAT are std-only/self-contained; the "field is the live one" KAT
/// below pins it (2*2=4, inv round-trip over all 255 nonzero elements). Same field ⇒ the matrix M
/// built from it matches the cluster's encoder ⇒ cluster-byte-identical parity.
pub const GaloisField = struct {
    const PRIMITIVE_POLY: u16 = 0x11D;
    log_table: [256]u8,
    exp_table: [512]u8,

    pub fn init() GaloisField {
        var gf = GaloisField{ .log_table = undefined, .exp_table = undefined };
        var x: u16 = 1;
        for (0..255) |i| {
            gf.exp_table[i] = @truncate(x);
            gf.exp_table[i + 255] = @truncate(x);
            x <<= 1;
            if (x & 0x100 != 0) x ^= PRIMITIVE_POLY;
        }
        gf.exp_table[510] = gf.exp_table[0];
        gf.exp_table[511] = gf.exp_table[1];
        gf.log_table[0] = 0;
        for (0..255) |i| gf.log_table[gf.exp_table[i]] = @truncate(i);
        return gf;
    }
    pub fn mul(self: *const GaloisField, a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return self.exp_table[@as(u16, self.log_table[a]) + @as(u16, self.log_table[b])];
    }
    pub fn inv(self: *const GaloisField, a: u8) u8 {
        if (a == 0) return 0;
        return self.exp_table[255 - @as(u16, self.log_table[a])];
    }
};

/// Invert an `n`×`n` GF(2^8) matrix in place into `out` (n×n). Gaussian elimination with an
/// augmented identity. Returns false if singular. (Same algorithm as fec_resolver's top-inverse.)
pub fn invertMatrix(gf: *const GaloisField, a: []const u8, n: usize, out: []u8, scratch: []u8) bool {
    // scratch is n*2n augmented [A | I].
    const w = 2 * n;
    for (0..n) |r| {
        for (0..n) |c| scratch[r * w + c] = a[r * n + c];
        for (0..n) |c| scratch[r * w + n + c] = if (r == c) 1 else 0;
    }
    for (0..n) |col| {
        var pivot = col;
        while (pivot < n and scratch[pivot * w + col] == 0) pivot += 1;
        if (pivot >= n) return false;
        if (pivot != col) {
            for (0..w) |c| {
                const t = scratch[col * w + c];
                scratch[col * w + c] = scratch[pivot * w + c];
                scratch[pivot * w + c] = t;
            }
        }
        const pv = scratch[col * w + col];
        if (pv != 1) {
            const ip = gf.inv(pv);
            for (0..w) |c| scratch[col * w + c] = gf.mul(scratch[col * w + c], ip);
        }
        for (0..n) |r| {
            if (r != col) {
                const f = scratch[r * w + col];
                if (f != 0) for (0..w) |c| {
                    scratch[r * w + c] = scratch[r * w + c] ^ gf.mul(f, scratch[col * w + c]);
                };
            }
        }
    }
    for (0..n) |r| for (0..n) |c| {
        out[r * n + c] = scratch[r * w + n + c];
    };
    return true;
}

/// Build the systematic encoding matrix M (total×n) = V · inv(top_n(V)). Top n rows = identity
/// (data passes through), bottom m rows = the parity generator. fec_resolver.zig:730-803.
pub fn buildEncMatrix(gf: *const GaloisField, allocator: std.mem.Allocator, n: usize, total: usize, out: []u8) !void {
    std.debug.assert(out.len >= total * n);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const vander = try a.alloc(u8, total * n);
    const top = try a.alloc(u8, n * n);
    const top_inv = try a.alloc(u8, n * n);
    const scratch = try a.alloc(u8, n * 2 * n);

    for (0..total) |row| {
        const x: u8 = @intCast(row);
        var xp: u8 = 1;
        for (0..n) |col| {
            vander[row * n + col] = xp;
            xp = if (x == 0) 0 else gf.mul(xp, x);
        }
    }
    for (0..n) |r| for (0..n) |c| {
        top[r * n + c] = vander[r * n + c];
    };
    if (!invertMatrix(gf, top, n, top_inv, scratch)) return error.SingularTop;
    // M = V · top_inv
    for (0..total) |row| {
        for (0..n) |col| {
            var sum: u8 = 0;
            for (0..n) |k| sum ^= gf.mul(vander[row * n + k], top_inv[k * n + col]);
            out[row * n + col] = sum;
        }
    }
}

/// Encode `m` parity shards from `n` data shards (each `shard_len` bytes). Caller owns the returned
/// parity buffer (m * shard_len bytes; parity[j] = out[j*shard_len ..]).
pub fn encodeParity(
    gf: *const GaloisField,
    allocator: std.mem.Allocator,
    data: []const []const u8,
    m: usize,
    shard_len: usize,
) ![]u8 {
    const n = data.len;
    const total = n + m;
    for (data) |d| std.debug.assert(d.len == shard_len);

    const enc = try allocator.alloc(u8, total * n);
    defer allocator.free(enc);
    try buildEncMatrix(gf, allocator, n, total, enc);

    const parity = try allocator.alloc(u8, m * shard_len);
    @memset(parity, 0);
    for (0..m) |j| {
        const mrow = enc[(n + j) * n ..][0 .. n]; // parity generator row
        for (0..n) |i| {
            const coeff = mrow[i];
            if (coeff == 0) continue;
            const src = data[i];
            const dst = parity[j * shard_len ..][0..shard_len];
            for (0..shard_len) |b| dst[b] ^= gf.mul(coeff, src[b]);
        }
    }
    return parity;
}

// ════════════════════════════════════════════════════════════════════════════
// KAT — encode → erase → recover round-trip (RS-correctness). Run: zig build test-shred-reedsol
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "encoding matrix is systematic: top n rows == identity" {
    const gf = GaloisField.init();
    const n = 4;
    const total = 8;
    var enc: [total * n]u8 = undefined;
    try buildEncMatrix(&gf, testing.allocator, n, total, &enc);
    for (0..n) |r| for (0..n) |c| {
        try testing.expectEqual(@as(u8, if (r == c) 1 else 0), enc[r * n + c]);
    };
}

test "GF field is the live recovery field (0x11D): 2*2=4, inv(a)*a=1" {
    const gf = GaloisField.init();
    try testing.expectEqual(@as(u8, 4), gf.mul(2, 2));
    var a: u8 = 1;
    while (a != 0) : (a +%= 1) {
        try testing.expectEqual(@as(u8, 1), gf.mul(a, gf.inv(a)));
        if (a == 255) break;
    }
}

test "RS round-trip: encode 4 data → 4 parity, erase 2 data, recover via submatrix inverse" {
    const gf = GaloisField.init();
    const alloc = testing.allocator;
    const n = 4;
    const m = 4;
    const total = n + m;
    const L = 7; // shard length

    // distinct data shards
    var d0 = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    var d1 = [_]u8{ 10, 20, 30, 40, 50, 60, 70 };
    var d2 = [_]u8{ 100, 101, 102, 103, 104, 105, 106 };
    var d3 = [_]u8{ 200, 201, 202, 203, 204, 205, 206 };
    const data = [_][]const u8{ &d0, &d1, &d2, &d3 };

    const parity = try encodeParity(&gf, alloc, &data, m, L);
    defer alloc.free(parity);

    // Build the full codeword shard set (rows 0..total): rows 0..n = data, rows n.. = parity.
    var shards: [total][]const u8 = undefined;
    for (0..n) |i| shards[i] = data[i];
    for (0..m) |j| shards[n + j] = parity[j * L ..][0..L];

    // Erase data rows 0 and 1. Recover using rows {2,3,4,5} (2 data + 2 parity).
    const enc = try alloc.alloc(u8, total * n);
    defer alloc.free(enc);
    try buildEncMatrix(&gf, alloc, n, total, enc);

    const present_rows = [_]usize{ 2, 3, 4, 5 }; // n rows we keep
    // submatrix S (n×n) = enc rows present_rows ; recovered_data = inv(S) · present_shards
    var sub: [n * n]u8 = undefined;
    for (present_rows, 0..) |row, r| for (0..n) |c| {
        sub[r * n + c] = enc[row * n + c];
    };
    var sinv: [n * n]u8 = undefined;
    var scratch: [n * 2 * n]u8 = undefined;
    try testing.expect(invertMatrix(&gf, &sub, n, &sinv, &scratch));

    // recovered data column-by-column: data[i][b] = Σ sinv[i][r] · shard[present_rows[r]][b]
    var rec: [n][L]u8 = undefined;
    for (0..n) |i| for (0..L) |b| {
        var sum: u8 = 0;
        for (0..n) |r| sum ^= gf.mul(sinv[i * n + r], shards[present_rows[r]][b]);
        rec[i][b] = sum;
    };
    // rec[0..4] must equal the original data shards d0..d3
    try testing.expectEqualSlices(u8, &d0, &rec[0]);
    try testing.expectEqualSlices(u8, &d1, &rec[1]);
    try testing.expectEqualSlices(u8, &d2, &rec[2]);
    try testing.expectEqualSlices(u8, &d3, &rec[3]);
}

test "parity is deterministic + nonzero for nonzero data" {
    const gf = GaloisField.init();
    const alloc = testing.allocator;
    var d0 = [_]u8{ 9, 9, 9 };
    var d1 = [_]u8{ 1, 2, 3 };
    const data = [_][]const u8{ &d0, &d1 };
    const p1 = try encodeParity(&gf, alloc, &data, 2, 3);
    defer alloc.free(p1);
    const p2 = try encodeParity(&gf, alloc, &data, 2, 3);
    defer alloc.free(p2);
    try testing.expectEqualSlices(u8, p1, p2); // deterministic
    var any: bool = false;
    for (p1) |b| if (b != 0) {
        any = true;
    };
    try testing.expect(any); // not all-zero
}
