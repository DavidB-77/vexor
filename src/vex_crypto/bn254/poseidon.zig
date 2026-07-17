//! Vexor Poseidon-BN254 hash (the `sol_poseidon` syscall leaf).
//!
//! Vexor's own implementation of the Poseidon permutation over the BN254 scalar
//! field Fr, following the light-poseidon v0.2.0 / circomlib bn254_x5 parameter
//! set that Agave and Firedancer Ballet use, and gated byte-for-byte against
//! Ballet by `kat.zig`.
//!
//! Field representation: we work in the NORMAL (non-Montgomery) residue domain.
//! Ballet keeps its round constants in Fr-Montgomery form and runs Montgomery
//! arithmetic; the round constants here were converted out of Montgomery once
//! (poseidon_params.zig), so plain add/mul-mod-r produces the identical field
//! element — Montgomery is only a representation, and the serialized output is
//! the same canonical residue either way. The differential gate proves this.
//!
//! Semantics mirror fd_poseidon exactly: state[0] is the (zero) capacity element
//! and also the output; the i-th appended input lands in state[i]; width =
//! cnt+1; the round schedule is 4 full · P partial · 4 full rounds of
//! ark → sbox(x⁵) → MDS, with P the width-specific partial-round count.

const std = @import("std");
const params = @import("poseidon_params.zig");

/// BN254 scalar field order r.
const r: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

pub const MAX_WIDTH: usize = 12; // up to 12 inputs (state width 13)
pub const HASH_SZ: usize = 32;

/// Width-indexed partial-round counts (light-poseidon bn254_x5); index = cnt-1.
const partial_rounds = [_]usize{ 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68 };
const full_rounds: usize = 8;

inline fn addMod(a: u256, b: u256) u256 {
    const s = a +% b; // a,b < r < 2^254 ⇒ no u256 overflow
    return if (s >= r) s - r else s;
}

inline fn mulMod(a: u256, b: u256) u256 {
    const wide: u512 = @as(u512, a) * @as(u512, b);
    return @intCast(wide % @as(u512, r));
}

/// x⁵ in Fr.
inline fn pow5(x: u256) u256 {
    const x2 = mulMod(x, x);
    const x4 = mulMod(x2, x2);
    return mulMod(x4, x);
}

/// In-progress Poseidon sponge state, matching fd_poseidon_t semantics.
pub const Hasher = struct {
    state: [MAX_WIDTH + 1]u256 = @splat(0),
    cnt: usize = 0,
    big_endian: bool,
    failed: bool = false,

    pub fn init(big_endian: bool) Hasher {
        return .{ .big_endian = big_endian };
    }

    /// Append one field element (1..32 bytes). Short elements are zero-extended;
    /// `enforce_padding` (SIMD-0359) requires exactly 32 bytes. Errors are latched
    /// so the final result is a soft-fail, matching the FFI leaf.
    pub fn append(self: *Hasher, data: []const u8, enforce_padding: bool) void {
        if (self.failed) return;
        if (data.len == 0 or data.len > 32 or self.cnt >= MAX_WIDTH) {
            self.failed = true;
            return;
        }
        if (enforce_padding and data.len != 32) {
            self.failed = true;
            return;
        }
        var buf: [32]u8 = @splat(0);
        if (self.big_endian) {
            // right-aligned big-endian, then read as big-endian integer
            @memcpy(buf[32 - data.len ..], data);
            const v = std.mem.readInt(u256, &buf, .big);
            if (v >= r) {
                self.failed = true;
                return;
            }
            self.cnt += 1;
            self.state[self.cnt] = v;
        } else {
            @memcpy(buf[0..data.len], data);
            const v = std.mem.readInt(u256, &buf, .little);
            if (v >= r) {
                self.failed = true;
                return;
            }
            self.cnt += 1;
            self.state[self.cnt] = v;
        }
    }

    /// Run the permutation and write the 32-byte hash. Returns false on any
    /// latched error or zero appended inputs (soft-fail → syscall `return 1`).
    pub fn finish(self: *Hasher, out: *[32]u8) bool {
        if (self.failed or self.cnt == 0) return false;
        const width = self.cnt + 1;
        const ark = params.ark[width - 2];
        const mds = params.mds[width - 2];
        const p = partial_rounds[self.cnt - 1];
        const half = full_rounds / 2;
        const total = full_rounds + p;

        var st = self.state[0..width];
        var round: usize = 0;
        while (round < total) : (round += 1) {
            // ark
            for (0..width) |i| st[i] = addMod(st[i], ark[round * width + i]);
            // sbox: full rounds apply x⁵ to all lanes, partial rounds only to lane 0
            const full = round < half or round >= half + p;
            if (full) {
                for (0..width) |i| st[i] = pow5(st[i]);
            } else {
                st[0] = pow5(st[0]);
            }
            // MDS: x = M · state
            var next: [MAX_WIDTH + 1]u256 = @splat(0);
            for (0..width) |i| {
                var acc: u256 = 0;
                for (0..width) |j| acc = addMod(acc, mulMod(st[j], mds[i * width + j]));
                next[i] = acc;
            }
            for (0..width) |i| st[i] = next[i];
        }

        // Output = state[0] (already normal residue); serialize in requested endian.
        std.mem.writeInt(u256, out, st[0], if (self.big_endian) .big else .little);
        return true;
    }
};

/// One-shot leaf matching the Ballet FFI wrapper contract:
/// `poseidonHash(out, inputs, big_endian, enforce_padding) -> bool`.
pub fn poseidonHash(out: []u8, inputs: []const []const u8, big_endian: bool, enforce_padding: bool) bool {
    if (out.len < 32) return false;
    var h = Hasher.init(big_endian);
    for (inputs) |seg| h.append(seg, enforce_padding);
    return h.finish(out[0..32]);
}
