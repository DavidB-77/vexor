const std = @import("std");

// @prov:crypto.lthash
/// Vexor 2048-byte Lattice Hash (LtHash).
/// 1024 wrapping 16-bit integers.
/// Uses @Vector for SIMD acceleration on AVX-512 (Zen4).
pub const LtHash = struct {
    elements: [1024]u16 align(64),

    pub fn init() LtHash {
        return .{ .elements = [_]u16{0} ** 1024 };
    }

    /// Add another LtHash (wrapping u16 addition per lane).
    /// Compiles to vpaddw on AVX-512 capable targets.
    pub fn wrappingAdd(self: *LtHash, other: *const LtHash) void {
        // Process 32 elements at a time via @Vector (512-bit / 16-bit = 32 lanes)
        const Vec = @Vector(32, u16);
        var i: usize = 0;
        while (i < 1024) : (i += 32) {
            const a: Vec = self.elements[i..][0..32].*;
            const b: Vec = other.elements[i..][0..32].*;
            self.elements[i..][0..32].* = a +% b;
        }
    }

    /// Subtract another LtHash (wrapping u16 subtraction per lane).
    /// Compiles to vpsubw on AVX-512 capable targets.
    pub fn wrappingSub(self: *LtHash, other: *const LtHash) void {
        const Vec = @Vector(32, u16);
        var i: usize = 0;
        while (i < 1024) : (i += 32) {
            const a: Vec = self.elements[i..][0..32].*;
            const b: Vec = other.elements[i..][0..32].*;
            self.elements[i..][0..32].* = a -% b;
        }
    }

    /// Raw bytes view (2048 bytes) for SHA256 input in bank hash computation.
    pub fn asBytes(self: *const LtHash) *const [2048]u8 {
        return @ptrCast(&self.elements);
    }
};
