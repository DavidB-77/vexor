const std = @import("std");

/// The core 32-byte SHA-256 hash used pervasively in the Vexor SVM execution model.
pub const Hash = extern struct {
    data: [32]u8,

    pub const SIZE = 32;
    pub const ZERO = Hash{ .data = [_]u8{0} ** 32 };

    pub fn init(data_bytes: [32]u8) Hash {
        return .{ .data = data_bytes };
    }

    pub fn fromBytes(bytes: [32]u8) Hash {
        return .{ .data = bytes };
    }

    pub fn fromSlice(slice: []const u8) !Hash {
        if (slice.len != 32) return error.InvalidLength;
        var hash: Hash = undefined;
        @memcpy(&hash.data, slice);
        return hash;
    }

    /// Default (all zeros)
    pub fn default() Hash {
        return ZERO;
    }

    /// Computes the SHA-256 hash of the provided bytes
    pub fn compute(data_bytes: []const u8) Hash {
        var out: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data_bytes, &out, .{});
        return Hash.init(out);
    }

    pub fn eql(self: *const Hash, other: *const Hash) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }
};

/// A 32-byte Ed25519 public key.
pub const Pubkey = extern struct {
    data: [32]u8,

    pub const SIZE = 32;

    pub fn init(data_bytes: [32]u8) Pubkey {
        return .{ .data = data_bytes };
    }

    pub fn fromBytes(bytes: [32]u8) Pubkey {
        return .{ .data = bytes };
    }

    pub fn fromSlice(slice: []const u8) !Pubkey {
        if (slice.len != 32) return error.InvalidLength;
        var pubkey: Pubkey = undefined;
        @memcpy(&pubkey.data, slice);
        return pubkey;
    }

    pub fn default() Pubkey {
        return .{ .data = [_]u8{0} ** 32 };
    }

    pub fn eql(self: *const Pubkey, other: *const Pubkey) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }

    pub fn isDefault(self: *const Pubkey) bool {
        return std.mem.allEqual(u8, &self.data, 0);
    }
};

/// A 64-byte Ed25519 signature.
pub const Signature = extern struct {
    data: [64]u8,

    pub const SIZE = 64;

    pub fn fromBytes(bytes: [64]u8) Signature {
        return .{ .data = bytes };
    }

    pub fn fromSlice(slice: []const u8) !Signature {
        if (slice.len != 64) return error.InvalidLength;
        var sig: Signature = undefined;
        @memcpy(&sig.data, slice);
        return sig;
    }

    pub fn isDefault(self: *const Signature) bool {
        return std.mem.allEqual(u8, &self.data, 0);
    }
};
