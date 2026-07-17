//! Vexor Keypair Module
//!
//! Handles loading, creating, and managing Ed25519 keypairs.
//! Compatible with Solana CLI JSON keypair format.

const std = @import("std");
const core_types = @import("types.zig");
const base58 = @import("base58.zig");
const crypto = @import("vex_crypto");

const Pubkey = core_types.Pubkey;
const Signature = core_types.Signature;

/// Ed25519 keypair
pub const Keypair = struct {
    /// Secret key (64 bytes: 32 private + 32 public)
    secret: [64]u8,

    /// Public key (derived from secret)
    public: Pubkey,

    const Self = @This();

    /// Generate a new random keypair
    pub fn generate() Self {
        const Ed25519 = std.crypto.sign.Ed25519;
        const kp = Ed25519.KeyPair.generate();

        return Self{
            .secret = kp.secret_key.toBytes(),
            .public = Pubkey{ .data = kp.public_key.toBytes() },
        };
    }

    /// Create keypair from secret bytes
    /// Solana format: [32-byte seed][32-byte public key]
    /// Firedancer reference: fd_keyload.c - loads 64 bytes, uses bytes 0-31 as private, 32-63 as public
    pub fn fromSecretBytes(secret: [64]u8) Self {
        // Solana stores the public key directly in bytes 32-64
        // We should use that directly, not try to derive it (as Firedancer does)
        var public: Pubkey = undefined;
        @memcpy(&public.data, secret[32..64]);

        return Self{
            .secret = secret,
            .public = public,
        };
    }

    /// Sign a message
    pub fn sign(self: *const Self, message: []const u8) Signature {
        return core_types.Signature{ .data = crypto.ed25519.sign(self.secret, message) };
    }

    /// Verify a signature
    pub fn verify(self: *const Self, sig: *const Signature, message: []const u8) bool {
        return crypto.ed25519.verify(&sig.data, &self.public.data, message);
    }

    /// Get public key
    pub fn pubkey(self: *const Self) Pubkey {
        return self.public;
    }
};

/// Load a keypair from a JSON file (Solana CLI format)
/// Format: [byte0, byte1, ..., byte63]
pub fn loadKeypairFromFile(allocator: std.mem.Allocator, path: []const u8) !Keypair {
    // Read file
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return loadKeypairFromJson(contents);
}

/// Parse keypair from JSON string
pub fn loadKeypairFromJson(json: []const u8) !Keypair {
    // Find the array bounds
    const start = std.mem.indexOf(u8, json, "[") orelse return error.InvalidFormat;
    const end = std.mem.lastIndexOf(u8, json, "]") orelse return error.InvalidFormat;

    if (start >= end) return error.InvalidFormat;

    const array_content = json[start + 1 .. end];

    // Parse byte values
    var secret: [64]u8 = undefined;
    var byte_idx: usize = 0;
    var num_start: ?usize = null;

    for (array_content, 0..) |c, i| {
        if (c >= '0' and c <= '9') {
            if (num_start == null) {
                num_start = i;
            }
        } else if (num_start != null) {
            // End of number
            const num_str = array_content[num_start.?..i];
            const value = std.fmt.parseInt(u8, num_str, 10) catch return error.InvalidNumber;

            if (byte_idx >= 64) return error.TooManyBytes;
            secret[byte_idx] = value;
            byte_idx += 1;

            num_start = null;
        }
    }

    // Handle last number
    if (num_start) |start_idx| {
        const num_str = array_content[start_idx..];
        const value = std.fmt.parseInt(u8, num_str, 10) catch return error.InvalidNumber;

        if (byte_idx >= 64) return error.TooManyBytes;
        secret[byte_idx] = value;
        byte_idx += 1;
    }

    if (byte_idx != 64) return error.WrongLength;

    return Keypair.fromSecretBytes(secret);
}

/// Save keypair to JSON file (Solana CLI format)
pub fn saveKeypairToFile(allocator: std.mem.Allocator, keypair: *const Keypair, path: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    const json = try keypairToJson(allocator, keypair);
    defer allocator.free(json);

    try file.writeAll(json);
}

/// Convert keypair to JSON string
pub fn keypairToJson(allocator: std.mem.Allocator, keypair: *const Keypair) ![]u8 {
    var result = std.ArrayListUnmanaged(u8){};
    errdefer result.deinit(allocator);

    try result.append(allocator, '[');

    for (keypair.secret, 0..) |byte, i| {
        if (i > 0) {
            try result.append(allocator, ',');
        }
        var buf: [4]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, "{d}", .{byte}) catch unreachable;
        try result.appendSlice(allocator, slice);
    }

    try result.append(allocator, ']');

    return try result.toOwnedSlice(allocator);
}

/// Pubkey to base58 string
pub fn pubkeyToBase58(allocator: std.mem.Allocator, pubkey: *const Pubkey) ![]u8 {
    return base58.encode(allocator, &pubkey.data);
}

/// Parse pubkey from base58 string
pub fn pubkeyFromBase58(base58_str: []const u8) !Pubkey {
    var pubkey = Pubkey{ .data = [_]u8{0} ** 32 };
    try base58.decodeToBuf(base58_str, &pubkey.data);
    return pubkey;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
test "keypair generation" {
    const kp = Keypair.generate();
    try std.testing.expect(kp.public.data[0] != 0 or kp.public.data[1] != 0);
}

test "keypair sign and verify" {
    const kp = Keypair.generate();
    const message = "Hello, Vexor!";

    const sig = kp.sign(message);
    try std.testing.expect(kp.verify(&sig, message));
}

test "keypair json roundtrip" {
    const kp = Keypair.generate();

    const json = try keypairToJson(std.testing.allocator, &kp);
    defer std.testing.allocator.free(json);

    const loaded = try loadKeypairFromJson(json);

    try std.testing.expectEqualSlices(u8, &kp.secret, &loaded.secret);
}

test "parse solana json keypair" {
    // Example Solana keypair format (truncated for test)
    const json =
        \\[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
        \\33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]
    ;

    const kp = try loadKeypairFromJson(json);
    try std.testing.expectEqual(@as(u8, 1), kp.secret[0]);
    try std.testing.expectEqual(@as(u8, 64), kp.secret[63]);
}
