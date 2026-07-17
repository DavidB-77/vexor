//! Base58 Encoding/Decoding (Bitcoin style)
//! Used for Solana addresses (Public Keys) and signatures.

const std = @import("std");

pub const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode data to Base58 string
pub fn encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    // Count leading zeros
    var leading_zeros: usize = 0;
    for (data) |byte| {
        if (byte != 0) break;
        leading_zeros += 1;
    }

    // Convert to big integer representation
    // Size estimate: log(256) / log(58) approx 1.37
    // For 32 bytes (Pubkey) -> ~44 chars
    // For 64 bytes (Signature) -> ~88 chars
    // We'll allocate a sufficient buffer for calculation
    const capacity = data.len * 2;
    var num = try allocator.alloc(u8, capacity);
    defer allocator.free(num);
    @memset(num, 0);

    var num_len: usize = 0;

    for (data) |byte| {
        var carry: u16 = byte;
        var i: usize = 0;

        // Apply "bignum" math: multiply by 256 and add new byte
        while (i < num_len or carry != 0) : (i += 1) {
            if (i < num_len) {
                carry += @as(u16, num[i]) * 256;
            }
            if (i < capacity) {
                num[i] = @intCast(carry % 58);
            }
            carry /= 58;
            if (i >= num_len) num_len = i + 1;
        }
    }

    // Build result string
    var result = try allocator.alloc(u8, leading_zeros + num_len);
    errdefer allocator.free(result);

    // Add leading '1's for leading zero bytes
    for (0..leading_zeros) |i| {
        result[i] = '1';
    }

    // Add base58 digits in reverse (num is little-endian base58 digits)
    for (0..num_len) |i| {
        result[leading_zeros + i] = alphabet[num[num_len - 1 - i]];
    }

    return result;
}

/// Encode into existing buffer.
/// Returns slice of the buffer used.
/// Buffer must be large enough.
pub fn encodeToBuf(data: []const u8, buf: []u8) ![]u8 {
    // Same logic but no allocator
    // This is tricky without temp buffer for bignum math.
    // However, types.zig uses `std.base58.Encoder.encode(buf, &self.data)`
    // We can implement a version that uses a fixed size temp buffer on stack if size is small (like Pubkey/Hash)

    // Max pubkey/hash size is 32 bytes.
    if (data.len > 64) return error.DataTooLarge; // Stack safety

    var num: [128]u8 = undefined; // Enough for 64 bytes input -> ~88 chars output
    var num_len: usize = 0;

    var leading_zeros: usize = 0;
    for (data) |byte| {
        if (byte != 0) break;
        leading_zeros += 1;
    }

    for (data) |byte| {
        var carry: u16 = byte;
        var i: usize = 0;
        while (i < num_len or carry != 0) : (i += 1) {
            if (i < num_len) {
                carry += @as(u16, num[i]) * 256;
            }
            num[i] = @intCast(carry % 58);
            carry /= 58;
            if (i >= num_len) num_len = i + 1;
        }
    }

    const total_len = leading_zeros + num_len;
    if (buf.len < total_len) return error.BufferTooSmall;

    for (0..leading_zeros) |i| {
        buf[i] = '1';
    }
    for (0..num_len) |i| {
        buf[leading_zeros + i] = alphabet[num[num_len - 1 - i]];
    }

    return buf[0..total_len];
}

/// Decode Base58 string to bytes
pub fn decode(allocator: std.mem.Allocator, base58_str: []const u8) ![]u8 {
    // Estimate size: log(58)/log(256) approx 0.73
    const capacity = base58_str.len;
    var bytes = try allocator.alloc(u8, capacity);
    errdefer allocator.free(bytes);

    var bytes_len: usize = 0;

    for (base58_str) |c| {
        const digit = std.mem.indexOf(u8, alphabet, &[_]u8{c}) orelse return error.InvalidBase58Char;

        var carry: u32 = @intCast(digit);
        var idx: usize = 0;

        // Multiply by 58, add digit
        while (idx < bytes_len or carry != 0) : (idx += 1) {
            if (idx < bytes_len) {
                carry += @as(u32, bytes[idx]) * 58;
            }
            if (idx < capacity) {
                bytes[idx] = @intCast(carry & 0xFF);
                if (idx >= bytes_len) bytes_len = idx + 1;
            }
            carry >>= 8;
        }
    }

    // Handle leading '1's
    var leading_ones: usize = 0;
    for (base58_str) |c| {
        if (c != '1') break;
        leading_ones += 1;
    }

    const total_len = leading_ones + bytes_len;

    // Result needs to be reversed (bytes is little-endian accumulator)
    // AND we need to handle the leading zeros.
    var result = try allocator.alloc(u8, total_len);

    @memset(result[0..leading_ones], 0);

    for (0..bytes_len) |i| {
        result[leading_ones + i] = bytes[bytes_len - 1 - i];
    }

    allocator.free(bytes);
    return result;
}

/// Decode to existing fixed-size array (like Pubkey.data)
/// Puts result at END of array if it's smaller?
/// Solana Pubkey decoding expects specific 32 byte output.
pub fn decodeToBuf(base58_str: []const u8, buf: []u8) !void {
    // Similar logic but specifically filling buf
    // Note: Keypair.zig logic was: "copy resulting bytes to end of buffer" to match 32 byte pubkey layout?

    // Let's implement a generic decode that fills a buffer.
    // For fixed size targets like 32-byte pubkeys, we usually want exact fit or padding.

    // Using a temp buffer for calculation
    var bytes: [128]u8 = undefined;
    var bytes_len: usize = 0;

    for (base58_str) |c| {
        const digit = std.mem.indexOf(u8, alphabet, &[_]u8{c}) orelse return error.InvalidBase58Char;
        var carry: u32 = @intCast(digit);
        var idx: usize = 0;
        while (idx < bytes_len or carry != 0) : (idx += 1) {
            if (idx < bytes_len) {
                carry += @as(u32, bytes[idx]) * 58;
            }
            bytes[idx] = @intCast(carry & 0xFF);
            if (idx >= bytes_len) bytes_len = idx + 1;
            carry >>= 8;
        }
    }

    var leading_ones: usize = 0;
    for (base58_str) |c| {
        if (c != '1') break;
        leading_ones += 1;
    }

    const total_len = leading_ones + bytes_len;
    if (total_len > buf.len) return error.BufferTooSmall;

    // Zero fill entire buffer first
    @memset(buf, 0);

    // Logic from keypair.zig:
    // const copy_start = 32 - bytes_len;
    // result.data[copy_start + i] = bytes[bytes_len - 1 - i];
    // This implies right-aligning the bytes in the buffer.

    const start_idx = buf.len - bytes_len;
    for (0..bytes_len) |i| {
        buf[start_idx + i] = bytes[bytes_len - 1 - i];
    }

    // Ensure leading ones (zeros) are respected if buffer is larger?
    // Actually right-aligning naturally handles it if the buffer is zeroed.
}

test "base58 encode" {
    const data = "Hello World";
    const encoded = try encode(std.testing.allocator, data);
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("JxF12TrwUP45BMd", encoded);
}
