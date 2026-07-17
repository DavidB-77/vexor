//! version.zig — single source of truth for Vexor's client identity.
//!
//! WHY THIS EXISTS (2026-07-10): Vexor advertised the DEFAULT client id in its
//! gossip ContactInfo (bincode.zig ContactInfo.initSelf: version 2.2.0,
//! commit=0, feature_set=0, version_client=0). Agave's client-id registry
//! (agave-4.2.0-beta.0-src/version/src/client_ids.rs) maps 0 → SolanaLabs, so
//! every explorer showed us as "Solana Labs 2.2.0". This module carries the
//! honest identity, consumed by BOTH the gossip self-advertisement (bincode.zig
//! / gossip.zig) and the metrics reporter boot announce (metrics_reporter.zig
//! via main.zig).
//!
//! CLIENT_ID = 86 ('V') is deliberately UNREGISTERED in Agave's registry
//! (0=SolanaLabs 1=JitoLabs 2=Frankendancer 3=Agave 4=AgavePaladin
//! 5=Firedancer 6=AgaveBam 7=Sig), so tooling renders Unknown(86) — honest,
//! unlike falsely claiming SolanaLabs.
//!
//! VEXOR_VERSION 0.9.0 = deliberate pre-production semver (operator decision).

const std = @import("std");

pub const VEXOR_VERSION = .{ .major = 0, .minor = 9, .patch = 0 };

/// @prov:version.client-id — 'V', unregistered ⇒ renders Unknown(86).
pub const CLIENT_ID: u16 = 86;

pub const SEMVER = std.fmt.comptimePrint("{d}.{d}.{d}", .{
    VEXOR_VERSION.major, VEXOR_VERSION.minor, VEXOR_VERSION.patch,
});

/// Wire `commit` u32 for the gossip ContactInfo version block. Set ONCE at boot
/// (main.zig, single-threaded, before gossip init) from the build-stamped git
/// hash; read-only afterwards.
pub var commit_u32: u32 = 0;

/// Stored git short-hash for version strings (set with commit_u32).
var git_hash_buf: [40]u8 = [_]u8{0} ** 40;
var git_hash_len: usize = 0;

/// @prov:version.commit-hash — parse the leading hex of a git hash into a u32:
/// first 8 hex chars, base 16. Short hashes (<8 chars) use what's there; any
/// non-hex input → 0 (never fails).
pub fn commitU32FromGitHash(hash: []const u8) u32 {
    const n = @min(hash.len, 8);
    if (n == 0) return 0;
    return std.fmt.parseInt(u32, hash[0..n], 16) catch 0;
}

pub fn setGitHash(hash: []const u8) void {
    commit_u32 = commitU32FromGitHash(hash);
    const n = @min(hash.len, git_hash_buf.len);
    @memcpy(git_hash_buf[0..n], hash[0..n]);
    git_hash_len = n;
}

pub fn gitHash() []const u8 {
    return if (git_hash_len > 0) git_hash_buf[0..git_hash_len] else "unknown";
}

/// "vexor-0.9.0 (src:<git-short-hash>; client:Vexor)"
pub fn buildVersionString(buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "vexor-{s} (src:{s}; client:Vexor)", .{ SEMVER, gitHash() }) catch "vexor-" ++ SEMVER;
}

test "semver string" {
    try std.testing.expectEqualStrings("0.9.0", SEMVER);
    try std.testing.expectEqual(@as(u16, 86), CLIENT_ID);
    try std.testing.expectEqual(@as(u16, 0), @as(u16, VEXOR_VERSION.major));
    try std.testing.expectEqual(@as(u16, 9), @as(u16, VEXOR_VERSION.minor));
    try std.testing.expectEqual(@as(u16, 0), @as(u16, VEXOR_VERSION.patch));
}

test "commit u32 from git hash" {
    try std.testing.expectEqual(@as(u32, 0xd2ae404), commitU32FromGitHash("d2ae404")); // 7-char short hash
    try std.testing.expectEqual(@as(u32, 0x3c63bbd2), commitU32FromGitHash("3c63bbd20ce6cfb2")); // full → first 8
    try std.testing.expectEqual(@as(u32, 0), commitU32FromGitHash("")); // empty
    try std.testing.expectEqual(@as(u32, 0), commitU32FromGitHash("unknown")); // non-hex
}

test "version string builder" {
    setGitHash("abc1234");
    var buf: [128]u8 = undefined;
    const s = buildVersionString(&buf);
    try std.testing.expectEqualStrings("vexor-0.9.0 (src:abc1234; client:Vexor)", s);
    try std.testing.expectEqual(@as(u32, 0xabc1234), commit_u32);
    // reset global state for other tests
    commit_u32 = 0;
    git_hash_len = 0;
}

test "version string with no git hash set" {
    var buf: [128]u8 = undefined;
    const s = buildVersionString(&buf);
    try std.testing.expectEqualStrings("vexor-0.9.0 (src:unknown; client:Vexor)", s);
}
