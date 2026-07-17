//! OFFLINE-VERIFY KAT: full-snapshot manifest accounts_lt_hash == archive filename suffix.
//!
//! Purpose (2026-06-22, snapshot interim hardening, task #39): GATE for arming the
//! full-only-boot lt_hash guard. The existing boot guard
//! (`bootstrap.zig:verifyBaseLtHashAgainstArchive`) only verifies the *incremental*
//! archive's filename suffix against the loaded manifest's accounts_lt_hash, and
//! warn-and-proceeds on a full-only boot. Closing that gap means applying the SAME
//! BLAKE3(manifest.accounts_lt_hash) == base58(filename-suffix) check to a
//! `snapshot-<slot>-<HASH>.tar.zst` full archive.
//!
//! Canonical justification (Agave 4.1.0-rc.1, VERIFIED from source):
//!   * snapshots/src/snapshot_hash.rs — `SnapshotHash::new(checksum)` is the SINGLE
//!     constructor for BOTH FullSnapshotHash and IncrementalSnapshotHash; the
//!     filename hash = `Hash::new_from_array(accounts_lt_hash_checksum.0)`.
//!   * lattice-hash/src/lt_hash.rs:53 — `checksum() = blake3::hash(&lattice)`
//!     (BLAKE3 of the 2048-byte lattice), matching Vexor's `Blake3.hash(&lt, ...)`.
//!   ⇒ a FULL snapshot's `snapshot-<slot>-<HASH>` suffix IS BLAKE3(accounts_lt_hash
//!     at <slot>) — identical derivation to the incremental.
//!
//! This KAT proves the remaining unknown the advisor flagged: that Vexor's
//! manifest-only forward-parse extracts a *full* manifest's accounts_lt_hash
//! byte-correctly (the incremental path is already proven live every boot). If
//! BLAKE3(Vexor-extracted full lt_hash) base58-encodes to the real archive's
//! filename suffix, the full-only guard is safe to ship ON-by-default.
//!
//! Run (env-gated — a no-op SKIP if the env vars are unset, so CI-safe):
//!   VEX_VERIFY_MANIFEST_DIR=/mnt/snapshots/vex-offline/extracted-415214213 \
//!   VEX_VERIFY_MANIFEST_SLOT=415214213 \
//!   VEX_VERIFY_MANIFEST_HASH=AmaHFXgaSRYB73eKn2oDKWRvNZKMxFo2J1bJ41BLMFiq \
//!   zig build test-manifest-lthash-verify

const std = @import("std");
const core = @import("core");
const snapshot_manifest = @import("snapshot_manifest.zig");

fn getEnv(allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
    return std.process.getEnvVarOwned(allocator, name) catch null;
}

/// Mirror of the archive-suffix scan in
/// `bootstrap.zig:verifyBaseLtHashAgainstArchive` — given a directory entry
/// `name`, a `prefix` ("snapshot-" for full, "incremental-snapshot-" for
/// incremental) and the `-<slot>-` `needle`, return the `<HASH>` suffix between
/// the needle and the `.tar.zst` extension, or null if it doesn't match. Kept
/// byte-identical to the method so this KAT guards the live algorithm.
fn extractArchiveSuffix(name: []const u8, prefix: []const u8, needle: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    if (!std.mem.endsWith(u8, name, ".tar.zst")) return null;
    const ndl_pos = std.mem.indexOf(u8, name, needle) orelse return null;
    const hs = ndl_pos + needle.len;
    const he = name.len - ".tar.zst".len;
    if (he <= hs) return null;
    return name[hs..he];
}

test "full-only-boot scan: full archive suffix extracted, incremental excluded" {
    const full_needle = "-415214213-"; // full-only boot: snapshot_slot == full slot

    // FULL archive: `snapshot-<slot>-<HASH>.tar.zst` → suffix extracted.
    const full_name = "snapshot-415214213-AmaHFXgaSRYB73eKn2oDKWRvNZKMxFo2J1bJ41BLMFiq.tar.zst";
    try std.testing.expectEqualStrings(
        "AmaHFXgaSRYB73eKn2oDKWRvNZKMxFo2J1bJ41BLMFiq",
        extractArchiveSuffix(full_name, "snapshot-", full_needle).?,
    );

    // An `incremental-snapshot-` name must NOT match the full prefix
    // ("incremental-…" does not start with "snapshot-").
    const inc_name = "incremental-snapshot-417060666-417150897-FB9WbHVVHAafFX5dV5a2w7gMpVvZNmezNf6HQRwGEitu.tar.zst";
    try std.testing.expect(extractArchiveSuffix(inc_name, "snapshot-", "-417150897-") == null);

    // The incremental name DOES match under the incremental prefix (existing path).
    try std.testing.expectEqualStrings(
        "FB9WbHVVHAafFX5dV5a2w7gMpVvZNmezNf6HQRwGEitu",
        extractArchiveSuffix(inc_name, "incremental-snapshot-", "-417150897-").?,
    );

    // Wrong slot → no match (the `-<slot>-` dashes anchor the slot field, so a
    // full archive for a DIFFERENT slot is not mistaken for this one).
    const other_full = "snapshot-415999999-2222222222222222222222222222222222222222222.tar.zst";
    try std.testing.expect(extractArchiveSuffix(other_full, "snapshot-", full_needle) == null);

    // Non-archive file → no match.
    try std.testing.expect(extractArchiveSuffix("snapshot-415214213-0b46.marker", "snapshot-", full_needle) == null);
}

test "full-snapshot manifest accounts_lt_hash BLAKE3 == archive filename suffix" {
    // ManifestResult owns several slices (vote stakes, epoch_stakes, hard_forks,
    // file_sz_map) with no single deinit(); back the parse with an arena so every
    // allocation is freed at once and the leak-checking testing allocator stays happy.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const dir = getEnv(allocator, "VEX_VERIFY_MANIFEST_DIR") orelse {
        std.debug.print("[manifest-lthash-verify] SKIP — VEX_VERIFY_MANIFEST_DIR not set\n", .{});
        return;
    };
    const slot_str = getEnv(allocator, "VEX_VERIFY_MANIFEST_SLOT") orelse {
        std.debug.print("[manifest-lthash-verify] SKIP — VEX_VERIFY_MANIFEST_SLOT not set\n", .{});
        return;
    };
    const expected_b58 = getEnv(allocator, "VEX_VERIFY_MANIFEST_HASH") orelse {
        std.debug.print("[manifest-lthash-verify] SKIP — VEX_VERIFY_MANIFEST_HASH not set\n", .{});
        return;
    };

    const slot = try std.fmt.parseInt(u64, std.mem.trim(u8, slot_str, " \t\r\n"), 10);

    // Vexor's OWN manifest-only forward-parse — the exact code path the boot
    // guard relies on (parallel_snapshot.zig:831 `m.accounts_lt_hash`). The arena
    // owns every allocation it makes.
    const m = try snapshot_manifest.parseManifest(allocator, dir, slot);

    const lt = m.accounts_lt_hash orelse {
        std.debug.print("[manifest-lthash-verify] ❌ FAIL — manifest has NO accounts_lt_hash (slot {d})\n", .{slot});
        return error.NoLtHashInManifest;
    };

    // BLAKE3 of the 2048-byte lattice — the canonical checksum that names the archive.
    var checksum: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&lt, &checksum, .{});

    const actual_b58 = try core.base58.encode(allocator, &checksum);
    defer allocator.free(actual_b58);

    const want = std.mem.trim(u8, expected_b58, " \t\r\n");
    std.debug.print(
        "[manifest-lthash-verify] slot={d}\n  expected (archive suffix): {s}\n  actual   (BLAKE3 of lt) : {s}\n",
        .{ slot, want, actual_b58 },
    );

    if (!std.mem.eql(u8, actual_b58, want)) {
        std.debug.print("[manifest-lthash-verify] ❌ MISMATCH — full-only guard NOT safe to arm on-by-default\n", .{});
        return error.LtHashChecksumMismatch;
    }
    std.debug.print("[manifest-lthash-verify] ✅ MATCH — Vexor's full-manifest lt_hash extraction is byte-correct; full-only guard safe\n", .{});
}
