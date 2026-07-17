//! KAT — Hard-Fork Family (F1 parse + F2 bank-hash mixin + F3 LastRestartSlot).
//!
//! Gates HARD-FORK-FAMILY-DESIGN-2026-06-17 (canonical vs Agave rc.0, crate
//! solana-hard-forks 3.1.0 + solana-sha256-hasher 3.1.0). Both F2 (mixin) and
//! F3 (LastRestartSlot) are DORMANT on post-restart testnet — a green 8/0 soak
//! validates NOTHING about their correctness (the design doc's explicit
//! warning). Correctness rests ENTIRELY on the firing vectors below.
//!
//! Coverage:
//!   F1  — parseHardForksForTest captures [(415524281,1)] exactly AND the byte
//!         cursor advances 8 + len*16 (the parity-critical "no manifest shift"
//!         invariant; the deleted skipHardForks consumed the same count).
//!         Also: empty list (len=0 → 8 bytes), multi-fork, garbage-len fallback.
//!   F2  — Bank.getHashData unit vectors (the 6 crate vectors, forks at 10 & 20)
//!         + the mixin vector: computeBankHash(..., Some(buf)) == sha256(base‖buf)
//!         and computeBankHash(..., null) == base (NO Step 3).
//!   F3  — FIRING: synthetic list with fork F, slot ≥ F, parent_slot < F →
//!         getHashData != null AND computeLastRestartSlot == highest fork ≤ slot.
//!         DORMANT: parent_slot ≥ F → getHashData == null (preserve path).
//!
//! Run: zig build test-hard-fork
//! Optional live check: VEX_HARDFORK_SNAPSHOT_DIR=<dir> VEX_HARDFORK_SLOT=<slot>
//!   asserts the real post-restart snapshot manifest parses to a non-empty
//!   list containing the 2026-06-15 restart fork 415524281. Skips trivially
//!   when the env vars are absent (so `zig build test-hard-fork` stays green).

const std = @import("std");
const vex_svm = @import("vex_svm");
const vex_store = @import("vex_store");

const bank = vex_svm.bank;
const Bank = bank.Bank; // getHashData / computeBankHash / computeLastRestartSlot are Bank methods
const Hash = vex_svm.Hash;
const HardFork = bank.HardFork;
const LtHash = @import("vex_crypto").LtHash;
const snapshot_manifest = vex_store.snapshot_manifest;

const RESTART_FORK_SLOT: u64 = 415_524_281; // 2026-06-15 testnet restart

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a raw `hard_forks` blob: 8-byte LE len, then len × (u64 slot, u64
/// count) LE. Mirrors Agave's bincode `Vec<(u64, u64)>` exactly.
fn buildHardForksBlob(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, forks: []const HardFork) !void {
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, forks.len, .little);
    try buf.appendSlice(allocator, &len_le);
    for (forks) |hf| {
        var slot_le: [8]u8 = undefined;
        var count_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &slot_le, hf.slot, .little);
        std.mem.writeInt(u64, &count_le, hf.count, .little);
        try buf.appendSlice(allocator, &slot_le);
        try buf.appendSlice(allocator, &count_le);
    }
}

// ── F1: parse + byte-consumption (the parity-critical invariant) ───────────────

test "F1 parseHardForks: single fork captured + cursor advances 8 + 1*16" {
    const a = std.testing.allocator;
    var blob = std.ArrayList(u8){};
    defer blob.deinit(a);
    try buildHardForksBlob(&blob, a, &[_]HardFork{.{ .slot = RESTART_FORK_SLOT, .count = 1 }});

    const r = try snapshot_manifest.parseHardForksForTest(a, blob.items);
    defer a.free(@constCast(r.forks));

    try std.testing.expectEqual(@as(usize, 1), r.forks.len);
    try std.testing.expectEqual(RESTART_FORK_SLOT, r.forks[0].slot);
    try std.testing.expectEqual(@as(u64, 1), r.forks[0].count);
    // The decisive parity assertion: identical byte consumption to skipHardForks.
    try std.testing.expectEqual(@as(usize, 8 + 1 * 16), r.consumed);
    try std.testing.expectEqual(blob.items.len, r.consumed);
}

test "F1 parseHardForks: empty list consumes exactly the 8-byte length" {
    const a = std.testing.allocator;
    var blob = std.ArrayList(u8){};
    defer blob.deinit(a);
    try buildHardForksBlob(&blob, a, &[_]HardFork{});

    const r = try snapshot_manifest.parseHardForksForTest(a, blob.items);
    // empty → returns a static empty slice; nothing to free.
    try std.testing.expectEqual(@as(usize, 0), r.forks.len);
    try std.testing.expectEqual(@as(usize, 8), r.consumed);
}

test "F1 parseHardForks: multi-fork captured in order + cursor 8 + 3*16" {
    const a = std.testing.allocator;
    const forks = [_]HardFork{
        .{ .slot = 100, .count = 1 },
        .{ .slot = 200, .count = 2 },
        .{ .slot = RESTART_FORK_SLOT, .count = 1 },
    };
    var blob = std.ArrayList(u8){};
    defer blob.deinit(a);
    try buildHardForksBlob(&blob, a, &forks);
    // A trailing sentinel: parseHardForks must STOP at 8+3*16, never read it.
    try blob.appendSlice(a, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD });

    const r = try snapshot_manifest.parseHardForksForTest(a, blob.items);
    defer a.free(@constCast(r.forks));

    try std.testing.expectEqual(@as(usize, 3), r.forks.len);
    try std.testing.expectEqual(@as(u64, 100), r.forks[0].slot);
    try std.testing.expectEqual(@as(u64, 2), r.forks[1].count);
    try std.testing.expectEqual(RESTART_FORK_SLOT, r.forks[2].slot);
    try std.testing.expectEqual(@as(usize, 8 + 3 * 16), r.consumed); // sentinel untouched
}

test "F1 parseHardForks: truncated body → MalformedManifest (graceful fallback)" {
    const a = std.testing.allocator;
    // len says 1 fork (16 bytes) but only 8 bytes of body follow.
    var blob = std.ArrayList(u8){};
    defer blob.deinit(a);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 1, .little);
    try blob.appendSlice(a, &len_le);
    try blob.appendSlice(a, &[_]u8{0} ** 8); // only the slot u64, missing count u64
    try std.testing.expectError(error.MalformedManifest, snapshot_manifest.parseHardForksForTest(a, blob.items));
}

// ── F2: getHashData unit vectors (crate tests, forks at 10 & 20) ───────────────

test "F2 getHashData: the six canonical crate vectors (forks at 10 & 20)" {
    const forks = [_]HardFork{ .{ .slot = 10, .count = 1 }, .{ .slot = 20, .count = 1 } };

    const one_le = std.mem.toBytes(@as(u64, 1));
    const two_le = std.mem.toBytes(@as(u64, 2));

    // (9,0)=None — no fork in (0,9]
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&forks, 9, 0));
    // (10,0)=Some([1,0..]) — fork@10 in (0,10]
    try std.testing.expectEqual(@as(?[8]u8, one_le), Bank.getHashData(&forks, 10, 0));
    // (19,0)=Some([1..]) — only fork@10 counted
    try std.testing.expectEqual(@as(?[8]u8, one_le), Bank.getHashData(&forks, 19, 0));
    // (20,0)=Some([2,0..]) — BOTH forks counted
    try std.testing.expectEqual(@as(?[8]u8, two_le), Bank.getHashData(&forks, 20, 0));
    // (20,10)=Some([1..]) — parent_slot 10 excludes fork@10, includes fork@20
    try std.testing.expectEqual(@as(?[8]u8, one_le), Bank.getHashData(&forks, 20, 10));
    // (21,20)=None — both forks ≤ parent_slot 20
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&forks, 21, 20));
}

test "F2 getHashData: empty list always None" {
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&[_]HardFork{}, 1_000_000, 0));
}

test "F2 getHashData: count>1 fork yields that count LE" {
    const forks = [_]HardFork{.{ .slot = 50, .count = 7 }};
    try std.testing.expectEqual(@as(?[8]u8, std.mem.toBytes(@as(u64, 7))), Bank.getHashData(&forks, 50, 49));
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&forks, 50, 50)); // parent==fork excludes
}

// ── F2: bank-hash mixin (Step 3 == sha256(base ‖ buf); null == base) ───────────

test "F2 computeBankHash: Some(buf) folds Step 3 == sha256(base ‖ buf); null == base" {
    // Distinctive, non-zero inputs so a dropped/mis-ordered field would change bytes.
    var lt = LtHash.init();
    for (0..1024) |i| lt.elements[i] = @intCast((i * 31 + 7) & 0xFFFF);
    const prev = Hash.init([_]u8{0x11} ** 32);
    const poh = Hash.init([_]u8{0x22} ** 32);
    const sigs: u64 = 12345;

    // base = Steps 1-2 only (null buf → no Step 3).
    const base = Bank.computeBankHash(&lt, &prev, &poh, sigs, null);

    // Independently recompute the base from first principles (Steps 1-2) so the
    // mixin assertion does not circularly depend on computeBankHash itself.
    var s1 = std.crypto.hash.sha2.Sha256.init(.{});
    s1.update(&prev.data);
    var sig_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sig_le, sigs, .little);
    s1.update(&sig_le);
    s1.update(&poh.data);
    var step1: [32]u8 = undefined;
    s1.final(&step1);
    var s2 = std.crypto.hash.sha2.Sha256.init(.{});
    s2.update(&step1);
    var lt_bytes: [2048]u8 = undefined;
    for (0..1024) |i| std.mem.writeInt(u16, lt_bytes[i * 2 ..][0..2], lt.elements[i], .little);
    s2.update(&lt_bytes);
    var base_expected: [32]u8 = undefined;
    s2.final(&base_expected);
    try std.testing.expectEqualSlices(u8, &base_expected, &base.data);

    // Mixin: buf = [1,0,0,0,0,0,0,0] (a single fork's count=1). Expected =
    // sha256(base ‖ buf).
    const buf: [8]u8 = std.mem.toBytes(@as(u64, 1));
    var s3 = std.crypto.hash.sha2.Sha256.init(.{});
    s3.update(&base_expected);
    s3.update(&buf);
    var mix_expected: [32]u8 = undefined;
    s3.final(&mix_expected);

    const mixed = Bank.computeBankHash(&lt, &prev, &poh, sigs, buf);
    try std.testing.expectEqualSlices(u8, &mix_expected, &mixed.data);
    // And the mixin MUST change the hash (Step 3 actually fired).
    try std.testing.expect(!std.mem.eql(u8, &base.data, &mixed.data));
}

test "F2 mixin via getHashData: at fork slot mixes; at fork+1 (parent=fork) does not" {
    const F: u64 = RESTART_FORK_SLOT;
    const forks = [_]HardFork{.{ .slot = F, .count = 1 }};
    var lt = LtHash.init();
    lt.elements[0] = 0xBEEF;
    const prev = Hash.init([_]u8{0x33} ** 32);
    const poh = Hash.init([_]u8{0x44} ** 32);
    const sigs: u64 = 9;

    // Replaying the fork slot itself (parent F-1 < F ≤ slot F) → Some → mixed.
    const buf_at_fork = Bank.getHashData(&forks, F, F - 1);
    try std.testing.expect(buf_at_fork != null);
    const at_fork = Bank.computeBankHash(&lt, &prev, &poh, sigs, buf_at_fork);

    // The next slot (parent F ≥ F) → None → base (DORMANT, the testnet case).
    const buf_after = Bank.getHashData(&forks, F + 1, F);
    try std.testing.expectEqual(@as(?[8]u8, null), buf_after);
    const after = Bank.computeBankHash(&lt, &prev, &poh, sigs, buf_after);
    const base = Bank.computeBankHash(&lt, &prev, &poh, sigs, null);
    try std.testing.expectEqualSlices(u8, &base.data, &after.data); // no Step 3
    try std.testing.expect(!std.mem.eql(u8, &at_fork.data, &after.data)); // fork slot differs
}

// ── F3: LastRestartSlot value (firing + dormant) ───────────────────────────────

test "F3 FIRING: fork crossed (parent,slot] → getHashData Some AND highest fork ≤ slot" {
    // Forks at 10 and F; bank slot ≥ F, parent_slot < F → a fork crossed.
    const F: u64 = RESTART_FORK_SLOT;
    const forks = [_]HardFork{ .{ .slot = 10, .count = 1 }, .{ .slot = F, .count = 1 } };

    // At slot F, parent F-1: getHashData fires AND last_restart_slot = F.
    try std.testing.expect(Bank.getHashData(&forks, F, F - 1) != null);
    try std.testing.expectEqual(F, Bank.computeLastRestartSlot(&forks, F));

    // At a slot well past F (parent also past F, no new crossing): DORMANT, but
    // the value (highest fork ≤ slot) is still F — proving the value computation
    // is independent of the firing condition.
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&forks, F + 100, F + 99));
    try std.testing.expectEqual(F, Bank.computeLastRestartSlot(&forks, F + 100));

    // Below the first fork: highest fork ≤ slot is 0.
    try std.testing.expectEqual(@as(u64, 0), Bank.computeLastRestartSlot(&forks, 9));
    // Between the two forks: highest fork ≤ slot is 10.
    try std.testing.expectEqual(@as(u64, 10), Bank.computeLastRestartSlot(&forks, 11));
}

test "F3 computeLastRestartSlot: max-scan does not assume sorted input" {
    // Deliberately UNSORTED to prove the helper is a max-scan, not last-wins.
    const forks = [_]HardFork{ .{ .slot = 500, .count = 1 }, .{ .slot = 100, .count = 1 }, .{ .slot = 300, .count = 1 } };
    try std.testing.expectEqual(@as(u64, 500), Bank.computeLastRestartSlot(&forks, 1000));
    try std.testing.expectEqual(@as(u64, 300), Bank.computeLastRestartSlot(&forks, 499));
    try std.testing.expectEqual(@as(u64, 100), Bank.computeLastRestartSlot(&forks, 299));
    try std.testing.expectEqual(@as(u64, 0), Bank.computeLastRestartSlot(&forks, 99));
}

test "F3 DORMANT: empty list → None (preserve path, no write) at any slot" {
    try std.testing.expectEqual(@as(?[8]u8, null), Bank.getHashData(&[_]HardFork{}, RESTART_FORK_SLOT, RESTART_FORK_SLOT - 1));
    try std.testing.expectEqual(@as(u64, 0), Bank.computeLastRestartSlot(&[_]HardFork{}, RESTART_FORK_SLOT));
}

test "F3 invariant: getHashData==Some ⟺ computeLastRestartSlot strictly rises from parent" {
    // The F3 fail-closed correctness invariant (design doc): a fork in
    // (parent, slot] ⟺ the LRS value changed. Sweep a small grid.
    const forks = [_]HardFork{ .{ .slot = 10, .count = 1 }, .{ .slot = 20, .count = 1 } };
    const slots = [_]u64{ 5, 9, 10, 11, 19, 20, 21, 30 };
    for (slots) |slot| {
        var parent: u64 = 0;
        while (parent <= slot) : (parent += 1) {
            const fired = Bank.getHashData(&forks, slot, parent) != null;
            const lrs_slot = Bank.computeLastRestartSlot(&forks, slot);
            const lrs_parent = Bank.computeLastRestartSlot(&forks, parent);
            // Some ⟺ value changed from parent.
            try std.testing.expectEqual(fired, lrs_slot != lrs_parent);
        }
    }
}

// ── F1 live snapshot check (env-gated; skips trivially without the asset) ───────

test "F1 live: real snapshot — hard_forks contains 415524281 AND downstream fields stay aligned" {
    // Uses an ArenaAllocator so this test asserts PARSE-correctness, not
    // free-correctness — the manifest owns many nested slices and a hand-rolled
    // teardown would be a fragile harness artifact, not an F1 signal (advisor).
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const dir = std.process.getEnvVarOwned(a, "VEX_HARDFORK_SNAPSHOT_DIR") catch return; // skip
    const slot_str = std.process.getEnvVarOwned(a, "VEX_HARDFORK_SLOT") catch return; // skip
    const slot = std.fmt.parseInt(u64, std.mem.trim(u8, slot_str, " \t\r\n"), 10) catch return;

    const m = try snapshot_manifest.parseManifest(a, dir, slot);

    // (1) the hard-fork list captured the 2026-06-15 restart fork.
    try std.testing.expect(m.hard_forks.len > 0);
    var found = false;
    for (m.hard_forks) |hf| {
        if (hf.slot == RESTART_FORK_SLOT) found = true;
    }
    try std.testing.expect(found);

    // (2) THE decisive end-to-end "no manifest shift" proof on REAL data: fields
    // read AFTER hard_forks (hashes_per_tick @ snapshot_manifest line 517,
    // ticks_per_slot @ 518) must still hold their known live testnet values. If
    // parseHardForks miscounted by even one byte, these go garbage. (bank_hash is
    // read BEFORE hard_forks so it cannot catch a shift — these can.)
    try std.testing.expectEqual(@as(?u64, 62500), m.hashes_per_tick);
    try std.testing.expectEqual(@as(u64, 64), m.ticks_per_slot);

    std.debug.print("[F1-LIVE] snapshot slot {d}: {d} hard fork(s), contains 415524281={}, hashes_per_tick={?d} ticks_per_slot={d} — downstream ALIGNED\n", .{ slot, m.hard_forks.len, found, m.hashes_per_tick, m.ticks_per_slot });
}
