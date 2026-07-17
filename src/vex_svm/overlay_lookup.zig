//! overlay_lookup.zig — newest-first write-overlay lookup for parallel tx execution.
//!
//! Stage B (parallel-exec) / B2a. See VEXOR-PARALLEL-EXEC-PORT-PLAN-2026-06-22.md.
//!
//! WHY THIS EXISTS
//! ───────────────
//! Executors read account pre-state by scanning the bank's pending-write list
//! NEWEST-FIRST for a key (e.g. executeSystemInstruction, replay_stage.zig:10966).
//! This is how intra-tx read-after-write works in the SERIAL path: instruction 1's
//! write lands in `bank.pending_writes`, instruction 2's scan finds it.
//!
//! In the WAVE-parallel path (B2c) a worker's writes go to its OWN buffer
//! (`bank_mod.worker_writes_override`), NOT `bank.pending_writes` — so a later
//! instruction of the same tx must scan the worker buffer FIRST, then pending_writes.
//! The DAG guarantees (tx_dispatcher addEdges Case-3 W-R + Step-4) that within a wave
//! no tx reads an account another wave-member writes, so a worker only ever needs its
//! OWN buffer + committed pending_writes — never another worker's buffer.
//!
//! This module is the testable CORE of that lookup. `Bank.overlayNewest` (bank.zig)
//! is a thin wrapper: scans worker_writes_override (if set) then pending_writes and
//! returns the newest matching write ENTRY POINTER. Callers keep their own field-read
//! + copy/lifetime logic unchanged (we return a pointer, not a flattened copy — the
//! nonce site's double-copy carrier must NOT be regressed). When the override is null
//! the result is byte-identical to the inline pending-only scans executors do today.

const std = @import("std");

/// Newest-first scan of a single write list for `key`. Returns a pointer to the
/// most-recent entry whose `pubkey.data` equals `key`, or null. Generic over any
/// element type W exposing `pubkey.data: [32]u8` (the real caller passes
/// bank_mod.AccountWrite). Pointer is valid only until the list is next mutated —
/// callers read/copy immediately (before any collectWrite), exactly as the inline
/// scans do today.
pub fn newestMatch(comptime W: type, list: []const W, key: *const [32]u8) ?*const W {
    var i: usize = list.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, &list[i].pubkey.data, key)) return &list[i];
    }
    return null;
}

/// Two-tier newest-first lookup with `primary` shadowing `secondary`: scans
/// `primary` newest-first (the worker's own write buffer in the parallel path),
/// then `secondary` newest-first (committed pending_writes). In the SERIAL path the
/// caller passes an EMPTY primary, so this reduces exactly to a pending-only scan.
pub fn newestMatchTwo(
    comptime W: type,
    primary: []const W,
    secondary: []const W,
    key: *const [32]u8,
) ?*const W {
    if (newestMatch(W, primary, key)) |w| return w;
    return newestMatch(W, secondary, key);
}

// ─────────────────────────────────────────────────────────────────────────────
// KAT — standalone (no bank). Build: test-overlay-lookup.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

const TestKey = struct { data: [32]u8 };
const TestWrite = struct { pubkey: TestKey, lamports: u64 };

fn k(b: u8) [32]u8 {
    var key = [_]u8{0} ** 32;
    key[0] = b;
    return key;
}

test "overlay_lookup: newestMatch finds the LAST matching entry (newest-first)" {
    const list = [_]TestWrite{
        .{ .pubkey = .{ .data = k(1) }, .lamports = 100 },
        .{ .pubkey = .{ .data = k(2) }, .lamports = 200 },
        .{ .pubkey = .{ .data = k(1) }, .lamports = 300 }, // newer write to key 1
    };
    const key1 = k(1);
    const hit = newestMatch(TestWrite, &list, &key1).?;
    try testing.expectEqual(@as(u64, 300), hit.lamports); // newest, not 100
    const key2 = k(2);
    try testing.expectEqual(@as(u64, 200), newestMatch(TestWrite, &list, &key2).?.lamports);
    const key9 = k(9);
    try testing.expect(newestMatch(TestWrite, &list, &key9) == null);
}

test "overlay_lookup: empty list returns null (no hang, no crash)" {
    const empty = [_]TestWrite{};
    const key1 = k(1);
    try testing.expect(newestMatch(TestWrite, &empty, &key1) == null);
    try testing.expect(newestMatchTwo(TestWrite, &empty, &empty, &key1) == null);
}

test "overlay_lookup: primary SHADOWS secondary (parallel-path precedence)" {
    // secondary = committed pending_writes (key1 -> 100); primary = worker buffer
    // (key1 -> 999, a later in-tx write). primary must win.
    const secondary = [_]TestWrite{.{ .pubkey = .{ .data = k(1) }, .lamports = 100 }};
    const primary = [_]TestWrite{.{ .pubkey = .{ .data = k(1) }, .lamports = 999 }};
    const key1 = k(1);
    try testing.expectEqual(@as(u64, 999), newestMatchTwo(TestWrite, &primary, &secondary, &key1).?.lamports);
}

test "overlay_lookup: empty primary reduces to secondary-only (SERIAL path == today)" {
    // The serial path passes an empty primary; result must equal a pending-only scan.
    const empty = [_]TestWrite{};
    const secondary = [_]TestWrite{
        .{ .pubkey = .{ .data = k(5) }, .lamports = 50 },
        .{ .pubkey = .{ .data = k(5) }, .lamports = 55 },
    };
    const key5 = k(5);
    const via_two = newestMatchTwo(TestWrite, &empty, &secondary, &key5).?;
    const via_one = newestMatch(TestWrite, &secondary, &key5).?;
    try testing.expectEqual(via_one.lamports, via_two.lamports);
    try testing.expectEqual(@as(u64, 55), via_two.lamports);
}

test "overlay_lookup: primary miss falls through to secondary" {
    const primary = [_]TestWrite{.{ .pubkey = .{ .data = k(7) }, .lamports = 7 }};
    const secondary = [_]TestWrite{.{ .pubkey = .{ .data = k(3) }, .lamports = 33 }};
    const key3 = k(3);
    try testing.expectEqual(@as(u64, 33), newestMatchTwo(TestWrite, &primary, &secondary, &key3).?.lamports);
}
