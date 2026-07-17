//! KAT for the canonical block tick-validity Verifier (verify_ticks.zig).
//!
//! Tests the EXACT code the live replay path runs (replay_stage.zig drives the
//! same `verify_ticks_mod.Verifier`), across all three levels + the alpenglow
//! skip semantics. Each case feeds a synthetic entry stream of (num_hashes,
//! is_tick) pairs into a Verifier and asserts the dead/pass outcome.
//!
//! Run:  zig build test-verify-ticks
//!
//! Canonical references mirrored:
//!   FD   src/discof/replay/fd_sched.c:1976-2020 (verify_ticks_eager/final),
//!        2166-2180 (per-tick hash accounting).
//!   Agave entry/src/entry.rs:675-698 (verify_tick_hash_count, rc.1 zero-hash),
//!        ledger/src/blockstore_processor.rs:1085-1101.

const std = @import("std");
const vt = @import("verify_ticks.zig");

const HPT: u64 = 62500; // effective testnet hashes_per_tick
const TPS: u64 = 64; // DEFAULT_TICKS_PER_SLOT

/// A synthetic entry: num_hashes + whether it is a tick (num_txs==0).
const Entry = struct { num_hashes: u64, is_tick: bool };

/// Drive a Verifier through an entry stream and return the resulting verdict.
/// Stops at the first dead verdict (mirrors the live path's early abort), then
/// runs onSlotEnd if no eager check fired.
fn run(level: vt.Level, hashes_per_tick: u64, parent_slot: u64, slot: u64, entries: []const Entry) vt.Verdict {
    var v = vt.Verifier.init(level, hashes_per_tick, parent_slot, slot, TPS);
    for (entries) |e| {
        const verdict = v.onEntry(e.num_hashes, e.is_tick);
        if (verdict.isDead()) return verdict;
    }
    return v.onSlotEnd();
}

/// Build a well-formed slot: `n_ticks` tick entries each with `hpt` hashes,
/// optionally preceded by a non-tick microblock carrying `lead_hashes` hashes
/// in the FIRST tick's window (so the first tick's cumulative hashcnt == hpt).
/// For the canonical empty-block shape we just emit n_ticks ticks each = hpt.
fn wellFormed(buf: []Entry, n_ticks: usize, hpt: u64) []Entry {
    std.debug.assert(buf.len >= n_ticks);
    for (0..n_ticks) |i| buf[i] = .{ .num_hashes = hpt, .is_tick = true };
    return buf[0..n_ticks];
}

// ════════════════════════════ zerohash level ════════════════════════════

test "zerohash: tick with num_hashes==0 (hpt=62500) -> dead" {
    // slot 100, parent 99 (consecutive) => 64 ticks expected.
    var buf: [64]Entry = undefined;
    var entries = wellFormed(&buf, 64, HPT);
    entries[10].num_hashes = 0; // a zero-hash tick
    const verdict = run(.zerohash, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_zero, verdict);
    try std.testing.expect(verdict.isDead());
}

test "zerohash: valid 62500-hash tick block -> pass" {
    var buf: [64]Entry = undefined;
    const entries = wellFormed(&buf, 64, HPT);
    const verdict = run(.zerohash, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.ok, verdict);
    try std.testing.expect(!verdict.isDead());
}

test "zerohash: hashes_per_tick<=1 -> NO reject even with a zero-hash tick" {
    // hashing disabled / low-power => the check is gated off (FD `>1`).
    var buf: [64]Entry = undefined;
    var entries = wellFormed(&buf, 64, 0);
    entries[5].num_hashes = 0;
    try std.testing.expectEqual(vt.Verdict.ok, run(.zerohash, 0, 99, 100, entries));
    try std.testing.expectEqual(vt.Verdict.ok, run(.zerohash, 1, 99, 100, entries));
}

test "zerohash: does NOT enforce tick COUNT (full-only) — short block passes" {
    // zerohash never marks dead on too-few/too-many ticks; only the zero-hash
    // tick triggers. A 60-tick block (would be TOO_FEW in full) passes here.
    var buf: [60]Entry = undefined;
    const entries = wellFormed(&buf, 60, HPT);
    try std.testing.expectEqual(vt.Verdict.ok, run(.zerohash, HPT, 99, 100, entries));
}

// ════════════════════════════════ full ════════════════════════════════

test "full: well-formed 64-tick/62500-hash consecutive slot -> pass" {
    var buf: [64]Entry = undefined;
    const entries = wellFormed(&buf, 64, HPT);
    const verdict = run(.full, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.ok, verdict);
}

test "full: TOO_MANY_TICKS (65 ticks, gap=1 expects 64) -> dead" {
    var buf: [65]Entry = undefined;
    const entries = wellFormed(&buf, 65, HPT);
    const verdict = run(.full, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.too_many_ticks, verdict);
}

test "full: TOO_FEW_TICKS (63 ticks, gap=1 expects 64) -> dead" {
    var buf: [63]Entry = undefined;
    const entries = wellFormed(&buf, 63, HPT);
    const verdict = run(.full, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.too_few_ticks, verdict);
}

test "full: INVALID_TICK_HASH_COUNT zero (a tick has 0 hashes) -> dead" {
    var buf: [64]Entry = undefined;
    var entries = wellFormed(&buf, 64, HPT);
    entries[0].num_hashes = 0; // first tick zero-hash
    const verdict = run(.full, HPT, 99, 100, entries);
    // The zerohash check fires first (it precedes the eager checks).
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_zero, verdict);
}

test "full: INVALID_TICK_HASH_COUNT a single later tick has wrong hashcnt -> dead" {
    var buf: [64]Entry = undefined;
    var entries = wellFormed(&buf, 64, HPT);
    // tick #3 carries fewer (but nonzero) hashes than hashes_per_tick.
    entries[3].num_hashes = HPT - 1;
    const verdict = run(.full, HPT, 99, 100, entries);
    // Caught by the EXACT per-tick check (HPT-1 != HPT) at tick #3 — Agave
    // entry.rs:687 / FD fd_sched.c:1983.
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_exact, verdict);
}

test "full: UNIFORMLY-wrong block (EVERY tick HPT-1, internally consistent) -> dead" {
    // The case the inter-tick-consistency check ALONE misses: every tick agrees
    // with the watermark (all HPT-1), so the watermark never disagrees — but the
    // canonical check is vs hashes_per_tick, not vs the watermark. Agave
    // entry.rs:687 and FD fd_sched.c:1983 both reject. Vexor MUST too (else it
    // would freeze/vote a block the cluster marked dead -> divergence).
    var buf: [64]Entry = undefined;
    const entries = wellFormed(&buf, 64, HPT - 1); // every tick HPT-1
    const verdict = run(.full, HPT, 99, 100, entries);
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_exact, verdict);
}

test "full: trailing non-tick microblock with leftover hashcnt >= hpt (no closing tick) -> dead" {
    // 64 well-formed ticks, then a trailing non-tick microblock carrying HPT
    // hashes with NO closing tick. Agave entry.rs:697 `tick_hash_count < hpt`
    // is false (HPT >= HPT) -> reject.
    var buf: [65]Entry = undefined;
    var entries = wellFormed(buf[0..64], 64, HPT);
    _ = &entries;
    buf[64] = .{ .num_hashes = HPT, .is_tick = false }; // trailing, no tick after
    const verdict = run(.full, HPT, 99, 100, buf[0..65]);
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_cumulative, verdict);
}

test "full: INVALID_TICK_HASH_COUNT cumulative (a microblock overshoots hpt) -> dead" {
    // A non-tick microblock with hashcnt > hashes_per_tick before any tick
    // resets the counter => cumulative DoS bound fires. Place a fat non-tick
    // entry first, then ticks.
    var buf: [65]Entry = undefined;
    buf[0] = .{ .num_hashes = HPT + 1, .is_tick = false }; // overshoot
    for (1..65) |i| buf[i] = .{ .num_hashes = HPT, .is_tick = true };
    const verdict = run(.full, HPT, 99, 100, buf[0..65]);
    try std.testing.expectEqual(vt.Verdict.invalid_tick_hash_count_cumulative, verdict);
}

// ──────── post-skip blocks (the case the flat ==64 model gets wrong) ────────

test "full: post-skip gap=2 block with 128 ticks -> pass" {
    // parent 98, slot 100 => (100-98)*64 = 128 ticks expected. A correct
    // post-skip block legitimately carries >64 ticks.
    var buf: [128]Entry = undefined;
    const entries = wellFormed(&buf, 128, HPT);
    const verdict = run(.full, HPT, 98, 100, entries);
    try std.testing.expectEqual(vt.Verdict.ok, verdict);
}

test "full: post-skip gap=2 block with only 64 ticks -> TOO_FEW dead" {
    // The flat `<64` gate would WRONGLY pass this (64 !< 64); the canonical
    // window correctly flags it (64 < 128).
    var buf: [64]Entry = undefined;
    const entries = wellFormed(&buf, 64, HPT);
    const verdict = run(.full, HPT, 98, 100, entries);
    try std.testing.expectEqual(vt.Verdict.too_few_ticks, verdict);
}

test "full: post-skip gap=3 with 193 ticks -> TOO_MANY dead" {
    // parent 97, slot 100 => 192 expected; 193 overshoots.
    var buf: [193]Entry = undefined;
    const entries = wellFormed(&buf, 193, HPT);
    const verdict = run(.full, HPT, 97, 100, entries);
    try std.testing.expectEqual(vt.Verdict.too_many_ticks, verdict);
}

// ──────── hashing-disabled (hpt<=1) skips hash checks but NOT tick count ────────

test "full: hpt=0 disables hash checks but TOO_FEW still enforced" {
    // With hashes_per_tick=0, hash-count checks are skipped, but the tick-count
    // window checks still run (they don't depend on hashing).
    var buf: [63]Entry = undefined;
    for (0..63) |i| buf[i] = .{ .num_hashes = 0, .is_tick = true };
    try std.testing.expectEqual(vt.Verdict.too_few_ticks, run(.full, 0, 99, 100, buf[0..63]));
    // And a correct 64-tick zero-hash block passes when hashing is disabled.
    var buf2: [64]Entry = undefined;
    for (0..64) |i| buf2[i] = .{ .num_hashes = 0, .is_tick = true };
    try std.testing.expectEqual(vt.Verdict.ok, run(.full, 0, 99, 100, buf2[0..64]));
}

// ──────── mixed microblocks: non-tick txs interleaved with ticks ────────

test "full: microblocks interleaved, hashes split across the tick window -> pass" {
    // First tick window = 2 non-tick microblocks (30000 + 32500 hashes) then a
    // tick with 0 extra... but a zero-hash tick is invalid. Instead: the tick
    // entry itself must carry hashes so the cumulative window hits HPT. Model a
    // window where a non-tick adds 1 hash and the tick adds HPT-1 => total HPT.
    var buf: [128]Entry = undefined;
    var n: usize = 0;
    for (0..64) |_| {
        buf[n] = .{ .num_hashes = 1, .is_tick = false };
        n += 1;
        buf[n] = .{ .num_hashes = HPT - 1, .is_tick = true };
        n += 1;
    }
    const verdict = run(.full, HPT, 99, 100, buf[0..n]);
    try std.testing.expectEqual(vt.Verdict.ok, verdict);
}

// ════════════════════════════════ off ════════════════════════════════

test "off: never rejects anything" {
    var buf: [64]Entry = undefined;
    var entries = wellFormed(&buf, 10, HPT); // wildly too few ticks
    entries[0].num_hashes = 0; // and a zero-hash tick
    try std.testing.expectEqual(vt.Verdict.ok, run(.off, HPT, 99, 100, entries));
}

// ════════════════════ BLOCKING flat tick-gate (PR-5ag-BLOCK) ════════════════════
//
// replay_stage.zig's zerohash/off builds enforce completeness with a BLOCKING
// flat `tick_count_seen < 64` gate (markSlotDead PRE-FREEZE) — the fix for
// incident 421935259 (froze+voted a 30/64-tick truncated block). The gate lives
// in the replay loop, so these KATs (1) pin the exact predicate and (2) prove the
// load-bearing SAFETY invariant against the canonical verify_ticks.zig oracle:
// the flat gate is a STRICT SUBSET of the canonical FD/Agave TOO_FEW_TICKS check,
// so it can only kill slots Agave/FD would ALSO mark dead — never a canonical one.

const EXPECTED_TICKS_PER_SLOT: u64 = 64;

/// The EXACT predicate promoted to blocking in replay_stage.zig:8967.
fn flatGateFires(tick_count_seen: u64) bool {
    return tick_count_seen < EXPECTED_TICKS_PER_SLOT;
}

/// Canonical oracle: does the full FD/Agave verifier mark a consecutive
/// (parent=slot-1) `n`-tick block dead? Uses the real verify_ticks.zig code.
fn canonicalDeadConsecutive(n: usize) bool {
    var buf: [256]Entry = undefined;
    std.debug.assert(n <= buf.len);
    for (0..n) |i| buf[i] = .{ .num_hashes = HPT, .is_tick = true };
    return run(.full, HPT, 99, 100, buf[0..n]).isDead();
}

test "flat-gate (a): incident shape 30/64 ticks -> gate FIRES and canonical agrees (TooFewTicks)" {
    // 421935259: ticks_seen=30, expected=64, claimed-complete -> truncated.
    try std.testing.expect(flatGateFires(30));
    // Canonical (consecutive parent) marks the same block dead: 30 < 64.
    var buf: [30]Entry = undefined;
    for (0..30) |i| buf[i] = .{ .num_hashes = HPT, .is_tick = true };
    try std.testing.expectEqual(vt.Verdict.too_few_ticks, run(.full, HPT, 99, 100, buf[0..30]));
}

test "flat-gate (b): healthy 64/64 consecutive slot -> gate does NOT fire, canonical ok" {
    try std.testing.expect(!flatGateFires(64));
    try std.testing.expect(!canonicalDeadConsecutive(64));
}

test "flat-gate (c): a block with >= 64 ticks (incl. gap-k long blocks) is never killed by the flat gate" {
    // A legitimately-complete block (64 ticks) and a legitimately-LONG post-skip
    // block (128 ticks, gap=2) both carry >= 64 ticks, so the flat gate lets them
    // through — it only kills the truncated (< 64) shape, never a full/long block.
    // (A still-streaming slot never reaches this gate at all: replayEntriesInternal
    // runs only AFTER the assembler signals SLOT-COMPLETED — see replay_stage:8927.)
    try std.testing.expect(!flatGateFires(64));
    try std.testing.expect(!flatGateFires(128));
    // The gap-2 128-tick block is canonically valid (not dead).
    var buf: [128]Entry = undefined;
    for (0..128) |i| buf[i] = .{ .num_hashes = HPT, .is_tick = true };
    try std.testing.expect(!run(.full, HPT, 98, 100, buf[0..128]).isDead());
}

test "flat-gate SAFETY: flat fire ==> canonical also marks dead (strict subset, zero over-fire)" {
    // For every tick count the flat gate could observe, if it fires then the
    // canonical verifier ALSO marks the (consecutive) slot dead. This is the
    // invariant that makes promoting the gate to blocking Agave-parity-safe:
    // the flat gate NEVER kills a slot the cluster would keep. (Converse need not
    // hold — the flat gate deliberately under-fires on gap-k deficits.)
    var n: usize = 0;
    while (n <= 128) : (n += 1) {
        if (flatGateFires(@intCast(n))) {
            try std.testing.expect(canonicalDeadConsecutive(n));
        }
    }
}
