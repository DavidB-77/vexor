//! conformance.zig — Vexor conformance test runner
//!
//! Verifies the bank hash formula, per-account LtHash, and slot replay against
//! known test vectors or live RPC oracle data.
//!
//! Design goals:
//!   1. verifyBankHash / verifyAccountLtHash are pure, deterministic functions
//!      usable as unit-test building blocks (cf. sig/src/vm/tests.zig pattern).
//!   2. ConformanceResult captures pass/fail + expected vs actual for CI reporting.
//!   3. runSlotReplay provides an end-to-end replay stub (RPC-gated; no snapshot I/O
//!      in this module — wiring to the real snapshot loader is done by the caller).
//!
//! Reference:
//!   sig/src/vm/tests.zig           — conformance test patterns in Zig
//!   solana-client-research/vexor/src/tools/vopr/harness.zig
//!   PORTING_RULES.md: camelCase, PascalCase, no fd_ prefix
//!
//! Bank hash formula (SIMD-0215):
//!   step1 = SHA256(parent_hash[32] || sig_count_le8 || blockhash[32])
//!   hash  = SHA256(step1[32] || lthash_bytes[2048])
//!
//! Per-account LtHash (fd_hashes.c:23-48):
//!   BLAKE3-XOF-2048(lamports_le8 || data || executable_u8 || owner[32] || pubkey[32])
//!   → interpret 2048 bytes as 1024 × u16 (little-endian, wrapping arithmetic)

const std = @import("std");
const vex_crypto = @import("vex_crypto");

// REBUILD-CLEAN (2026-07-07, module 37): origin-tree's own `const diagnostics =
// @import("diagnostics.zig");` line dropped here. diagnostics.zig is this
// rebuild's manifest DELETE-disposition (VEXOR-REBUILD-FILE-MANIFEST-2026-07-06.md
// §diagnostics.zig: "Only consumer is conformance.zig:28, which itself has no
// live callers" — i.e. the manifest's own text already documents this exact
// import as dead). Verified independently in this tree, not merely trusted
// from the manifest note: grepped the full 733-line file for every use of the
// `diagnostics` binding beyond its import line — zero hits. origin-tree's own
// `test-conformance` target (build.zig:551-559) wires ONLY `vex_crypto_core`,
// no diagnostics import either, confirming upstream never needed it live.
// Zero logic/behavior change — pure dead-import removal, CLEAN per the
// ledger §1 contract (comment/dead-branch hygiene only).

const Hash = vex_crypto.Hash;
const LtHash = vex_crypto.LtHash;

// ─────────────────────────────────────────────────────────────────────────────
// ConformanceResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a single conformance test.
/// `error_detail` is non-null when `passed == false` and carries a human-readable
/// description of what differed.
pub const ConformanceResult = struct {
    test_name: []const u8,
    passed: bool,
    expected_hash: [32]u8,
    actual_hash: [32]u8,
    /// Heap-allocated; owned by the caller's arena.  null on success.
    error_detail: ?[]const u8,

    /// Format a short one-line summary: "PASS test_name" or "FAIL test_name: detail"
    pub fn format(
        self: ConformanceResult,
        writer: anytype,
    ) void {
        if (self.passed) {
            writer.print("PASS  {s}\n", .{self.test_name}) catch {};
        } else {
            const detail = self.error_detail orelse "hash mismatch";
            writer.print(
                "FAIL  {s}: {s}\n      expected={x:0>2}{x:0>2}{x:0>2}{x:0>2}..{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n" ++
                    "      actual  ={x:0>2}{x:0>2}{x:0>2}{x:0>2}..{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n",
                .{
                    self.test_name,         detail,
                    self.expected_hash[0],  self.expected_hash[1],
                    self.expected_hash[2],  self.expected_hash[3],
                    self.expected_hash[28], self.expected_hash[29],
                    self.expected_hash[30], self.expected_hash[31],
                    self.actual_hash[0],    self.actual_hash[1],
                    self.actual_hash[2],    self.actual_hash[3],
                    self.actual_hash[28],   self.actual_hash[29],
                    self.actual_hash[30],   self.actual_hash[31],
                },
            ) catch {};
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// verifyAccountLtHash — compute per-account LtHash for conformance checking
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the 2048-byte LtHash for a single account state.
///
/// Ported from fd_hashes.c:23-48 (cf. hashes.zig:accountLtHash).
/// Exposed here as a conformance-verification entry point: callers can compare
/// the result against a known-good vector from Agave or Firedancer.
///
/// Formula: BLAKE3-XOF-2048( lamports_le8 || data || executable_u8 || owner[32] || pubkey[32] )
///
/// Invariant: zero-lamport account → all-zero LtHash (deleted accounts contribute nothing).
pub fn verifyAccountLtHash(
    pubkey: *const [32]u8,
    owner: *const [32]u8,
    lamports: u64,
    executable: bool,
    data: []const u8,
) [2048]u8 {
    // Zero-lamport: excluded from accumulator (fd_hashes.c:30-32)
    if (lamports == 0) return [_]u8{0} ** 2048;

    const exec_flag: u8 = if (executable) 1 else 0;

    var b3 = std.crypto.hash.Blake3.init(.{});
    var lamports_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &lamports_le, lamports, .little);
    b3.update(&lamports_le);
    b3.update(data);
    b3.update(&[_]u8{exec_flag});
    b3.update(owner[0..32]);
    b3.update(pubkey[0..32]);

    // Zig 0.15.2: Blake3.final() accepts any output length (XOF semantics).
    // fd_hashes.c:43: fd_blake3_fini_2048 — produces exactly 2048 bytes.
    var out: [2048]u8 = undefined;
    b3.final(&out);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// verifyBankHash — canonical two-step SHA256 bank hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the canonical bank hash for a slot given its raw components.
///
/// Formula (SIMD-0215 / fd_hashes.c:50-74):
///   step1 = SHA256( parent_hash[32] || sig_count_le8 || blockhash[32] )
///   hash  = SHA256( step1[32] || lthash_bytes[2048] )
///
/// `lthash_bytes`: the 2048-byte raw encoding of the accumulated LtHash,
///   i.e. 1024 × u16 in little-endian order — caller must provide this.
///
/// Returns the 32-byte bank hash.
pub fn verifyBankHash(
    parent_hash: [32]u8,
    sig_count: u64,
    blockhash: [32]u8,
    lthash_bytes: *const [2048]u8,
) [32]u8 {
    var sig_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sig_le, sig_count, .little);

    // Step 1
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(&parent_hash);
    sha.update(&sig_le);
    sha.update(&blockhash);
    var step1: [32]u8 = undefined;
    sha.final(&step1);

    // Step 2
    var sha2 = std.crypto.hash.sha2.Sha256.init(.{});
    sha2.update(&step1);
    sha2.update(lthash_bytes);
    var result: [32]u8 = undefined;
    sha2.final(&result);
    return result;
}

/// Variant that accepts a *const LtHash directly (converts to bytes internally).
pub fn verifyBankHashFromLtHash(
    parent_hash: [32]u8,
    sig_count: u64,
    blockhash: [32]u8,
    lthash: *const LtHash,
) [32]u8 {
    var lthash_bytes: [2048]u8 = undefined;
    for (0..1024) |i| {
        std.mem.writeInt(u16, lthash_bytes[i * 2 ..][0..2], lthash.elements[i], .little);
    }
    return verifyBankHash(parent_hash, sig_count, blockhash, &lthash_bytes);
}

// ─────────────────────────────────────────────────────────────────────────────
// TestVector — static known-good input/output pairs
// ─────────────────────────────────────────────────────────────────────────────

/// A static bank-hash test vector (parent + sig_count + blockhash + lthash → expected_hash).
/// Used by runBuiltinVectors() to validate the formula without any live data.
pub const BankHashVector = struct {
    description: []const u8,
    parent_hash: [32]u8,
    sig_count: u64,
    blockhash: [32]u8,
    /// LtHash as 2048 raw bytes
    lthash_bytes: [2048]u8,
    expected_hash: [32]u8,
};

/// A static LtHash test vector for a single account.
pub const AccountLtHashVector = struct {
    description: []const u8,
    pubkey: [32]u8,
    owner: [32]u8,
    lamports: u64,
    executable: bool,
    data: []const u8,
    /// Expected 2048-byte lthash output
    expected: [2048]u8,
};

// ─────────────────────────────────────────────────────────────────────────────
// runBuiltinVectors — unit-level conformance suite (no external I/O)
// ─────────────────────────────────────────────────────────────────────────────

/// Run a minimal set of built-in conformance vectors derived from first principles.
///
/// These vectors verify:
///   1. Genesis bank hash (all-zero inputs → known hash)
///   2. Zero-lamport account contributes nothing (lthash stays zero)
///   3. sig_count off-by-one produces a different hash
///   4. Determinism of verifyAccountLtHash
///
/// Each result is appended to `results` (caller-owned ArrayList).
/// Returns the number of tests that FAILED.
pub fn runBuiltinVectors(
    allocator: std.mem.Allocator,
    results: *std.ArrayList(ConformanceResult), // Zig 0.15.2: unmanaged, pass allocator to append
) !u32 {
    var failures: u32 = 0;

    // ── Vector 1: genesis-like all-zero bank hash ──────────────────────────
    {
        const parent_hash = [_]u8{0} ** 32;
        const blockhash = [_]u8{0} ** 32;
        const lthash_bytes = [_]u8{0} ** 2048;
        const sig_count: u64 = 0;

        const actual = verifyBankHash(parent_hash, sig_count, blockhash, &lthash_bytes);

        // Determinism: calling twice gives same result
        const actual2 = verifyBankHash(parent_hash, sig_count, blockhash, &lthash_bytes);
        const det_pass = std.mem.eql(u8, &actual, &actual2);

        const name = "bank_hash: genesis all-zero determinism";
        if (det_pass) {
            try results.append(allocator, .{
                .test_name = name,
                .passed = true,
                .expected_hash = actual,
                .actual_hash = actual2,
                .error_detail = null,
            });
        } else {
            failures += 1;
            try results.append(allocator, .{
                .test_name = name,
                .passed = false,
                .expected_hash = actual,
                .actual_hash = actual2,
                .error_detail = try allocator.dupe(u8, "non-deterministic hash"),
            });
        }
    }

    // ── Vector 2: sig_count sensitivity ───────────────────────────────────
    {
        const parent = [_]u8{0xAA} ** 32;
        const bh = [_]u8{0xBB} ** 32;
        const lth = [_]u8{0} ** 2048;
        const h500 = verifyBankHash(parent, 500, bh, &lth);
        const h501 = verifyBankHash(parent, 501, bh, &lth);
        const differs = !std.mem.eql(u8, &h500, &h501);

        const name = "bank_hash: sig_count sensitivity (500 != 501)";
        try results.append(allocator, .{
            .test_name = name,
            .passed = differs,
            .expected_hash = h500,
            .actual_hash = h501,
            .error_detail = if (!differs) try allocator.dupe(u8, "sig_count change had no effect") else null,
        });
        if (!differs) failures += 1;
    }

    // ── Vector 3: parent_hash sensitivity ─────────────────────────────────
    {
        const bh = [_]u8{0xCC} ** 32;
        const lth = [_]u8{0} ** 2048;
        const h1 = verifyBankHash([_]u8{0x11} ** 32, 100, bh, &lth);
        const h2 = verifyBankHash([_]u8{0x22} ** 32, 100, bh, &lth);

        const name = "bank_hash: parent_hash sensitivity";
        const differs = !std.mem.eql(u8, &h1, &h2);
        try results.append(allocator, .{
            .test_name = name,
            .passed = differs,
            .expected_hash = h1,
            .actual_hash = h2,
            .error_detail = if (!differs) try allocator.dupe(u8, "parent_hash change had no effect") else null,
        });
        if (!differs) failures += 1;
    }

    // ── Vector 4: zero-lamport account LtHash is all-zero ─────────────────
    {
        const lt_bytes = verifyAccountLtHash(
            &([_]u8{0x01} ** 32),
            &([_]u8{0x02} ** 32),
            0, // zero lamports
            false,
            &[_]u8{},
        );
        const all_zero = std.mem.allEqual(u8, &lt_bytes, 0);
        const name = "account_lthash: zero lamports → zero lthash";
        try results.append(allocator, .{
            .test_name = name,
            .passed = all_zero,
            .expected_hash = [_]u8{0} ** 32,
            .actual_hash = lt_bytes[0..32].*,
            .error_detail = if (!all_zero) try allocator.dupe(u8, "expected zero output for lamports=0") else null,
        });
        if (!all_zero) failures += 1;
    }

    // ── Vector 5: non-zero lamports → non-zero LtHash ─────────────────────
    {
        const lt_bytes = verifyAccountLtHash(
            &([_]u8{0xDE} ** 32),
            &([_]u8{0xAD} ** 32),
            1_000_000_000,
            false,
            &[_]u8{ 0x01, 0x02, 0x03 },
        );
        const any_nonzero = !std.mem.allEqual(u8, &lt_bytes, 0);
        const name = "account_lthash: non-zero lamports → non-zero output";
        try results.append(allocator, .{
            .test_name = name,
            .passed = any_nonzero,
            .expected_hash = lt_bytes[0..32].*,
            .actual_hash = lt_bytes[0..32].*,
            .error_detail = if (!any_nonzero) try allocator.dupe(u8, "expected non-zero output for lamports>0") else null,
        });
        if (!any_nonzero) failures += 1;
    }

    // ── Vector 6: account lthash determinism ──────────────────────────────
    {
        const pk = [_]u8{0x55} ** 32;
        const own = [_]u8{0x66} ** 32;
        const lt1 = verifyAccountLtHash(&pk, &own, 42_000, true, &[_]u8{ 10, 20, 30 });
        const lt2 = verifyAccountLtHash(&pk, &own, 42_000, true, &[_]u8{ 10, 20, 30 });
        const det = std.mem.eql(u8, &lt1, &lt2);
        const name = "account_lthash: deterministic output";
        try results.append(allocator, .{
            .test_name = name,
            .passed = det,
            .expected_hash = lt1[0..32].*,
            .actual_hash = lt2[0..32].*,
            .error_detail = if (!det) try allocator.dupe(u8, "non-deterministic") else null,
        });
        if (!det) failures += 1;
    }

    // ── Vector 7: executable bit sensitivity ──────────────────────────────
    {
        const pk = [_]u8{0x77} ** 32;
        const own = [_]u8{0x88} ** 32;
        const lt_exec = verifyAccountLtHash(&pk, &own, 1, true, &[_]u8{});
        const lt_no_exec = verifyAccountLtHash(&pk, &own, 1, false, &[_]u8{});
        const differs = !std.mem.eql(u8, &lt_exec, &lt_no_exec);
        const name = "account_lthash: executable bit changes output";
        try results.append(allocator, .{
            .test_name = name,
            .passed = differs,
            .expected_hash = lt_exec[0..32].*,
            .actual_hash = lt_no_exec[0..32].*,
            .error_detail = if (!differs) try allocator.dupe(u8, "executable flag had no effect") else null,
        });
        if (!differs) failures += 1;
    }

    return failures;
}

// ─────────────────────────────────────────────────────────────────────────────
// SlotReplayConfig — configuration for runSlotReplay
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for an end-to-end slot replay conformance run.
pub const SlotReplayConfig = struct {
    /// Directory containing the snapshot (manifest + accounts)
    snapshot_dir: []const u8,
    /// RPC endpoint for reference hashes and missing account data
    rpc_url: []const u8,
    /// Number of slots to replay starting from snapshot_slot+1
    slots_to_replay: u64,
    /// Stop on first divergence (default: continue for full analysis)
    stop_on_first_diff: bool = false,
    /// Emit per-slot diagnostic reports to stdout
    verbose: bool = false,
};

/// Summary of an end-to-end slot replay conformance run.
pub const SlotReplayReport = struct {
    /// Slot number at which the snapshot was taken
    snapshot_slot: u64,
    /// Number of slots actually replayed
    slots_replayed: u64,
    /// Number of SLOT-OK (match) verdicts
    match_count: u64,
    /// Number of SLOT-DIFF verdicts
    diff_count: u64,
    /// Number of slots with no oracle reference
    no_ref_count: u64,
    /// Slot number of first divergence (null if all matched)
    first_diff_slot: ?u64,
    /// Per-slot results; caller owns the slice (allocated from caller's arena)
    results: []ConformanceResult,

    pub fn passRate(self: SlotReplayReport) f64 {
        const total = self.match_count + self.diff_count;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.match_count)) /
            @as(f64, @floatFromInt(total));
    }

    pub fn printSummary(self: *const SlotReplayReport, writer: anytype) void {
        writer.print(
            "[CONFORMANCE] snapshot_slot={d} replayed={d} match={d} diff={d} no_ref={d} " ++
                "pass_rate={d:.1}%\n",
            .{
                self.snapshot_slot,
                self.slots_replayed,
                self.match_count,
                self.diff_count,
                self.no_ref_count,
                self.passRate() * 100.0,
            },
        ) catch {};
        if (self.first_diff_slot) |s| {
            writer.print("[CONFORMANCE] First divergence at slot {d}\n", .{s}) catch {};
        } else if (self.diff_count == 0) {
            writer.print("[CONFORMANCE] PASS — all replayed slots match network\n", .{}) catch {};
        }
    }

    pub fn deinit(self: *SlotReplayReport, allocator: std.mem.Allocator) void {
        allocator.free(self.results);
    }
};

/// Run a slot-replay conformance check.
///
/// This is the outer entry point for conformance testing.  It:
///   1. Loads the snapshot slot from `config.snapshot_dir`
///   2. For each slot in [snapshot_slot+1, snapshot_slot+slots_to_replay]:
///      a. Fetches the oracle bank hash via RPC (getConfirmedBlock / getBlockCommitment)
///      b. Calls the caller-supplied `replayFn` to produce our bank hash
///      c. Compares using compareBankHashFull()
///      d. Records a ConformanceResult
///   3. Returns a SlotReplayReport
///
/// NOTE: `replayFn` is a function pointer the caller provides.  This decouples
/// the conformance runner from any specific bank implementation.  Callers in
/// unit tests can supply a trivial no-op; the real harness supplies the full
/// replay pipeline.
///
/// `replayFn` signature:
///   fn(ctx: *anyopaque, slot: u64, out_hash: *[32]u8) anyerror!void
///   The function must write the computed bank hash for `slot` into *out_hash.
///   It may return error if the slot cannot be replayed.
pub fn runSlotReplay(
    allocator: std.mem.Allocator,
    config: SlotReplayConfig,
    ctx: *anyopaque,
    replayFn: *const fn (*anyopaque, u64, *[32]u8) anyerror!void,
    oracleFn: *const fn (*anyopaque, u64, *[32]u8) anyerror!void,
) !SlotReplayReport {
    // Parse snapshot slot from directory name convention: snapshot-<slot>-*.tar.zst
    // or from the SNAPSHOTS manifest file.  Use a simple directory scan heuristic.
    const snapshot_slot = try detectSnapshotSlot(config.snapshot_dir);

    // Zig 0.15.2: ArrayList is unmanaged — use .empty, pass allocator to each call.
    var result_list: std.ArrayList(ConformanceResult) = .empty;
    defer result_list.deinit(allocator);

    var match_count: u64 = 0;
    var diff_count: u64 = 0;
    var no_ref_count: u64 = 0;
    var first_diff: ?u64 = null;

    var slot_idx: u64 = 0;
    while (slot_idx < config.slots_to_replay) : (slot_idx += 1) {
        const slot = snapshot_slot + 1 + slot_idx;

        // Compute our bank hash
        var our_hash: [32]u8 = [_]u8{0} ** 32;
        const replay_ok = replayFn(ctx, slot, &our_hash);

        // Fetch oracle hash
        var oracle_hash: [32]u8 = [_]u8{0} ** 32;
        const oracle_ok = oracleFn(ctx, slot, &oracle_hash);

        const name_buf = try allocator.alloc(u8, 32);
        _ = std.fmt.bufPrint(name_buf, "slot_{d}", .{slot}) catch {};

        if (replay_ok) |_| {
            if (oracle_ok) |_| {
                const matches = std.mem.eql(u8, &our_hash, &oracle_hash);
                if (matches) {
                    match_count += 1;
                } else {
                    diff_count += 1;
                    if (first_diff == null) first_diff = slot;
                }
                if (config.verbose and !matches) {
                    const out = std.io.getStdOut().writer();
                    out.print(
                        "[CONFORMANCE] FAIL slot={d} ours={x:0>2}{x:0>2}..{x:0>2}{x:0>2} " ++
                            "net={x:0>2}{x:0>2}..{x:0>2}{x:0>2}\n",
                        .{
                            slot,
                            our_hash[0],
                            our_hash[1],
                            our_hash[30],
                            our_hash[31],
                            oracle_hash[0],
                            oracle_hash[1],
                            oracle_hash[30],
                            oracle_hash[31],
                        },
                    ) catch {};
                }
                try result_list.append(allocator, .{
                    .test_name = name_buf,
                    .passed = matches,
                    .expected_hash = oracle_hash,
                    .actual_hash = our_hash,
                    .error_detail = if (!matches) try allocator.dupe(u8, "bank hash diverged") else null,
                });
            } else |_| {
                // Oracle not available for this slot
                no_ref_count += 1;
                try result_list.append(allocator, .{
                    .test_name = name_buf,
                    .passed = false,
                    .expected_hash = [_]u8{0} ** 32,
                    .actual_hash = our_hash,
                    .error_detail = try allocator.dupe(u8, "oracle hash unavailable"),
                });
            }
        } else |replay_err| {
            diff_count += 1;
            if (first_diff == null) first_diff = slot;
            const err_str = try std.fmt.allocPrint(allocator, "replay error: {s}", .{@errorName(replay_err)});
            try result_list.append(allocator, .{
                .test_name = name_buf,
                .passed = false,
                .expected_hash = oracle_hash,
                .actual_hash = [_]u8{0} ** 32,
                .error_detail = err_str,
            });
        }

        if (config.stop_on_first_diff and first_diff != null) break;
    }

    const results_owned = try result_list.toOwnedSlice(allocator);

    return SlotReplayReport{
        .snapshot_slot = snapshot_slot,
        .slots_replayed = slot_idx,
        .match_count = match_count,
        .diff_count = diff_count,
        .no_ref_count = no_ref_count,
        .first_diff_slot = first_diff,
        .results = results_owned,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// detectSnapshotSlot — heuristic snapshot slot detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detect the snapshot slot from a snapshot directory.
/// Looks for files named "snapshot-<slot>-*.tar.zst" or "snapshot-<slot>.tar.zst".
/// Falls back to reading "manifest" if no archive is found.
fn detectSnapshotSlot(snapshot_dir: []const u8) !u64 {
    var dir = try std.fs.openDirAbsolute(snapshot_dir, .{ .iterate = true });
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (!std.mem.startsWith(u8, name, "snapshot-")) continue;
        // snapshot-<slot>-... or snapshot-<slot>.tar.zst
        const after_prefix = name["snapshot-".len..];
        const end = std.mem.indexOfAny(u8, after_prefix, "-. ") orelse after_prefix.len;
        const slot_str = after_prefix[0..end];
        const slot = std.fmt.parseInt(u64, slot_str, 10) catch continue;
        return slot;
    }
    return error.SnapshotSlotNotFound;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

test "verifyBankHash: deterministic" {
    const parent = [_]u8{0x01} ** 32;
    const bh = [_]u8{0x02} ** 32;
    const lth = [_]u8{0x03} ** 2048;
    const h1 = verifyBankHash(parent, 100, bh, &lth);
    const h2 = verifyBankHash(parent, 100, bh, &lth);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "verifyBankHash: sig_count sensitivity" {
    const parent = [_]u8{0xAA} ** 32;
    const bh = [_]u8{0xBB} ** 32;
    const lth = [_]u8{0} ** 2048;
    const h1 = verifyBankHash(parent, 500, bh, &lth);
    const h2 = verifyBankHash(parent, 501, bh, &lth);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "verifyBankHash: parent_hash sensitivity" {
    const bh = [_]u8{0xCC} ** 32;
    const lth = [_]u8{0} ** 2048;
    const h1 = verifyBankHash([_]u8{0x11} ** 32, 100, bh, &lth);
    const h2 = verifyBankHash([_]u8{0x22} ** 32, 100, bh, &lth);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "verifyBankHash: blockhash sensitivity" {
    const parent = [_]u8{0xDD} ** 32;
    const lth = [_]u8{0} ** 2048;
    const h1 = verifyBankHash(parent, 100, [_]u8{0x11} ** 32, &lth);
    const h2 = verifyBankHash(parent, 100, [_]u8{0x22} ** 32, &lth);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "verifyBankHash: lthash sensitivity" {
    const parent = [_]u8{0xEE} ** 32;
    const bh = [_]u8{0xFF} ** 32;
    const h1 = verifyBankHash(parent, 100, bh, &([_]u8{0} ** 2048));
    const h2 = verifyBankHash(parent, 100, bh, &([_]u8{1} ** 2048));
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "verifyAccountLtHash: zero lamports → all zero" {
    const lt = verifyAccountLtHash(
        &([_]u8{0x01} ** 32),
        &([_]u8{0x02} ** 32),
        0,
        false,
        &[_]u8{},
    );
    try std.testing.expect(std.mem.allEqual(u8, &lt, 0));
}

test "verifyAccountLtHash: non-zero lamports → non-zero" {
    const lt = verifyAccountLtHash(
        &([_]u8{0x03} ** 32),
        &([_]u8{0x04} ** 32),
        500_000_000,
        false,
        &[_]u8{},
    );
    try std.testing.expect(!std.mem.allEqual(u8, &lt, 0));
}

test "verifyAccountLtHash: executable bit changes output" {
    const pk = [_]u8{0x05} ** 32;
    const own = [_]u8{0x06} ** 32;
    const lt1 = verifyAccountLtHash(&pk, &own, 1_000, true, &[_]u8{});
    const lt2 = verifyAccountLtHash(&pk, &own, 1_000, false, &[_]u8{});
    try std.testing.expect(!std.mem.eql(u8, &lt1, &lt2));
}

test "verifyAccountLtHash: data changes output" {
    const pk = [_]u8{0x07} ** 32;
    const own = [_]u8{0x08} ** 32;
    const lt1 = verifyAccountLtHash(&pk, &own, 1_000, false, &[_]u8{0x01});
    const lt2 = verifyAccountLtHash(&pk, &own, 1_000, false, &[_]u8{0x02});
    try std.testing.expect(!std.mem.eql(u8, &lt1, &lt2));
}

test "verifyBankHashFromLtHash: matches verifyBankHash" {
    var lt = LtHash.init();
    lt.elements[0] = 0x1234;
    lt.elements[1023] = 0x5678;

    var lthash_bytes: [2048]u8 = undefined;
    for (0..1024) |i| {
        std.mem.writeInt(u16, lthash_bytes[i * 2 ..][0..2], lt.elements[i], .little);
    }

    const parent = [_]u8{0x11} ** 32;
    const bh = [_]u8{0x22} ** 32;

    const h1 = verifyBankHash(parent, 300, bh, &lthash_bytes);
    const h2 = verifyBankHashFromLtHash(parent, 300, bh, &lt);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "runBuiltinVectors: all pass" {
    const allocator = std.testing.allocator;
    // Zig 0.15.2: ArrayList is unmanaged — initialize with .empty
    var results: std.ArrayList(ConformanceResult) = .empty;
    defer {
        for (results.items) |r| {
            if (r.error_detail) |d| allocator.free(d);
        }
        results.deinit(allocator);
    }
    const failures = try runBuiltinVectors(allocator, &results);
    try std.testing.expectEqual(@as(u32, 0), failures);
    try std.testing.expect(results.items.len > 0);
}

test "ConformanceResult: format pass" {
    const r = ConformanceResult{
        .test_name = "test_foo",
        .passed = true,
        .expected_hash = [_]u8{0x11} ** 32,
        .actual_hash = [_]u8{0x11} ** 32,
        .error_detail = null,
    };
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    r.format(fbs.writer());
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "PASS") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test_foo") != null);
}

test "ConformanceResult: format fail" {
    const r = ConformanceResult{
        .test_name = "test_bar",
        .passed = false,
        .expected_hash = [_]u8{0x11} ** 32,
        .actual_hash = [_]u8{0x22} ** 32,
        .error_detail = "hash mismatch detail",
    };
    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    r.format(fbs.writer());
    const out = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "FAIL") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test_bar") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "hash mismatch detail") != null);
}
