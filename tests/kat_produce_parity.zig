//! PRODUCE-PARITY KAT — the durable execute-once-and-record produce executor (block_executor.zig).
//!
//! STEP 1 (this file, initial): unit-drive BlockExecutor.executeAndCommit — prove the Agave
//! was_processed / fee semantics offline:
//!   - funded System transfer → PROCESSED, balances committed, sig counted, bank_hash reflects state;
//!   - fee-payer can't pay the fee → dropped_not_loaded (NotLoaded), no state mutation;
//!   - non-System program / unmodeled System disc / v0 → dropped_unexecutable (never packed, no fee);
//!   - instruction failure (transfer exceeds post-fee balance) → included_exec_failed: PROCESSED
//!     (fee retained + sig counted), instruction effects rolled back atomically;
//!   - cross-block duplicate signature → dropped_already_processed.
//!
//! STEP 3 (appended below): produce a MIXED mempool via execute-and-commit, replay the packed bytes
//! via the SAME executor, assert byte-identical bank_hash + zero dead blocks + the drain-chain
//! correctness case the delta-model gate mishandles but the executor gets right.
//!
//! HONEST BOUNDARY: produce-via-executor vs replay-via-the-SAME-executor is a determinism/parity
//! check across two runs of one seam — it is NOT proof of parity with replay_stage's real bank.freeze
//! (that is the live at-tip step). See block_executor.zig's header + forensics/txbearing-fix-report.md.

const std = @import("std");
const testing = std.testing;
const block_executor = @import("block_executor");
const block_produce = @import("block_produce");
const banking_stage = @import("banking_stage");
const tx_ingest = @import("tx_ingest");

const BlockExecutor = block_executor.BlockExecutor;
const Account = block_executor.Account;
const Hash = [32]u8;
const SYSTEM_ID: [32]u8 = [_]u8{0} ** 32;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Compact tx builders (same wire layout as tests/kat_txbearing_exec.zig: [payer, recipient, program]
// account keys, one instruction). Kept local so this KAT is self-contained.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A System instruction tx with caller-chosen discriminator + 12-byte data (disc(4) ‖ amount(8)).
fn buildSystemDiscTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, disc: u32, out: []u8) []u8 {
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 1; // num_readonly_unsigned (system program key)
    mpos += 3;
    out[mpos] = 3; // 3 account keys
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM_ID);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1; // 1 instruction
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (system program)
    mpos += 1;
    out[mpos] = 2; // 2 account indices
    mpos += 1;
    out[mpos] = 0; // from = payer
    out[mpos + 1] = 1; // to = recipient
    mpos += 2;
    out[mpos] = 12; // 12 data bytes
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], disc, .little);
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little);
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

fn buildTransferTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, blockhash: [32]u8, amount: u64, out: []u8) []u8 {
    return buildSystemDiscTx(kp, recipient, blockhash, amount, 2, out);
}

/// A tx invoking a NON-System program id at static key index 2 (the executor cannot run it → drop).
fn buildNonSystemProgramTx(kp: std.crypto.sign.Ed25519.KeyPair, recipient: [32]u8, program_id: [32]u8, blockhash: [32]u8, out: []u8) []u8 {
    var mpos: usize = 1 + 64;
    const msg_start = mpos;
    out[mpos] = 1;
    out[mpos + 1] = 0;
    out[mpos + 2] = 1;
    mpos += 3;
    out[mpos] = 3;
    mpos += 1;
    @memcpy(out[mpos..][0..32], &kp.public_key.bytes);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &recipient);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &program_id);
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1;
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 2;
    mpos += 1;
    out[mpos] = 0;
    out[mpos + 1] = 1;
    mpos += 2;
    out[mpos] = 4;
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], 0xDEADBEEF, .little);
    mpos += 4;
    const message = out[msg_start..mpos];
    const sig = kp.sign(message, null) catch unreachable;
    out[0] = 1;
    @memcpy(out[1..][0..64], &sig.toBytes());
    return out[0..mpos];
}

fn parseWire(wire: []const u8, ssig: *[tx_ingest.MAX_SIGNATURES][64]u8, skey: *[tx_ingest.MAX_SIGNATURES][32]u8) !tx_ingest.ParsedTx {
    return tx_ingest.parse(wire, ssig, skey);
}

const LPS = block_produce.LAMPORTS_PER_SIGNATURE; // 5000

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 1 — unit-drive BlockExecutor.executeAndCommit.
// ════════════════════════════════════════════════════════════════════════════════════════════════

test "executor: funded System transfer is PROCESSED, balances committed, sig counted, bank_hash reflects state" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x71} ** 32);
    const recipient: [32]u8 = [_]u8{0x99} ** 32;
    const bh: [32]u8 = [_]u8{0x33} ** 32;
    const amount: u64 = 1_000_000;
    const payer_start: u64 = 5_000_000;
    const recip_start: u64 = 2_000_000;
    const parent_hash: Hash = [_]u8{0xCA} ** 32;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = payer_start });
    try ex.seedAccount(recipient, .{ .lamports = recip_start });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, amount, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);
    const fee = block_produce.txFee(parsed, wire);

    const bank_hash_pre = ex.bankHash(&parent_hash, &bh);
    const r = ex.executeAndCommit(parsed, wire);

    try testing.expect(r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.included_ok, r.outcome);
    try testing.expectEqual(fee, r.fee_charged);
    // balances: payer -= fee + amount; recipient += amount.
    try testing.expectEqual(payer_start - fee - amount, ex.getLamports(kp.public_key.bytes).?);
    try testing.expectEqual(recip_start + amount, ex.getLamports(recipient).?);
    try testing.expectEqual(@as(u64, 1), ex.signatureCount()); // one signer counted.

    // bank_hash reflects the executed state (post ≠ pre over the same parent/poh) and is deterministic.
    const bank_hash_post = ex.bankHash(&parent_hash, &bh);
    try testing.expect(!std.mem.eql(u8, &bank_hash_pre, &bank_hash_post));
    try testing.expectEqualSlices(u8, &bank_hash_post, &ex.bankHash(&parent_hash, &bh));
}

test "executor: fee-payer that cannot pay the fee → dropped_not_loaded, no state change" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x72} ** 32);
    const recipient: [32]u8 = [_]u8{0x98} ** 32;
    const bh: [32]u8 = [_]u8{0x34} ** 32;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = LPS - 1 }); // below one signature fee.
    try ex.seedAccount(recipient, .{ .lamports = 0 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, 100, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expect(!r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.dropped_not_loaded, r.outcome);
    try testing.expectEqual(@as(u64, LPS - 1), ex.getLamports(kp.public_key.bytes).?); // untouched.
    try testing.expectEqual(@as(u64, 0), ex.signatureCount()); // not processed ⇒ not counted.
}

test "executor: fee-payer RENT FLOOR RED→GREEN — a data-carrying payer must use its ACTUAL data_len floor, not the 0-data floor" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x79} ** 32);
    const recipient: [32]u8 = [_]u8{0x91} ** 32;
    const bh: [32]u8 = [_]u8{0x3E} ** 32;
    const amount: u64 = 100;

    // A 200-byte fee-payer (the standard shape of a stake-sized System-owned account). Its TRUE
    // rent-exempt minimum is (200+128)*3480*2 = 2_282_880 (== the standard 200-byte stake
    // rent_exempt_reserve, native/stake_program.zig:261) — far above the 0-data floor
    // (block_produce.RENT_EXEMPT_MIN_ZERO = 890_880) the pre-fix code used regardless of data_len.
    var data_buf: [200]u8 = [_]u8{0} ** 200;
    const fee = LPS; // 1 signer, no priority fee.
    // Post-fee balance sits ABOVE the 0-data floor but BELOW the true 200-byte floor:
    //   890_880 < (payer_start - fee) < 2_282_880 — the exact carrier the 0-data floor misses.
    const payer_start: u64 = 1_000_000 + fee;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = payer_start, .data = &data_buf });
    try ex.seedAccount(recipient, .{ .lamports = 0 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, amount, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    // GREEN (post-fix): the true 200-byte floor drops it. RED (pre-fix): the 0-data floor wrongly
    // admits it (890_880 + fee < payer_start), which is EXACTLY the bug — a fee-payer that carries
    // data could be packed even though Agave's validate_fee_payer would reject it (post-fee balance
    // below its REAL rent-exempt minimum) → a tx the cluster rejects, packed → dead block.
    try testing.expect(!r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.dropped_not_loaded, r.outcome);
    try testing.expectEqual(payer_start, ex.getLamports(kp.public_key.bytes).?); // untouched.
}

test "executor: non-System program tx → dropped_unexecutable, NO fee charged (never packed)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x73} ** 32);
    const recipient: [32]u8 = [_]u8{0x97} ** 32;
    const prog: [32]u8 = [_]u8{0x42} ** 32;
    const bh: [32]u8 = [_]u8{0x35} ** 32;
    const start: u64 = 1_000_000_000;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = start });

    var buf: [512]u8 = undefined;
    const wire = buildNonSystemProgramTx(kp, recipient, prog, bh, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expect(!r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.dropped_unexecutable, r.outcome);
    try testing.expectEqual(start, ex.getLamports(kp.public_key.bytes).?); // fee NOT charged.
    try testing.expectEqual(@as(u64, 0), ex.signatureCount());
}

test "executor: unmodeled System discriminator (disc 11) → dropped_unexecutable" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x74} ** 32);
    const recipient: [32]u8 = [_]u8{0x96} ** 32;
    const bh: [32]u8 = [_]u8{0x36} ** 32;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = 1_000_000_000 });

    var buf: [512]u8 = undefined;
    const wire = buildSystemDiscTx(kp, recipient, bh, 1_000, 11, &buf); // TransferWithSeed-proxy: unmodeled.
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expectEqual(block_executor.Outcome.dropped_unexecutable, r.outcome);
    try testing.expectEqual(@as(u64, 1_000_000_000), ex.getLamports(kp.public_key.bytes).?);
}

test "executor: instruction failure (transfer exceeds post-fee balance) → PROCESSED (fee retained), effects rolled back" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x75} ** 32);
    const recipient: [32]u8 = [_]u8{0x95} ** 32;
    const bh: [32]u8 = [_]u8{0x37} ** 32;
    // Funded to LOAD (rent-exempt floor + fee) with a small surplus, but NOT enough for the transfer:
    // after the fee the payer holds RENT_EXEMPT_MIN_ZERO + 100, and the transfer of 1_000_000 exceeds it.
    const start: u64 = block_produce.RENT_EXEMPT_MIN_ZERO + LPS + 100;
    const amount: u64 = 1_000_000;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = start });
    try ex.seedAccount(recipient, .{ .lamports = 7 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, amount, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    // A processed-with-error tx is INCLUDED (Agave committer.rs): fee retained + sig counted, but the
    // transfer effect is rolled back atomically.
    try testing.expect(r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.included_exec_failed, r.outcome);
    try testing.expectEqual(start - LPS, ex.getLamports(kp.public_key.bytes).?); // only the fee was debited.
    try testing.expectEqual(@as(u64, 7), ex.getLamports(recipient).?); // recipient unchanged (rolled back).
    try testing.expectEqual(@as(u64, 1), ex.signatureCount()); // still counted (processed).
}

test "executor: cross-block duplicate signature → dropped_already_processed (before any state mutation)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x76} ** 32);
    const recipient: [32]u8 = [_]u8{0x94} ** 32;
    const bh: [32]u8 = [_]u8{0x38} ** 32;
    const start: u64 = 1_000_000_000;
    const committed_slot: u64 = 500_000;

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, 1_000, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    var cache = block_produce.RecentSigCache{};
    defer cache.deinit(a);
    cache.record(a, wire[1..65], committed_slot); // record the wire's first signature.

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    ex.recent_sigs = &cache;
    ex.producing_slot = committed_slot + 100; // within the 150-slot window.
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = start });

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expectEqual(block_executor.Outcome.dropped_already_processed, r.outcome);
    try testing.expectEqual(start, ex.getLamports(kp.public_key.bytes).?); // no fee, no execution.
}

test "executor: invalid signature → dropped_invalid (sigverify enforced; executor path bypasses admit)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x77} ** 32);
    const recipient: [32]u8 = [_]u8{0x93} ** 32;
    const bh: [32]u8 = [_]u8{0x39} ** 32;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = 1_000_000_000 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, 1_000, &buf);
    wire[10] ^= 0xFF; // corrupt a signature byte → sigverify must fail.
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expectEqual(block_executor.Outcome.dropped_invalid, r.outcome);
    try testing.expectEqual(@as(u64, 1_000_000_000), ex.getLamports(kp.public_key.bytes).?); // untouched.
}

test "executor: stale blockhash → dropped_invalid (blockhash-age enforced when the window is armed)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x78} ** 32);
    const recipient: [32]u8 = [_]u8{0x92} ** 32;
    const tx_bh: [32]u8 = [_]u8{0x3A} ** 32; // the blockhash the tx carries.
    const other_bh: [32]u8 = [_]u8{0xBB} ** 32; // the only blockhash in the recent window (≠ tx_bh).

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    const known = [_][32]u8{other_bh};
    ex.known_blockhashes = &known; // armed: the tx's blockhash is NOT in the window.
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = 1_000_000_000 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, tx_bh, 1_000, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expectEqual(block_executor.Outcome.dropped_invalid, r.outcome);
    try testing.expectEqual(@as(u64, 1_000_000_000), ex.getLamports(kp.public_key.bytes).?); // untouched.

    // GREEN control: with the tx's own blockhash in the window, it processes.
    const known_ok = [_][32]u8{tx_bh};
    ex.known_blockhashes = &known_ok;
    const r2 = ex.executeAndCommit(parsed, wire);
    try testing.expect(r2.wasProcessed());
}

test "executor: OVERSIZED blockhash window (> Agave's 150-entry cap) → no panic, deterministic outcome (regression guard)" {
    // Investigation finding (forensics/txbearing-fix-report.md WIRE-POINT PROGRESS flag #3): the
    // fixed-size `bh_buf: [150][32]u8` copy some callers use lives ONLY in replay_stage.zig (out of
    // scope for this tree; already cap-guarded there by bank.RecentBlockhashQueue's construction,
    // which never yields more than 150 entries). `known_blockhashes` here is a plain unbounded slice
    // (`[]const [32]u8`), iterated with a for loop — no fixed buffer, so there is nothing that CAN
    // overflow regardless of window size. This KAT pins that safe shape as a regression guard: it
    // must stay green if `known_blockhashes` is ever "optimized" into a fixed-capacity buffer.
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x7A} ** 32);
    const recipient: [32]u8 = [_]u8{0x90} ** 32;
    // A non-constant-byte pattern (0x50, 0x51, ..., 0x6F) so it can never collide with the window's
    // fill pattern below (each fill entry is a single repeated byte — a 32-distinct-byte hash can't
    // equal any of them).
    const tx_bh: [32]u8 = blk: {
        var h: [32]u8 = undefined;
        for (&h, 0..) |*b, i| b.* = @truncate(i +% 0x50);
        break :blk h;
    };

    // A window FAR larger than Agave's MAX_RECENT_BLOCKHASHES (150) — 300 unrelated (single-repeated-
    // byte) hashes plus the tx's own hash spliced in at an arbitrary (non-edge) position.
    var window: [300][32]u8 = undefined;
    for (&window, 0..) |*h, i| h.* = [_]u8{@truncate(i)} ** 32;
    window[173] = tx_bh;

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    ex.known_blockhashes = &window; // 300 entries, no panic iterating any length.
    try ex.seedAccount(kp.public_key.bytes, .{ .lamports = 1_000_000_000 });

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, tx_bh, 1_000, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expect(r.wasProcessed()); // present in the oversized window → processes, no panic.

    // Same oversized window, tx's hash absent → deterministically dropped_invalid (not a crash).
    window[173] = [_]u8{0xEE} ** 32; // overwrite the ONLY occurrence — tx_bh's non-constant pattern
    // cannot reappear anywhere else in the constant-byte fill.
    const r2 = ex.executeAndCommit(parsed, wire); // (dup sig, but blockhash-age is checked first)
    try testing.expectEqual(block_executor.Outcome.dropped_invalid, r2.outcome);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP A (2026-07-19) — LOAD-ON-DEMAND executor: the live-wiring seam. The offline STEP-1/3 tests
// pre-seed the whole parent via seedAccount; the LIVE path instead supplies a read-only load_fn that
// fetches a touched account from accounts_db into the overlay on first use (block_executor.zig
// materialize). These KATs drive that path against an in-memory backing store standing in for
// accounts_db and prove: (a) touched accounts materialize + execute exactly as if pre-seeded;
// (b) the ISOLATION crux — commits land only in the overlay, the backing store is byte-unchanged (an
// aborted produce cannot corrupt parent_bank); (c) the overlay is the LAST-WRITER — an account an
// earlier same-block tx debited is NOT re-loaded, so a drain chain accumulates correctly.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// In-memory stand-in for accounts_db: pubkey → Account. `load` mirrors getAccountInSlot semantics
/// (returns null when the account is absent OR holds zero lamports — Agave AccountNotFound).
const BackingStore = struct {
    map: std.AutoHashMapUnmanaged([32]u8, Account) = .{},
    a: std.mem.Allocator,
    /// Count of load calls — lets a test assert the overlay-first invariant (no re-load of a written acct).
    loads: usize = 0,

    fn put(self: *BackingStore, key: [32]u8, acct: Account) !void {
        try self.map.put(self.a, key, acct);
    }
    fn deinit(self: *BackingStore) void {
        self.map.deinit(self.a);
    }
    /// The load_fn the executor calls: read-only, null on absent/zero-lamport (getAccountInSlot parity).
    fn load(ctx: ?*anyopaque, pubkey: [32]u8) ?Account {
        const self: *BackingStore = @ptrCast(@alignCast(ctx.?));
        self.loads += 1;
        const acct = self.map.get(pubkey) orelse return null;
        if (acct.lamports == 0) return null;
        return acct;
    }
};

test "load-on-demand: touched accounts materialize + execute; backing store UNCHANGED (isolation crux)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x81} ** 32);
    const recipient: [32]u8 = [_]u8{0x8A} ** 32;
    const bh: [32]u8 = [_]u8{0x3B} ** 32;
    const amount: u64 = 1_000_000;
    const payer_start: u64 = 5_000_000;
    const recip_start: u64 = 2_000_000;

    var store = BackingStore{ .a = a };
    defer store.deinit();
    try store.put(kp.public_key.bytes, .{ .lamports = payer_start });
    try store.put(recipient, .{ .lamports = recip_start });

    // Executor is NOT pre-seeded — it reaches the accounts purely via the load_fn backing.
    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    ex.load_ctx = &store;
    ex.load_fn = BackingStore.load;

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, amount, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);
    const fee = block_produce.txFee(parsed, wire);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expect(r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.included_ok, r.outcome);

    // Overlay carries the committed post-state (materialized then mutated).
    try testing.expectEqual(payer_start - fee - amount, ex.getLamports(kp.public_key.bytes).?);
    try testing.expectEqual(recip_start + amount, ex.getLamports(recipient).?);
    try testing.expectEqual(@as(u64, 1), ex.signatureCount());

    // ISOLATION: the backing store (the "parent bank") is byte-unchanged — commits never leaked out.
    try testing.expectEqual(payer_start, store.map.get(kp.public_key.bytes).?.lamports);
    try testing.expectEqual(recip_start, store.map.get(recipient).?.lamports);
}

test "load-on-demand: fee-payer absent in backing store → dropped_not_loaded (null load = NotLoaded)" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x82} ** 32);
    const recipient: [32]u8 = [_]u8{0x8B} ** 32;
    const bh: [32]u8 = [_]u8{0x3C} ** 32;

    var store = BackingStore{ .a = a };
    defer store.deinit();
    // Only the recipient exists; the fee-payer is absent → load returns null → NotLoaded.
    try store.put(recipient, .{ .lamports = 1_000_000 });

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    ex.load_ctx = &store;
    ex.load_fn = BackingStore.load;

    var buf: [512]u8 = undefined;
    const wire = buildTransferTx(kp, recipient, bh, 1_000, &buf);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
    const parsed = try parseWire(wire, &ssig, &skey);

    const r = ex.executeAndCommit(parsed, wire);
    try testing.expect(!r.wasProcessed());
    try testing.expectEqual(block_executor.Outcome.dropped_not_loaded, r.outcome);
    try testing.expectEqual(@as(u64, 0), ex.signatureCount());
    try testing.expectEqual(@as(?u64, null), ex.getLamports(kp.public_key.bytes)); // never materialized.
}

test "load-on-demand: drain chain — overlay is LAST-WRITER, a debited fee-payer is NOT re-loaded" {
    const a = testing.allocator;
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0x83} ** 32);
    const r1: [32]u8 = [_]u8{0x8C} ** 32;
    const r2: [32]u8 = [_]u8{0x8D} ** 32;
    const bh: [32]u8 = [_]u8{0x3D} ** 32;

    // P is funded to afford EXACTLY tx1 (fee + amount) and land at the rent-exempt floor. If materialize
    // wrongly RE-LOADED P from the backing store on tx2, P would reset to its full start balance and tx2
    // would process (double-spend). Overlay-as-last-writer ⇒ tx2 sees P at the floor ⇒ NotLoaded.
    const amount1: u64 = 1_000_000;
    const p_start: u64 = block_produce.RENT_EXEMPT_MIN_ZERO + LPS + amount1; // enough for tx1 only.

    var store = BackingStore{ .a = a };
    defer store.deinit();
    try store.put(kp.public_key.bytes, .{ .lamports = p_start });
    try store.put(r1, .{ .lamports = 0 });
    try store.put(r2, .{ .lamports = 0 });

    var ex = BlockExecutor.init(a);
    defer ex.deinit();
    ex.load_ctx = &store;
    ex.load_fn = BackingStore.load;

    var b1: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    const w1 = buildTransferTx(kp, r1, bh, amount1, &b1);
    const w2 = buildTransferTx(kp, r2, bh, 1_000, &b2);
    var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;

    const p1 = try parseWire(w1, &ssig, &skey);
    const o1 = ex.executeAndCommit(p1, w1);
    try testing.expect(o1.wasProcessed()); // tx1 lands.
    try testing.expectEqual(block_produce.RENT_EXEMPT_MIN_ZERO, ex.getLamports(kp.public_key.bytes).?); // P at floor.
    const loads_after_tx1 = store.loads;

    const p2 = try parseWire(w2, &ssig, &skey);
    const o2 = ex.executeAndCommit(p2, w2);
    try testing.expect(!o2.wasProcessed()); // tx2 DROPS — P is at the floor, can't afford tx2 (no re-load).
    try testing.expectEqual(block_executor.Outcome.dropped_not_loaded, o2.outcome);
    try testing.expectEqual(block_produce.RENT_EXEMPT_MIN_ZERO, ex.getLamports(kp.public_key.bytes).?); // unchanged.
    // Overlay-first invariant: tx2 did NOT re-load P (already in overlay). It may load r2 (a fresh touch).
    try testing.expect(store.loads <= loads_after_tx1 + 1);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP 3 — PRODUCE→REPLAY parity harness: produce a block via the executor hook on produceSlotBytes,
// replay the packed bytes via the SAME executor from the same parent, assert byte-identical bank_hash
// + zero dead blocks + the drain-chain correctness case (RED on the legacy delta gate, GREEN on the
// executor). The executor IS the replay reference here (see block_executor.zig honest boundary).
// ════════════════════════════════════════════════════════════════════════════════════════════════

const SeededAccount = struct { pubkey: [32]u8, acct: Account };

/// A 2-SIGNER System transfer: keys [P(fee-payer,signer0,writable), X(signer1,writable), Sys], one
/// instruction transferring `amount` from X (idx 1) to P (idx 0). This is the THIRD-PARTY-MOVER shape
/// the delta gate mishandles: applyLamportEffects sees `from`(X) != fee-payer(P), credits P
/// OPTIMISTICALLY without verifying X can afford it. Both P and X sign the message.
fn buildTransfer2Signer(fee_payer: std.crypto.sign.Ed25519.KeyPair, from: std.crypto.sign.Ed25519.KeyPair, blockhash: [32]u8, amount: u64, out: []u8) []u8 {
    var mpos: usize = 1 + 128; // compactU16(2 sigs)=0x02, then 2×64-byte signatures.
    const msg_start = mpos;
    out[mpos] = 2; // num_required_signatures
    out[mpos + 1] = 0; // num_readonly_signed
    out[mpos + 2] = 1; // num_readonly_unsigned (system program)
    mpos += 3;
    out[mpos] = 3; // 3 account keys
    mpos += 1;
    @memcpy(out[mpos..][0..32], &fee_payer.public_key.bytes); // [0] P (fee-payer, signer, writable, = to)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &from.public_key.bytes); // [1] X (signer, writable, = from)
    mpos += 32;
    @memcpy(out[mpos..][0..32], &SYSTEM_ID); // [2] system program
    mpos += 32;
    @memcpy(out[mpos..][0..32], &blockhash);
    mpos += 32;
    out[mpos] = 1; // 1 instruction
    mpos += 1;
    out[mpos] = 2; // program_id_index = 2 (system)
    mpos += 1;
    out[mpos] = 2; // 2 account indices
    mpos += 1;
    out[mpos] = 1; // from = X (account index 1)
    out[mpos + 1] = 0; // to = P (account index 0)
    mpos += 2;
    out[mpos] = 12; // 12 data bytes
    mpos += 1;
    std.mem.writeInt(u32, out[mpos..][0..4], 2, .little); // Transfer
    mpos += 4;
    std.mem.writeInt(u64, out[mpos..][0..8], amount, .little);
    mpos += 8;
    const message = out[msg_start..mpos];
    const sig_p = fee_payer.sign(message, null) catch unreachable;
    const sig_x = from.sign(message, null) catch unreachable;
    out[0] = 2; // compactU16: 2 signatures
    @memcpy(out[1..][0..64], &sig_p.toBytes()); // signer[0] = fee-payer
    @memcpy(out[65..][0..64], &sig_x.toBytes()); // signer[1] = X
    return out[0..mpos];
}

/// Seed a BlockExecutor from a parent snapshot.
fn seedExec(ex: *BlockExecutor, snapshot: []const SeededAccount) !void {
    for (snapshot) |s| try ex.seedAccount(s.pubkey, s.acct);
}

const Mode = enum { legacy, executor };
const ProduceReplay = struct {
    packed_count: usize,
    any_dead_block: bool,
    produce_bank_hash: Hash, // meaningful in executor mode (produce-side executor freeze).
    replay_bank_hash: Hash,
};

/// A trivially-true admit for the executor mode (bypassed because gate.execute != null).
fn admitStubTrue(_: *anyopaque, _: []const u8) bool {
    return true;
}

/// Legacy admit: the REAL whitelist+delta gate (admitTxSeq) against a frozen-parent FeePayerView map —
/// exactly bankAdmitTxForBroadcast's decision. Ctx carries the parent view + running SeqGateState.
const LegacyCtx = struct {
    parent_view: *const std.AutoHashMapUnmanaged([32]u8, block_produce.FeePayerView),
    state: *block_produce.SeqGateState,
    known: []const [32]u8,
    a: std.mem.Allocator,
    fn admit(ctx: *anyopaque, wire: []const u8) bool {
        const self: *LegacyCtx = @ptrCast(@alignCast(ctx));
        var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest.parse(wire, &ssig, &skey) catch return false;
        const fpv = self.parent_view.get(parsed.signer_keys[0]);
        return block_produce.admitTxSeq(self.a, self.state, parsed, wire, self.known, fpv);
    }
};

/// Executor mode ctx: the produce-side BlockExecutor. Its `execute` hook executes-and-commits each
/// candidate and returns was_processed — the pack decision.
const ExecCtx = struct {
    ex: *BlockExecutor,
    fn execute(ctx: *anyopaque, wire: []const u8) bool {
        const self: *ExecCtx = @ptrCast(@alignCast(ctx));
        var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
        const parsed = tx_ingest.parse(wire, &ssig, &skey) catch return false;
        return self.ex.executeAndCommit(parsed, wire).wasProcessed();
    }
};

/// Produce a block from `mempool` (priority = order, mempool[0] highest) in `mode`, then REPLAY the
/// packed bytes via a fresh executor seeded from the SAME `snapshot`. Returns packed count, whether
/// any packed tx is NotLoaded on replay (a dead block), and the two bank_hashes.
fn produceAndReplay(a: std.mem.Allocator, snapshot: []const SeededAccount, mempool: []const []const u8, mode: Mode, parent_hash: Hash, recent_blockhash: [32]u8) !ProduceReplay {
    const seed: Hash = [_]u8{0x5E} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    for (mempool, 0..) |w, idx| try banking.queueTransaction(w, @intCast(mempool.len - idx), false, .tpu);

    // Build the gate for the chosen mode.
    const known = [_][32]u8{recent_blockhash};
    var produce_exec = BlockExecutor.init(a);
    defer produce_exec.deinit();
    produce_exec.known_blockhashes = &known; // arm blockhash-age validation.
    try seedExec(&produce_exec, snapshot);
    var exec_ctx = ExecCtx{ .ex = &produce_exec };

    var parent_view: std.AutoHashMapUnmanaged([32]u8, block_produce.FeePayerView) = .{};
    defer parent_view.deinit(a);
    for (snapshot) |s| try parent_view.put(a, s.pubkey, .{ .lamports = s.acct.lamports, .owner = s.acct.owner, .data_len = 0 });
    var seq_state = block_produce.SeqGateState{};
    defer seq_state.deinit(a);
    var legacy_ctx = LegacyCtx{ .parent_view = &parent_view, .state = &seq_state, .known = &known, .a = a };

    const gate: block_produce.InclusionGate = switch (mode) {
        .legacy => .{ .ctx = &legacy_ctx, .admit = LegacyCtx.admit },
        .executor => .{ .ctx = &exec_ctx, .admit = admitStubTrue, .exec_ctx = &exec_ctx, .execute = ExecCtx.execute },
    };

    var blockhash: Hash = undefined;
    const bytes = try block_produce.produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, gate, block_produce.MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // REPLAY: walk the packed entries; execute each packed tx via a fresh executor from the same parent.
    var replay_exec = BlockExecutor.init(a);
    defer replay_exec.deinit();
    replay_exec.known_blockhashes = &known;
    try seedExec(&replay_exec, snapshot);

    var packed_count: usize = 0;
    var any_dead_block = false;
    const count = try block_produce.readEntryCount(bytes);
    var offset: usize = 8;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try block_produce.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            // one tx per entry; find its blob length by matching against a mempool wire.
            var blob_len: usize = 0;
            for (mempool) |w| {
                if (h.txs_offset + w.len <= bytes.len and std.mem.eql(u8, w, bytes[h.txs_offset..][0..w.len])) {
                    blob_len = w.len;
                    break;
                }
            }
            try testing.expect(blob_len > 0); // every packed tx must be one of our mempool wires.
            const blob = bytes[h.txs_offset..][0..blob_len];
            var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = try tx_ingest.parse(blob, &ssig, &skey);
            const rr = replay_exec.executeAndCommit(parsed, blob);
            if (!rr.wasProcessed()) any_dead_block = true; // packed but NotLoaded on replay = dead block.
            packed_count += 1;
            offset = h.txs_offset + blob_len;
        } else {
            offset = h.txs_offset;
        }
    }

    return .{
        .packed_count = packed_count,
        .any_dead_block = any_dead_block,
        .produce_bank_hash = produce_exec.bankHash(&parent_hash, &blockhash),
        .replay_bank_hash = replay_exec.bankHash(&parent_hash, &blockhash),
    };
}

test "PRODUCE-PARITY GREEN core: mixed System-transfer mempool — every tx lands, zero dead blocks, produce==replay bank_hash" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x5A} ** 32;
    const parent_hash: Hash = [_]u8{0xAB} ** 32;
    const N = 5;
    var kps: [N]std.crypto.sign.Ed25519.KeyPair = undefined;
    var recipients: [N][32]u8 = undefined;
    var bufs: [N][512]u8 = undefined;
    var wires: [N][]const u8 = undefined;
    var snap_buf: [2 * N]SeededAccount = undefined;
    var sn: usize = 0;
    var sb: u8 = 0x20;
    for (0..N) |i| {
        kps[i] = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{sb} ** 32);
        sb += 1;
        recipients[i] = [_]u8{sb} ** 32;
        sb += 1;
        const amount: u64 = 1_000_000 * @as(u64, i + 1);
        wires[i] = buildTransferTx(kps[i], recipients[i], bh, amount, &bufs[i]);
        snap_buf[sn] = .{ .pubkey = kps[i].public_key.bytes, .acct = .{ .lamports = 100_000_000 } };
        sn += 1;
        snap_buf[sn] = .{ .pubkey = recipients[i], .acct = .{ .lamports = 0 } };
        sn += 1;
    }
    const snapshot = snap_buf[0..sn];
    var mempool: [N][]const u8 = undefined;
    for (0..N) |i| mempool[i] = wires[i];

    const r = try produceAndReplay(a, snapshot, &mempool, .executor, parent_hash, bh);
    try testing.expectEqual(@as(usize, N), r.packed_count); // all mixed txs land (throughput preserved).
    try testing.expect(!r.any_dead_block); // block ⊆ was_processed.
    // produce-via-executor == replay-via-executor, byte-for-byte (inclusion == execution).
    try testing.expectEqualSlices(u8, &r.produce_bank_hash, &r.replay_bank_hash);

    // Determinism: a second identical run yields the identical bank_hash.
    const r2 = try produceAndReplay(a, snapshot, &mempool, .executor, parent_hash, bh);
    try testing.expectEqualSlices(u8, &r.replay_bank_hash, &r2.replay_bank_hash);
}

test "PRODUCE-PARITY RED→GREEN: third-party-mover drain chain — legacy delta gate DEAD-BLOCKS, executor is clean" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x7C} ** 32;
    const parent_hash: Hash = [_]u8{0xDC} ** 32;

    const p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xA1} ** 32); // fee-payer of A and B
    const x = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xB2} ** 32); // third-party `from` in A
    const y: [32]u8 = [_]u8{0xC3} ** 32; // recipient of B

    // A: 2-signer transfer X→P of 1_000_000, fee-payer P. X is funded with only 100 (< 1_000_000) so
    //    A's instruction FAILS on real execution — P is NOT credited. B: P→Y transfer, fee-payer P.
    // P is funded with exactly the rent-exempt floor + A's fee (2 sigs × 5000 = 10_000): it LOADS for A
    //    (passing the gate's rent-exempt floor), but after A's fee P sits at exactly RENT_EXEMPT_MIN,
    //    so it can NOT afford B's fee-plus-rent-floor ⇒ NotLoaded. The legacy delta gate credits P
    //    OPTIMISTICALLY from A (never checking third-party X), admits B, and packs a DEAD block; the
    //    executor executes A for real, sees P undrained-but-only-rent-exempt, and DROPS B — a clean,
    //    dead-block-free block of just [A].
    const fee_a: u64 = 2 * LPS;
    const p_fund: u64 = block_produce.RENT_EXEMPT_MIN_ZERO + fee_a;
    var buf_a: [512]u8 = undefined;
    var buf_b: [512]u8 = undefined;
    const wire_a = buildTransfer2Signer(p, x, bh, 1_000_000, &buf_a);
    const wire_b = buildTransferTx(p, y, bh, 1_000, &buf_b);
    const mempool = [_][]const u8{ wire_a, wire_b }; // A highest priority.

    const snapshot = [_]SeededAccount{
        .{ .pubkey = p.public_key.bytes, .acct = .{ .lamports = p_fund } }, // rent floor + A's fee.
        .{ .pubkey = x.public_key.bytes, .acct = .{ .lamports = 100 } }, // cannot afford A's transfer.
        .{ .pubkey = y, .acct = .{ .lamports = 0 } },
    };

    // RED — legacy whitelist+delta gate: admits both, packs a block the cluster marks dead.
    const red = try produceAndReplay(a, &snapshot, &mempool, .legacy, parent_hash, bh);
    std.debug.print("[PRODUCE-PARITY-RED] legacy: packed={d} any_dead_block={}\n", .{ red.packed_count, red.any_dead_block });
    try testing.expectEqual(@as(usize, 2), red.packed_count); // A + B both packed (B on optimistic credit).
    try testing.expect(red.any_dead_block); // B is NotLoaded on replay → DEAD BLOCK (the bug).

    // GREEN — executor: A executes (instruction fails, fee paid → included), P drained to 0, B dropped.
    const green = try produceAndReplay(a, &snapshot, &mempool, .executor, parent_hash, bh);
    std.debug.print("[PRODUCE-PARITY-GREEN] executor: packed={d} any_dead_block={}\n", .{ green.packed_count, green.any_dead_block });
    try testing.expectEqual(@as(usize, 1), green.packed_count); // only A packed; B correctly dropped.
    try testing.expect(!green.any_dead_block); // no dead block.
    try testing.expectEqualSlices(u8, &green.produce_bank_hash, &green.replay_bank_hash); // produce==replay.
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// STEP C (2026-07-19) — accounts-db-SHAPED produce-parity: the WIRED shape end to end. STEP 3 above
// pre-seeds the whole parent via seedExec (an in-memory map, byte-identical result but not the shape
// the LIVE loader uses). STEP C instead sources BOTH the produce-side and replay-side executors from
// ONE shared BackingStore via `load_fn` — the SAME load-on-demand path bankLoadAccountForBroadcast
// wires (data=&.{}, null on absent — accounts_db `getAccountInSlot` semantics) — and builds the
// legacy gate's parent_view from the IDENTICAL store, mirroring bankAdmitTxForBroadcast reading the
// same accounts_db-backed parent. produce_exec/replay_exec are fresh per call; the store itself is
// read-only (load_fn never mutates it — the STEP-A isolation KATs already prove this), so calling
// this helper twice against the same store (once legacy, once executor) is safe.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Same shape as `produceAndReplay` (STEP 3) but sourced from a shared `BackingStore` via load-on-
/// demand instead of a pre-seeded snapshot. `packed_flags` (len == mempool.len, caller-zeroed) is set
/// true at index `i` iff `mempool[i]` appears in the produced block — lets a test assert the packed
/// set at per-tx granularity (not just the aggregate count).
fn produceAndReplayLOD(a: std.mem.Allocator, store: *BackingStore, mempool: []const []const u8, mode: Mode, parent_hash: Hash, recent_blockhash: [32]u8, packed_flags: []bool) !ProduceReplay {
    const seed: Hash = [_]u8{0x5F} ** 32;
    const hpt: u64 = 64;
    const tps: u64 = 64;

    var banking = banking_stage.BankingStage.init(a, .{});
    defer banking.deinit();
    for (mempool, 0..) |w, idx| try banking.queueTransaction(w, @intCast(mempool.len - idx), false, .tpu);

    const known = [_][32]u8{recent_blockhash};
    var produce_exec = BlockExecutor.init(a);
    defer produce_exec.deinit();
    produce_exec.known_blockhashes = &known;
    produce_exec.load_ctx = store;
    produce_exec.load_fn = BackingStore.load;
    var exec_ctx = ExecCtx{ .ex = &produce_exec };

    // Legacy parent_view mirrors the SAME accounts_db-backed parent (data_len = a.data.len, which is 0
    // for every BackingStore entry here — matching the live loader's `data=&.{}` shape exactly): the
    // legacy gate and the executor read the IDENTICAL backing store, not two different fixtures.
    var parent_view: std.AutoHashMapUnmanaged([32]u8, block_produce.FeePayerView) = .{};
    defer parent_view.deinit(a);
    var store_it = store.map.iterator();
    while (store_it.next()) |e| {
        try parent_view.put(a, e.key_ptr.*, .{ .lamports = e.value_ptr.lamports, .owner = e.value_ptr.owner, .data_len = e.value_ptr.data.len });
    }
    var seq_state = block_produce.SeqGateState{};
    defer seq_state.deinit(a);
    var legacy_ctx = LegacyCtx{ .parent_view = &parent_view, .state = &seq_state, .known = &known, .a = a };

    const gate: block_produce.InclusionGate = switch (mode) {
        .legacy => .{ .ctx = &legacy_ctx, .admit = LegacyCtx.admit },
        .executor => .{ .ctx = &exec_ctx, .admit = admitStubTrue, .exec_ctx = &exec_ctx, .execute = ExecCtx.execute },
    };

    var blockhash: Hash = undefined;
    const bytes = try block_produce.produceSlotBytes(a, seed, hpt, tps, &banking, &blockhash, gate, block_produce.MAX_BLOCK_UNITS);
    defer a.free(bytes);

    // REPLAY: a FRESH executor over the SAME backing store (load-on-demand, read-only — isolation
    // holds, so replay sees the identical parent state the produce side saw, never a mutated one).
    var replay_exec = BlockExecutor.init(a);
    defer replay_exec.deinit();
    replay_exec.known_blockhashes = &known;
    replay_exec.load_ctx = store;
    replay_exec.load_fn = BackingStore.load;

    var packed_count: usize = 0;
    var any_dead_block = false;
    const count = try block_produce.readEntryCount(bytes);
    var offset: usize = 8;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const h = try block_produce.readEntryHeader(bytes, offset);
        if (h.num_txs > 0) {
            var blob_len: usize = 0;
            for (mempool, 0..) |w, mi| {
                if (h.txs_offset + w.len <= bytes.len and std.mem.eql(u8, w, bytes[h.txs_offset..][0..w.len])) {
                    blob_len = w.len;
                    packed_flags[mi] = true;
                    break;
                }
            }
            try testing.expect(blob_len > 0); // every packed tx must be one of our mempool wires.
            const blob = bytes[h.txs_offset..][0..blob_len];
            var ssig: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
            var skey: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;
            const parsed = try tx_ingest.parse(blob, &ssig, &skey);
            const rr = replay_exec.executeAndCommit(parsed, blob);
            if (!rr.wasProcessed()) any_dead_block = true; // packed but NotLoaded on replay = dead block.
            packed_count += 1;
            offset = h.txs_offset + blob_len;
        } else {
            offset = h.txs_offset;
        }
    }

    return .{
        .packed_count = packed_count,
        .any_dead_block = any_dead_block,
        .produce_bank_hash = produce_exec.bankHash(&parent_hash, &blockhash),
        .replay_bank_hash = replay_exec.bankHash(&parent_hash, &blockhash),
    };
}

test "PRODUCE-PARITY accounts-db-SHAPED RED→GREEN: mixed mempool (3 payers + drain chain + absent + insufficient-fee) over a shared load-on-demand backing store" {
    const a = testing.allocator;
    const bh: [32]u8 = [_]u8{0x9B} ** 32;
    const parent_hash: Hash = [_]u8{0x9C} ** 32;

    // Three independent fee-payers (p1, p2, P — P also fee-pays the drain-chain B) satisfy "≥3 payers".
    const p1 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE1} ** 32);
    const p2 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE3} ** 32);
    const p = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE5} ** 32); // drain-chain fee-payer
    const x = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE6} ** 32); // drain-chain third-party mover
    const absent_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE8} ** 32); // never in the store
    const insuff_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic([_]u8{0xE9} ** 32); // in the store, can't pay

    const r1: [32]u8 = [_]u8{0xE2} ** 32;
    const r2: [32]u8 = [_]u8{0xE4} ** 32;
    const y: [32]u8 = [_]u8{0xE7} ** 32; // drain-chain B's recipient
    const r_absent: [32]u8 = [_]u8{0xEB} ** 32;
    const r_insuff: [32]u8 = [_]u8{0xEC} ** 32;

    // Drain-chain funding (same shape as the STEP 3 RED→GREEN test): P loads for A (rent-exempt floor
    // + A's 2-sig fee) but X can't afford A's transfer → A's instruction fails (fee retained, P ends
    // at exactly the rent floor) → B (P→Y) can't afford its own fee-plus-floor → NotLoaded.
    const fee_a: u64 = 2 * LPS;
    const p_fund: u64 = block_produce.RENT_EXEMPT_MIN_ZERO + fee_a;

    var store = BackingStore{ .a = a };
    defer store.deinit();
    try store.put(p1.public_key.bytes, .{ .lamports = 50_000_000 });
    try store.put(r1, .{ .lamports = 0 });
    try store.put(p2.public_key.bytes, .{ .lamports = 30_000_000 });
    try store.put(r2, .{ .lamports = 0 });
    try store.put(p.public_key.bytes, .{ .lamports = p_fund });
    try store.put(x.public_key.bytes, .{ .lamports = 100 }); // cannot afford A's 1_000_000 transfer.
    try store.put(y, .{ .lamports = 0 });
    // absent_kp deliberately NOT put into the store (dropped_not_loaded: null load = NotLoaded).
    try store.put(insuff_kp.public_key.bytes, .{ .lamports = 1_000 }); // below RENT_EXEMPT_MIN_ZERO+fee.
    try store.put(r_insuff, .{ .lamports = 0 });

    var buf_a: [512]u8 = undefined;
    var buf_b: [512]u8 = undefined;
    var buf_p1: [512]u8 = undefined;
    var buf_p2: [512]u8 = undefined;
    var buf_absent: [512]u8 = undefined;
    var buf_insuff: [512]u8 = undefined;
    const wire_a = buildTransfer2Signer(p, x, bh, 1_000_000, &buf_a);
    const wire_b = buildTransferTx(p, y, bh, 1_000, &buf_b);
    const wire_p1 = buildTransferTx(p1, r1, bh, 1_000_000, &buf_p1);
    const wire_p2 = buildTransferTx(p2, r2, bh, 2_000_000, &buf_p2);
    const wire_absent = buildTransferTx(absent_kp, r_absent, bh, 500, &buf_absent);
    const wire_insuff = buildTransferTx(insuff_kp, r_insuff, bh, 500, &buf_insuff);
    // A before B (priority = mempool order) so the drain-chain sequencing is exercised; the rest are
    // independent and order-agnostic.
    const mempool = [_][]const u8{ wire_a, wire_b, wire_p1, wire_p2, wire_absent, wire_insuff };

    // RED — legacy whitelist+delta gate over the SAME shared store: the drain-chain pair alone (the
    // real bug carrier) is admitted BOTH-not just A-because the delta model credits P from A
    // optimistically without checking whether X can actually afford it.
    var red_flags = [_]bool{false} ** 2;
    const drain_only = [_][]const u8{ wire_a, wire_b };
    const red = try produceAndReplayLOD(a, &store, &drain_only, .legacy, parent_hash, bh, &red_flags);
    std.debug.print("[PRODUCE-PARITY-RED] legacy (accounts-db-shaped): packed={d} any_dead_block={}\n", .{ red.packed_count, red.any_dead_block });
    try testing.expectEqual(@as(usize, 2), red.packed_count); // A + B both packed on the legacy gate.
    try testing.expect(red.any_dead_block); // B is NotLoaded on replay → DEAD BLOCK (the bug, reconfirmed accounts-db-shaped).

    // GREEN — executor over the full MIXED mempool, same shared store.
    var flags = [_]bool{false} ** 6;
    const green = try produceAndReplayLOD(a, &store, &mempool, .executor, parent_hash, bh, &flags);
    std.debug.print("[PRODUCE-PARITY-GREEN] executor (accounts-db-shaped mixed): packed={d} any_dead_block={}\n", .{ green.packed_count, green.any_dead_block });

    // (a) packed set == was_processed set, at per-tx granularity: p1, p2, A packed; B, absent,
    //     insufficient-fee all dropped (NOT packed) — the exact was_processed/dropped split.
    try testing.expect(flags[0]); // A: PROCESSED (instruction failed, fee retained → included_exec_failed).
    try testing.expect(!flags[1]); // B: dropped_not_loaded (P only rent-exempt after A's fee).
    try testing.expect(flags[2]); // p1: included_ok.
    try testing.expect(flags[3]); // p2: included_ok.
    try testing.expect(!flags[4]); // absent: dropped_not_loaded (null load).
    try testing.expect(!flags[5]); // insufficient-fee: dropped_not_loaded.
    try testing.expectEqual(@as(usize, 3), green.packed_count); // p1 + p2 + A only.

    // (c) zero dead outcomes: every packed tx (p1, p2, A) is confirmed was_processed on REPLAY over
    //     the identical shared store — no packed-but-NotLoaded divergence.
    try testing.expect(!green.any_dead_block);

    // (b) produce bank_hash == replay bank_hash byte-for-byte (both executors sourced from the SAME
    //     backing store via load_fn — the wired shape, not just the pre-seeded one).
    try testing.expectEqualSlices(u8, &green.produce_bank_hash, &green.replay_bank_hash);

    // Determinism: a second identical run over the SAME (untouched — isolation) store yields the
    // identical bank_hash.
    var flags2 = [_]bool{false} ** 6;
    const green2 = try produceAndReplayLOD(a, &store, &mempool, .executor, parent_hash, bh, &flags2);
    try testing.expectEqualSlices(u8, &green.replay_bank_hash, &green2.replay_bank_hash);
}
