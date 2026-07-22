//! P5 MOAT #2 — bank_hash Divergence ALARM: the pure 4-input LOCALIZER engine.
//!
//! MILESTONE: M1 — the OFFLINE localization core (this file). The LIVE always-on
//! alarm thread + freeze-tap enqueue is M2 (design sketch in §M2 below); M1 wires
//! NOTHING into the live replay hot path. This module is std-only, allocation-free,
//! and has ZERO dependency on the validator — it is a passive analyzer.
//!
//! WHAT THIS IS: `classify()` — the block-vs-execution discriminator of design §2,
//! promoted from the manual `/drift-localizer` skill to a native, KAT-covered pure
//! function. Given our slot's 4 bank_hash inputs (from the FlightRecord / the
//! [BANK-FROZEN] log line, bank.zig:4925) and the cluster's canonical inputs (public
//! testnet RPC oracle: getBlock blockhash + Σ signatures; oracle-node bank-hash-details
//! bank_hash — read-only, never a Vexor flag pointed at the oracle), it names the
//! FIRST input that diverged in the fixed precedence:
//!
//!   1 parent_hash   → PARENT         (divergence is upstream — re-anchor at parent)
//!   2 poh_hash      → BLOCK_CONTENT  (different entries replayed — shred/FEC/AF_XDP)
//!   3 signature_cnt → SIG_ACCOUNTING (sig-count accounting bug)
//!   4 accounts_lt   → EXECUTION      (account-state divergence — go to per-account diff)
//!
//! bank_hash = computeBankHash(parent_hash, signature_count, poh_hash, accounts_lt_hash)
//! (bank.zig:4513). The lt_hash is NOT exposed on RPC, so an EXECUTION carrier is
//! confirmed BY ELIMINATION (parent ok + poh ok + sigs ok ⇒ the diff is in execution)
//! and then localized to the exact account+field+owner by the offline re-replay +
//! per-account lt_hash diff (design §3) — that account-naming step is driven by the
//! wrapper `tools/divergence-localize.sh` (reuses vex-slot-diff.sh / per-pk analyzer),
//! NOT by this pure function. This function names the CLASS; the wrapper names the ACCOUNT.
//!
//! XOR-cancellation guard (feedback_xor_cancellation): the precedence reports the first
//! DIVERGING input even when bank_hash coincidentally matches, so a masked input diff is
//! never hidden.

const std = @import("std");

/// A 32-byte hash (bank_hash / parent_hash / poh_hash / lthash-digest).
pub const Hash32 = [32]u8;

/// Per-input compare outcome. `unknown` = the oracle did not (or cannot) supply this
/// input, so it is neither a match nor a miss — for lt_hash this is the normal state
/// (not on RPC → confirmed by elimination).
pub const Match = enum { match, differ, unknown };

/// The named carrier class — the design §2 discriminator output.
pub const CarrierClass = enum {
    /// No realized divergence: every AVAILABLE input matched (and bank_hash, if the
    /// oracle supplied it, matched). The known-good / M1-test verdict.
    convergent,
    /// parent_hash diverged → the divergence is upstream; walk back to the parent.
    parent,
    /// poh_hash diverged → we replayed different block entries (shred/FEC/AF_XDP-race).
    block_content,
    /// signature_count diverged → sig-count accounting bug (rare; vote/dedup).
    sig_accounting,
    /// parent+poh+sigs all matched but bank_hash differs → account-state divergence.
    /// Trigger the per-account lt_hash diff to name the exact account+field+owner.
    execution,
    /// Contradiction: every available input matched, yet bank_hash differs. Should be
    /// impossible (bank_hash is a pure function of the inputs); flags a tooling/oracle
    /// gap (e.g. a missing input the oracle couldn't supply). Surfaced, never hidden.
    inconsistent,

    pub fn asStr(self: CarrierClass) []const u8 {
        return switch (self) {
            .convergent => "CONVERGENT",
            .parent => "PARENT",
            .block_content => "BLOCK_CONTENT",
            .sig_accounting => "SIG_ACCOUNTING",
            .execution => "EXECUTION",
            .inconsistent => "INCONSISTENT",
        };
    }
};

/// Our side: the 4 bank_hash inputs read off the FROZEN bank (the FlightRecord /
/// [BANK-FROZEN] log line). `lthash_digest` is the blake3(2048-byte accounts_lt_hash)
/// digest that bank.zig:4921 emits as `lthash_full` (the raw 2048B lives in the
/// FlightRecord; the digest is what the log carries and what a human eyeballs).
pub const FlightInputs = struct {
    slot: u64,
    bank_hash: Hash32,
    parent_hash: Hash32,
    signature_count: u64,
    poh_hash: Hash32,
    lthash_digest: Hash32,
};

/// Cluster canonical, as far as it is observable. Every field is optional because the
/// oracle supplies different subsets depending on what is reachable:
///   - `parent_matches`: TRANSITIVE — the parent slot's own alarm verdict (did the
///     parent's bank_hash match the cluster?). null when the parent hasn't been checked.
///   - `poh_hash`: getBlock(S).blockhash, base58→bytes (decoded by the caller/wrapper).
///   - `signature_count`: Σ signatures over getBlock(S) txs (summed the way Agave does).
///   - `bank_hash`: oracle-node agave-ledger-tool bank-hash-details (RULE #2 cross-check,
///     read-only). null when oracle-node is not consulted — EXECUTION is then by elimination.
/// The lt_hash is intentionally absent: the cluster does not expose it over RPC.
pub const OracleInputs = struct {
    parent_matches: ?bool = null,
    poh_hash: ?Hash32 = null,
    signature_count: ?u64 = null,
    bank_hash: ?Hash32 = null,
};

/// The classifier's structured output. The wrapper turns this into verdict.json and
/// then (for EXECUTION) appends the account/field/owner from the per-account diff.
pub const Verdict = struct {
    class: CarrierClass,
    parent: Match,
    poh: Match,
    sigs: Match,
    /// lt_hash is never a direct compare (not on RPC) — `unknown` unless class==execution,
    /// in which case it is the by-elimination carrier (`differ`).
    lthash: Match,
    /// True when the class is one the design says to re-anchor at the parent and re-run.
    reanchor_parent: bool,
    /// True when the class needs the §3 offline re-replay + per-account diff to be *named*
    /// (EXECUTION). PARENT/BLOCK_CONTENT/SIG_ACCOUNTING are named without the account diff.
    needs_account_diff: bool,
};

fn eqlHash(a: Hash32, b: Hash32) bool {
    return std.mem.eql(u8, &a, &b);
}

/// The pure 4-input discriminator — design §2, fixed precedence. Names the FIRST input
/// that diverges. Runs in nanoseconds, no allocation, no I/O; safe to call on the alarm
/// thread (M2) or a CLI (M1). See module header for the precedence and semantics.
pub fn classify(f: FlightInputs, o: OracleInputs) Verdict {
    // Per-input compare outcomes (unknown when the oracle didn't supply the field).
    const parent_m: Match = if (o.parent_matches) |pm| (if (pm) .match else .differ) else .unknown;
    const poh_m: Match = if (o.poh_hash) |ph| (if (eqlHash(f.poh_hash, ph)) .match else .differ) else .unknown;
    const sigs_m: Match = if (o.signature_count) |sc| (if (f.signature_count == sc) .match else .differ) else .unknown;
    const bank_differs: ?bool = if (o.bank_hash) |bh| !eqlHash(f.bank_hash, bh) else null;

    var v = Verdict{
        .class = .convergent,
        .parent = parent_m,
        .poh = poh_m,
        .sigs = sigs_m,
        .lthash = .unknown,
        .reanchor_parent = false,
        .needs_account_diff = false,
    };

    // Fixed precedence — the FIRST diverging input names the class (design §2 table).
    if (parent_m == .differ) {
        v.class = .parent;
        v.reanchor_parent = true;
        return v;
    }
    if (poh_m == .differ) {
        v.class = .block_content;
        return v;
    }
    if (sigs_m == .differ) {
        v.class = .sig_accounting;
        return v;
    }
    // parent+poh+sigs all match-or-unknown. Resolve on bank_hash (elimination).
    if (bank_differs) |differs| {
        if (differs) {
            // bank_hash differs but no earlier input did → the diff is in execution
            // (accounts_lt_hash) BY ELIMINATION — the exact-account localizer (§3) runs.
            v.class = .execution;
            v.lthash = .differ;
            v.needs_account_diff = true;
            return v;
        }
        // bank_hash matches and no input diverged → truly convergent.
        v.class = .convergent;
        return v;
    }
    // No canonical bank_hash to eliminate against.
    //  - If SOME input was actually compared and all matched → convergent-by-available.
    //  - If NOTHING was compared at all (all unknown) → still convergent (nothing to fire on).
    v.class = .convergent;
    return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// §M2 (design sketch only — NOT built in M1)
// ─────────────────────────────────────────────────────────────────────────────
// The LIVE always-on alarm (M2) wraps THIS pure classifier with:
//   1. Freeze-tap enqueue at replay_stage.zig:3828 (right after putFlightRecord),
//      gated on a new `diverge_alarm_enabled` bool set in setVexLedgerFlight from
//      VEX_DIVERGE_ALARM=1. A single non-blocking 40-byte SPSC push {slot,bank_hash};
//      the replay thread NEVER does RPC/replay/blocking (design §1.1, §5.1 invariant).
//   2. A dedicated low-priority alarm thread pinned OFF the consensus cores that drains
//      the ring, lazily polls the public-testnet-RPC oracle for rooted-lag slots
//      (≤1 call/2s, jittered — design §1.3), applies the §1.4 false-positive guards
//      (rooted-both-sides, debounce, first-divergent walk-back, latch), and calls
//      classify() above.
//   3. On an EXECUTION verdict, SPAWNS A CHILD PROCESS for the offline re-replay
//      (VEX_SNAPSHOT_OFFLINE + VEX_LEDGER_REPLAY=<S>:<K> + VEX_FREEZE_DUMP_SLOT) —
//      exactly what `tools/divergence-localize.sh` (M1) already orchestrates — never
//      replaying in-process, so the live node is never blocked (design §3.1, §5.2).
// classify() and Verdict are the stable seam between M1 (offline tool) and M2 (live
// thread): M2 adds the tap + thread + oracle client; the localization logic is shared.
//
// FORMAT-COMPAT (design §5.3): MOAT #2 adds NO new on-disk record type — it is purely a
// CONSUMER of the P5 #1 FlightRecord (KIND_FLIGHT=12 / KIND_BANK_HASH=13). A public
// VexLedger reader that does not understand the alarm simply skips those KINDs; the alarm
// is non-invasive to the ledger format. M1 touches no ledger write path at all.

// ═════════════════════════════════ KATs ═════════════════════════════════════
// Design §5.4 item 4: the classifier truth-table — each of the 4 inputs flipped in turn
// must yield the correct class, precedence must hold, and unknown oracle fields must not
// fire. (Debounce/latch/first-divergent-walk-back are M2 thread concerns, sketched above.)

const testing = std.testing;

fn h(byte: u8) Hash32 {
    return [_]u8{byte} ** 32;
}

/// A baseline where every one of our 4 inputs equals the cluster's — the convergent case.
fn convergentPair() struct { f: FlightInputs, o: OracleInputs } {
    const f = FlightInputs{
        .slot = 420_859_999,
        .bank_hash = h(0xBB),
        .parent_hash = h(0xAA),
        .signature_count = 128,
        .poh_hash = h(0xCC),
        .lthash_digest = h(0xDD),
    };
    const o = OracleInputs{
        .parent_matches = true,
        .poh_hash = h(0xCC),
        .signature_count = 128,
        .bank_hash = h(0xBB),
    };
    return .{ .f = f, .o = o };
}

test "convergent: all four inputs + bank_hash match → CONVERGENT (the known-good verdict)" {
    const p = convergentPair();
    const v = classify(p.f, p.o);
    try testing.expectEqual(CarrierClass.convergent, v.class);
    try testing.expectEqual(Match.match, v.parent);
    try testing.expectEqual(Match.match, v.poh);
    try testing.expectEqual(Match.match, v.sigs);
    try testing.expect(!v.needs_account_diff);
    try testing.expect(!v.reanchor_parent);
}

test "flip parent → PARENT + re-anchor" {
    const p = convergentPair();
    var o = p.o;
    o.parent_matches = false;
    const v = classify(p.f, o);
    try testing.expectEqual(CarrierClass.parent, v.class);
    try testing.expect(v.reanchor_parent);
    try testing.expectEqual(Match.differ, v.parent);
}

test "flip poh → BLOCK_CONTENT" {
    const p = convergentPair();
    var o = p.o;
    o.poh_hash = h(0x99); // cluster PoH ≠ ours
    const v = classify(p.f, o);
    try testing.expectEqual(CarrierClass.block_content, v.class);
    try testing.expectEqual(Match.differ, v.poh);
    try testing.expect(!v.needs_account_diff);
}

test "flip sig_count → SIG_ACCOUNTING" {
    const p = convergentPair();
    var o = p.o;
    o.signature_count = 129;
    const v = classify(p.f, o);
    try testing.expectEqual(CarrierClass.sig_accounting, v.class);
    try testing.expectEqual(Match.differ, v.sigs);
}

test "flip bank_hash only (parent/poh/sigs match) → EXECUTION by elimination + needs account diff" {
    const p = convergentPair();
    var f = p.f;
    f.bank_hash = h(0x77); // our bank_hash ≠ canonical, but the 3 named inputs still match
    const v = classify(f, p.o);
    try testing.expectEqual(CarrierClass.execution, v.class);
    try testing.expectEqual(Match.differ, v.lthash);
    try testing.expect(v.needs_account_diff);
}

test "precedence: parent beats poh beats sigs beats bank when several diverge at once" {
    const p = convergentPair();
    var f = p.f;
    var o = p.o;
    // Diverge ALL of them; the earliest in precedence must win.
    o.parent_matches = false;
    o.poh_hash = h(0x11);
    o.signature_count = 999;
    f.bank_hash = h(0x22);
    try testing.expectEqual(CarrierClass.parent, classify(f, o).class);

    // Now parent matches → poh should win.
    o.parent_matches = true;
    try testing.expectEqual(CarrierClass.block_content, classify(f, o).class);

    // poh matches too → sigs should win.
    o.poh_hash = p.f.poh_hash;
    try testing.expectEqual(CarrierClass.sig_accounting, classify(f, o).class);

    // sigs match too → bank/execution.
    o.signature_count = p.f.signature_count;
    try testing.expectEqual(CarrierClass.execution, classify(f, o).class);
}

test "unknown oracle fields do not fire (null everywhere → CONVERGENT, nothing to compare)" {
    const p = convergentPair();
    const o = OracleInputs{}; // all null
    const v = classify(p.f, o);
    try testing.expectEqual(CarrierClass.convergent, v.class);
    try testing.expectEqual(Match.unknown, v.parent);
    try testing.expectEqual(Match.unknown, v.poh);
    try testing.expectEqual(Match.unknown, v.sigs);
}

test "partial oracle: only bank_hash available and it matches → CONVERGENT" {
    const p = convergentPair();
    const o = OracleInputs{ .bank_hash = h(0xBB) };
    try testing.expectEqual(CarrierClass.convergent, classify(p.f, o).class);
}

test "XOR-cancellation guard: bank_hash coincidentally matches but poh differs → still BLOCK_CONTENT" {
    const p = convergentPair();
    var o = p.o;
    o.poh_hash = h(0x42); // real block-content divergence…
    // …yet bank_hash left matching (the masked/cancelled case). The precedence must
    // still surface the poh diff rather than declaring convergent.
    const v = classify(p.f, o);
    try testing.expectEqual(CarrierClass.block_content, v.class);
}
