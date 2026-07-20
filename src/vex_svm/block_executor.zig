//! BlockExecutor — the test-rootable "execute-once-and-record" seam for tx-bearing block production.
//!
//! WHY THIS EXISTS (forensics/txbearing-produce-parity-rootcause.md §3 "Primary recommendation"):
//!   The durable fix for the [PRODUCE-PARITY-FAIL] dead-block class is to converge the produce path
//!   onto Agave's execute-once-and-record model: instead of a hand-rolled pre-filter that PREDICTS
//!   whether a tx will load (block_produce.admitTxSeq's delta simulation + the txFullyModelable
//!   whitelist), ACTUALLY EXECUTE each packing candidate sequentially against a working child state at
//!   produce time and pack a tx IFF it `was_processed()` (Agave consumer.rs:362 / committer.rs). That
//!   makes inclusion == execution STRUCTURALLY — the produced block is a subset of the processed set,
//!   so the cluster's sequential replay can never find a packed tx NotLoaded → no dead block.
//!
//! WHAT THIS MODULE IS:
//!   A self-contained executor over an IN-MEMORY account map (no Bank / AccountsDb / validator graph),
//!   so a KAT can drive the exact produce-time execute+commit decision offline. It dispatches the ONLY
//!   instructions a produce-time executor can run WITHOUT a BPF VM — System Transfer / CreateAccount —
//!   through the SAME `native/system.zig` processor the live replay path uses (via the KAT's system
//!   shim). Any tx it cannot fully execute (non-System program, an unmodeled System discriminator, an
//!   ALT/v0-loaded index, or a fee-payer that can't pay) is DROPPED, never packed — identical
//!   containment to the interim whitelist, but reached by real execution rather than a static guess.
//!
//! HONEST BOUNDARY (do NOT overclaim):
//!   * This is NOT a widening of the admitted instruction set beyond System Transfer/CreateAccount — a
//!     produce-time executor cannot run a BPF program offline, so a non-System tx is still dropped. The
//!     value here is CORRECTNESS (it executes-and-commits, so a later tx sees an earlier tx's REAL
//!     post-state — closing the third-party-mover / drain-chain residual the delta gate mishandles) and
//!     the SEAM (produce and replay can call ONE executor, making produce==replay provable, not asserted).
//!   * The bank_hash primitives are BYTE-MIRRORED from bank.zig (same discipline as
//!     tests/kat_txbearing_exec.zig) to avoid dragging the full Bank module graph into a test root.
//!   * Live wiring (a real accounts_db-backed executor supplied to produceSlotBytes from
//!     replay_stage.zig) is NOT in this module and is NOT compile-verifiable while the node votes — it
//!     is the documented live-enable prerequisite (see forensics/txbearing-fix-report.md PASS 3).
//!
//! Fee / was_processed semantics MATCH Agave (advisor-directed, committer.rs):
//!   - fee-payer can't pay the fee (or isn't loadable)  → NotLoaded → NOT processed → DROP (no fee, no pack).
//!   - fee paid, every instruction succeeds             → PROCESSED → INCLUDE (pack). sig_count += n_sigs.
//!   - fee paid, an instruction FAILS                   → PROCESSED → INCLUDE (pack); the tx's instruction
//!       effects roll back atomically but the FEE IS RETAINED and sig_count still counts (a processed-
//!       with-error tx is included; only a load failure is excluded). signature_count feeds bank_hash
//!       Step1, so this counting is consensus-load-bearing.

const std = @import("std");
const tx_ingest = @import("tx_ingest");
// System processor imported RELATIVELY (not a named "system" module): this lets block_executor.zig join
// the vex_svm module (replay_stage.zig imports it via `@import("block_executor.zig")`) and SHARE
// vex_svm's already-owned native/system.zig — a separate "system" module would double-own that file
// ("file exists in modules 'vex_svm' and 'system'"). native/system.zig needs only `vex_crypto` (named),
// present in every module that roots block_executor (vex_svm live + the test-produce-parity KAT module).
const system = @import("native/system.zig");
const vex_crypto = @import("vex_crypto");
const block_produce = @import("block_produce");
// Relative import (same reasoning as native/system.zig above): runtime.zig only pulls std/vex_crypto/
// types.zig/hashes.zig (no Bank/AccountsDb), so it joins vex_svm's module without dragging in the
// heavy graph the header explicitly avoids. This is the CANONICAL rent-exempt-minimum helper (mirrors
// fd_rent_exempt_minimum_balance(); value-identical to the live-wired integer helper
// instruction_dispatch.rentExemptMinimumBalanceDefault, which is NOT imported here because it drags
// in bank_mod/vex_store/vex_bpf2/vex_bpf).
const runtime = @import("runtime.zig");

const Hash = [32]u8;
const LtHash = vex_crypto.LtHash;
const AccountMeta = system.AccountMeta;
const Pubkey = system.Pubkey;

const SYSTEM_PROGRAM_ID: [32]u8 = [_]u8{0} ** 32;
const SYS_DISC_CREATE_ACCOUNT: u32 = 0; // native/system.zig InstructionOpcodes.CreateAccount
const SYS_DISC_TRANSFER: u32 = 2; //       native/system.zig InstructionOpcodes.Transfer

/// Agave genesis-fixed rent constants (identical testnet/mainnet; same values block_produce.
/// RENT_EXEMPT_MIN_ZERO and instruction_dispatch.rentExemptMinimumBalanceDefault use — see bank.zig:3379).
const RENT_PARAMS_DEFAULT = runtime.RentParams{ .lamports_per_byte_year = 3480, .exemption_threshold = 2.0, .burn_percent = 50 };

// ════════════════════════════════════════════════════════════════════════════════════════════════
// BYTE-MIRRORED bank_hash primitives (the REAL ones live in bank.zig). Identical bodies to
// tests/kat_txbearing_exec.zig's mirror + bank.zig:747/:874 — kept here so the executor is a
// self-contained freeze (produce and replay through THIS module yield a directly comparable hash).
// ════════════════════════════════════════════════════════════════════════════════════════════════

fn accountLtHash(pubkey: *const [32]u8, owner: *const [32]u8, lamports: u64, executable: bool, data: []const u8) LtHash {
    if (lamports == 0) return LtHash.init();
    const executable_flag: u8 = if (executable) 1 else 0;
    var b3 = vex_crypto.blake3.Blake3.init(.{});
    var lamports_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &lamports_le, lamports, .little);
    b3.update(&lamports_le);
    b3.update(data);
    b3.update(&[_]u8{executable_flag});
    b3.update(owner);
    b3.update(pubkey);
    var out: [2048]u8 = undefined;
    b3.final(&out);
    var lt = LtHash.init();
    for (0..1024) |i| lt.elements[i] = std.mem.readInt(u16, out[i * 2 ..][0..2], .little);
    return lt;
}

fn computeBankHash(lthash: *const LtHash, prev_bank_hash: *const Hash, poh_hash: *const Hash, signature_count: u64) Hash {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(prev_bank_hash);
    var sig_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &sig_le, signature_count, .little);
    sha.update(&sig_le);
    sha.update(poh_hash);
    var step1: [32]u8 = undefined;
    sha.final(&step1);

    var sha2 = std.crypto.hash.sha2.Sha256.init(.{});
    sha2.update(&step1);
    var lthash_bytes: [2048]u8 = undefined;
    for (0..1024) |i| std.mem.writeInt(u16, lthash_bytes[i * 2 ..][0..2], lthash.elements[i], .little);
    sha2.update(&lthash_bytes);
    var result: [32]u8 = undefined;
    sha2.final(&result);
    return result;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// The executor.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// One account's committed state in the working child map.
pub const Account = struct {
    lamports: u64,
    owner: [32]u8 = SYSTEM_PROGRAM_ID,
    executable: bool = false,
    /// Account data — borrowed (not owned/freed by the executor); empty for Transfer/CreateAccount(space=0).
    data: []const u8 = &.{},
};

/// The processing outcome for one candidate tx. `wasProcessed()` is the Agave inclusion predicate
/// (block ⊆ was_processed): the producer packs a tx iff this is true.
pub const Outcome = enum {
    included_ok, // processed; every instruction succeeded.
    included_exec_failed, // processed (fee paid + counted); an instruction failed → effects rolled back.
    dropped_not_loaded, // fee-payer absent or can't pay the fee (InsufficientFundsForFee / NotLoaded).
    dropped_unexecutable, // an instruction the executor cannot run (non-System / unmodeled disc / ALT / v0).
    dropped_already_processed, // first signature already committed within the recent window (AlreadyProcessed).
    dropped_invalid, // failed sigverify OR its blockhash is not in the recent window (cluster would reject).
};

pub const ProcessResult = struct {
    outcome: Outcome,
    fee_charged: u64 = 0,

    /// Agave `was_processed()` — the block-inclusion predicate. A processed-with-error tx is included.
    pub fn wasProcessed(self: ProcessResult) bool {
        return self.outcome == .included_ok or self.outcome == .included_exec_failed;
    }
};

pub const BlockExecutor = struct {
    allocator: std.mem.Allocator,
    /// pubkey → committed account state (the working child bank, seeded from the frozen parent).
    map: std.AutoHashMapUnmanaged([32]u8, Account) = .{},
    /// Running signature_count over PROCESSED txs (feeds bank_hash Step1). Matches replay serial counting.
    sig_count: u64 = 0,
    /// Optional cross-block AlreadyProcessed dedup (P1's RecentSigCache), consulted before execution.
    recent_sigs: ?*const block_produce.RecentSigCache = null,
    producing_slot: u64 = 0,
    /// Recent-blockhash window for blockhash-age validation (Agave check_transactions / BlockhashNotFound).
    /// ARMED only when non-empty; the LIVE executor MUST supply it (a stale-blockhash tx the cluster would
    /// reject is otherwise packed → dead block). Empty ⇒ blockhash-age check dormant (unit-probe convenience;
    /// the produce path arms it). Sigverify is ALWAYS enforced regardless (no config).
    known_blockhashes: []const [32]u8 = &.{},

    // ── Load-on-demand backing (the LIVE path — forensics/txbearing-fix-report.md §WIRE-POINT) ────────
    // When `load_fn` is set, an account a candidate tx TOUCHES that is ABSENT from the working overlay
    // `map` is fetched read-only via `load_fn(load_ctx, pubkey)` and inserted into the overlay before it
    // is read or mutated — so the executor never needs the whole parent bank pre-seeded (`seedAccount`
    // stays the offline/KAT path). ISOLATION CRUX: `load_fn` is READ-ONLY against the backing store; all
    // commits (fee debit, transfer effects) land ONLY in `map`, so an aborted produce can never mutate
    // the parent bank. `materialize` consults the overlay FIRST (`map.contains`), so an account already
    // written this block is NEVER re-loaded — the overlay is the last-writer (correct drain-chain state).
    // A null return = the account does not exist at the parent (getAccountInSlot returns null on
    // lamports==0) → treated as absent (fee-payer ⇒ NotLoaded; a touched account ⇒ zero-lamport), exactly
    // as the pre-seed path treats an unseeded key. Live: supplied by replay_stage.zig (accounts_db at the
    // parent slot). null ⇒ pure pre-seed behaviour, byte-identical to pre-load-on-demand.
    load_ctx: ?*anyopaque = null,
    load_fn: ?*const fn (ctx: ?*anyopaque, pubkey: [32]u8) ?Account = null,

    pub fn init(allocator: std.mem.Allocator) BlockExecutor {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BlockExecutor) void {
        self.map.deinit(self.allocator);
    }

    /// Seed a parent-snapshot account into the working map (value-copied; `data` is borrowed).
    pub fn seedAccount(self: *BlockExecutor, pubkey: [32]u8, acct: Account) !void {
        try self.map.put(self.allocator, pubkey, acct);
    }

    /// Ensure `key` is materialized in the working overlay: if it is ABSENT and a load-on-demand backing
    /// is configured, fetch it read-only and insert it. Overlay-first (`map.contains`) so an account
    /// already written this block is never re-loaded (overlay = last-writer). Absent-with-no-loader (or a
    /// null load result) leaves the overlay unchanged — the key is then treated downstream as
    /// zero-lamport / not-loaded, exactly as an unseeded key is on the pre-seed path. Returns true iff a
    /// NEW entry was inserted (used by `executeAndCommit` to un-materialize on a `dropped_not_loaded`
    /// abort — a read-only touch by a tx that never commits must leave zero footprint, matching a real
    /// bank where an uncommitted load never becomes part of the block's write/account set).
    fn materialize(self: *BlockExecutor, key: [32]u8) bool {
        if (self.load_fn == null) return false;
        if (self.map.contains(key)) return false;
        if (self.load_fn.?(self.load_ctx, key)) |acct| {
            self.map.put(self.allocator, key, acct) catch {};
            return true;
        }
        return false;
    }

    /// Undo this tx's `materialize` inserts (called only on a `dropped_not_loaded` abort, AFTER
    /// materialize but before any commit): removes exactly the keys THIS call to `executeAndCommit`
    /// newly inserted, restoring the overlay to its pre-tx membership. Keys already present before this
    /// tx (committed by an earlier tx, or pre-seeded) are untouched — only this tx's own read-only
    /// touches are undone.
    fn unmaterialize(self: *BlockExecutor, newly_materialized: *const std.ArrayListUnmanaged([32]u8)) void {
        for (newly_materialized.items) |k| _ = self.map.remove(k);
    }

    pub fn getLamports(self: *const BlockExecutor, pubkey: [32]u8) ?u64 {
        return if (self.map.get(pubkey)) |a| a.lamports else null;
    }

    pub fn signatureCount(self: *const BlockExecutor) u64 {
        return self.sig_count;
    }

    /// Freeze: bank_hash over the current committed account set (lattice-hash addition is commutative,
    /// so this is order-independent). poh_hash = the produced/replayed blockhash.
    pub fn bankHash(self: *const BlockExecutor, parent_hash: *const Hash, poh_hash: *const Hash) Hash {
        var lt = LtHash.init();
        var it = self.map.iterator();
        while (it.next()) |e| {
            const a = e.value_ptr.*;
            if (a.lamports == 0) continue; // excluded (fd_hashes.c:30-32)
            var leaf = accountLtHash(e.key_ptr, &a.owner, a.lamports, a.executable, a.data);
            lt.wrappingAdd(&leaf);
        }
        return computeBankHash(&lt, parent_hash, poh_hash, self.sig_count);
    }

    /// Resolve a static account index to its 32-byte key (null if it is ALT-loaded, i.e. >= num_keys).
    fn resolveStatic(parsed: tx_ingest.ParsedTx, wire: []const u8, idx: u8) ?[32]u8 {
        if (idx >= parsed.num_keys) return null;
        const off = parsed.keys_offset + @as(usize, idx) * 32;
        if (off + 32 > wire.len) return null;
        var k: [32]u8 = undefined;
        @memcpy(&k, wire[off..][0..32]);
        return k;
    }

    /// A single instruction, resolved to static keys — the executor's canonical unit of work.
    const Ix = struct {
        disc: u32,
        from: [32]u8,
        to: [32]u8,
        /// Transfer/CreateAccount lamports field (data[4..12]).
        lamports: u64,
        /// CreateAccount space (data[12..20]); 0 for Transfer.
        space: u64,
        /// CreateAccount new owner (data[20..52]); undefined for Transfer.
        new_owner: [32]u8,
    };

    /// Pre-scan every instruction and resolve it to an executable `Ix`. Returns null (⇒ tx is DROPPED,
    /// unexecutable) if ANY instruction is not a statically-resolvable System Transfer/CreateAccount
    /// with well-formed data. This is the "can the executor fully process this tx" gate; only if it
    /// returns a full list do we charge the fee and execute — so an unexecutable tx is never packed and
    /// never charged (identical containment to txFullyModelable, reached before any state mutation).
    fn scanInstructions(parsed: tx_ingest.ParsedTx, wire: []const u8, out: *std.ArrayListUnmanaged(Ix), allocator: std.mem.Allocator) bool {
        if (parsed.is_versioned) return false; // v0 may load ALT writable accounts the static list can't resolve.
        var p = parsed.instructions_offset;
        if (p >= wire.len) return true; // zero-instruction tx: trivially processable (nothing to execute).
        const num_ix = readCompactU16(wire, &p) orelse return false;
        var i: u16 = 0;
        while (i < num_ix) : (i += 1) {
            if (p >= wire.len) return false;
            const program_id_index = wire[p];
            p += 1;
            const num_accounts = readCompactU16(wire, &p) orelse return false;
            if (p + num_accounts > wire.len) return false;
            const acct_idx_start = p;
            p += num_accounts;
            const data_len = readCompactU16(wire, &p) orelse return false;
            if (p + data_len > wire.len) return false;
            const data = wire[p..][0..data_len];
            p += data_len;

            const prog_key = resolveStatic(parsed, wire, program_id_index) orelse return false;
            if (!std.mem.eql(u8, &prog_key, &SYSTEM_PROGRAM_ID)) return false;
            if (data_len < 4 or num_accounts < 2) return false;
            const disc = std.mem.readInt(u32, data[0..4], .little);

            // Every account index must be a static (non-ALT) key.
            var k: u16 = 0;
            while (k < num_accounts) : (k += 1) {
                if (wire[acct_idx_start + k] >= parsed.num_keys) return false;
            }
            const from = resolveStatic(parsed, wire, wire[acct_idx_start]) orelse return false;
            const to = resolveStatic(parsed, wire, wire[acct_idx_start + 1]) orelse return false;

            var ix = Ix{ .disc = disc, .from = from, .to = to, .lamports = 0, .space = 0, .new_owner = SYSTEM_PROGRAM_ID };
            switch (disc) {
                SYS_DISC_TRANSFER => {
                    if (data_len < 12) return false; // disc(4) + lamports(8)
                    ix.lamports = std.mem.readInt(u64, data[4..12], .little);
                },
                SYS_DISC_CREATE_ACCOUNT => {
                    if (data_len < 52) return false; // disc(4) + lamports(8) + space(8) + owner(32)
                    ix.lamports = std.mem.readInt(u64, data[4..12], .little);
                    ix.space = std.mem.readInt(u64, data[12..20], .little);
                    @memcpy(&ix.new_owner, data[20..52]);
                },
                else => return false, // an unmodeled System discriminator: cannot execute → drop.
            }
            out.append(allocator, ix) catch return false;
        }
        return true;
    }

    /// Execute one candidate tx sequentially against the working map and COMMIT its effects (Agave
    /// execute-once-and-record). Returns the processing outcome; the caller packs the tx iff
    /// `result.wasProcessed()`. The next candidate then sees this tx's real post-commit state.
    pub fn executeAndCommit(self: *BlockExecutor, parsed: tx_ingest.ParsedTx, wire: []const u8) ProcessResult {
        // (-1) Sigverify + blockhash-age — the checks the static admit gate (checkStaticAndOwner) runs and
        //      that the executor path BYPASSES admit, so they must live here or a stale-blockhash /
        //      invalid-sig tx (the cluster rejects BlockhashNotFound / signature failure) would be packed
        //      → dead block. Sigverify is unconditional; blockhash-age arms when a recent window is supplied.
        if (!tx_ingest.verifySignatures(parsed)) return .{ .outcome = .dropped_invalid };
        if (self.known_blockhashes.len > 0) {
            if (parsed.instructions_offset < 32 or parsed.instructions_offset > wire.len) return .{ .outcome = .dropped_invalid };
            const bh = wire[parsed.instructions_offset - 32 ..][0..32];
            var known = false;
            for (self.known_blockhashes) |h| {
                if (std.mem.eql(u8, &h, bh)) {
                    known = true;
                    break;
                }
            }
            if (!known) return .{ .outcome = .dropped_invalid };
        }

        // (0) Cross-block AlreadyProcessed dedup (P1) — a tx whose first signature was committed in the
        //     recent window is dropped BEFORE any state mutation (the cluster would mark us dead).
        if (self.recent_sigs) |rsc| {
            if (rsc.isRecent(&parsed.signatures[0], self.producing_slot)) return .{ .outcome = .dropped_already_processed };
        }

        // (1) Resolve every instruction; drop the WHOLE tx (no fee, no pack) if any is unexecutable.
        var ixs: std.ArrayListUnmanaged(Ix) = .{};
        defer ixs.deinit(self.allocator);
        if (!scanInstructions(parsed, wire, &ixs, self.allocator)) return .{ .outcome = .dropped_unexecutable };

        // (1b) Load-on-demand: materialize every account this tx TOUCHES from the backing store into the
        //      working overlay before it is read or mutated (no-op when the overlay is pre-seeded or no
        //      loader is set). The fee-payer is materialized UNCONDITIONALLY (a zero-instruction tx still
        //      charges the fee → still needs the payer loaded); then each instruction's from/to. Overlay-
        //      first, so an account an earlier same-block tx already committed is not re-loaded (drain-chain
        //      correctness). This is the ONLY read path against the backing store — commits stay in `map`.
        //      Newly-inserted keys are tracked so a subsequent `dropped_not_loaded` abort (2) can undo
        //      them: a read-only touch by a tx that never commits must leave the overlay byte-identical
        //      to before the touch (a real bank never records an uncommitted load as part of its account
        //      set) — otherwise produce (which attempts every candidate) and replay (which only re-runs
        //      the PACKED subset) would materialize different account sets from the same store and diverge
        //      on `bankHash` even though neither actually committed anything different.
        var newly_materialized: std.ArrayListUnmanaged([32]u8) = .{};
        defer newly_materialized.deinit(self.allocator);
        if (self.materialize(parsed.signer_keys[0])) newly_materialized.append(self.allocator, parsed.signer_keys[0]) catch {};
        for (ixs.items) |ix| {
            if (self.materialize(ix.from)) newly_materialized.append(self.allocator, ix.from) catch {};
            if (self.materialize(ix.to)) newly_materialized.append(self.allocator, ix.to) catch {};
        }

        // (2) Load the fee-payer (signer[0]) and charge the fee. Can't-pay ⇒ NotLoaded ⇒ drop. Agave
        //     requires the fee-payer to remain RENT-EXEMPT after the fee (validate_fee_payer), and the
        //     rent-exempt minimum depends on the payer's ACTUAL data length — a 0-data floor
        //     (block_produce.RENT_EXEMPT_MIN_ZERO) UNDER-counts a fee-payer that carries data (e.g. a
        //     stake-sized account), which could admit a tx Agave's validate_fee_payer would reject
        //     (dead block). So the floor is computed from `fp_entry.data.len` via the canonical
        //     exempt-minimum-balance helper (runtime.RentParams.exemptMinBalance — same genesis-fixed
        //     constants as block_produce.RENT_EXEMPT_MIN_ZERO / instruction_dispatch.
        //     rentExemptMinimumBalanceDefault; value-identical to RENT_EXEMPT_MIN_ZERO at data_len=0).
        //     This is CONSERVATIVE vs Agave's "may go to exactly zero when closed" exception (we drop
        //     that case): dropping a loadable tx is a throughput loss, never a dead block.
        const fp_key = parsed.signer_keys[0];
        const fee = block_produce.txFee(parsed, wire);
        const fp_entry = self.map.getPtr(fp_key) orelse {
            self.unmaterialize(&newly_materialized);
            return .{ .outcome = .dropped_not_loaded };
        };
        const fp_rent_min = RENT_PARAMS_DEFAULT.exemptMinBalance(fp_entry.data.len);
        if (fp_entry.lamports < fp_rent_min + fee) {
            self.unmaterialize(&newly_materialized);
            return .{ .outcome = .dropped_not_loaded };
        }
        fp_entry.lamports -= fee; // fee committed — never rolled back, even on instruction failure.
        self.sig_count += parsed.num_required_sigs; // consensus-load-bearing (bank_hash Step1).

        // (3) Snapshot every touched account's post-fee state so a failed instruction rolls the WHOLE
        //     tx's instruction effects back atomically (the fee stays debited).
        var snap: std.ArrayListUnmanaged(SnapEntry) = .{};
        defer snap.deinit(self.allocator);
        for (ixs.items) |ix| {
            self.snapshotIfAbsent(&snap, ix.from);
            self.snapshotIfAbsent(&snap, ix.to);
        }

        // (4) Execute instructions in wire order against the live map.
        var exec_failed = false;
        for (ixs.items) |ix| {
            if (!self.applyInstruction(ix)) {
                exec_failed = true;
                break;
            }
        }

        // (5) On any instruction failure, roll back all instruction effects (fee retained).
        if (exec_failed) {
            for (snap.items) |s| self.map.put(self.allocator, s.key, s.acct) catch {};
            return .{ .outcome = .included_exec_failed, .fee_charged = fee };
        }
        return .{ .outcome = .included_ok, .fee_charged = fee };
    }

    const SnapEntry = struct { key: [32]u8, acct: Account };

    fn snapshotIfAbsent(self: *BlockExecutor, snap: *std.ArrayListUnmanaged(SnapEntry), key: [32]u8) void {
        for (snap.items) |s| if (std.mem.eql(u8, &s.key, &key)) return;
        const cur = self.map.get(key) orelse Account{ .lamports = 0 };
        snap.append(self.allocator, .{ .key = key, .acct = cur }) catch {};
    }

    /// Dispatch one resolved System instruction through the REAL native/system.zig processor, writing
    /// committed state back into the map. Returns false on an instruction error (→ whole-tx rollback).
    fn applyInstruction(self: *BlockExecutor, ix: Ix) bool {
        const from_acct = self.map.get(ix.from) orelse Account{ .lamports = 0 };
        const to_acct = self.map.get(ix.to) orelse Account{ .lamports = 0 };
        var from = toMeta(ix.from, from_acct);
        var to = toMeta(ix.to, to_acct);
        switch (ix.disc) {
            SYS_DISC_TRANSFER => {
                system.executeTransfer(&from, &to, ix.lamports) catch return false;
            },
            SYS_DISC_CREATE_ACCOUNT => {
                system.executeCreateAccount(&from, &to, ix.lamports, ix.space, Pubkey.init(ix.new_owner)) catch return false;
            },
            else => return false,
        }
        // Commit the processor's post-state back to the map.
        self.writeBack(ix.from, from);
        self.writeBack(ix.to, to);
        return true;
    }

    fn toMeta(key: [32]u8, a: Account) AccountMeta {
        return .{
            .pubkey = Pubkey.init(key),
            .lamports = a.lamports,
            .owner = Pubkey.init(a.owner),
            .executable = a.executable,
            .rent_epoch = 0,
            .data = @constCast(a.data),
        };
    }

    fn writeBack(self: *BlockExecutor, key: [32]u8, m: AccountMeta) void {
        const existing = self.map.get(key) orelse Account{ .lamports = 0 };
        self.map.put(self.allocator, key, .{
            .lamports = m.lamports,
            .owner = m.owner.data,
            .executable = m.executable,
            .data = existing.data, // executor does not grow account data (space=0 KAT scope).
        }) catch {};
    }
};

/// Local compact-u16 (shortvec) reader — same shape as tx_ingest.readCompactU16 / block_produce's
/// readCompactU16Wire. Returns null on truncation so a malformed instruction stream drops the tx.
fn readCompactU16(data: []const u8, pos: *usize) ?u16 {
    var val: u32 = 0;
    var shift: u5 = 0;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        if (pos.* >= data.len) return null;
        const byte = data[pos.*];
        pos.* += 1;
        val |= @as(u32, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) return @intCast(val & 0xffff);
        shift += 7;
    }
    return @intCast(val & 0xffff);
}
