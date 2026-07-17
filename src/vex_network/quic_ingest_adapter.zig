//! QUIC TPU-ingest → BankingStage adapter (2026-06-15).
//!
//! Connects the dormant QUIC TPU-ingest path to the transaction mempool:
//!
//!   SolanaTpuQuic (raw []const u8 on stream FIN)
//!       → QuicIngestAdapter.onTransaction
//!           → tx_ingest.parse   (validate wire well-formedness, no AccountsDb needed)
//!           → BankingStage.queueTransaction (deep-copies the raw bytes into the priority queue)
//!
//! WHY this seam (and NOT tpu.zig): tpu.zig declares its callback as
//! `fn(?*anyopaque, runtime.transaction.ParsedTransaction) void`, but the types
//! `runtime.transaction.ParsedTransaction` / `TransactionParser` are NOT defined anywhere in the
//! tree (grep-confirmed: the only references are tpu.zig's own). tpu.zig is an orphan built on
//! phantom types that has never compiled against the real `vex_svm`. So we wire the working seam
//! that DOES exist: `SolanaTpuQuic.setTransactionCallback` hands raw wire bytes on FIN, and
//! `BankingStage.queueTransaction(tx_data, cu_price, is_vote, source)` already stores RAW bytes
//! (deep-copied) in its priority queue. The adapter is the small piece between them.
//!
//! This module is DORMANT: nothing in main.zig / the live validator startup constructs or installs
//! it. It is consensus-safe (no replay/voting/bank path touched). It exists to be installed onto a
//! `SolanaTpuQuic` server when block production drives the QUIC ingest path, and is gated by the
//! QUIC loopback integration KAT in solana_quic.zig.
//!
//! Parsing choice (mainnet-honest, not a stub): we parse the wire form with `tx_ingest.parse` to
//! REJECT malformed transactions before they reach the mempool (a real validator does not enqueue
//! garbage), then enqueue the RAW bytes — banking_stage stores raw bytes, exactly like Agave's
//! banking stage holds packets. Priority derivation (ComputeBudget cu_price, vote detection) is a
//! follow-up: today we enqueue at base priority (cu_price=0, is_vote=false). The header-only parser
//! does NOT resolve address-table lookups and does NOT touch AccountsDb, so it is safe to run on the
//! ingest thread with no bank state.

const std = @import("std");
const banking_stage = @import("banking_stage");
const tx_ingest = @import("tx_ingest");
const compute_budget = @import("compute_budget");

const BankingStage = banking_stage.BankingStage;

pub const AdapterError = error{
    /// The QUIC bytes did not parse as a well-formed Solana transaction.
    Malformed,
};

/// Stateless bridge from a `SolanaTpuQuic` raw-bytes callback to a `BankingStage` queue.
///
/// Construct one bound to the live `BankingStage`, then install it on the QUIC server with
/// `quic_server.setTransactionCallback(&adapter, QuicIngestAdapter.onTransaction)`.
pub const QuicIngestAdapter = struct {
    banking: *BankingStage,

    /// Count of txs the adapter rejected as malformed before enqueue (observability; not consensus).
    rejected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(banking: *BankingStage) QuicIngestAdapter {
        return .{ .banking = banking };
    }

    /// The `SolanaTpuQuic` transaction callback. Signature matches
    /// `fn(ctx: ?*anyopaque, data: []const u8) void`. `data` is a view into the QUIC stream's
    /// receive buffer and is NOT owned — `queueTransaction` deep-copies it, so it is safe to let
    /// the QUIC layer reuse/free the buffer immediately after this returns.
    pub fn onTransaction(ctx: ?*anyopaque, data: []const u8) void {
        const self: *QuicIngestAdapter = @ptrCast(@alignCast(ctx orelse return));
        self.ingest(data) catch |err| {
            // Dropped at ingest: malformed wire or queue full. A dropped tx is not a consensus
            // event (the cluster will route it elsewhere); count it and move on.
            switch (err) {
                error.Malformed => _ = self.rejected.fetchAdd(1, .monotonic),
                else => {}, // QueueFull etc. — banking_stage already bumped its dropped stat.
            }
        };
    }

    /// Parse-validate the wire bytes, then enqueue the RAW bytes into the banking-stage mempool.
    /// Returns the same errors a real ingest path would surface so callers/tests can assert them.
    pub fn ingest(self: *QuicIngestAdapter, data: []const u8) !void {
        var scratch_sigs: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
        var scratch_keys: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;

        // Validate well-formedness (signature count, header, signer-key bounds). We intentionally do
        // NOT sigverify here — sigverify is a separate, parallelizable stage; the mempool's job is to
        // hold candidate txs. Rejecting only structurally-malformed bytes mirrors banking-stage intake.
        const parsed = tx_ingest.parse(data, &scratch_sigs, &scratch_keys) catch return error.Malformed;

        // Rank by the tx's declared ComputeBudget price (micro-lamports/CU); 0 if it sets none. The
        // mempool then orders higher-fee txs first for the next leader block. Votes arrive on the
        // dedicated tpu_vote path, so is_vote stays false on this general-TPU ingest seam.
        const cu_price = compute_budget.parseComputeUnitPriceFromWire(
            data,
            parsed.keys_offset,
            parsed.num_keys,
            parsed.instructions_offset,
        );

        // banking_stage deep-copies `data`; ownership of the QUIC buffer stays with the caller.
        try self.banking.queueTransaction(data, cu_price, false, .tpu);
    }
};
