//! Compute Budget Program instruction parser — priority fee extraction.
//!
//! r40.5 — extract per-tx priority fee from ComputeBudget program instructions
//! so they accumulate into bank.priority_fees (already wired into settleFees at
//! bank.zig:1248-1252 for fees_to_leader).
//!
//! @prov:compute-budget.priority-fee — full Agave 4.1.0-rc.1 citation trail
//! (crate versions, file:line, re-verification history) in PROVENANCE.md.

const std = @import("std");

/// Compute Budget Program ID: ComputeBudget111111111111111111111111111111
pub const COMPUTE_BUDGET_PROG_ID: [32]u8 = .{
    0x03, 0x06, 0x46, 0x6f, 0xe5, 0x21, 0x17, 0x32,
    0xff, 0xec, 0xad, 0xba, 0x72, 0xc3, 0x9b, 0xe7,
    0xbc, 0x8c, 0xe5, 0xbb, 0xc5, 0xf7, 0x12, 0x6b,
    0x2c, 0x43, 0x9b, 0x3a, 0x40, 0x00, 0x00, 0x00,
};

// r71-fix-3 (2026-04-28): builtin program IDs per Agave 4.1.0-rc.1 (re-cited from the
// stale 4.0-beta.7 label at module-20 migration time; same table, zero drift)
// builtins-default-costs/src/lib.rs BUILTIN_INSTRUCTION_COSTS table.
// Each builtin ix contributes 3,000 CU to the default cu_limit when no
// explicit SetComputeUnitLimit instruction is present (vs 200,000 for
// non-builtin BPF programs). Bytes verified against vex_svm/executor.zig:51-115
// (already production-tested).
//
// Stake / AddressLookupTable / Config are NOT in Agave's default-cu-limit
// builtin set despite being native programs — they're treated as non-builtin
// (200,000 default) per Agave 4.1.0-rc.1 (module-10's builtin_cu_costs.zig migration
// independently re-confirmed stake/config/ALT are absent from rc.1's
// MIGRATING_BUILTINS_COSTS/NON_MIGRATING_BUILTINS_COSTS entirely — core-BPF-migrated
// away; this file's narrower "non-builtin default" framing for those 3 remains
// consistent with that finding). Vote is migrating but feature
// `bls_pubkey_management_in_vote_account` (2uxQgtKa2ECHGs67Zdj7dgmzn2w9HiqhdcedwCWfYzzq)
// re-verified INACTIVE at module-20 migration time (2026-07-06, testnet epoch 985 per
// the public cluster oracle — getAccountInfo on the feature pubkey returns null; stale
// citation was "epoch 949") → Vote still classifies as builtin, same as the stale
// citation's conclusion, only the epoch number was out of date.

/// System program (11111111111111111111111111111111).
const SYSTEM_PROG_ID: [32]u8 = [_]u8{0} ** 32;

/// BPFLoader1111111111111111111111111111111111
/// r71-fix-7-followup: bytes verified via `base58.b58decode(b58str).hex()`,
/// replaces wrong bytes copy-pasted from executor.zig:51-115 (which had a
/// template-copy bug — 4 of 9 builtins shared the same wrong bytes 8-27,
/// only differing in byte 27). CLAUDE.md HARD RULE: never hand-type pubkey
/// bytes; always derive from base58.
const BPF_LOADER_1_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6b,
    0xbd, 0x23, 0x95, 0x85, 0x5f, 0x64, 0x04, 0xd9,
    0xb4, 0xf4, 0x56, 0xb7, 0x82, 0x1b, 0xb0, 0x14,
    0x57, 0x49, 0x42, 0x8c, 0x00, 0x00, 0x00, 0x00,
};

/// BPFLoader2111111111111111111111111111111111
const BPF_LOADER_2_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0x6e,
    0x39, 0x5a, 0xe1, 0x28, 0x94, 0x8f, 0xfa, 0x69,
    0x56, 0x93, 0x37, 0x68, 0x18, 0xdd, 0x47, 0x43,
    0x52, 0x21, 0xf3, 0xc6, 0x00, 0x00, 0x00, 0x00,
};

/// BPFLoaderUpgradeab1e11111111111111111111111
const BPF_UPGRADEABLE_PROG_ID: [32]u8 = .{
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0,
    0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2,
    0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
};

/// LoaderV4111111111111111111111111111111111111
const LOADER_V4_PROG_ID: [32]u8 = .{
    0x05, 0x12, 0xb4, 0x11, 0x51, 0x51, 0xe3, 0x7a,
    0xad, 0x0a, 0x8b, 0xc5, 0xd3, 0x88, 0x2e, 0x7b,
    0x7f, 0xda, 0x4c, 0xf3, 0xd2, 0xc0, 0x28, 0xc8,
    0xcf, 0x83, 0x36, 0x18, 0x00, 0x00, 0x00, 0x00,
};

/// Ed25519SigVerify111111111111111111111111111
const ED25519_PRECOMPILE_ID: [32]u8 = .{
    0x03, 0x7d, 0x46, 0xd6, 0x7c, 0x93, 0xfb, 0xbe,
    0x12, 0xf9, 0x42, 0x8f, 0x83, 0x8d, 0x40, 0xff,
    0x05, 0x70, 0x74, 0x49, 0x27, 0xf4, 0x8a, 0x64,
    0xfc, 0xca, 0x70, 0x44, 0x80, 0x00, 0x00, 0x00,
};

/// KeccakSecp256k11111111111111111111111111111
const SECP256K1_PRECOMPILE_ID: [32]u8 = .{
    0x04, 0xc6, 0xfc, 0x20, 0xf0, 0x50, 0xcc, 0xf0,
    0x55, 0x84, 0xd7, 0x21, 0x1c, 0x9f, 0x8c, 0xf5,
    0x9e, 0xc1, 0x47, 0x85, 0xbb, 0x16, 0x6a, 0x1e,
    0x28, 0x30, 0xe8, 0x12, 0x20, 0x00, 0x00, 0x00,
};

/// Secp256r1SigVerify1111111111111111111111111 (SIMD-0075)
const SECP256R1_PRECOMPILE_ID: [32]u8 = .{
    0x06, 0x92, 0x0d, 0xec, 0x2f, 0xea, 0x71, 0xb5,
    0xb7, 0x23, 0x81, 0x4d, 0x74, 0x2d, 0xa9, 0x03,
    0x1c, 0x83, 0xe7, 0x5f, 0xdb, 0x79, 0x5d, 0x56,
    0x8e, 0x75, 0x47, 0x80, 0x20, 0x00, 0x00, 0x00,
};

/// Vote111111111111111111111111111111111111111
const VOTE_PROG_ID: [32]u8 = .{
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
};

/// Returns true if `program_id` is in Agave's BUILTIN_INSTRUCTION_COSTS table
/// for default-cu-limit allocation purposes (3,000 CU vs 200,000 for non-builtin).
fn isBuiltinForBudget(program_id: *const [32]u8) bool {
    if (std.mem.eql(u8, program_id, &SYSTEM_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &COMPUTE_BUDGET_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &BPF_LOADER_1_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &BPF_LOADER_2_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &BPF_UPGRADEABLE_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &LOADER_V4_PROG_ID)) return true;
    if (std.mem.eql(u8, program_id, &ED25519_PRECOMPILE_ID)) return true;
    if (std.mem.eql(u8, program_id, &SECP256K1_PRECOMPILE_ID)) return true;
    if (std.mem.eql(u8, program_id, &VOTE_PROG_ID)) return true;
    return false;
}

/// Agave: solana-program-runtime-4.0.0-beta.7/src/execution_budget.rs
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
pub const MICRO_LAMPORTS_PER_LAMPORT: u64 = 1_000_000;

/// Discriminators per Agave solana-compute-budget-interface-3.0.0/src/lib.rs:
///   0 = Unused (deprecated, reserved)
///   1 = RequestHeapFrame(u32) — irrelevant to fee calc, but feeds heapSize()/
///       calculateHeapCost() below (fix/cu-parity-batch2)
///   2 = SetComputeUnitLimit(u32)
///   3 = SetComputeUnitPrice(u64) — micro-lamports per CU
///   4 = SetLoadedAccountsDataSizeLimit(u32) — irrelevant to fee calc
/// Iterate instructions of a parsed tx; extract explicit compute_unit_limit +
/// compute_unit_price (both Optional). Caller resolves defaults.
///
/// Generic over instruction type — accepts any struct with `program_id_index: u8`
/// and `data: []const u8` fields, and any account_keys slice that yields [32]u8
/// per index.
/// fix/compute-budget-parse-p1 (2026-07-19) — the 3 P1 parse-layer divergences vs
/// Agave's `ComputeBudgetInstructionDetails::try_from` +
/// `sanitize_and_convert_to_compute_budget_limits`
/// (compute-budget-instruction/src/compute_budget_instruction_details.rs, Agave
/// 4.3.0-alpha.1 — re-checked against 4.2.0-beta.1's copy, byte-identical logic).
/// All 3 are, in Agave, a whole-TRANSACTION sanitize-time rejection: the error is
/// produced while constructing `RuntimeTransaction`/`TransactionMeta`, BEFORE fee
/// determination or execution — the transaction cannot appear committed (not even
/// fee-only) in a block an honest Agave leader produced. @prov:compute-budget.sanitize
pub const SanitizeError = error{
    /// Two compute-budget instructions of the SAME kind (RequestHeapFrame /
    /// SetComputeUnitLimit / SetComputeUnitPrice / SetLoadedAccountsDataSizeLimit).
    /// Agave: TransactionError::DuplicateInstruction(index) (index = the SECOND
    /// occurrence's instruction index).
    DuplicateInstruction,
    /// Empty/too-short instruction data for the recognized discriminator, OR
    /// discriminator 0 ("Unused", reserved) / >=5 (undefined) — Agave's borsh
    /// `try_from_slice_unchecked` fails or lands on an unhandled variant.
    /// ALSO covers an out-of-[MIN_HEAP_FRAME_BYTES,MAX_HEAP_FRAME_BYTES]-or-
    /// non-1024-multiple RequestHeapFrame VALUE (Agave's separate
    /// `sanitize_requested_heap_size` check inside `sanitize_and_convert_to_
    /// compute_budget_limits` — same `TransactionError::InstructionError(index,
    /// InstructionError::InvalidInstructionData)` error class, just raised later).
    InvalidInstructionData,
};

pub const ComputeBudgetParsed = struct {
    /// Set if SetComputeUnitLimit instruction present
    explicit_limit: ?u32 = null,
    /// Set if SetComputeUnitPrice instruction present (micro-lamports per CU)
    explicit_price: ?u64 = null,
    /// Set if RequestHeapFrame instruction present (raw requested byte count,
    /// pre-sanitization — see heapSize() for the Agave-matching clamp/default).
    explicit_heap_bytes: ?u32 = null,
    /// Instruction index of the RequestHeapFrame instruction that set
    /// `explicit_heap_bytes` above (only meaningful when that field is non-null) —
    /// needed to attribute a post-loop invalid-heap-VALUE sanitize error (checked
    /// once the full instruction scan completes, mirroring Agave's
    /// `sanitize_and_convert_to_compute_budget_limits`) to the right index.
    explicit_heap_ix: u8 = 0,
    /// Set if SetLoadedAccountsDataSizeLimit instruction present (raw
    /// requested byte value, pre-sanitization — see loadedAccountsDataSizeLimit()).
    explicit_loaded_accounts_data_size: ?u32 = null,
    /// Count of instructions whose program is in Agave's BUILTIN_INSTRUCTION_COSTS
    /// table — used in default-cu-limit calculation at 3,000 CU per ix.
    builtin_count: u32 = 0,
    /// Count of instructions whose program is non-builtin (BPF) — 200,000 CU each.
    non_builtin_count: u32 = 0,
    /// fix/compute-budget-parse-p1: non-null iff Agave would reject this WHOLE
    /// transaction at sanitize time (see SanitizeError doc). First-occurrence-wins
    /// (mirrors Agave's `?`-short-circuit in `ComputeBudgetInstructionDetails::
    /// try_from` — process_instruction returns on the FIRST bad instruction; later
    /// instructions are still scanned here to preserve the existing counting
    /// fields' behavior for callers that don't check this field, but the reported
    /// error/index is always the first one, matching what Agave itself would
    /// report). NOT wired into any reject path yet — replay never sees this shape
    /// (an honest Agave leader never produces it); the produce/admit path
    /// (block_produce.zig admitTx/admitTxSeq) is the intended future consumer once
    /// its txFullyModelable whitelist is relaxed to admit ComputeBudget-bearing
    /// txs (tracked follow-up, see compute-budget-p1-fixes-2026-07-19.md).
    sanitize_error: ?SanitizeError = null,
    /// Instruction index the error above pertains to. Agave's own `index` field is
    /// a `u8` (`process_instruction(index: u8, ...)`, called via `i as u8`) — same
    /// narrow width + wrap-on-overflow, though real txs never approach 256 ixs.
    sanitize_error_ix: u8 = 0,
};

/// True iff `parsed.sanitize_error` is set — i.e. Agave would reject this whole
/// transaction before fee determination or execution. Convenience wrapper for
/// future admit-path callers (see ComputeBudgetParsed.sanitize_error doc).
pub fn hasSanitizeError(parsed: ComputeBudgetParsed) bool {
    return parsed.sanitize_error != null;
}

pub fn parseInstructions(
    instructions: anytype,
    account_keys: []const [32]u8,
) ComputeBudgetParsed {
    var out = ComputeBudgetParsed{};
    for (instructions, 0..) |ix, ix_idx_usize| {
        const ix_idx: u8 = @truncate(ix_idx_usize);
        if (ix.program_id_index >= account_keys.len) {
            out.non_builtin_count +|= 1;
            continue;
        }
        const program_id = &account_keys[ix.program_id_index];
        const is_cb = std.mem.eql(u8, program_id, &COMPUTE_BUDGET_PROG_ID);
        if (isBuiltinForBudget(program_id)) {
            out.builtin_count +|= 1;
        } else {
            out.non_builtin_count +|= 1;
        }
        if (!is_cb) continue;
        if (ix.data.len == 0) {
            // fix/compute-budget-parse-p1 (#2): empty data — Agave's borsh decode of
            // ComputeBudgetInstruction can't even read the discriminant byte.
            if (out.sanitize_error == null) {
                out.sanitize_error = error.InvalidInstructionData;
                out.sanitize_error_ix = ix_idx;
            }
            continue;
        }
        switch (ix.data[0]) {
            1 => {
                // RequestHeapFrame(u32) — 4 bytes LE. @prov:compute-budget.heap-size —
                // still recorded even though it's "irrelevant to fee calc" (label above
                // predates the heap-cost-parity fix); needed now for calculate_heap_cost()
                // at every VM creation (fix/cu-parity-batch2).
                if (ix.data.len < 5) {
                    // fix/compute-budget-parse-p1 (#2): short data.
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.InvalidInstructionData;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                if (out.explicit_heap_bytes != null) {
                    // fix/compute-budget-parse-p1 (#1): duplicate — Agave:
                    // TransactionError::DuplicateInstruction(index).
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.DuplicateInstruction;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                out.explicit_heap_bytes = std.mem.readInt(u32, ix.data[1..5], .little);
                out.explicit_heap_ix = ix_idx;
            },
            2 => {
                // SetComputeUnitLimit(u32) — 4 bytes LE
                if (ix.data.len < 5) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.InvalidInstructionData;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                if (out.explicit_limit != null) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.DuplicateInstruction;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                out.explicit_limit = std.mem.readInt(u32, ix.data[1..5], .little);
            },
            3 => {
                // SetComputeUnitPrice(u64) — 8 bytes LE
                if (ix.data.len < 9) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.InvalidInstructionData;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                if (out.explicit_price != null) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.DuplicateInstruction;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                out.explicit_price = std.mem.readInt(u64, ix.data[1..9], .little);
            },
            4 => {
                // SetLoadedAccountsDataSizeLimit(u32) — 4 bytes LE. fix/cu-parity-batch2
                // fix 3: needed for loadedAccountsDataSizeLimit() below.
                if (ix.data.len < 5) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.InvalidInstructionData;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                if (out.explicit_loaded_accounts_data_size != null) {
                    if (out.sanitize_error == null) {
                        out.sanitize_error = error.DuplicateInstruction;
                        out.sanitize_error_ix = ix_idx;
                    }
                    continue;
                }
                out.explicit_loaded_accounts_data_size = std.mem.readInt(u32, ix.data[1..5], .little);
            },
            else => {
                // fix/compute-budget-parse-p1 (#2): discriminator 0 ("Unused",
                // reserved) or >=5 (undefined) — Agave's borsh decode either lands
                // on an unhandled variant or fails outright; both hit the `_ =>`
                // wildcard arm in process_instruction ⇒ InvalidInstructionData.
                if (out.sanitize_error == null) {
                    out.sanitize_error = error.InvalidInstructionData;
                    out.sanitize_error_ix = ix_idx;
                }
            },
        }
    }
    // fix/compute-budget-parse-p1 (#3): invalid RequestHeapFrame VALUE — mirrors
    // Agave's sanitize_and_convert_to_compute_budget_limits, which runs only once
    // try_from (the loop above) has succeeded end-to-end with no per-instruction
    // error (its `?` short-circuit means Agave never reaches this check otherwise).
    if (out.sanitize_error == null) {
        if (out.explicit_heap_bytes) |raw| {
            const valid = raw >= MIN_HEAP_FRAME_BYTES and raw <= MAX_HEAP_FRAME_BYTES and raw % 1024 == 0;
            if (!valid) {
                out.sanitize_error = error.InvalidInstructionData;
                out.sanitize_error_ix = out.explicit_heap_ix;
            }
        }
    }
    return out;
}

/// Read a compact-u16 from `data` starting at `*pos`, advance `pos`.
/// Returns null on truncation. Matches Solana's compact-u16 wire format.
fn readCompactU16(data: []const u8, pos: *usize) ?u16 {
    var result: u16 = 0;
    var shift: u4 = 0;
    while (true) : (shift += 7) {
        if (pos.* >= data.len) return null;
        const b = data[pos.*];
        pos.* += 1;
        result |= @as(u16, @intCast(b & 0x7f)) << shift;
        if (b & 0x80 == 0) break;
        if (shift >= 14) return null;
    }
    return result;
}

/// Walk a tx wire-format slice and extract priority_fee.
///
/// Inputs:
///   - tx_data: raw transaction bytes
///   - keys_start_offset: byte offset to the first account_key in tx_data (after sig count + sigs + msg header)
///   - num_keys: number of account keys
///   - instructions_start_offset: byte offset to num_instructions compact-u16 (after keys + blockhash)
///
/// Returns 0 on parse error or no priority instructions.
pub fn parsePriorityFeeFromWire(
    tx_data: []const u8,
    keys_start_offset: usize,
    num_keys: u16,
    instructions_start_offset: usize,
) u64 {
    var p = instructions_start_offset;
    if (p >= tx_data.len) return 0;
    const num_ix = readCompactU16(tx_data, &p) orelse return 0;
    if (num_ix == 0) return 0;

    var parsed = ComputeBudgetParsed{};
    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (p >= tx_data.len) return 0;
        const program_id_index = tx_data[p];
        p += 1;

        const num_accounts = readCompactU16(tx_data, &p) orelse return 0;
        if (p + num_accounts > tx_data.len) return 0;
        p += num_accounts; // skip account_indices

        const data_len = readCompactU16(tx_data, &p) orelse return 0;
        if (p + data_len > tx_data.len) return 0;
        const data_pos = p;
        p += data_len;

        // Resolve program_id by indexing into keys
        if (program_id_index >= num_keys) {
            parsed.non_builtin_count +|= 1;
            continue;
        }
        const prog_offset = keys_start_offset + @as(usize, program_id_index) * 32;
        if (prog_offset + 32 > tx_data.len) return 0;
        const prog_id_slice = tx_data[prog_offset .. prog_offset + 32];
        const prog_id_arr: *const [32]u8 = @ptrCast(prog_id_slice.ptr);
        const is_cb = std.mem.eql(u8, prog_id_slice, &COMPUTE_BUDGET_PROG_ID);
        if (isBuiltinForBudget(prog_id_arr)) {
            parsed.builtin_count +|= 1;
        } else {
            parsed.non_builtin_count +|= 1;
        }
        if (!is_cb) continue;

        if (data_len == 0) continue;
        switch (tx_data[data_pos]) {
            2 => {
                if (data_len < 5 or parsed.explicit_limit != null) continue;
                parsed.explicit_limit = std.mem.readInt(u32, tx_data[data_pos + 1 ..][0..4], .little);
            },
            3 => {
                if (data_len < 9 or parsed.explicit_price != null) continue;
                parsed.explicit_price = std.mem.readInt(u64, tx_data[data_pos + 1 ..][0..8], .little);
            },
            else => {},
        }
    }

    return priorityFee(parsed);
}

/// (Dormant QUIC TPU-ingest mempool helper — NOT on the consensus fee path.) Walk a tx's instructions
/// and return the explicit ComputeBudget SetComputeUnitPrice value (micro-lamports per CU), or 0 if
/// absent / parse-error. `banking_stage.calculatePriority(cu_price)` consumes this to rank pending txs
/// in the mempool. Mirrors the wire walk of `parsePriorityFeeFromWire` but extracts only discriminator-3
/// — no fee math, no builtin/non-builtin counting — so it is independent of the consensus fee logic.
pub fn parseComputeUnitPriceFromWire(
    tx_data: []const u8,
    keys_start_offset: usize,
    num_keys: u16,
    instructions_start_offset: usize,
) u64 {
    var p = instructions_start_offset;
    if (p >= tx_data.len) return 0;
    const num_ix = readCompactU16(tx_data, &p) orelse return 0;
    if (num_ix == 0) return 0;

    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (p >= tx_data.len) return 0;
        const program_id_index = tx_data[p];
        p += 1;
        const num_accounts = readCompactU16(tx_data, &p) orelse return 0;
        if (p + num_accounts > tx_data.len) return 0;
        p += num_accounts; // skip account_indices
        const data_len = readCompactU16(tx_data, &p) orelse return 0;
        if (p + data_len > tx_data.len) return 0;
        const data_pos = p;
        p += data_len;

        if (program_id_index >= num_keys) continue;
        const prog_offset = keys_start_offset + @as(usize, program_id_index) * 32;
        if (prog_offset + 32 > tx_data.len) return 0;
        if (!std.mem.eql(u8, tx_data[prog_offset .. prog_offset + 32], &COMPUTE_BUDGET_PROG_ID)) continue;
        // SetComputeUnitPrice(u64) = discriminator 3 followed by 8 LE bytes.
        if (data_len >= 9 and tx_data[data_pos] == 3) {
            return std.mem.readInt(u64, tx_data[data_pos + 1 ..][0..8], .little);
        }
    }
    return 0;
}

/// Sum of precompile signatures embedded in the transaction's instructions.
///
/// r75-bug-class-d11 (2026-05-07): every Ed25519SigVerify / Secp256k1SigVerify /
/// Secp256r1SigVerify instruction encodes its signature count as the first byte
/// of its instruction data. Per Agave canonical (`solana-fee/src/lib.rs:
/// calculate_fee_details`), each of those signatures contributes a base-fee
/// signature. Pre-fix, Vexor's base_fee = 5000 * num_required_signatures only,
/// undercharging by 5,000 lamports per precompile signature.
///
/// Slot 919 carrier: 20 HistoryJT::CopyGossipContactInfo txs each with 1 tx-sig
/// + 1 Ed25519SigVerify precompile sig. Vexor charged 5,000 instead of 10,000
/// base fee → 100,000 under-debit on fee_payer + 50,000 under-credit on leader
/// (50/50 burn split).
///
/// Returns 0 on parse error or no precompile instructions. Walks the tx wire
/// the same way as `parsePriorityFeeFromWire`.
pub fn parsePrecompileSigCountFromWire(
    tx_data: []const u8,
    keys_start_offset: usize,
    num_keys: u16,
    instructions_start_offset: usize,
) u16 {
    var p = instructions_start_offset;
    if (p >= tx_data.len) return 0;
    const num_ix = readCompactU16(tx_data, &p) orelse return 0;
    if (num_ix == 0) return 0;

    var total: u16 = 0;
    var i: u16 = 0;
    while (i < num_ix) : (i += 1) {
        if (p >= tx_data.len) return 0;
        const program_id_index = tx_data[p];
        p += 1;

        const num_accounts = readCompactU16(tx_data, &p) orelse return 0;
        if (p + num_accounts > tx_data.len) return 0;
        p += num_accounts; // skip account_indices

        const data_len = readCompactU16(tx_data, &p) orelse return 0;
        if (p + data_len > tx_data.len) return 0;
        const data_pos = p;
        p += data_len;

        if (program_id_index >= num_keys) continue;
        const prog_offset = keys_start_offset + @as(usize, program_id_index) * 32;
        if (prog_offset + 32 > tx_data.len) continue;
        const prog_id_slice = tx_data[prog_offset .. prog_offset + 32];
        const is_precompile =
            std.mem.eql(u8, prog_id_slice, &ED25519_PRECOMPILE_ID) or
            std.mem.eql(u8, prog_id_slice, &SECP256K1_PRECOMPILE_ID) or
            std.mem.eql(u8, prog_id_slice, &SECP256R1_PRECOMPILE_ID);
        if (!is_precompile) continue;

        // Each precompile encodes num_signatures as the first byte of its data.
        if (data_len == 0) continue;
        const ns = tx_data[data_pos];
        total +|= ns;
    }

    return total;
}

/// Per-tx execution CU limit — the SAME derivation the fee path uses, now also
/// the EXECUTION meter's initial value (CU-METER fix, carrier 419786142).
/// @prov:compute-budget.exec-limit
pub fn executionLimit(parsed: ComputeBudgetParsed) u32 {
    if (parsed.explicit_limit) |l| return @min(l, MAX_COMPUTE_UNIT_LIMIT);
    const builtin_alloc = @as(u64, parsed.builtin_count) * @as(u64, MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT);
    const non_builtin_alloc = @as(u64, parsed.non_builtin_count) * @as(u64, DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT);
    return @intCast(@min(builtin_alloc +| non_builtin_alloc, MAX_COMPUTE_UNIT_LIMIT));
}

/// @prov:compute-budget.heap-size
pub const MIN_HEAP_FRAME_BYTES: u32 = 32 * 1024; // solana_program_entrypoint::HEAP_LENGTH
pub const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
/// @prov:compute-budget.heap-cost — cost-per-32KiB-page-above-the-first.
pub const DEFAULT_HEAP_COST: u64 = 8;

/// Per-tx heap_size in bytes. @prov:compute-budget.heap-size — explicit
/// RequestHeapFrame(bytes) if present AND valid, else MIN_HEAP_FRAME_BYTES (32768).
///
/// NOTE: an explicit-but-INVALID RequestHeapFrame makes the whole
/// transaction sanitization-fail in Agave (TransactionError::
/// InstructionError(index, InvalidInstructionData)) — it can never appear
/// committed in a block produced by an honest leader, which is the only
/// input this replay-focused function ever sees. Vexor does not currently
/// implement that pre-execution rejection path (would reject a tx before
/// building the ParsedTx at all, an unrelated ingest-layer change) — for
/// that theoretical case this falls back to the default MIN_HEAP_FRAME_BYTES
/// rather than miscomputing a cost, which is the safe direction (cost 0).
pub fn heapSize(parsed: ComputeBudgetParsed) u32 {
    const raw = parsed.explicit_heap_bytes orelse return MIN_HEAP_FRAME_BYTES;
    const valid = raw >= MIN_HEAP_FRAME_BYTES and raw <= MAX_HEAP_FRAME_BYTES and raw % 1024 == 0;
    if (!valid) return MIN_HEAP_FRAME_BYTES;
    return @min(raw, MAX_HEAP_FRAME_BYTES);
}

/// @prov:compute-budget.heap-cost — consumed at EVERY VM creation, top-level and
/// every CPI-level VM, all using this same tx-wide heap_size.
///   rounded = heap_size + (32*1024 - 1)
///   cost = (rounded / (32*1024) - 1) * heap_cost
/// Default heap_size=32768 → cost=0 (the overwhelming majority of txs never
/// set RequestHeapFrame, so this is a strict no-op for them).
pub fn calculateHeapCost(heap_size: u32) u64 {
    const KIBIBYTE: u64 = 1024;
    const PAGE_SIZE_KB: u64 = 32;
    const page_bytes: u64 = PAGE_SIZE_KB * KIBIBYTE; // 32768
    const rounded: u64 = @as(u64, heap_size) +| (page_bytes -| 1);
    const pages: u64 = rounded / page_bytes; // page_bytes > 0, no div-by-zero
    return (pages -| 1) *| DEFAULT_HEAP_COST;
}

/// @prov:bpf.loaded-accts-gate
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES: u32 = 64 * 1024 * 1024; // 67,108,864
/// @prov:bpf.loaded-accts-gate
pub const TRANSACTION_ACCOUNT_BASE_SIZE: u64 = 64;
/// @prov:bpf.loaded-accts-gate
pub const ADDRESS_LOOKUP_TABLE_BASE_SIZE: u64 = 8248;

pub const LoadedAccountsDataSizeLimitError = error{InvalidLoadedAccountsDataSizeLimit};

/// Per-tx loaded_accounts_data_size limit. @prov:bpf.loaded-accts-gate — explicit
/// SetLoadedAccountsDataSizeLimit(bytes) if present, clamped down to (never up past)
/// MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES; else the max itself.
/// SetLoadedAccountsDataSizeLimit(0) is NonZeroU32::new(0) = None → a sanitize-time tx
/// rejection (same class as an invalid RequestHeapFrame: the tx can never appear
/// committed in a block an honest leader produced, so this is unreachable in honest
/// replay; returned here so callers CAN reject it if they choose to, without this
/// module guessing at a fallback the way heapSize() does for the heap case).
pub fn loadedAccountsDataSizeLimit(parsed: ComputeBudgetParsed) LoadedAccountsDataSizeLimitError!u32 {
    const raw = parsed.explicit_loaded_accounts_data_size orelse return MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;
    if (raw == 0) return error.InvalidLoadedAccountsDataSizeLimit;
    return @min(raw, MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES);
}

/// Compute priority fee in lamports. @prov:compute-budget.priority-fee
/// `priority_fee = ceil(price * limit / 1_000_000)`, saturating to u64::MAX.
///
/// r71-fix-3 (2026-04-28): default cu_limit now follows Agave's calculate_default_compute_unit_limit:
///   builtin_count × MAX_BUILTIN_ALLOCATION (3,000)
///   + non_builtin_count × DEFAULT_INSTRUCTION (200,000)
/// For tx with 1 ComputeBudget ix + 2 BPF ixs at 100k micro/cu price:
///   limit = 3,000 + 200,000 + 200,000 = 403,000
///   priority_fee = 403,000 * 100,000 / 1,000,000 = 40,300
/// Pre-r71-fix-3 (non_cb_count × 200,000) gave 40,000 — undercount of 300 per tx,
/// which was the slot-483 leader-fee carrier verified against oracle-node.
pub fn priorityFee(parsed: ComputeBudgetParsed) u64 {
    const price = parsed.explicit_price orelse 0;
    if (price == 0) return 0;
    const limit: u32 = executionLimit(parsed);
    const micro_fee: u128 = @as(u128, price) *| @as(u128, limit);
    const ceil_div = (micro_fee +| (MICRO_LAMPORTS_PER_LAMPORT - 1)) / MICRO_LAMPORTS_PER_LAMPORT;
    return std.math.cast(u64, ceil_div) orelse std.math.maxInt(u64);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

const TestInstruction = struct {
    program_id_index: u8,
    data: []const u8,
};

test "executionLimit: explicit SetComputeUnitLimit(218000) — carrier 419786142 tx#289 KAT" {
    // ComputeBudget SetComputeUnitLimit(218000): disc 2, u32 LE = 0x00035390.
    const ix_data = [_]u8{ 0x02, 0x90, 0x53, 0x03, 0x00 };
    const cb_ix = TestInstruction{ .program_id_index = 0, .data = &ix_data };
    const keys = [_][32]u8{COMPUTE_BUDGET_PROG_ID};
    const parsed = parseInstructions(&[_]TestInstruction{cb_ix}, &keys);
    try std.testing.expectEqual(@as(?u32, 218000), parsed.explicit_limit);
    try std.testing.expectEqual(@as(u32, 218000), executionLimit(parsed));
}

test "executionLimit: explicit capped at MAX_COMPUTE_UNIT_LIMIT" {
    try std.testing.expectEqual(
        MAX_COMPUTE_UNIT_LIMIT,
        executionLimit(.{ .explicit_limit = std.math.maxInt(u32) }),
    );
}

test "executionLimit: default rule builtin×3000 + non_builtin×200000, capped" {
    // 1 CB ix + 2 BPF ixs → 3,000 + 400,000 (r71-fix-3 example).
    try std.testing.expectEqual(
        @as(u32, 403_000),
        executionLimit(.{ .builtin_count = 1, .non_builtin_count = 2 }),
    );
    // 10 BPF ixs → 2M → capped at 1.4M.
    try std.testing.expectEqual(
        MAX_COMPUTE_UNIT_LIMIT,
        executionLimit(.{ .non_builtin_count = 10 }),
    );
}

test "per-tx CU meter: shared draw-down reproduces the tx#289 trace — KAT" {
    // Ground truth from cluster logs, slot 419786142 tx#289 (the carrier).
    // Two ComputeBudget builtins at 150 CU each, then three BPF dispatches;
    // ix4 must see exactly 33,254 CU remaining and exceed.
    var remaining: u64 = executionLimit(.{ .explicit_limit = 218000 });
    remaining -= 150; // ix0 ComputeBudget SetComputeUnitLimit
    try std.testing.expectEqual(@as(u64, 217850), remaining);
    remaining -= 150; // ix1 ComputeBudget SetComputeUnitPrice
    try std.testing.expectEqual(@as(u64, 217700), remaining);
    remaining -= 92223; // ix2 BPF (5TSsG9…) actual consumed
    try std.testing.expectEqual(@as(u64, 125477), remaining);
    remaining -= 92223; // ix3 BPF actual consumed
    try std.testing.expectEqual(@as(u64, 33254), remaining);
    // ix4 BPF (2br3u…) needs 92,223 but only 33,254 remain → the VM meter
    // (previous_instruction_meter = 33254) exhausts mid-run →
    // ExceededMaxInstructions → M4_RunFailed → ProgramFailedToComplete →
    // whole-tx rollback. Pre-fix Vexor handed ix4 a fresh 1.4M and committed.
    try std.testing.expect(@as(u64, 92223) > remaining);
}

test "priorityFee: no instructions → 0" {
    const result = priorityFee(.{});
    try std.testing.expectEqual(@as(u64, 0), result);
}

test "priorityFee: explicit price=0 → 0 (matches Agave test_new_with_no_fee)" {
    const result = priorityFee(.{ .explicit_price = 0, .explicit_limit = 200_000 });
    try std.testing.expectEqual(@as(u64, 0), result);
}

test "priorityFee: ceil-rounds (Agave test_new_with_compute_unit_price)" {
    // 999_999 * 1 / 1_000_000 = 0.999... → ceil = 1
    try std.testing.expectEqual(
        @as(u64, 1),
        priorityFee(.{ .explicit_price = MICRO_LAMPORTS_PER_LAMPORT - 1, .explicit_limit = 1 }),
    );
    // 1_000_000 * 1 / 1_000_000 = 1.0 → 1
    try std.testing.expectEqual(
        @as(u64, 1),
        priorityFee(.{ .explicit_price = MICRO_LAMPORTS_PER_LAMPORT, .explicit_limit = 1 }),
    );
    // 1_000_001 * 1 / 1_000_000 = 1.000001 → ceil = 2
    try std.testing.expectEqual(
        @as(u64, 2),
        priorityFee(.{ .explicit_price = MICRO_LAMPORTS_PER_LAMPORT + 1, .explicit_limit = 1 }),
    );
    // 200 * 100_000 / 1_000_000 = 20
    try std.testing.expectEqual(
        @as(u64, 20),
        priorityFee(.{ .explicit_price = 200, .explicit_limit = 100_000 }),
    );
}

test "priorityFee: u64::MAX saturation" {
    const result = priorityFee(.{
        .explicit_price = MICRO_LAMPORTS_PER_LAMPORT,
        .explicit_limit = MAX_COMPUTE_UNIT_LIMIT,
    });
    // 1_000_000 * 1_400_000 / 1_000_000 = 1_400_000
    try std.testing.expectEqual(@as(u64, 1_400_000), result);
}

test "parseInstructions: vote-only tx → no CB instructions, default fee=0" {
    // vote tx has 1 non-CB instruction (vote program), no CB instructions
    const vote_program: [32]u8 = [_]u8{0x07} ** 32; // dummy non-CB
    const account_keys = [_][32]u8{vote_program};
    const ix = TestInstruction{ .program_id_index = 0, .data = &[_]u8{} };
    const parsed = parseInstructions(&[_]TestInstruction{ix}, &account_keys);
    try std.testing.expectEqual(@as(?u64, null), parsed.explicit_price);
    try std.testing.expectEqual(@as(u64, 0), priorityFee(parsed));
}

test "parseInstructions: tx with SetComputeUnitPrice(200) + SetComputeUnitLimit(100_000) → 20 lamports" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const other_program: [32]u8 = [_]u8{0x07} ** 32;
    const account_keys = [_][32]u8{ cb_program, other_program };

    // SetComputeUnitLimit(100_000): [2, 0xa0, 0x86, 0x01, 0x00]
    const limit_data = [_]u8{ 2, 0xa0, 0x86, 0x01, 0x00 };
    // SetComputeUnitPrice(200): [3, 0xc8, 0, 0, 0, 0, 0, 0, 0]
    const price_data = [_]u8{ 3, 0xc8, 0, 0, 0, 0, 0, 0, 0 };
    // Some non-CB instruction
    const other_data = [_]u8{};

    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &limit_data },
        .{ .program_id_index = 0, .data = &price_data },
        .{ .program_id_index = 1, .data = &other_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?u32, 100_000), parsed.explicit_limit);
    try std.testing.expectEqual(@as(?u64, 200), parsed.explicit_price);
    // 2 CB ixs (builtin) + 1 dummy 0x07-prefixed (non-builtin)
    try std.testing.expectEqual(@as(u32, 2), parsed.builtin_count);
    try std.testing.expectEqual(@as(u32, 1), parsed.non_builtin_count);
    try std.testing.expectEqual(@as(u64, 20), priorityFee(parsed));
}

test "parseInstructions: skips RequestHeapFrame (1) and SetLoadedAccountsDataSizeLimit (4)" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};

    // RequestHeapFrame(8192): [1, 0x00, 0x20, 0, 0]
    const heap_data = [_]u8{ 1, 0x00, 0x20, 0, 0 };
    // SetLoadedAccountsDataSizeLimit(65536): [4, 0x00, 0x00, 0x01, 0x00]
    const data_size_data = [_]u8{ 4, 0x00, 0x00, 0x01, 0x00 };

    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &heap_data },
        .{ .program_id_index = 0, .data = &data_size_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?u32, null), parsed.explicit_limit);
    try std.testing.expectEqual(@as(?u64, null), parsed.explicit_price);
    try std.testing.expectEqual(@as(u64, 0), priorityFee(parsed));
}

test "parseInstructions: default limit when only price is set" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const other: [32]u8 = [_]u8{0x07} ** 32;
    const account_keys = [_][32]u8{ cb_program, other };

    // SetComputeUnitPrice(MICRO_LAMPORTS_PER_LAMPORT) only — limit defaults
    const price_data = [_]u8{ 3, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0 }; // 1_000_000 LE
    const other_data = [_]u8{};
    // 1 CB ix (builtin = 3,000) + 2 non-builtin ixs (200,000 each) = 403,000
    // priority_fee = ceil(1_000_000 * 403_000 / 1_000_000) = 403_000
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &price_data },
        .{ .program_id_index = 1, .data = &other_data },
        .{ .program_id_index = 1, .data = &other_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(u32, 1), parsed.builtin_count);
    try std.testing.expectEqual(@as(u32, 2), parsed.non_builtin_count);
    try std.testing.expectEqual(@as(u64, 403_000), priorityFee(parsed));
}

// r71-fix-3 (2026-04-28): regression test for slot 404,692,483 leader-fee carrier.
// Tx: ComputeBudget::SetComputeUnitPrice(100_000) + ATA + Router (no SetComputeUnitLimit).
// Pre-fix Vexor: priority = 200,000 × 2 × 100,000 / 10⁶ = 40,000 (300 lamport short).
// Post-fix Vexor matches Agave: priority = 403,000 × 100,000 / 10⁶ = 40,300.
test "parseInstructions: slot-483 carrier — CB+2BPF defaults to 403,000 not 400,000" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const ata: [32]u8 = [_]u8{0xa1} ** 32; // dummy non-builtin BPF
    const router: [32]u8 = [_]u8{0xb2} ** 32; // dummy non-builtin BPF
    const account_keys = [_][32]u8{ cb_program, ata, router };

    // SetComputeUnitPrice(100_000): [3, ...]
    const price_data = [_]u8{ 3, 0xa0, 0x86, 0x01, 0, 0, 0, 0, 0 };
    const other_data = [_]u8{};
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &price_data },
        .{ .program_id_index = 1, .data = &other_data },
        .{ .program_id_index = 2, .data = &other_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(u32, 1), parsed.builtin_count);
    try std.testing.expectEqual(@as(u32, 2), parsed.non_builtin_count);
    try std.testing.expectEqual(@as(u64, 40_300), priorityFee(parsed));
}

test "parseInstructions: System+Vote builtins counted at 3,000 each" {
    const sys_program: [32]u8 = [_]u8{0} ** 32;
    const vote_program: [32]u8 = .{
        0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
        0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
        0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
        0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
    };
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{ sys_program, vote_program, cb_program };

    const price_data = [_]u8{ 3, 0xa0, 0x86, 0x01, 0, 0, 0, 0, 0 }; // 100,000
    const sys_data = [_]u8{};
    const vote_data = [_]u8{};
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 2, .data = &price_data }, // CB
        .{ .program_id_index = 0, .data = &sys_data }, // System
        .{ .program_id_index = 1, .data = &vote_data }, // Vote
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    // 3 builtins × 3,000 = 9,000 → priority = 100_000 * 9_000 / 10⁶ = 900
    try std.testing.expectEqual(@as(u32, 3), parsed.builtin_count);
    try std.testing.expectEqual(@as(u32, 0), parsed.non_builtin_count);
    try std.testing.expectEqual(@as(u64, 900), priorityFee(parsed));
}

test "parseInstructions: limit clamps to MAX_COMPUTE_UNIT_LIMIT" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};

    // SetComputeUnitLimit(u32::MAX): [2, 0xff, 0xff, 0xff, 0xff]
    const limit_data = [_]u8{ 2, 0xff, 0xff, 0xff, 0xff };
    // SetComputeUnitPrice(1): [3, 1, 0, 0, 0, 0, 0, 0, 0]
    const price_data = [_]u8{ 3, 1, 0, 0, 0, 0, 0, 0, 0 };
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &limit_data },
        .{ .program_id_index = 0, .data = &price_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    // explicit_limit = u32::MAX, but clamped to MAX_COMPUTE_UNIT_LIMIT in priorityFee
    // priority_fee = ceil(1 * 1_400_000 / 1_000_000) = 2
    try std.testing.expectEqual(@as(u64, 2), priorityFee(parsed));
}

test "heapSize/calculateHeapCost: default (no RequestHeapFrame) → 32768 bytes, 0 CU" {
    const parsed = ComputeBudgetParsed{};
    try std.testing.expectEqual(@as(u32, 32768), heapSize(parsed));
    try std.testing.expectEqual(@as(u64, 0), calculateHeapCost(heapSize(parsed)));
}

test "heapSize/calculateHeapCost: RequestHeapFrame(262144) — MAX_HEAP_FRAME_BYTES → 56 CU/VM" {
    const parsed = ComputeBudgetParsed{ .explicit_heap_bytes = 262144 };
    try std.testing.expectEqual(@as(u32, 262144), heapSize(parsed));
    try std.testing.expectEqual(@as(u64, 56), calculateHeapCost(heapSize(parsed)));
}

test "heapSize: RequestHeapFrame(40960) — 40KiB, one page above default → 8 CU/VM" {
    // @prov:compute-budget.heap-size — Agave test fixture value: 40*1024.
    const parsed = ComputeBudgetParsed{ .explicit_heap_bytes = 40 * 1024 };
    try std.testing.expectEqual(@as(u32, 40 * 1024), heapSize(parsed));
    try std.testing.expectEqual(@as(u64, 8), calculateHeapCost(heapSize(parsed)));
}

test "heapSize: invalid explicit values fall back to MIN_HEAP_FRAME_BYTES (0 CU)" {
    // 0 bytes, not a multiple of 1024, and > MAX_HEAP_FRAME_BYTES all sanitize-fail
    // in Agave (would reject the whole tx pre-execution); replay-side fallback = default.
    try std.testing.expectEqual(@as(u32, MIN_HEAP_FRAME_BYTES), heapSize(.{ .explicit_heap_bytes = 0 }));
    try std.testing.expectEqual(@as(u32, MIN_HEAP_FRAME_BYTES), heapSize(.{ .explicit_heap_bytes = MIN_HEAP_FRAME_BYTES + 1 }));
    try std.testing.expectEqual(@as(u32, MIN_HEAP_FRAME_BYTES), heapSize(.{ .explicit_heap_bytes = MAX_HEAP_FRAME_BYTES + 1024 }));
}

test "parseInstructions: RequestHeapFrame(8192) parsed as explicit_heap_bytes (previously ignored)" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    // RequestHeapFrame(8192): [1, 0x00, 0x20, 0, 0]
    const heap_data = [_]u8{ 1, 0x00, 0x20, 0, 0 };
    const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &heap_data }};
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?u32, 8192), parsed.explicit_heap_bytes);
    // 8192 < MIN_HEAP_FRAME_BYTES → sanitize-fail → falls back to default.
    try std.testing.expectEqual(@as(u32, MIN_HEAP_FRAME_BYTES), heapSize(parsed));
}

test "loadedAccountsDataSizeLimit: default (no SetLoadedAccountsDataSizeLimit) -> 64MiB" {
    const parsed = ComputeBudgetParsed{};
    try std.testing.expectEqual(@as(u32, 67_108_864), try loadedAccountsDataSizeLimit(parsed));
}

test "loadedAccountsDataSizeLimit: explicit value under the max is honored" {
    const parsed = ComputeBudgetParsed{ .explicit_loaded_accounts_data_size = 100_000 };
    try std.testing.expectEqual(@as(u32, 100_000), try loadedAccountsDataSizeLimit(parsed));
}

test "loadedAccountsDataSizeLimit: explicit value over the max is clamped down" {
    const parsed = ComputeBudgetParsed{ .explicit_loaded_accounts_data_size = 200 * 1024 * 1024 };
    try std.testing.expectEqual(@as(u32, MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES), try loadedAccountsDataSizeLimit(parsed));
}

test "loadedAccountsDataSizeLimit: SetLoadedAccountsDataSizeLimit(0) rejected" {
    const parsed = ComputeBudgetParsed{ .explicit_loaded_accounts_data_size = 0 };
    try std.testing.expectError(error.InvalidLoadedAccountsDataSizeLimit, loadedAccountsDataSizeLimit(parsed));
}

test "parseInstructions: SetLoadedAccountsDataSizeLimit(65536) parsed (previously ignored)" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    // SetLoadedAccountsDataSizeLimit(65536): [4, 0x00, 0x00, 0x01, 0x00]
    const data_size_data = [_]u8{ 4, 0x00, 0x00, 0x01, 0x00 };
    const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &data_size_data }};
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?u32, 65536), parsed.explicit_loaded_accounts_data_size);
    try std.testing.expectEqual(@as(u32, 65536), try loadedAccountsDataSizeLimit(parsed));
}

// ─────────────────────────────────────────────────────────────────────────────
// RED-GREEN: compute-budget-parse-divergences-2026-07-12 P1s #1-#3.
// RED (pre-fix): these reference `parsed.sanitize_error` / `SanitizeError`, which
// do not exist yet on the unfixed struct — compile fails, proving the gap (Agave
// rejects the whole tx; Vexor has no mechanism to detect any of these 3 shapes at
// all). GREEN (post-fix): compiles and the assertions hold.
// ─────────────────────────────────────────────────────────────────────────────

test "P1#1 RED-GREEN: duplicate SetComputeUnitLimit -> DuplicateInstruction(ix1), Agave test_try_from_compute_unit_limit shape" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    // SetComputeUnitLimit(0): [2,0,0,0,0]; SetComputeUnitLimit(u32::MAX): [2,0xff,0xff,0xff,0xff]
    const first = [_]u8{ 2, 0, 0, 0, 0 };
    const second = [_]u8{ 2, 0xff, 0xff, 0xff, 0xff };
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &first },
        .{ .program_id_index = 0, .data = &second },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    // Pre-fix Vexor tolerates this (first-wins, no signal) — assert the CORRECT,
    // Agave-matching outcome: whole-tx sanitize-time reject at ix index 1 (the
    // SECOND occurrence, matching Agave's `test_try_from_compute_unit_limit`).
    try std.testing.expectEqual(@as(?SanitizeError, error.DuplicateInstruction), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 1), parsed.sanitize_error_ix);
    // First value is still recorded (Agave: Some((index, first_value)) unchanged by the Err).
    try std.testing.expectEqual(@as(?u32, 0), parsed.explicit_limit);
}

test "P1#1 RED-GREEN: duplicate RequestHeapFrame -> DuplicateInstruction, Agave test_try_from_request_heap shape" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const first = [_]u8{ 1, 0x00, 0xa0, 0x00, 0x00 }; // 40*1024
    const second = [_]u8{ 1, 0x00, 0xa4, 0x00, 0x00 }; // 41*1024
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &first },
        .{ .program_id_index = 0, .data = &second },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, error.DuplicateInstruction), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 1), parsed.sanitize_error_ix);
}

test "P1#1 RED-GREEN: duplicate SetComputeUnitPrice -> DuplicateInstruction" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const first = [_]u8{ 3, 0, 0, 0, 0, 0, 0, 0, 0 };
    const second = [_]u8{ 3, 1, 0, 0, 0, 0, 0, 0, 0 };
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &first },
        .{ .program_id_index = 0, .data = &second },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, error.DuplicateInstruction), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 1), parsed.sanitize_error_ix);
}

test "P1#1 RED-GREEN: duplicate SetLoadedAccountsDataSizeLimit -> DuplicateInstruction" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const first = [_]u8{ 4, 0, 0, 1, 0 };
    const second = [_]u8{ 4, 0, 0, 2, 0 };
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &first },
        .{ .program_id_index = 0, .data = &second },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, error.DuplicateInstruction), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 1), parsed.sanitize_error_ix);
}

test "P1#2 RED-GREEN: empty CB instruction data -> InvalidInstructionData" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &[_]u8{} }};
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 0), parsed.sanitize_error_ix);
}

test "P1#2 RED-GREEN: short SetComputeUnitLimit data (3 bytes, needs 5) -> InvalidInstructionData" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const short = [_]u8{ 2, 0, 0 };
    const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &short }};
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
}

test "P1#2 RED-GREEN: unknown discriminant 0 (Unused) and 5 (undefined) -> InvalidInstructionData" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    {
        const data0 = [_]u8{0};
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &data0 }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    }
    {
        const data5 = [_]u8{5};
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &data5 }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    }
}

test "P1#3 RED-GREEN: invalid RequestHeapFrame value (too small / too large / not x1024) -> InvalidInstructionData, Agave sanitize_requested_heap_size shape" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    // 0 bytes: sanitize-fails (< MIN_HEAP_FRAME_BYTES).
    {
        const data = [_]u8{ 1, 0, 0, 0, 0 };
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &data }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
        try std.testing.expectEqual(@as(u8, 0), parsed.sanitize_error_ix);
    }
    // MIN_HEAP_FRAME_BYTES - 1 (not a multiple of 1024, below floor).
    {
        var buf: [5]u8 = undefined;
        buf[0] = 1;
        std.mem.writeInt(u32, buf[1..5], MIN_HEAP_FRAME_BYTES - 1, .little);
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &buf }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    }
    // MAX_HEAP_FRAME_BYTES + 1024 (over the ceiling).
    {
        var buf: [5]u8 = undefined;
        buf[0] = 1;
        std.mem.writeInt(u32, buf[1..5], MAX_HEAP_FRAME_BYTES + 1024, .little);
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &buf }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    }
    // Valid value (40*1024) -> no sanitize error.
    {
        var buf: [5]u8 = undefined;
        buf[0] = 1;
        std.mem.writeInt(u32, buf[1..5], 40 * 1024, .little);
        const ixs = [_]TestInstruction{.{ .program_id_index = 0, .data = &buf }};
        const parsed = parseInstructions(&ixs, &account_keys);
        try std.testing.expectEqual(@as(?SanitizeError, null), parsed.sanitize_error);
    }
}

test "sanitize_error: first-error-wins across multiple bad instructions (Agave try_from short-circuit)" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const account_keys = [_][32]u8{cb_program};
    const short = [_]u8{ 2, 0, 0 }; // ix0: InvalidInstructionData (short)
    const dup1 = [_]u8{ 3, 1, 0, 0, 0, 0, 0, 0, 0 }; // ix1: price
    const dup2 = [_]u8{ 3, 2, 0, 0, 0, 0, 0, 0, 0 }; // ix2: DuplicateInstruction (would-be)
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &short },
        .{ .program_id_index = 0, .data = &dup1 },
        .{ .program_id_index = 0, .data = &dup2 },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    // The FIRST error (ix0, InvalidInstructionData) wins, not the later duplicate.
    try std.testing.expectEqual(@as(?SanitizeError, error.InvalidInstructionData), parsed.sanitize_error);
    try std.testing.expectEqual(@as(u8, 0), parsed.sanitize_error_ix);
}

test "sanitize_error: clean tx (no CB errors) -> null, unaffected by non-CB/no-limit instructions" {
    const cb_program = COMPUTE_BUDGET_PROG_ID;
    const other: [32]u8 = [_]u8{0x07} ** 32;
    const account_keys = [_][32]u8{ cb_program, other };
    const price_data = [_]u8{ 3, 0xa0, 0x86, 0x01, 0, 0, 0, 0, 0 };
    const other_data = [_]u8{};
    const ixs = [_]TestInstruction{
        .{ .program_id_index = 0, .data = &price_data },
        .{ .program_id_index = 1, .data = &other_data },
    };
    const parsed = parseInstructions(&ixs, &account_keys);
    try std.testing.expectEqual(@as(?SanitizeError, null), parsed.sanitize_error);
}

test "parseComputeUnitPriceFromWire: extracts SetComputeUnitPrice from a full tx wire (and 0 when absent)" {
    // Build a complete legacy-tx wire the way tx_ingest.parse lays it out:
    //   [0]=sigcount(1) [1..65]=sig  | msg: [65]=num_req(1) [66,67]=ro  [68]=n_keys(2)
    //   [69..101]=key0(signer) [101..133]=key1(=ComputeBudget)  [133..165]=blockhash
    //   [165]=num_ix(1) [166]=prog_idx(1) [167]=n_accts(0) [168]=data_len(9) [169..178]=SetCUPrice(12345)
    var wire: [178]u8 = undefined;
    @memset(&wire, 0);
    wire[0] = 1; // 1 signature
    // 65..68 header (num_req=1, ro=0,0)
    wire[65] = 1;
    wire[68] = 2; // 2 account keys
    @memset(wire[69..101], 0xAA); // key0 = dummy signer
    @memcpy(wire[101..133], &COMPUTE_BUDGET_PROG_ID); // key1 = ComputeBudget program
    // 133..165 blockhash (zero)
    wire[165] = 1; // 1 instruction
    wire[166] = 1; // program_id_index → key1 = ComputeBudget
    wire[167] = 0; // 0 account indices
    wire[168] = 9; // data_len = 9
    wire[169] = 3; // SetComputeUnitPrice discriminator
    std.mem.writeInt(u64, wire[170..178], 12345, .little);

    const keys_start_offset: usize = 69;
    const instructions_start_offset: usize = 165;
    try std.testing.expectEqual(@as(u64, 12345), parseComputeUnitPriceFromWire(&wire, keys_start_offset, 2, instructions_start_offset));

    // Point the program_id_index at key0 (the signer, NOT ComputeBudget) → no price found → 0.
    var wire2 = wire;
    wire2[166] = 0;
    try std.testing.expectEqual(@as(u64, 0), parseComputeUnitPriceFromWire(&wire2, keys_start_offset, 2, instructions_start_offset));

    // Out-of-range instruction offset → treated as "no instructions" → 0 (no panic).
    try std.testing.expectEqual(@as(u64, 0), parseComputeUnitPriceFromWire(&wire, keys_start_offset, 2, wire.len + 100));
}
