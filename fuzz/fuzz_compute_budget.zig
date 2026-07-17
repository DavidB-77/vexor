//! Fuzz harness: compute-budget instruction parse (src/vex_svm/compute_budget.zig).
//!
//! Untrusted-input surface: the fee/CU-limit extraction walk over a transaction's
//! raw instruction list, done directly against wire bytes (not a decoded struct) via
//! offsets that come out of tx_ingest.parse — the exact real integrated call shape
//! used on the fee path. Reuses tx_ingest to get real keys_offset/instructions_offset
//! for the SAME fuzz buffer, since compute_budget's wire walkers take those offsets
//! as parameters rather than re-deriving them.
//!
//! No network, filesystem, or validator state required — pure in-memory decode.
const std = @import("std");
const tx_ingest = @import("tx_ingest");
const compute_budget = @import("compute_budget");

pub fn fuzzOne(data: []const u8) void {
    var scratch_sigs: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var scratch_keys: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;

    const parsed = tx_ingest.parse(data, &scratch_sigs, &scratch_keys) catch return;

    _ = compute_budget.parsePriorityFeeFromWire(
        data,
        parsed.keys_offset,
        parsed.num_keys,
        parsed.instructions_offset,
    );
    _ = compute_budget.parseComputeUnitPriceFromWire(
        data,
        parsed.keys_offset,
        parsed.num_keys,
        parsed.instructions_offset,
    );
    _ = compute_budget.parsePrecompileSigCountFromWire(
        data,
        parsed.keys_offset,
        parsed.num_keys,
        parsed.instructions_offset,
    );
}

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    fuzzOne(data[0..len]);
    return 0;
}

test "fuzz: compute_budget wire walkers survive arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn call(_: void, input: []const u8) anyerror!void {
            fuzzOne(input);
        }
    }.call, .{});
}
