//! Fuzz harness: shred wire-format decode (src/vex_network/shred_parse.zig).
//!
//! Untrusted-input surface: every shred a peer sends over the TVU/repair socket goes
//! through `parseShred` before any FEC or replay logic ever sees it. This is the
//! parsing layer implicated in the slot-422359406 truncated-block incident class —
//! malformed or adversarial shred bytes reaching this parser must fail cleanly
//! (a returned error), never panic, overflow, or read out of bounds.
//!
//! No network, filesystem, or validator state required — pure in-memory decode.
const std = @import("std");
const shred_parse = @import("shred_parse");

pub fn fuzzOne(data: []const u8) void {
    const shred = shred_parse.parseShred(data) catch return;

    // Exercise every derived-field accessor: each one reads further into `data`
    // at offsets computed from attacker-controlled header fields (variant byte,
    // proof_size, index, fec_set_index), so each is its own bounds-check surface.
    _ = shred.slot();
    _ = shred.index();
    _ = shred.isData();
    _ = shred.parentOffset();
    _ = shred.rawData();
    _ = shred.dataSize();
    _ = shred.numData();
    _ = shred.numCoding();
    _ = shred.codingPosition();
    _ = shred.fecSetIndex();
    _ = shred.version();
    _ = shred.isLastInSlot();
    _ = shred.isDataComplete();
    _ = shred.proofSize();
    _ = shred.isMerkle();

    // Merkle-root reconstruction walks the proof region at the tail of the
    // payload using proof_size/resigned/chained flags parsed from the variant
    // byte — the exact arithmetic the d27mm/d28ll incidents were about.
    _ = shred.merkleRoot();
    _ = shred.merkleRoot32();
    _ = shred.chainedMerkleRoot();

    _ = shred_parse.isUnexpectedDataComplete(&shred);
}

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    fuzzOne(data[0..len]);
    return 0;
}

test "fuzz: shred_parse survives arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn call(_: void, input: []const u8) anyerror!void {
            fuzzOne(input);
        }
    }.call, .{});
}
