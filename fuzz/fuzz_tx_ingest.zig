//! Fuzz harness: transaction wire decode + sanitize (src/vex_svm/tx_ingest.zig).
//!
//! Untrusted-input surface: the "accept a tx off the wire" stage shared by RPC
//! sendTransaction, simulateTransaction, and TPU ingest. Parses signatures + message
//! header + signer keys straight out of attacker-controlled bytes via compact-u16
//! (shortvec) decoding and offset arithmetic — a classic parser-bug surface.
//!
//! No network, filesystem, or validator state required — pure in-memory decode.
const std = @import("std");
const tx_ingest = @import("tx_ingest");

pub fn fuzzOne(data: []const u8) void {
    var scratch_sigs: [tx_ingest.MAX_SIGNATURES][64]u8 = undefined;
    var scratch_keys: [tx_ingest.MAX_SIGNATURES][32]u8 = undefined;

    const parsed = tx_ingest.parse(data, &scratch_sigs, &scratch_keys) catch return;

    // Exercise the sigverify gate too — it re-walks parsed.signatures/signer_keys
    // against parsed.message, all views into the original fuzz buffer.
    _ = tx_ingest.verifySignatures(parsed);
    _ = parsed.id();
}

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    fuzzOne(data[0..len]);
    return 0;
}

test "fuzz: tx_ingest.parse survives arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn call(_: void, input: []const u8) anyerror!void {
            fuzzOne(input);
        }
    }.call, .{});
}
