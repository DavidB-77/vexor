//! Fuzz harness: gossip Protocol / CrdsValue / ContactInfo decode (src/vex_network/crds.zig).
//!
//! Untrusted-input surface: every UDP gossip packet a peer sends decodes through
//! `Protocol.deserialize`, which dispatches by tag into PullRequest/PullResponse/
//! PushMessage/PruneMessage/Ping/Pong, and — for PullRequest — into a full
//! CrdsValue/CrdsData union carrying ContactInfo, Vote, EpochSlots, DuplicateShred,
//! etc. All of it is little-endian bincode read straight off the wire.
//!
//! No network, filesystem, or validator state required — pure in-memory decode.
const std = @import("std");
const crds = @import("crds");

pub fn fuzzOne(data: []const u8) void {
    var fbs = std.io.fixedBufferStream(data);
    const msg = crds.Protocol.deserialize(fbs.reader()) catch return;

    switch (msg) {
        // PullRequest is the one variant that decodes a full CrdsValue (bincode
        // union dispatch over CrdsDataType, incl. ContactInfo/LegacyContactInfo/
        // Vote/EpochSlots/DuplicateShred/...), so also exercise its signature
        // verification path (re-serializes the decoded data into a fixed buffer).
        .PullRequest => |pr| _ = pr.value.verify(),
        .PullResponse, .PushMessage, .PruneMessage, .PingMessage, .PongMessage => {},
    }
}

pub export fn LLVMFuzzerTestOneInput(data: [*]const u8, len: usize) c_int {
    fuzzOne(data[0..len]);
    return 0;
}

test "fuzz: gossip Protocol.deserialize survives arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        fn call(_: void, input: []const u8) anyerror!void {
            fuzzOne(input);
        }
    }.call, .{});
}
