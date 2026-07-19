// ⚠ NON-COMPILING SCAFFOLD — DO NOT add to the build until seeded (see SEEDING below).
// Boot-time KAT: slot 414098006 — 3 sequential BfX self-votes (tx417/419 REJECT Custom17,
// tx421 ACCEPT). Intended to prove: (1) rejected TowerSyncs leave vote-account data
// BYTE-UNCHANGED, (2) the 3 sequential votes do NOT interact (rejects don't write, so each
// reads the same clean base), (3) the accepted vote (tx421) writes exactly one transition
// whose post-bytes == cluster bank_hash_details for BfX.
//
// SEEDING REQUIRED before this runs/compiles green (advisor 2026-06-08):
//   * `data`      = BfX's REAL pre-006 V4 vote-state bytes (agave-ledger-tool verify
//                   --halt-at-slot 414098005 + account dump of BfX).
//   * `sh_data`   = canonical SlotHashes bytes for 414098006 (414097970 AND 414097971 ABSENT —
//                   that absence is WHAT makes 417/419 reject; with sh_data=null the
//                   RootOnDifferentFork check is unreachable and the reject assertion FAILS).
//   * `hash417/9` = each tx's real proposed TowerSync hash (must match SH[last_slot]).
//   * call sig    = verify against origin-tree replaceTowerStateCheckedWithFallbackTraced
//                   (current arity incl. the trailing current_epoch/voter args).
const std = @import("std");
const vss = @import("vote_state_serde.zig");

test "414098006: rejected TowerSync leaves vote-account bytes unchanged (Custom 17)" {
    var data: [vss.VOTE_STATE_V3_SZ]u8 = undefined; // SEED: BfX real pre-006 bytes
    var before: [vss.VOTE_STATE_V3_SZ]u8 = undefined;
    @memcpy(&before, &data);

    // tx417: root=414097970 (cluster-SKIPPED, ≥earliest_slot_hash, ABSENT from SH) => Custom 17.
    var lk417: [31]vss.Lockout = undefined;
    var n: usize = 0;
    var s: u64 = 414097971;
    while (s <= 414098001) : (s += 1) {
        lk417[n] = .{ .slot = s, .confirmation_count = @intCast(31 - n) };
        n += 1;
    }
    const sh_data: ?[]const u8 = null; // SEED: real SlotHashes (414097970/971 absent) — null = test is RED
    var hash417 = [_]u8{0} ** 32; // SEED: real proposed hash
    const ok417 = vss.replaceTowerStateCheckedWithFallbackTraced(
        &data,
        lk417[0..n],
        414097970,
        null,
        414098006,
        sh_data,
        &hash417,
        null,
        null,
        null,
    );
    try std.testing.expectEqual(false, ok417); // REJECTED == cluster Custom 17
    try std.testing.expectEqualSlices(u8, &before, &data); // bytes UNCHANGED — no phantom write
    // tx419 (root=414097971) identical pattern; tx421 (root=414097973, in SH) ACCEPTED —
    // assert post-bytes == BfX cluster bank_hash_details once seeded.
}
