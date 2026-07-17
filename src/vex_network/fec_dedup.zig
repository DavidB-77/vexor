//! Ed25519 FEC-set signature dedup cache (canonical Agave rc.1 port).
//!
//! Agave `ledger/src/sigverify_shreds.rs:16,47` keys a bounded LRU on the TUPLE
//! `(signature, pubkey, merkle_root)` and verifies every shred, but the first
//! shred of a FEC set runs ed25519 and its ~63 siblings (identical sig+pubkey+root)
//! hit the cache and skip it. Vexor mirrors that exactly, per-worker in verify_tile
//! (Agave is per-rayon-thread).
//!
//! SAFETY (why a cache hit can never accept a shred the single-sig path rejects):
//!   - the leader pubkey is IN the key, so a hit implies the shred's leader matches
//!     a previously-ed25519-verified entry (slot-rewrite → different leader → miss);
//!   - merkle_root is reconstructed from THIS shred's own leaf+proof, and the leaf
//!     covers the slot field (shred bytes 65..72), so a hit implies a matching slot
//!     and content (content rewrite → different root → miss);
//!   - we only insert a key AFTER a successful verifySignature, so "hit" ⟺ "this
//!     exact tuple was already ed25519-verified". The cache is a pure perf shortcut;
//!     every accept is still backed by a real ed25519 verify.
//!
//! This module is intentionally `std`-only so the KAT below runs via a plain
//! `zig test src/vex_network/fec_dedup.zig` with no module graph.

const std = @import("std");

/// Cache key: (ed25519 signature, leader pubkey, reconstructed 20-byte merkle root).
pub const DedupKey = struct {
    sig: [64]u8,
    pubkey: [32]u8,
    root: [20]u8,
};

pub const DedupKeyCtx = struct {
    pub fn hash(_: DedupKeyCtx, k: DedupKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&k.sig);
        h.update(&k.pubkey);
        h.update(&k.root);
        return h.final();
    }
    pub fn eql(_: DedupKeyCtx, a: DedupKey, b: DedupKey) bool {
        return std.mem.eql(u8, &a.sig, &b.sig) and
            std.mem.eql(u8, &a.pubkey, &b.pubkey) and
            std.mem.eql(u8, &a.root, &b.root);
    }
};

/// Presence in the map = the tuple has been ed25519-verified (value is `void`).
pub const DedupCache = std.HashMap(DedupKey, void, DedupKeyCtx, std.hash_map.default_max_load_percentage);

/// Per-worker cap. A slot holds ~512 FEC sets (≈512 distinct sigs); 1<<14 retains
/// ~32 slots of FEC signatures — far more than the within-slot window where FEC
/// siblings actually arrive — at ~1.9 MB/worker. On reaching the cap we clear the
/// whole cache (a crude eviction; correctness is unaffected since misses just
/// re-verify), bounding memory without an LRU's bookkeeping.
pub const FEC_DEDUP_CAP: u32 = 1 << 14;

// ─────────────────────────────────────────────────────────────────────────────
// KAT: cache key isolation (the safety property).
//
// The dedup is safe iff a HIT can occur ONLY for the exact tuple that was already
// ed25519-verified. Since we only insert after a successful verify, "hit ⟺ exact
// prior verify" ⇒ every dedup-accept equals a single-sig-accept; no fork where the
// cache accepts a shred the canonical path would reject.
test "fec-dedup cache key isolation (no cross-leader/root/sig false hits)" {
    const sigA = [_]u8{0xA1} ** 64;
    const sigB = [_]u8{0xB2} ** 64;
    const pkA = [_]u8{0x11} ** 32;
    const pkB = [_]u8{0x22} ** 32;
    const rootA = [_]u8{0x33} ** 20;
    const rootB = [_]u8{0x44} ** 20;

    var cache = DedupCache.init(std.testing.allocator);
    defer cache.deinit();

    const keyA = DedupKey{ .sig = sigA, .pubkey = pkA, .root = rootA };
    try cache.put(keyA, {});

    // Exact tuple → HIT (legitimate FEC-set sibling).
    try std.testing.expect(cache.contains(keyA));
    // Different leader (same sig+root) → MISS — proves the leader binding (slot-rewrite guard).
    try std.testing.expect(!cache.contains(.{ .sig = sigA, .pubkey = pkB, .root = rootA }));
    // Different root (same sig+leader) → MISS — proves the slot/content binding.
    try std.testing.expect(!cache.contains(.{ .sig = sigA, .pubkey = pkA, .root = rootB }));
    // Different signature (equivocation) → MISS — independent verify.
    try std.testing.expect(!cache.contains(.{ .sig = sigB, .pubkey = pkA, .root = rootA }));

    // Clear-on-cap eviction empties the cache (correctness unaffected; misses re-verify).
    cache.clearRetainingCapacity();
    try std.testing.expect(!cache.contains(keyA));
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}

// KAT: interleaved multi-slot arrival never produces a cross-slot hit. With the
// tuple key this holds by construction (different slot → different leaf → different
// root → different key), but we pin it so a future refactor that weakens the key
// (e.g. dropping root) fails loudly here.
test "fec-dedup interleaved multi-slot: no cross-slot hit" {
    var cache = DedupCache.init(std.testing.allocator);
    defer cache.deinit();

    const sig = [_]u8{0xCC} ** 64;
    const pk = [_]u8{0xDD} ** 32;
    // Two slots' FEC sets share a (hypothetical) signature/leader but differ in root.
    const root_slotN = [_]u8{0x01} ** 20;
    const root_slotN1 = [_]u8{0x02} ** 20;

    try cache.put(.{ .sig = sig, .pubkey = pk, .root = root_slotN }, {});
    // Sibling in slot N → HIT.
    try std.testing.expect(cache.contains(.{ .sig = sig, .pubkey = pk, .root = root_slotN }));
    // Shred from slot N+1 (different root) → MISS, must be verified independently.
    try std.testing.expect(!cache.contains(.{ .sig = sig, .pubkey = pk, .root = root_slotN1 }));
}
