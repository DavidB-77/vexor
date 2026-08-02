//! Differential KAT: avx512.zig vs generic.zig (F102).
//!
//! Only ever @import()'d (and therefore only ever semantically analyzed) from
//! `root.zig`'s `if (builtin.is_test) { if (use_avx512_ifma) { ... } }` gate —
//! i.e. exactly the target-safety pattern the rest of this module already
//! uses for avx512.zig's own unit tests. Do NOT import this file unguarded:
//! avx512.zig's vpmadd52 IFMA LLVM intrinsics do not legalize on a target
//! lacking AVX-512-IFMA, and this file references both backends directly.
//!
//! Why this exists: the canonical production build (`-Dcpu=znver4`) compiles
//! and runs `avx512.zig` as the active `ExtendedPoint`/`CachedPoint` backend
//! for every ed25519 point operation, but both public CI workflows pin
//! `-Dcpu=x86_64_v2` (no AVX-512), so `avx512.zig` never runs in CI — a real
//! bug in it could ship without ever failing a CI check. This test closes
//! that gap the cheap way: it self-activates on any AVX-512-IFMA-capable
//! build host (including this dev box, at `zig build test-vex-ed25519`)
//! without needing new CI runner hardware, by asserting avx512.zig produces
//! byte-identical output to the CI-covered, Wycheproof-proven generic.zig for
//! the same sequence of group operations on the same inputs.
const std = @import("std");
const avx512 = @import("avx512.zig");
const generic = @import("generic.zig");

const Ed25519 = std.crypto.ecc.Edwards25519;

/// Run the same chain of ExtendedPoint/CachedPoint operations through a given
/// backend namespace and return the final canonical-encoded 32 bytes.
fn runChain(comptime backend: type, p: Ed25519, q: Ed25519) [32]u8 {
    const ep = backend.ExtendedPoint.fromPoint(p);
    const eq = backend.ExtendedPoint.fromPoint(q);
    const cq = backend.CachedPoint.fromExtended(eq);

    const added = ep.add(eq);
    const added_cached = ep.addCached(cq);
    const subbed_cached = ep.subCached(cq);
    const doubled = ep.dbl();
    const scaled = ep.mulByPow2(3);

    // Fold every intermediate into one point so a divergence in ANY single
    // op (add/addCached/subCached/dbl/mulByPow2) shows up in the final bytes.
    var acc = added;
    acc = acc.add(added_cached);
    acc = acc.addCached(backend.CachedPoint.fromExtended(subbed_cached));
    acc = acc.add(doubled);
    acc = acc.add(scaled);

    return acc.toPoint().toBytes();
}

test "avx512.zig matches generic.zig byte-for-byte on the same ExtendedPoint/CachedPoint op chain" {
    // Fixed, deterministic sample points — no RNG, so this is reproducible
    // across runs and hosts. basePoint/identityElement exercise the two
    // curve-law edge cases; the scalar-derived points exercise the general
    // case with distinct, non-trivial coordinates.
    const base = Ed25519.basePoint;
    const identity = Ed25519.identityElement;

    var scalar_a = [_]u8{0} ** 32;
    scalar_a[0] = 0x07;
    scalar_a[13] = 0x91;
    scalar_a[31] = 0x2c;
    const point_a = try base.mul(scalar_a);

    var scalar_b = [_]u8{0} ** 32;
    scalar_b[1] = 0x55;
    scalar_b[17] = 0x03;
    scalar_b[30] = 0x81;
    const point_b = try base.mul(scalar_b);

    const doubled_base = base.dbl();

    const sample_points = [_]Ed25519{ base, identity, point_a, point_b, doubled_base };

    for (sample_points) |p| {
        for (sample_points) |q| {
            const avx512_bytes = runChain(avx512, p, q);
            const generic_bytes = runChain(generic, p, q);
            try std.testing.expectEqualSlices(u8, &generic_bytes, &avx512_bytes);
        }
    }
}
