//! Vexor BN254 pure-Zig CORRECTNESS GATE (byte-exact).
//!
//! Root with `zig build test-vex-bn254` (core-pinned 28-31). This is THE
//! correctness gate for the pure-Zig alt_bn128 leaf — bn254/poseidon run INSIDE
//! tx execution and feed account state → bank_hash, so one wrong bit forks the
//! validator off the network. There is no std.crypto fallback; this gate is the
//! safety net.
//!
//! Two arms, per crypto-review discipline:
//!   (B) ABSOLUTE — pin a subset of the solana-bn254 v3.2.1 / Firedancer
//!       test_bn254.c published vectors, asserted byte-for-byte against pure-Zig.
//!   (C) INDEPENDENT ORACLE — go-ethereum EIP-196/197 precompile fixtures +
//!       py_ecc-computed G2 vectors + solana-bn254 v3.2.1 compression constants,
//!       none of which share code, author, or lineage with each other, asserted
//!       byte-for-byte against pure-Zig.
//!
//! (The former Ballet-FFI differential arm was removed 2026-07-12 when the FFI
//! backend was deleted — Vexor now runs a fully FFI-free crypto leaf.)

const std = @import("std");
const pure = @import("root.zig");
const poseidon = @import("poseidon.zig");

// ── helpers ─────────────────────────────────────────────────────────────────
fn hx(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// The BN254 canonical generators (big-endian), from Firedancer test #6.
const G1_GEN = hx("0000000000000000000000000000000000000000000000000000000000000001" ++
    "0000000000000000000000000000000000000000000000000000000000000002");
const G2_GEN = hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2" ++
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed" ++
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b" ++
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa");

// ═══════════════════════════════ ARM B: ABSOLUTE ═══════════════════════════════

const AddVec = struct { in: []const u8, out: []const u8 };

test "ABS g1_add: Firedancer test_bn254.c concrete vectors" {
    const vecs = [_]AddVec{
        .{ .in = &hx("18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f3726607c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7"), .out = &hx("2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915") },
        // doubling of (1,2)
        .{ .in = &hx("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002" ++ "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"), .out = &hx("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4") },
    };
    var out: [64]u8 = undefined;
    for (vecs, 0..) |v, i| {
        try std.testing.expect(pure.g1Add(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("ABS g1_add vector {d} mismatch\n  got ={x}\n  want={x}\n", .{ i, out, v.out });
            return e;
        };
    }
    std.debug.print("[ABS g1_add] {d} FD vectors byte-exact\n", .{vecs.len});
}

test "ABS g1_mul: Firedancer test_bn254.c concrete vectors" {
    const vecs = [_]AddVec{
        .{ .in = &hx("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2"), .out = &hx("070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc") },
        .{ .in = &hx("1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), .out = &hx("2cde5879ba6f13c0b5aa4ef627f159a3347df9722efce88a9afbb20b763b4c411aa7e43076f6aee272755a7f9b84832e71559ba0d2e0b17d5f9f01755e5b0d11") },
    };
    var out: [64]u8 = undefined;
    for (vecs, 0..) |v, i| {
        try std.testing.expect(pure.g1Mul(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("ABS g1_mul vector {d} mismatch\n  got ={x}\n  want={x}\n", .{ i, out, v.out });
            return e;
        };
    }
    std.debug.print("[ABS g1_mul] {d} FD vectors byte-exact\n", .{vecs.len});
}

test "ABS pairing: generator pair is NOT one" {
    var out: [32]u8 = undefined;
    var in: [192]u8 = undefined;
    @memcpy(in[0..64], &G1_GEN);
    @memcpy(in[64..192], &G2_GEN);
    try std.testing.expect(pure.pairingIsOne(&out, &in, true));
    var expect: [32]u8 = @splat(0); // not one
    try std.testing.expect(std.mem.eql(u8, &out, &expect));
    // empty input → one
    try std.testing.expect(pure.pairingIsOne(&out, in[0..0], true));
    expect[31] = 1;
    try std.testing.expect(std.mem.eql(u8, &out, &expect));
    std.debug.print("[ABS pairing] generator-pair=not-one, empty=one OK\n", .{});
}

// ═══════════════════════════════ ARM C: INDEPENDENT ORACLE ═══════════════════
// Arms A/B above prove pure-Zig == Ballet (byte-identical differential + a
// handful of vectors *sourced from* Firedancer's test_bn254.c). That closes
// "did we re-implement Ballet's bugs faithfully" but NOT "is Ballet itself
// right" — both arms bottom out in the one codebase we are replacing.
//
// This arm checks pure-Zig against TWO sources that share no code, no author,
// and no lineage with Ballet/Firedancer:
//
//   (1) go-ethereum core/vm/testdata/precompiles/{bn256Add,bn256ScalarMul,
//       bn256Pairing}.json — the canonical EIP-196/EIP-197 alt_bn128 precompile
//       conformance vectors (the "chfast"/"cdetrio"/"jeff"/"two_point_match"
//       series), computed by go-ethereum's Cloudflare-derived bn256 Go library.
//       Fetched 2026-07-11 from
//       https://raw.githubusercontent.com/ethereum/go-ethereum/master/core/vm/testdata/precompiles/
//       and pinned verbatim as byte constants below (no network at test time).
//       Wire format is big-endian, matching Solana's ALT_BN128_*_BE / EIP-197.
//
//   (2) py_ecc (github.com/ethereum/py_ecc, the Ethereum Foundation's
//       from-scratch pure-Python bn128 implementation — a third, independently
//       written codebase distinct from go-ethereum's Go bn256, Ballet's C, and
//       solana-bn254's Rust/ark-bn254). Ethereum has NO G2-add/G2-mul precompile
//       (only G1 add/mul + pairing are EIP-196/197 precompiles), so no canonical
//       fixture file exists for those two ops; we instead independently COMPUTED
//       them with py_ecc and serialized with the EIP-197 Fp2 wire convention
//       (Fp2 element = c0 + c1·i, wire = [c1, c0] big-endian — cross-checked
//       against our own G2_GEN constant below and against a canonical
//       go-ethereum G1-add vector before generating, so the encoding itself
//       isn't trusted blindly). Generation script + raw output retained
//       out-of-tree; not re-run at test time.
//
// Every vector below is asserted byte-for-byte against pure.* directly — no
// Ballet involved in this arm at all.

const IndVec = struct { name: []const u8, in: []const u8, out: []const u8 };

test "IND g1_add: EIP-197 go-ethereum bn256Add.json (chfast/cdetrio series)" {
    const vecs = [_]IndVec{
        .{ .name = "chfast1", .in = &hx("18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f3726607c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7"), .out = &hx("2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915") },
        .{ .name = "chfast2", .in = &hx("2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c91518b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"), .out = &hx("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204") },
        .{ .name = "cdetrio4_empty_input_is_infinity_plus_infinity", .in = &hx(""), .out = &hx("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") },
        .{ .name = "cdetrio11_doubling_of_generator", .in = &hx("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002"), .out = &hx("030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4") },
    };
    var out: [64]u8 = undefined;
    for (vecs) |v| {
        try std.testing.expect(pure.g1Add(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("IND g1_add '{s}' mismatch\n  got ={x}\n  want={x}\n", .{ v.name, out, v.out });
            return e;
        };
    }
    std.debug.print("[IND g1_add] {d} go-ethereum EIP-197 vectors byte-exact\n", .{vecs.len});
}

test "IND g1_mul: EIP-197 go-ethereum bn256ScalarMul.json (incl. scalar > r, scalar=0/1)" {
    const vecs = [_]IndVec{
        .{ .name = "chfast1", .in = &hx("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2"), .out = &hx("070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc") },
        .{ .name = "chfast2", .in = &hx("070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46"), .out = &hx("025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e") },
        .{ .name = "chfast3", .in = &hx("025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3"), .out = &hx("14789d0d4a730b354403b5fac948113739e276c23e0258d8596ee72f9cd9d3230af18a63153e0ec25ff9f2951dd3fa90ed0197bfef6e2a1a62b5095b9d2b4a27") },
        .{ .name = "cdetrio11_scalar_gt_r_wraparound", .in = &hx("039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), .out = &hx("00a1a234d08efaa2616607e31eca1980128b00b415c845ff25bba3afcb81dc00242077290ed33906aeb8e42fd98c41bcb9057ba03421af3f2d08cfc441186024") },
        .{ .name = "cdetrio15_scalar_one_identity", .in = &hx("039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000000000000000000000000000000000001"), .out = &hx("039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98") },
        .{ .name = "zeroScalar_gives_infinity", .in = &hx("039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000000000000000000000000000000000000"), .out = &hx("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") },
    };
    var out: [64]u8 = undefined;
    for (vecs) |v| {
        try std.testing.expect(pure.g1Mul(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("IND g1_mul '{s}' mismatch\n  got ={x}\n  want={x}\n", .{ v.name, out, v.out });
            return e;
        };
    }
    std.debug.print("[IND g1_mul] {d} go-ethereum EIP-197 vectors byte-exact\n", .{vecs.len});
}

test "IND pairing: EIP-197 go-ethereum bn256Pairing.json (empty=1, single-pair, 2-pair cancel/non-cancel)" {
    const vecs = [_]IndVec{
        .{ .name = "empty_data_zero_pairs_is_one", .in = &hx(""), .out = &hx("0000000000000000000000000000000000000000000000000000000000000001") },
        .{ .name = "one_point_single_generator_pair_not_one", .in = &hx("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000000") },
        .{ .name = "two_point_match_2_classic_ecpairing_check", .in = &hx("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000001") },
        .{ .name = "jeff6_two_pair_not_one", .in = &hx("1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c103188585e2364128fe25c70558f1560f4f9350baf3959e603cc91486e110936198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000000") },
    };
    var out: [32]u8 = undefined;
    for (vecs) |v| {
        try std.testing.expect(pure.pairingIsOne(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("IND pairing '{s}' mismatch\n  got ={x}\n  want={x}\n", .{ v.name, out, v.out });
            return e;
        };
    }
    std.debug.print("[IND pairing] {d} go-ethereum EIP-197 vectors byte-exact\n", .{vecs.len});
}

test "IND g2_add: py_ecc (Ethereum Foundation) independently-computed vectors" {
    const vecs = [_]IndVec{
        .{ .name = "g2_3x_plus_5x", .in = &hx("1014772f57bb9742735191cd5dcfe4ebbc04156b6878a0a7c9824f32ffb66e8506064e784db10e9051e52826e192715e8d7e478cb09a5e0012defa0694fbc7f5021e2335f3354bb7922ffcc2f38d3323dd9453ac49b55441452aeaca147711b2058e1d5681b5b9e0074b0f9c8d2c68a069b920d74521e79765036d57666c55970a09ccf561b55fd99d1c1208dee1162457b57ac5af3759d50671e510e428b2a12e539c423b302d13f4e5773c603948eaf5db5df8ae8a9a9113708390a06410d819b763513924a736e4eebd0d78c91c1bc1d657fee4214057d21414011cfcc7632f8d9f9ab83727c77a2fec063cb7b6e5eb23044ccf535ad49d46d394fb6f6bf6"), .out = &hx("03589520df85791604b5a2b720a21139aabdb41949d47779484b0db588bfa69918afc7fd8df1c902383c213b6d989f0066b7eca1388be49721792278984d9a292cc25982f4a3b75f57f8f3e966d75e6da8c51776bf0828c7ce3f10171793cd2a17623e9e90176bcdf8454daa96008240b12709ca5d79de805744cfd137609bec") },
        .{ .name = "g2_doubling_7x", .in = &hx("2903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b30803c8b7cda6b2dedb7aeeaf5fda464ad17036bea1c4e6f7adbaed1ebe0335e0d81d92fff52a265017eeccb372e37d7a7bd431800eca28dfd82e21e8054114233f2903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b30803c8b7cda6b2dedb7aeeaf5fda464ad17036bea1c4e6f7adbaed1ebe0335e0d81d92fff52a265017eeccb372e37d7a7bd431800eca28dfd82e21e8054114233f"), .out = &hx("2338fa808b805bff0213886f5632496481608c8e8eb83904af0abe720f2f11ac0c8464318b31911447c39fdf6ab73ed72cc13033b426e66b223b13e28c2bbf3c2fb13d9d7724cd6fd6fdaf4b661ae7b8da56d7794327958ca5d1dd2feab13f7408f9a8699b6ec1d342a131f47b9615a5182dbd8e6b06e0d894d3cd2a7d2b02bf") },
        .{ .name = "g2_plus_infinity", .in = &hx("2903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b30803c8b7cda6b2dedb7aeeaf5fda464ad17036bea1c4e6f7adbaed1ebe0335e0d81d92fff52a265017eeccb372e37d7a7bd431800eca28dfd82e21e8054114233f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), .out = &hx("2903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b30803c8b7cda6b2dedb7aeeaf5fda464ad17036bea1c4e6f7adbaed1ebe0335e0d81d92fff52a265017eeccb372e37d7a7bd431800eca28dfd82e21e8054114233f") },
        .{ .name = "g2_negated_pair_is_infinity", .in = &hx("00fde667faf46ac5c419be1d6f28ff535a43c9efe5600584162084d55d8b508a070f2ac0bc3263aafb2cae9c281d492b5dfe1573aa83198f8befac6fa375181d06be0ca53e55034aa6719b194db361c07fee1ef3dfdff59c44b80788770c08f21e089b71af82470ee99b660d89dcfbdfccc7108e12215ad0fca5d627ebf0bc8c00fde667faf46ac5c419be1d6f28ff535a43c9efe5600584162084d55d8b508a070f2ac0bc3263aafb2cae9c281d492b5dfe1573aa83198f8befac6fa375181d29a641cda2dc9cdf11deaa9d33cdf69d17934b9d8891d4f0f768848e6170f455125bb30131af591aceb4dfa8f7a45c7dcaba5a0356506fbc3f7ab5eeec8c40bb"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") },
    };
    var out: [128]u8 = undefined;
    for (vecs) |v| {
        try std.testing.expect(pure.g2Add(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("IND g2_add '{s}' mismatch\n  got ={x}\n  want={x}\n", .{ v.name, out, v.out });
            return e;
        };
    }
    std.debug.print("[IND g2_add] {d} py_ecc-computed vectors byte-exact\n", .{vecs.len});
}

test "IND g2_mul: py_ecc (Ethereum Foundation) independently-computed vectors (incl. scalar > r)" {
    const vecs = [_]IndVec{
        .{ .name = "g2_mul_12345", .in = &hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa0000000000000000000000000000000000000000000000000000000000003039"), .out = &hx("00fde667faf46ac5c419be1d6f28ff535a43c9efe5600584162084d55d8b508a070f2ac0bc3263aafb2cae9c281d492b5dfe1573aa83198f8befac6fa375181d06be0ca53e55034aa6719b194db361c07fee1ef3dfdff59c44b80788770c08f21e089b71af82470ee99b660d89dcfbdfccc7108e12215ad0fca5d627ebf0bc8c") },
        .{ .name = "g2_mul_r_plus_7_wraps_to_7", .in = &hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000008"), .out = &hx("2903ba015a9abde26a5d081e84551e63be0fd4516e46ee6d593edeba46362455224bdc5d4327fcf8ed702e01de1c2f1657a253ba75e32a89c390142aaa28b30803c8b7cda6b2dedb7aeeaf5fda464ad17036bea1c4e6f7adbaed1ebe0335e0d81d92fff52a265017eeccb372e37d7a7bd431800eca28dfd82e21e8054114233f") },
        .{ .name = "g2_mul_max_u256_scalar_gt_r", .in = &hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), .out = &hx("18c1beedba41ddf9af588015b878aca9dc39ab7c42f25492229ae1796076ab3f2fca16fc43f7283679e062bfc2bbf54f708772c60b0f4b45358613c3eca371132c64a7dba9f4202c9a4bd4089bcf281c4c7c90c80efa266bbb36256e82047ceb1edc0a927e4e6907abe201f714d3d89d7f0dbb7001293d37ff1233d208208404") },
        .{ .name = "g2_mul_zero_scalar_is_infinity", .in = &hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa0000000000000000000000000000000000000000000000000000000000000000"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") },
        .{ .name = "g2_mul_r_scalar_is_infinity", .in = &hx("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"), .out = &hx("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") },
    };
    var out: [128]u8 = undefined;
    for (vecs) |v| {
        try std.testing.expect(pure.g2Mul(&out, v.in, true));
        std.testing.expect(std.mem.eql(u8, &out, v.out)) catch |e| {
            std.debug.print("IND g2_mul '{s}' mismatch\n  got ={x}\n  want={x}\n", .{ v.name, out, v.out });
            return e;
        };
    }
    std.debug.print("[IND g2_mul] {d} py_ecc-computed vectors byte-exact\n", .{vecs.len});
}

// (3) solana-bn254 v3.2.1 (crates.io, Solana Labs — Rust/ark-bn254, no lineage
// to Ballet/Firedancer C or go-ethereum/py_ecc either) IS the exact syscall-
// level implementation Agave validators run. Its own src/compression.rs test
// module (alt_bn128_g1_compression / alt_bn128_g2_compression) hard-codes two
// fixed numeric BE points as g1_be/g2_be (its own test ALSO negates each via
// ark-bn254 .neg() to get a flag=1 point); the compressed forms below —
// including the negated/flag=1 ones — were produced by linking that exact
// crate (a throwaway `cargo run` against solana-bn254 = "=3.2.1" + ark-bn254,
// g1/g2Compress on the published + negated g1_be/g2_be inputs) and pinned
// here verbatim. No compression util in go-ethereum or py_ecc, so this is the
// only one of the three independent sources that reaches compress/decompress
// at all — and the negated points are what give it teeth on the y-sign-flag
// path (the flag=0 points alone never set the sign bit).
test "IND compress/decompress: solana-bn254 v3.2.1 published test constants" {
    const g1_pt = hx("2dceffa69837808a4fd991a4194a78eaead94495a22c8578b8cd0c2caf62a8ac1418d80fd1af6a4b93ec5a657bdbf597d1cada68940820fef3bfda7a2a51c154");
    const g1_c = hx("2dceffa69837808a4fd991a4194a78eaead94495a22c8578b8cd0c2caf62a8ac");
    const g2_pt = hx("2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038101ad21412517a8e683efba9628d15fd3282b60f216de41f4fb75893ae6c04160e81a80650f6fe64da835e31f7d303f516c8b15b3c9093ae5a1113bd3e939812");
    const g2_c = hx("2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038");

    var out32: [32]u8 = undefined;
    var out64: [64]u8 = undefined;
    var out128: [128]u8 = undefined;

    try std.testing.expect(pure.g1Compress(&out32, &g1_pt, true));
    try std.testing.expect(std.mem.eql(u8, &out32, &g1_c));
    try std.testing.expect(pure.g1Decompress(&out64, &g1_c, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &g1_pt));

    try std.testing.expect(pure.g2Compress(&out64, &g2_pt, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &g2_c));
    try std.testing.expect(pure.g2Decompress(&out128, &g2_c, true));
    try std.testing.expect(std.mem.eql(u8, &out128, &g2_pt));

    // Negated points (g1_pt.neg() / g2_pt.neg(), same crate) — the flag=0
    // vectors above never set the sign bit (0x2d/0x28 both have bit7 clear),
    // so they alone don't exercise the y-sign-flag encode/decode path. The
    // negated forms set it (0xad/0xa8), independently proving both the
    // compress-side flag-set AND the decompress-side flag-read + correct-root
    // selection agree with solana-bn254's own ark-serialize convention.
    const g1n_pt = hx("2dceffa69837808a4fd991a4194a78eaead94495a22c8578b8cd0c2caf62a8ac1c4b76630f8235de2463eb5105a562c5c5b69028d469a98e4860b19cae2b3bf3");
    const g1n_c = hx("adceffa69837808a4fd991a4194a78eaead94495a22c8578b8cd0c2caf62a8ac");
    const g2n_pt = hx("2839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b03820497c5ecee0259b50114a0d1ef4426064feb4824703e66dec6933832a10f93121e2a66c903aa1c4ddcce78489ae546880b8b9362be136dee20f785999e96535");
    const g2n_c = hx("a839e9cdb42e236fd705175d0c4776e1072ef7932f826abdb85092678d34f21900cb7cb06e2297d442b4ee97ecbd85d11189cdb7a8c45c9f4bae51a81256b038");

    try std.testing.expect(pure.g1Compress(&out32, &g1n_pt, true));
    try std.testing.expect(std.mem.eql(u8, &out32, &g1n_c));
    try std.testing.expect(pure.g1Decompress(&out64, &g1n_c, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &g1n_pt));

    try std.testing.expect(pure.g2Compress(&out64, &g2n_pt, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &g2n_c));
    try std.testing.expect(pure.g2Decompress(&out128, &g2n_c, true));
    try std.testing.expect(std.mem.eql(u8, &out128, &g2n_pt));

    // infinity round-trips (solana-bn254's alt_bn128_compression_g{1,2}_point_of_infitity)
    var g1_inf: [64]u8 = @splat(0);
    try std.testing.expect(pure.g1Compress(&out32, &g1_inf, true));
    try std.testing.expect(std.mem.eql(u8, &out32, &([_]u8{0} ** 32)));
    try std.testing.expect(pure.g1Decompress(&out64, &out32, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &g1_inf));

    var g2_inf: [128]u8 = @splat(0);
    try std.testing.expect(pure.g2Compress(&out64, &g2_inf, true));
    try std.testing.expect(std.mem.eql(u8, &out64, &([_]u8{0} ** 64)));
    try std.testing.expect(pure.g2Decompress(&out128, &out64, true));
    try std.testing.expect(std.mem.eql(u8, &out128, &g2_inf));

    std.debug.print("[IND compress] solana-bn254 v3.2.1 g1/g2 (flag=0 + flag=1 negated + infinity) round-trips byte-exact\n", .{});
}

// ═══════════════════════════════ POSEIDON ══════════════════════════════════

test "ABS poseidon: single input 32×0x01 (LE + BE) — FD test_poseidon.c" {
    const ones32 = [_]u8{1} ** 32;
    const inputs = [_][]const u8{&ones32};
    var out: [32]u8 = undefined;
    // little-endian
    try std.testing.expect(poseidon.poseidonHash(&out, &inputs, false, false));
    try std.testing.expect(std.mem.eql(u8, &out, &hx("e6751b7fd2e091b99d63ac07841ef18288a66363c5c619cc7761ee81e5acbf05")));
    // big-endian
    try std.testing.expect(poseidon.poseidonHash(&out, &inputs, true, false));
    try std.testing.expect(std.mem.eql(u8, &out, &hx("05bface581ee6177cc19c6c56363a68882f11e8407ac639db991e0d27f1b75e6")));
    std.debug.print("[ABS poseidon] single-input LE+BE byte-exact\n", .{});
}

test "ABS poseidon: N big-endian ones, N=1..12 — FD test_poseidon.c" {
    // N=1 for a value-1 input is intentionally omitted: the FD source's single
    // "value 1" hash is not published separately (the N=1 slot in the extracted
    // table was the 32×0x01 vector, a different input); N=1 value-1 is covered by
    // the differential arm. N=2..12 are the published value-1 chain.
    const one_be = hx("0000000000000000000000000000000000000000000000000000000000000001");
    const expected = [_][]const u8{
        &hx("007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81"), // 2
        &hx("02c0066e10a72abd2b33c3b214cb3e81bcb1b6e30961cd23c202b18673bf2543"), // 3
        &hx("082c9c370a0d24f4416fbc414a37681f78442d27d86385991c17d6fc0c4b7d71"), // 4
        &hx("10389605ae688d4f14db853122c47d66a803c72b41589cb1bf868741b206b9bb"), // 5
        &hx("2a73f679328c3eab724aa3e5bdbf50b39035d7729f135b9709890f85c5dc5e76"), // 6
        &hx("2276310aa7f3343a284214139d9da959be2a31b2c708a5f81954b265e53a30b8"), // 7
        &hx("177e1453c446e1b07d2b4233425147095c4fcabb233d230b6d46a214d95b2884"), // 8
        &hx("0e8fee2fe49da30fdeeb48c42ebb44cc6ee7055f61fbca5e313b8a5fca834c47"), // 9
        &hx("2ec4c65e6378ab8c7330854f4a7077c1ff9260e44885c4b81dd131ad3a86cd96"), // 10
        &hx("00713d41eca635f117d4ecbceb5f3a66dc4142eb70b56765bc358f1bec40bb9b"), // 11
        &hx("14390be0baef249bd47c65ddac65c2e52e8513c081c1cd72c98006098e9a8fbe"), // 12
    };
    var inputs: [12][]const u8 = undefined;
    for (0..12) |k| inputs[k] = &one_be;
    var out: [32]u8 = undefined;
    for (expected, 2..) |want, n| {
        try std.testing.expect(poseidon.poseidonHash(&out, inputs[0..n], true, false));
        std.testing.expect(std.mem.eql(u8, &out, want)) catch |e| {
            std.debug.print("ABS poseidon N={d} mismatch\n  got ={x}\n  want={x}\n", .{ n, out, want });
            return e;
        };
    }
    std.debug.print("[ABS poseidon] N-ones N=2..12 byte-exact\n", .{});
}

test "ABS poseidon: FLIST cumulative chain — FD test_poseidon.c" {
    const F = [_][32]u8{
        hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e00"),
        hx("14a3e57892ce69760cb9aeac1264b93bc1b2cf2396582fa179ab45cfcad11a56"),
        hx("286ccc8e20c39275fb09874b125c04edefa69ffcdc85f09fda57ccc0517be29f"),
        hx("3059b39f6bbdef5e748a8e4d29cbb5579dcd0ce388d7b66764cb561e7aaccaf0"),
        hx("2349ea4043ca5bc09e645f3273e250305367d1488ebd9d4e6a8bffd4fc198269"),
        hx("27c60479e68630e02c1ab68fac1ca51fbf9138575e2142eaef0060e0cbc7c4e6"),
        hx("11521129a736c3b689b1f0c6e80857208945fb0155fe7924fbe2fb8d793ba781"),
        hx("24c7138347c754f4abd53a301a98a4f49fcec1719d1209a4277779bc67a4aa91"),
        hx("29d7d041cf5caeb9e8da05a84ed55d78eb2ec43088b991d9bed7a1b885c6a0f5"),
        hx("001a9b567920ec412b6078cdfcae3b089fbc03719844e6749f6386bb2fb39f28"),
        hx("2ee6f62922dc93ab42c4ac77fb23860f235a5bd0a8133cf842f000ce355d1173"),
        hx("1216ea4c02e1ad8f00278bec2a80ea80f448014440c0dde6a410762c13416689"),
        hx("00f74084d69bb8630c9e9d032d26ed0f695d781a6987ff3d49e32b69fd8bfadf"),
    };
    var inputs: [12][]const u8 = undefined;
    var out: [32]u8 = undefined;
    for (0..12) |i| {
        inputs[i] = &F[i];
        try std.testing.expect(poseidon.poseidonHash(&out, inputs[0 .. i + 1], true, false));
        std.testing.expect(std.mem.eql(u8, &out, &F[i + 1])) catch |e| {
            std.debug.print("ABS poseidon FLIST step {d} mismatch\n  got ={x}\n  want={x}\n", .{ i, out, F[i + 1] });
            return e;
        };
    }
    std.debug.print("[ABS poseidon] FLIST 12-step chain byte-exact\n", .{});
}

test {
    std.testing.refAllDecls(pure);
}
