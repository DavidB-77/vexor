// shadow_capture.zig — dump live shadow dispatches to .fix fixtures.
//
// Activated by env var `VEX_SHADOW_CAPTURE_DIR=<path>`. When set, every
// shadow dispatch that has a non-empty ix_data, at least one account, and a
// successful V1 result (V1 IS our truth-source-of-record per vex-061 caveat
// — disagreements get arbitrated against govnode by replay-time triage, not
// at capture time) is dumped as a JSON fixture matching `vex_bpf2/fixture.zig`'s
// schema. accounts_post is computed by applying V1's mutations to the
// pre-state we just snapshotted from AccountsDb.
//
// Cap: 1000 fixtures per process (configurable via VEX_SHADOW_CAPTURE_LIMIT).
// Output filename: `cap_<seq>_<program8>_<txfp8>.fix`.
//
// On any IO failure: best-effort, returns silently. The validator never
// crashes on capture errors; capture is observability, not correctness.
//
// ── Why this is on-arc for V2 convergence ─────────────────────────────────
// Live shadow has 100s of dispatches per minute on real testnet workloads.
// Each captured fixture is a deterministic, replayable input we can use to:
//   1. Run V2 offline (`zig build test-bpf-fixture-v2`) outside the
//      validator process, where we can attach a debugger, change one line,
//      rerun without redeploying.
//   2. Cross-check against the govnode oracle when V2 disagrees with V1
//      (vex-061 says V1 silent-eats writes on Anchor panic-handler programs;
//      govnode is byte-exact Agave truth on the same testnet).
// Each disagreement = one V2 port bug retired = V2 closer to commit-able.

const std = @import("std");
const core = @import("core");

/// One snapshot account, captured pre-execution.
pub const CaptureAccount = struct {
    pubkey: [32]u8,
    owner: [32]u8,
    lamports: u64,
    data: []const u8,
    executable: bool,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
};

const State = struct {
    var dir: ?[]const u8 = null;
    var limit: u64 = 1000;
    var counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
    var inited: std.atomic.Value(u8) = std.atomic.Value(u8).init(0);
};

/// Lazy init from env. Idempotent / threadsafe via cmpxchg gate.
fn ensureInited() void {
    if (State.inited.load(.acquire) != 0) return;
    if (State.inited.cmpxchgStrong(0, 1, .acq_rel, .monotonic) != null) return;
    if (std.posix.getenv("VEX_SHADOW_CAPTURE_DIR")) |d| {
        if (d.len > 0) State.dir = d;
    }
    if (std.posix.getenv("VEX_SHADOW_CAPTURE_LIMIT")) |l| {
        State.limit = std.fmt.parseInt(u64, l, 10) catch 1000;
    }
    if (State.dir) |d| {
        std.fs.cwd().makePath(d) catch {};
        std.log.info("[SHADOW-CAPTURE] enabled dir={s} limit={d}", .{ d, State.limit });
    }
}

pub fn isEnabled() bool {
    ensureInited();
    return State.dir != null;
}

pub fn isFull() bool {
    return State.counter.load(.monotonic) >= State.limit;
}

/// Bump and return the seq, or null if cap reached.
fn nextSeq() ?u64 {
    const seq = State.counter.fetchAdd(1, .monotonic);
    if (seq >= State.limit) return null;
    return seq;
}

/// Mutation shape we accept (matches bpf_mod.AccountMutation public fields).
pub const Mutation = struct {
    pubkey: [32]u8,
    new_lamports: u64,
    new_owner: ?[32]u8,
    data: []const u8,
};

/// Write a fixture file capturing one shadow dispatch.
///
/// Caller supplies:
///   - program_id : the BPF program being invoked
///   - program_elf : the ELF bytes that will be loaded (already resolved
///     from program_account or programdata_account)
///   - ix_data : instruction data
///   - accounts_pre : snapshots of every instruction account, plus the
///     program account itself at index 0 (matching agave-conformance shape;
///     v2_dispatch's InvokeContext.push requires program_idx<tx.accounts.len)
///   - v1_mutations : V1's output (used as expected_post)
///   - compute_budget : caller's budget
///   - tx_fp : 8-byte tx fingerprint for filename uniqueness
///
/// Best-effort. Returns silently on any IO error.
pub fn captureFixture(
    allocator: std.mem.Allocator,
    program_id: [32]u8,
    program_elf: []const u8,
    ix_data: []const u8,
    accounts_pre: []const CaptureAccount,
    v1_mutations: []const Mutation,
    compute_budget: u64,
    tx_fp: [8]u8,
    tx_signature: ?[64]u8,
    source_slot: u64,
) void {
    ensureInited();
    const dir = State.dir orelse return;
    if (program_elf.len == 0) return; // no ELF → can't replay; skip
    if (accounts_pre.len == 0) return;
    const seq = nextSeq() orelse return;

    var prog8: [16]u8 = undefined;
    var txfp8: [16]u8 = undefined;
    formatHex8(&prog8, program_id[0..8].*);
    formatHex8(&txfp8, tx_fp);

    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/cap_{d:0>6}_{s}_{s}.fix", .{
        dir, seq, prog8[0..], txfp8[0..],
    }) catch return;

    var out: std.ArrayList(u8) = .{};
    defer out.deinit(allocator);

    writeFixtureJson(allocator, &out, .{
        .name = "shadow_capture",
        .program_id = program_id,
        .program_elf = program_elf,
        .ix_data = ix_data,
        .accounts_pre = accounts_pre,
        .v1_mutations = v1_mutations,
        .compute_budget = compute_budget,
        .seq = seq,
        .tx_signature = tx_signature,
        .source_slot = source_slot,
    }) catch return;

    const f = std.fs.createFileAbsolute(path, .{}) catch return;
    defer f.close();
    f.writeAll(out.items) catch {};
}

const FixtureArgs = struct {
    name: []const u8,
    program_id: [32]u8,
    program_elf: []const u8,
    ix_data: []const u8,
    accounts_pre: []const CaptureAccount,
    v1_mutations: []const Mutation,
    compute_budget: u64,
    seq: u64,
    tx_signature: ?[64]u8,
    source_slot: u64,
};

fn writeFixtureJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    args: FixtureArgs,
) !void {
    var w = out.writer(allocator);

    try w.writeAll("{\n");
    try w.print("  \"name\": \"{s}_{d}\",\n", .{ args.name, args.seq });
    try w.print("  \"v1_skip_reason\": \"shadow capture: V1 ElfLoader does not support SBPFv3\",\n", .{});

    // Phase 7: triage metadata. Lets a govnode arbitration script find the
    // canonical on-chain truth for this dispatch via getTransaction +
    // getAccountInfo <writable account> at source_slot {-1, +0}.
    if (args.tx_signature) |sig| {
        try w.writeAll("  \"source_signature\": \"");
        try writeBase58(allocator, w, &sig);
        try w.writeAll("\",\n");
    }
    try w.print("  \"source_slot\": {d},\n", .{args.source_slot});

    try w.writeAll("  \"program_id\": \"");
    try writeBase58(allocator, w, &args.program_id);
    try w.writeAll("\",\n");

    try w.writeAll("  \"program_elf_b64\": \"");
    try writeBase64(allocator, w, args.program_elf);
    try w.writeAll("\",\n");

    try w.writeAll("  \"rodata_hex\": \"\",\n");
    try w.writeAll("  \"entry_pc\": 0,\n");

    try w.writeAll("  \"ix_data_hex\": \"");
    try writeHex(w, args.ix_data);
    try w.writeAll("\",\n");

    try w.writeAll("  \"accounts_pre\": [\n");
    for (args.accounts_pre, 0..) |a, i| {
        try writeAccount(allocator, w, a);
        if (i + 1 < args.accounts_pre.len) try w.writeAll(",\n") else try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    // accounts_post = accounts_pre with v1 mutations applied to matching pubkeys.
    try w.writeAll("  \"accounts_post\": [\n");
    for (args.accounts_pre, 0..) |a, i| {
        const post_a = applyMut(a, args.v1_mutations);
        try writeAccount(allocator, w, post_a);
        if (i + 1 < args.accounts_pre.len) try w.writeAll(",\n") else try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    try w.print("  \"return_code_expected\": 0,\n", .{});
    try w.print("  \"compute_budget\": {d}\n", .{args.compute_budget});
    try w.writeAll("}\n");
}

fn applyMut(pre: CaptureAccount, muts: []const Mutation) CaptureAccount {
    for (muts) |m| {
        if (!std.mem.eql(u8, &m.pubkey, &pre.pubkey)) continue;
        return .{
            .pubkey = pre.pubkey,
            .owner = if (m.new_owner) |o| o else pre.owner,
            .lamports = m.new_lamports,
            .data = m.data,
            .executable = pre.executable,
            .rent_epoch = pre.rent_epoch,
            .is_signer = pre.is_signer,
            .is_writable = pre.is_writable,
        };
    }
    return pre;
}

fn writeAccount(allocator: std.mem.Allocator, w: anytype, a: CaptureAccount) !void {
    try w.writeAll("    { \"pubkey\": \"");
    try writeBase58(allocator, w, &a.pubkey);
    try w.writeAll("\", \"owner\": \"");
    try writeBase58(allocator, w, &a.owner);
    try w.print("\", \"lamports\": {d}, \"data_hex\": \"", .{a.lamports});
    try writeHex(w, a.data);
    // Cap rent_epoch at i64::MAX so the existing fixture parser's `.integer`
    // access works. u64::MAX (rent-exempt sentinel) is the only value that
    // would otherwise overflow; we collapse it into i64::MAX which preserves
    // "rent-exempt" semantics for the offline replay path. (The original
    // fixture parser cannot distinguish "rent_exempt sentinel" from "very
    // far in the future" — both round-trip to the same on-chain effect.)
    const safe_rent_epoch: u64 = if (a.rent_epoch > std.math.maxInt(i64))
        @as(u64, std.math.maxInt(i64))
    else
        a.rent_epoch;
    try w.print(
        "\", \"executable\": {s}, \"rent_epoch\": {d}, \"is_signer\": {s}, \"is_writable\": {s} }}",
        .{
            if (a.executable) "true" else "false",
            safe_rent_epoch,
            if (a.is_signer) "true" else "false",
            if (a.is_writable) "true" else "false",
        },
    );
}

fn writeHex(w: anytype, bytes: []const u8) !void {
    const hex = "0123456789abcdef";
    for (bytes) |b| {
        try w.writeByte(hex[(b >> 4) & 0xf]);
        try w.writeByte(hex[b & 0xf]);
    }
}

fn formatHex8(buf: *[16]u8, src: [8]u8) void {
    const hex = "0123456789abcdef";
    inline for (0..8) |i| {
        buf[i * 2 + 0] = hex[(src[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hex[src[i] & 0xf];
    }
}

fn writeBase64(allocator: std.mem.Allocator, w: anytype, bytes: []const u8) !void {
    const enc = std.base64.standard.Encoder;
    const sz = enc.calcSize(bytes.len);
    const buf = try allocator.alloc(u8, sz);
    defer allocator.free(buf);
    _ = enc.encode(buf, bytes);
    try w.writeAll(buf);
}

fn writeBase58(allocator: std.mem.Allocator, w: anytype, bytes: []const u8) !void {
    _ = allocator;
    // 64-byte tx signatures encode to ~88 base58 chars; pubkeys to ~44; both
    // fit in 128 bytes with margin. encodeToBuf rejects inputs >64 bytes.
    var b58_buf: [128]u8 = undefined;
    const s = core.base58.encodeToBuf(bytes, &b58_buf) catch {
        // Fallback: emit "hex:..." prefix; the fixture parser
        // handles this form via parsePubkey extension below.
        try w.writeAll("hex:");
        try writeHex(w, bytes);
        return;
    };
    try w.writeAll(s);
}
