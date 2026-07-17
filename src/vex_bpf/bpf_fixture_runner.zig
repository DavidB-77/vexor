// bpf_fixture_runner.zig — execute a BpfFixture against Vexor's sBPF executor
// and assert post-state parity.
//
// Wires the existing public API (`SbpfExecutor.execute`) without modifying it.
// Captures the AccountMutation slice the executor returns and diffs it against
// the fixture's `accounts_post` expectation.
//
// HONEST API GAPS (intentionally not worked around — proposed for post-merge):
//
//   1. `SbpfExecutor.execute()` swallows non-zero return codes and VM errors,
//      returning an empty mutation slice in both cases. Therefore this runner
//      cannot today distinguish "ran clean, return r0=0, no mutations" from
//      "VM aborted". `return_code_expected` is reported but not strictly
//      enforced; `runFixture` flags it as `unverifiable_return_code` in the
//      report. PROPOSAL (post-merge) for sbpf_executor.zig:
//
//          pub const ExecuteResult = struct {
//              return_code: u64,
//              status: enum { ok, reverted, vm_error, cpi_required },
//              mutations: []AccountMutation,
//          };
//          pub fn executeVerbose(...) !ExecuteResult { ... }
//
//   2. We pass `accounts_db = null`, so CPI to System (a native program) cannot
//      succeed via the current cpiHandler — it tries to load System as a BPF
//      ELF from accounts_db and fails. That is exactly what W3 fixes; the
//      System fixture is gated via `skip_reason` until it lands.

const std = @import("std");
const core = @import("core");
const fixture = @import("bpf_fixture.zig");
const bpf = @import("root.zig");
const elf = @import("elf_loader.zig");
const sbpf = @import("sbpf_executor.zig");

pub const FixtureReport = struct {
    name: []const u8,
    passed: bool,
    skipped: bool,
    skip_reason: ?[]const u8 = null,
    /// Human-readable lines explaining the diff. Owned by the caller.
    detail_lines: std.ArrayListUnmanaged([]u8) = .{},
    /// Number of expected post-state accounts that didn't match.
    mismatched_accounts: usize = 0,
    /// True iff the executor's empty-slice ambiguity prevented a return-code check.
    unverifiable_return_code: bool = false,

    pub fn deinit(self: *FixtureReport, allocator: std.mem.Allocator) void {
        for (self.detail_lines.items) |line| allocator.free(line);
        self.detail_lines.deinit(allocator);
    }

    pub fn print(self: *const FixtureReport) void {
        const status = if (self.skipped) "SKIP" else if (self.passed) "PASS" else "FAIL";
        std.log.warn("[BPF-FIX] {s}  {s}", .{ status, self.name });
        if (self.skip_reason) |sr| std.log.warn("         skip_reason: {s}", .{sr});
        for (self.detail_lines.items) |line| std.log.warn("         {s}", .{line});
    }
};

pub const RunError = error{
    ElfLoadFailed,
    NoProgramBytes,
    OutOfMemory,
    ExecutorFailure,
};

/// Execute a fixture and return a heap-allocated FixtureReport. Caller must
/// call `report.deinit(allocator)`.
pub fn runFixture(
    allocator: std.mem.Allocator,
    fix: *const fixture.BpfFixture,
) !FixtureReport {
    var report: FixtureReport = .{
        .name = fix.name,
        .passed = false,
        .skipped = false,
    };
    errdefer report.deinit(allocator);

    if (fix.isSkipped()) {
        report.skipped = true;
        report.skip_reason = fix.skip_reason orelse fix.v1_skip_reason;
        return report;
    }

    // 1. Build LoadedProgram. Either parse ELF or hand-roll from rodata.
    var program: bpf.LoadedProgram = undefined;
    var owned_program = false;
    var owned_synth_buf: ?[]u8 = null;
    defer {
        if (owned_program) program.deinit();
        if (owned_synth_buf) |b| allocator.free(b);
    }

    if (fix.program_elf.len > 0) {
        var loader = elf.ElfLoader.init(allocator);
        program = loader.load(fix.program_elf) catch return RunError.ElfLoadFailed;
        owned_program = true;
    } else if (fix.synthesised_rodata.len > 0) {
        // Synthesised: rodata == .text == the whole program. No symbols.
        const buf = try allocator.dupe(u8, fix.synthesised_rodata);
        owned_synth_buf = buf;
        program = .{
            .rodata_combined = buf,
            .text_offset = 0,
            .text_size = buf.len,
            .entry_pc = fix.entry_pc,
            .sbpf_version = .v1,
            .rodata_vaddr = bpf.interpreter.VM_PROG_START,
            .symbols = std.StringHashMap(u64).init(allocator),
            .function_registry = .{},
            .allocator = allocator,
        };
        // We don't set owned_program=true because we own the parts ourselves.
        defer program.symbols.deinit();
    } else {
        return RunError.NoProgramBytes;
    }

    // 2. Translate AccountState[] → AccountEntry[] (executor's input shape).
    const entries = try allocator.alloc(sbpf.AccountEntry, fix.accounts_pre.len);
    defer allocator.free(entries);
    for (fix.accounts_pre, 0..) |a, i| {
        entries[i] = .{
            .pubkey = a.pubkey,
            .owner = a.owner,
            .lamports = a.lamports,
            .data = a.data,
            .executable = a.executable,
            .rent_epoch = a.rent_epoch,
            .is_signer = a.is_signer,
            .is_writable = a.is_writable,
        };
    }

    // 3. Run the executor.
    var executor = sbpf.SbpfExecutor.init(allocator) catch return RunError.ExecutorFailure;
    defer executor.deinit();

    const mutations = executor.execute(
        &program,
        entries,
        fix.ix_data,
        &fix.program_id,
    ) catch |e| {
        const line = try std.fmt.allocPrint(
            allocator,
            "executor returned error: {s}",
            .{@errorName(e)},
        );
        try report.detail_lines.append(allocator, line);
        return report;
    };
    defer {
        for (mutations) |m| allocator.free(m.data);
        allocator.free(mutations);
    }

    // 4. Empty-slice ambiguity (see HONEST API GAPS at top of file). We can
    //    only meaningfully assert return_code == 0 today; a non-zero r0
    //    looks identical to a clean run that produced no mutations.
    if (fix.return_code_expected != 0) {
        report.unverifiable_return_code = true;
        const line = try std.fmt.allocPrint(
            allocator,
            "WARN: cannot verify return_code_expected={d} — executor swallows r0",
            .{fix.return_code_expected},
        );
        try report.detail_lines.append(allocator, line);
    }

    // 5. Diff observed mutations against expected post-state.
    //
    //    For every pubkey in accounts_post we look up either a returned
    //    AccountMutation (if the program wrote it) or the matching pre-state
    //    (if the program left it untouched). Mismatch => fail.
    var mismatches: usize = 0;
    for (fix.accounts_post) |expected| {
        const observed = pickObserved(fix, mutations, expected.pubkey);
        if (!accountsMatch(observed, expected)) {
            mismatches += 1;
            const line = try std.fmt.allocPrint(
                allocator,
                "mismatch pubkey={s} expected{{lamports={d},data_len={d},owner={s}}} got{{lamports={d},data_len={d},owner={s}}}",
                .{
                    fmtPk(expected.pubkey),
                    expected.lamports,
                    expected.data.len,
                    fmtPk(expected.owner),
                    observed.lamports,
                    observed.data.len,
                    fmtPk(observed.owner),
                },
            );
            try report.detail_lines.append(allocator, line);
        }
    }

    report.mismatched_accounts = mismatches;
    report.passed = (mismatches == 0) and !report.unverifiable_return_code;
    return report;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const Observed = struct {
    lamports: u64,
    data: []const u8,
    owner: core.Pubkey,
    /// Whether the executor reported a write for this pubkey. False ⇒
    /// account was untouched, observed values are the pre-state.
    written: bool,
};

fn pickObserved(
    fix: *const fixture.BpfFixture,
    mutations: []const sbpf.AccountMutation,
    pk: core.Pubkey,
) Observed {
    for (mutations) |m| {
        if (pubkeyEq(m.pubkey, pk)) {
            // SbpfExecutor.AccountMutation only carries lamports + data. Owner
            // change isn't reported by the current API; assume pre-state owner.
            const pre = findPre(fix, pk);
            return .{
                .lamports = m.new_lamports,
                .data = m.data,
                .owner = if (pre) |p| p.owner else core.Pubkey{ .data = .{0} ** 32 },
                .written = true,
            };
        }
    }
    if (findPre(fix, pk)) |p| {
        return .{ .lamports = p.lamports, .data = p.data, .owner = p.owner, .written = false };
    }
    return .{ .lamports = 0, .data = &[_]u8{}, .owner = .{ .data = .{0} ** 32 }, .written = false };
}

fn findPre(fix: *const fixture.BpfFixture, pk: core.Pubkey) ?fixture.AccountState {
    for (fix.accounts_pre) |a| if (pubkeyEq(a.pubkey, pk)) return a;
    return null;
}

fn accountsMatch(o: Observed, e: fixture.AccountState) bool {
    if (o.lamports != e.lamports) return false;
    if (!std.mem.eql(u8, o.data, e.data)) return false;
    if (!pubkeyEq(o.owner, e.owner)) return false;
    return true;
}

fn pubkeyEq(a: core.Pubkey, b: core.Pubkey) bool {
    return std.mem.eql(u8, &a.data, &b.data);
}

/// Short pubkey formatter (first 8 hex chars) — for log lines only, not
/// meant to round-trip.
fn fmtPk(pk: core.Pubkey) [16]u8 {
    var out: [16]u8 = undefined;
    const hex = "0123456789abcdef";
    for (pk.data[0..8], 0..) |b, i| {
        out[i * 2 + 0] = hex[(b >> 4) & 0xF];
        out[i * 2 + 1] = hex[b & 0xF];
    }
    return out;
}

// ── Tests ────────────────────────────────────────────────────────────────────

test "runFixture: synthesised no-op (just an EXIT) returns empty mutations" {
    const allocator = std.testing.allocator;

    // sBPF EXIT instruction = 0x95, encoded as 8-byte little-endian:
    //   opcode=0x95 dst=0 src=0 off=0 imm=0  →  bytes 95 00 00 00 00 00 00 00
    const noop_program = [_]u8{ 0x95, 0, 0, 0, 0, 0, 0, 0 };

    var pre = try allocator.alloc(fixture.AccountState, 0);
    var post = try allocator.alloc(fixture.AccountState, 0);
    var rodata = try allocator.dupe(u8, &noop_program);
    var ix = try allocator.alloc(u8, 0);

    var fix: fixture.BpfFixture = .{
        .name = try allocator.dupe(u8, "noop"),
        .skip_reason = null,
        .program_id = .{ .data = .{0} ** 32 },
        .program_elf = try allocator.alloc(u8, 0),
        .synthesised_rodata = rodata,
        .entry_pc = 0,
        .ix_data = ix,
        .accounts_pre = pre,
        .accounts_post = post,
        .return_code_expected = 0,
        .compute_budget = 1_400_000,
    };
    _ = &fix; // silence "unused mutable" in older Zig

    defer fix.deinit(allocator);
    _ = &rodata;
    _ = &pre;
    _ = &post;
    _ = &ix;

    var report = try runFixture(allocator, &fix);
    defer report.deinit(allocator);

    try std.testing.expect(!report.skipped);
    try std.testing.expect(report.passed);
    try std.testing.expectEqual(@as(usize, 0), report.mismatched_accounts);
}

test "runFixture: skipped fixture short-circuits with skip_reason set" {
    const allocator = std.testing.allocator;
    var fix: fixture.BpfFixture = .{
        .name = try allocator.dupe(u8, "skipme"),
        .skip_reason = try allocator.dupe(u8, "W3 not landed"),
        .program_id = .{ .data = .{0} ** 32 },
        .program_elf = try allocator.alloc(u8, 0),
        .synthesised_rodata = try allocator.alloc(u8, 0),
        .entry_pc = 0,
        .ix_data = try allocator.alloc(u8, 0),
        .accounts_pre = try allocator.alloc(fixture.AccountState, 0),
        .accounts_post = try allocator.alloc(fixture.AccountState, 0),
        .return_code_expected = 0,
        .compute_budget = 1_400_000,
    };
    defer fix.deinit(allocator);
    var report = try runFixture(allocator, &fix);
    defer report.deinit(allocator);
    try std.testing.expect(report.skipped);
    try std.testing.expect(!report.passed);
}
