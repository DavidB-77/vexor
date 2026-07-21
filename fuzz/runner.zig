//! Local bounded fuzz driver — NOT part of the OSS-Fuzz harness contract.
//!
//! The harness files (`fuzz_*.zig`) are plain libFuzzer-ABI modules with no `main`,
//! so a real OSS-Fuzz/libFuzzer toolchain can build them unchanged. This file exists
//! only so the SAME harness logic (`target.fuzzOne`) can be exercised locally today,
//! since the Zig 0.15.2 toolchain on this box cannot emit the full sancov
//! instrumentation (`-fsanitize=fuzzer`) that a modern libFuzzer runtime requires
//! (bare `-fsanitize-coverage-trace-pc-guard` is accepted by `zig build-obj` but
//! rejected at runtime by clang-14's libFuzzer as "no longer supported" —
//! see fuzz/README.md). This is a small mutation fuzzer: fork-per-input for crash
//! isolation, a handful of byte-level mutation operators, corpus seeding from
//! fuzz/seeds/<target>/, and crash files saved to fuzz/crashes/.
//!
//! Accepts (and honors) the libFuzzer-style flags the task's bounded run uses:
//!   -max_total_time=<seconds>   stop after this many seconds (default 60)
//!   -rss_limit_mb=<mb>          per-child address-space rlimit (default 2048)
//! plus one positional seed-corpus directory.
const std = @import("std");
const target = @import("target_harness");
const meta = @import("fuzz_meta");

// Lightweight panic handler: write the message to stderr then @trap(), skipping
// the default handler's Dwarf/filesystem-backed stack-trace symbolication. Two
// reasons: (1) that machinery is itself filesystem I/O, which the harnesses'
// "pure in-memory decode" contract shouldn't depend on to report a crash; (2) it
// turns every crash into a fast SIGILL/SIGTRAP instead of paying full
// symbolication per crashing input, which matters once a bug is common enough
// that the mutator keeps re-finding it.
pub const panic = std.debug.simple_panic;

const max_input_len: usize = 4096;

fn parseArgs() struct { max_total_time: u64, rss_limit_mb: u64, corpus_dir: ?[]const u8 } {
    var max_total_time: u64 = 60;
    var rss_limit_mb: u64 = 2048;
    var corpus_dir: ?[]const u8 = null;

    var it = std.process.args();
    _ = it.next(); // argv[0]
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-max_total_time=")) {
            max_total_time = std.fmt.parseInt(u64, arg["-max_total_time=".len..], 10) catch max_total_time;
        } else if (std.mem.startsWith(u8, arg, "-rss_limit_mb=")) {
            rss_limit_mb = std.fmt.parseInt(u64, arg["-rss_limit_mb=".len..], 10) catch rss_limit_mb;
        } else if (arg.len > 0 and arg[0] != '-') {
            corpus_dir = arg;
        }
    }
    return .{ .max_total_time = max_total_time, .rss_limit_mb = rss_limit_mb, .corpus_dir = corpus_dir };
}

fn loadSeeds(allocator: std.mem.Allocator, dir_path: ?[]const u8) std.ArrayListUnmanaged([]u8) {
    var seeds: std.ArrayListUnmanaged([]u8) = .{};
    const path = dir_path orelse return seeds;
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch return seeds;
    defer dir.close();
    var walker = dir.iterate();
    while (walker.next() catch null) |entry_| {
        if (entry_.kind != .file) continue;
        const f = dir.openFile(entry_.name, .{}) catch continue;
        defer f.close();
        const bytes = f.readToEndAlloc(allocator, max_input_len) catch continue;
        seeds.append(allocator, bytes) catch {};
    }
    return seeds;
}

var rng_state: std.Random.DefaultPrng = std.Random.DefaultPrng.init(0);

/// Fill `out` with a mutated input derived from `seeds` (or pure random if empty),
/// return the used length. Simple byte-level mutator: flip/overwrite/insert/delete,
/// a handful of rounds. Deliberately not coverage-guided (see module doc).
fn mutate(rng: std.Random, seeds: []const []u8, out: []u8) usize {
    var len: usize = 0;
    if (seeds.len > 0) {
        const seed = seeds[rng.uintLessThan(usize, seeds.len)];
        len = @min(seed.len, out.len);
        @memcpy(out[0..len], seed[0..len]);
    }

    const rounds = 1 + rng.uintLessThan(u8, 8);
    var r: u8 = 0;
    while (r < rounds) : (r += 1) {
        const op = rng.uintLessThan(u8, 5);
        switch (op) {
            0 => { // flip a random bit
                if (len == 0) continue;
                const i = rng.uintLessThan(usize, len);
                out[i] ^= @as(u8, 1) << rng.int(u3);
            },
            1 => { // overwrite a byte with a random (occasionally "interesting") value
                if (len == 0) continue;
                const i = rng.uintLessThan(usize, len);
                const interesting = [_]u8{ 0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff };
                out[i] = if (rng.boolean()) interesting[rng.uintLessThan(usize, interesting.len)] else rng.int(u8);
            },
            2 => { // insert a random byte
                if (len >= out.len) continue;
                const i = rng.uintLessThan(usize, len + 1);
                var j = len;
                while (j > i) : (j -= 1) out[j] = out[j - 1];
                out[i] = rng.int(u8);
                len += 1;
            },
            3 => { // delete a byte
                if (len == 0) continue;
                const i = rng.uintLessThan(usize, len);
                var j = i;
                while (j + 1 < len) : (j += 1) out[j] = out[j + 1];
                len -= 1;
            },
            4 => { // truncate to a random shorter length (exercises truncation handling)
                if (len == 0) continue;
                len = rng.uintLessThan(usize, len + 1);
            },
            else => unreachable,
        }
    }
    return len;
}

fn saveCrash(allocator: std.mem.Allocator, signal: u32, data: []const u8, idx: u64) void {
    std.fs.cwd().makePath("fuzz/crashes") catch {};
    var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    const name = std.fmt.allocPrint(allocator, "fuzz/crashes/{s}-sig{d}-{d}-{x}", .{
        meta.harness_name, signal, idx, hash[0..8],
    }) catch return;
    defer allocator.free(name);
    const f = std.fs.cwd().createFile(name, .{}) catch return;
    defer f.close();
    f.writeAll(data) catch {};
    std.debug.print("  saved reproducer: {s}\n", .{name});
}

pub fn main() !void {
    // page_allocator, not GeneralPurposeAllocator: the seed list intentionally
    // lives for the whole run (freed by process exit), so a leak-checking
    // allocator would just report it as a false positive at shutdown.
    const allocator = std.heap.page_allocator;

    const args = parseArgs();
    const seeds = loadSeeds(allocator, args.corpus_dir);

    var rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
    const random = rng.random();

    var scratch: [max_input_len]u8 = undefined;

    var timer = try std.time.Timer.start();
    const budget_ns: u64 = args.max_total_time * std.time.ns_per_s;

    var execs: u64 = 0;
    var crashes: u64 = 0;
    var saved: u64 = 0;
    const max_saved: u64 = 20;

    std.debug.print(
        "[{s}] starting: max_total_time={d}s rss_limit_mb={d} seeds={d}\n",
        .{ meta.harness_name, args.max_total_time, args.rss_limit_mb, seeds.items.len },
    );

    while (timer.read() < budget_ns) {
        const len = mutate(random, seeds.items, &scratch);
        const input = scratch[0..len];

        const pid = std.posix.fork() catch {
            // Can't fork (resource exhaustion) — run in-process as a fallback for
            // this one input rather than dying; loses crash isolation for it.
            target.fuzzOne(input);
            execs += 1;
            continue;
        };
        if (pid == 0) {
            // Child: best-effort bound CPU + address space, then run the target
            // once and exit. A Zig safety panic calls simple_panic -> @trap(),
            // which the kernel delivers as SIGILL/SIGTRAP — caught by the parent
            // below via WIFSIGNALED, exactly like a real memory-safety crash would be.
            _ = std.posix.setrlimit(.CPU, .{ .cur = 5, .max = 5 }) catch {};
            if (args.rss_limit_mb > 0) {
                const bytes: u64 = args.rss_limit_mb * 1024 * 1024;
                _ = std.posix.setrlimit(.AS, .{ .cur = bytes, .max = bytes }) catch {};
            }
            target.fuzzOne(input);
            std.posix.exit(0);
        }

        const res = std.posix.waitpid(pid, 0);
        execs += 1;

        if (std.posix.W.IFSIGNALED(res.status)) {
            const sig = std.posix.W.TERMSIG(res.status);
            crashes += 1;
            std.debug.print("[CRASH] exec={d} signal={d} len={d}\n", .{ execs, sig, input.len });
            if (saved < max_saved) {
                saveCrash(allocator, sig, input, crashes);
                saved += 1;
            }
        }

        if (execs % 20000 == 0) {
            const elapsed_s = timer.read() / std.time.ns_per_s;
            std.debug.print("  execs={d} elapsed={d}s crashes={d}\n", .{ execs, elapsed_s, crashes });
        }
    }

    const elapsed_s = timer.read() / std.time.ns_per_s;
    const execs_per_s = if (elapsed_s > 0) execs / elapsed_s else execs;
    std.debug.print(
        "[{s}] done: execs={d} elapsed={d}s execs/s={d} crashes={d} saved={d}\n",
        .{ meta.harness_name, execs, elapsed_s, execs_per_s, crashes, saved },
    );

    // A crash found and saved to fuzz/crashes/ must fail the process (and
    // therefore CI, per .github/workflows/fuzz.yml) — otherwise a bounded run
    // that catches a real memory-safety bug still exits 0 and the failure-only
    // crash-upload step never fires. fuzz/crashes/ already ships two committed
    // repros from a past real find (see fuzz/README.md "Findings"), so "the
    // directory is non-empty" can't be the CI signal; the exit code has to be.
    if (crashes > 0) {
        std.debug.print("[{s}] FUZZ FOUND {d} CRASH(ES) — see fuzz/crashes/\n", .{ meta.harness_name, crashes });
        return error.FuzzCrashFound;
    }
}
