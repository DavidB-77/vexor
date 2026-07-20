// bpf_fixture_test.zig — entrypoint for `zig build test-bpf-fixture`.
//
// Walks `tests/bpf_fixtures/*.fix`, loads each with bpf_fixture.loadFromFile,
// runs it through bpf_fixture_runner.runFixture, and prints the report.
// Skipped fixtures are reported as SKIP, never fail the build. Mismatched
// fixtures cause the test to fail with a stderr diff.

const std = @import("std");
const fixture = @import("bpf_fixture.zig");
const runner  = @import("bpf_fixture_runner.zig");

const FIXTURE_DIR = "tests/bpf_fixtures";

test "bpf-fixture: walk tests/bpf_fixtures/*.fix" {
    const allocator = std.testing.allocator;

    var dir = std.fs.cwd().openDir(FIXTURE_DIR, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound => {
            std.log.debug(
                "[BPF-FIX] SKIP: directory '{s}' not found (run from repo root)\n",
                .{FIXTURE_DIR},
            );
            return error.SkipZigTest;
        },
        else => return e,
    };
    defer dir.close();

    var it = dir.iterate();
    var n_total:   usize = 0;
    var n_passed:  usize = 0;
    var n_skipped: usize = 0;
    var n_failed:  usize = 0;

    while (try it.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".fix")) continue;

        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ FIXTURE_DIR, entry.name });
        defer allocator.free(path);

        n_total += 1;

        var fix = fixture.loadFromFile(allocator, path) catch |e| {
            std.log.debug("[BPF-FIX] LOAD-FAIL {s}: {s}\n", .{ path, @errorName(e) });
            n_failed += 1;
            continue;
        };
        defer fix.deinit(allocator);

        var report = runner.runFixture(allocator, &fix) catch |e| {
            std.log.debug("[BPF-FIX] RUN-FAIL {s}: {s}\n", .{ path, @errorName(e) });
            n_failed += 1;
            continue;
        };
        defer report.deinit(allocator);

        report.print();

        if (report.skipped) {
            n_skipped += 1;
        } else if (report.passed) {
            n_passed += 1;
        } else {
            n_failed += 1;
        }
    }

    std.log.warn(
        "[BPF-FIX] summary: total={d} passed={d} skipped={d} failed={d}",
        .{ n_total, n_passed, n_skipped, n_failed },
    );

    try std.testing.expectEqual(@as(usize, 0), n_failed);
}
