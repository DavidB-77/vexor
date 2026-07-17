//! vex_bpf2.shadow_safety — Stage-D shadow-mode safety primitives.
//!
//! Shadow mode runs V2 BPF dispatch alongside V1 for diagnostic-only diff
//! emission. V1 owns commit; V2 runs parallel. The Wave-5/6 bring-up of this
//! path swallowed V2 errors with `catch {}`, shared the bank's allocator
//! with V2, used a static rate limit that hid early failures, and let the
//! V1 commit path live inside the same try-block as V2 — meaning a V1
//! commit failure could be mistaken for a V2 issue.
//!
//! This module is the safety substrate the shadow path layers on top of:
//!
//!   • `ShadowMetrics`  — atomic counters every shadow dispatch updates.
//!   • `RateLimiter`    — adaptive log gating (every 1, then 10, then 100,
//!                        then user-pinned). Errors are NEVER rate-limited.
//!   • `ShadowError`    — typed error variants distinguishing benign V2
//!                        failures from V1-commit-failure (fail-stop).
//!   • `CacheTx`        — tx-scoped cache view that rolls back puts on
//!                        dispatch error so V2 failures can't pollute the
//!                        V2 program cache.
//!
//! The shadow dispatch site (`replay_stage.zig::shadowDispatch`) wires all
//! four together. Each fix corresponds 1:1 with a documented risk in
//! `vault/rebuild-scope/STAGE-D-SAFETY.md`.

const std = @import("std");

// ── Risk 1: typed error variants ──────────────────────────────────────────

/// Errors raised by `shadowDispatch`. The dispatch boundary distinguishes
/// fail-stop (`Shadow_V1CommitFailed`) from log-and-continue (everything
/// else). The previous implementation funneled all errors into a single
/// `catch {}` at the call site, hiding real corruption.
pub const ShadowError = error{
    /// V1's BPF execution + commit-loop failed. This is bank-corrupting if
    /// ignored: the slot's mutation list is incomplete. Caller MUST NOT
    /// swallow — bubble up so the slot fails fast.
    Shadow_V1CommitFailed,
    /// V2 dispatch frame errored (dispatch invariant broken — distinct from
    /// a normal `v2_err` recorded inside the diff line). Diagnostic-only.
    Shadow_DispatchFailed,
    /// Could not write the shadow log line. Diagnostic-only.
    Shadow_LogWriteFailed,
    /// V2 arena allocator OOM'd. Diagnostic-only — V1 has its own allocator.
    Shadow_AllocatorFailed,
};

// ── Risk 1: atomic metrics ────────────────────────────────────────────────

/// Atomic counters surfacing shadow-mode health. Read via `selfTest`
/// dashboard or by direct field access from a diagnostics RPC.
pub const ShadowMetrics = struct {
    dispatches_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// V2 dispatch panic'd (caught by Zig's @panic handler — instrumented
    /// via the per-dispatch panic_dbg hook).
    v2_panics: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// V2 returned a named error (M5_BankBackedBpfNotPlumbed,
    /// M9_*VariantPending_*, M9_*FallbackFailed, etc.) — this is the EXPECTED
    /// failure mode for unimplemented paths and is logged in `v2_err=`.
    v2_errors_named: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// File write to the shadow log failed.
    log_write_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// CRITICAL: V1's commit path failed. Each tick is a slot that
    /// fail-stopped. Should be 0 in production.
    v1_commit_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn snapshot(self: *ShadowMetrics) Snapshot {
        return .{
            .dispatches_total = self.dispatches_total.load(.acquire),
            .v2_panics = self.v2_panics.load(.acquire),
            .v2_errors_named = self.v2_errors_named.load(.acquire),
            .log_write_failures = self.log_write_failures.load(.acquire),
            .v1_commit_failures = self.v1_commit_failures.load(.acquire),
        };
    }

    pub const Snapshot = struct {
        dispatches_total: u64,
        v2_panics: u64,
        v2_errors_named: u64,
        log_write_failures: u64,
        v1_commit_failures: u64,
    };
};

/// Process-global metrics. Replay threads share the same instance — every
/// counter is atomic so this is race-free.
pub var g_metrics: ShadowMetrics = .{};

// ── Risk 4: adaptive rate limiter ─────────────────────────────────────────

/// Rate-limit override. `auto` rides the adaptive curve; the integer values
/// pin a fixed period.
pub const RateMode = enum(u8) {
    auto = 0,
    every_1 = 1,
    every_10 = 10,
    every_100 = 100,
    every_1000 = 200, // distinct enum tag; numeric divisor read separately
};

/// Process-wide override (set once from CLI before threads spawn — same
/// pattern as `dispatch_mode._mode`).
var _rate_override: RateMode = .auto;

pub fn setRateOverride(m: RateMode) void {
    _rate_override = m;
}

pub fn rateOverride() RateMode {
    return _rate_override;
}

/// Adaptive ramp:
///   sequence 0..999     → log every 1   (1000 lines)
///   sequence 1000..9999 → log every 10  (900 lines)
///   sequence 10000+     → log every 100
///
/// Errors bypass this — see `RateLimiter.errorAlwaysLogs`.
pub const RateLimiter = struct {
    /// Returns true if the line at sequence `seq` should be emitted under
    /// the current override + adaptive ramp.
    pub fn shouldLog(seq: u64) bool {
        const override = _rate_override;
        const period: u64 = switch (override) {
            .auto => autoPeriod(seq),
            .every_1 => 1,
            .every_10 => 10,
            .every_100 => 100,
            .every_1000 => 1000,
        };
        if (period <= 1) return true;
        return (seq % period) == 0;
    }

    /// Errors are unconditionally logged — the rate limit only governs
    /// the steady-state `[VBPF2-SHADOW]` lines, never the
    /// `[VBPF2-SHADOW-ERR]` lines.
    pub fn errorAlwaysLogs() bool {
        return true;
    }

    fn autoPeriod(seq: u64) u64 {
        if (seq < 1000) return 1;
        if (seq < 10000) return 10;
        return 100;
    }
};

// ── Risk 6: tx-scoped cache rollback helper ───────────────────────────────

/// Records cache `put` operations performed during a single shadow
/// dispatch so they can be rolled back on dispatch error. The shadow path
/// drives this around `v2DispatchInternal`.
///
/// Generic over the cache + key + value types so it can be reused for any
/// future tx-scoped cache (v2_program_cache today; cpi_resolver next).
///
/// USAGE:
///   var ctx = CacheTx(Cache, [32]u8, *Entry).init(alloc, &cache);
///   defer ctx.deinit();
///   ctx.recordPut(key, prior_entry_or_null) catch {};
///   // ... do dispatch work ...
///   if (failed) ctx.rollback() else ctx.commit();
///
/// The cache type must expose `put(key, val)` and `invalidate(key)` and
/// `get(key) ?Val`. The recorded `prior` is either a valid prior entry
/// (rollback restores) or null (rollback invalidates).
pub fn CacheTx(comptime Cache: type, comptime Key: type, comptime Val: type) type {
    return struct {
        const Self = @This();
        const Record = struct {
            key: Key,
            prior: ?Val,
        };

        records: std.ArrayListUnmanaged(Record),
        alloc: std.mem.Allocator,
        cache: *Cache,
        committed: bool,

        pub fn init(alloc: std.mem.Allocator, cache: *Cache) Self {
            return .{
                .records = .{},
                .alloc = alloc,
                .cache = cache,
                .committed = false,
            };
        }

        pub fn deinit(self: *Self) void {
            self.records.deinit(self.alloc);
        }

        /// Record a put about to happen. `prior` is the cache's value for
        /// `key` *before* the put (caller queries via `cache.get(key)`).
        pub fn recordPut(self: *Self, key: Key, prior: ?Val) !void {
            try self.records.append(self.alloc, .{ .key = key, .prior = prior });
        }

        /// On dispatch success: drop the rollback log; cache state is final.
        pub fn commit(self: *Self) void {
            self.committed = true;
        }

        /// On dispatch error: restore each recorded key to its prior value
        /// (or invalidate if there was no prior). Idempotent.
        pub fn rollback(self: *Self) void {
            if (self.committed) return;
            // Walk in reverse so nested puts roll back in LIFO order.
            var i = self.records.items.len;
            while (i > 0) {
                i -= 1;
                const rec = self.records.items[i];
                if (rec.prior) |p| {
                    self.cache.put(rec.key, p) catch {
                        // Best-effort: if put fails during rollback the
                        // cache may be in a degraded state. Invalidate to
                        // force a re-resolve on next access.
                        self.cache.invalidate(rec.key);
                    };
                } else {
                    self.cache.invalidate(rec.key);
                }
            }
        }
    };
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

test "ShadowMetrics: counters increment atomically" {
    var m: ShadowMetrics = .{};
    _ = m.dispatches_total.fetchAdd(1, .monotonic);
    _ = m.dispatches_total.fetchAdd(1, .monotonic);
    _ = m.v1_commit_failures.fetchAdd(1, .monotonic);
    const s = m.snapshot();
    try std.testing.expectEqual(@as(u64, 2), s.dispatches_total);
    try std.testing.expectEqual(@as(u64, 1), s.v1_commit_failures);
}

test "RateLimiter.auto: 1000 logs in 0..999, 900 in 1000..9999, then every 100" {
    setRateOverride(.auto);
    defer setRateOverride(.auto);
    var phase1: u64 = 0;
    var i: u64 = 0;
    while (i < 1000) : (i += 1) if (RateLimiter.shouldLog(i)) {
        phase1 += 1;
    };
    try std.testing.expectEqual(@as(u64, 1000), phase1);

    var phase2: u64 = 0;
    i = 1000;
    while (i < 10000) : (i += 1) if (RateLimiter.shouldLog(i)) {
        phase2 += 1;
    };
    try std.testing.expectEqual(@as(u64, 900), phase2);

    var phase3: u64 = 0;
    i = 10000;
    while (i < 14000) : (i += 1) if (RateLimiter.shouldLog(i)) {
        phase3 += 1;
    };
    try std.testing.expectEqual(@as(u64, 40), phase3);
    // 1000 + 900 + 40 = 1940
    try std.testing.expectEqual(@as(u64, 1940), phase1 + phase2 + phase3);
}

test "RateLimiter.every_1: every line logs regardless of seq" {
    setRateOverride(.every_1);
    defer setRateOverride(.auto);
    var n: u64 = 0;
    var i: u64 = 0;
    while (i < 100) : (i += 1) if (RateLimiter.shouldLog(i)) {
        n += 1;
    };
    try std.testing.expectEqual(@as(u64, 100), n);
}

test "RateLimiter.every_100: 1 in 100 lines logs" {
    setRateOverride(.every_100);
    defer setRateOverride(.auto);
    var n: u64 = 0;
    var i: u64 = 0;
    while (i < 5000) : (i += 1) if (RateLimiter.shouldLog(i)) {
        n += 1;
    };
    try std.testing.expectEqual(@as(u64, 50), n);
}

test "RateLimiter.errorAlwaysLogs is invariant" {
    try std.testing.expect(RateLimiter.errorAlwaysLogs());
    setRateOverride(.every_1000);
    defer setRateOverride(.auto);
    try std.testing.expect(RateLimiter.errorAlwaysLogs());
}

test "CacheTx: rollback restores prior values" {
    const TestCache = struct {
        const TC = @This();
        map: std.AutoHashMap([32]u8, u32),

        pub fn init(alloc: std.mem.Allocator) TC {
            return .{ .map = std.AutoHashMap([32]u8, u32).init(alloc) };
        }
        pub fn deinit(self: *TC) void {
            self.map.deinit();
        }
        pub fn get(self: *TC, k: [32]u8) ?u32 {
            return self.map.get(k);
        }
        pub fn put(self: *TC, k: [32]u8, v: u32) !void {
            try self.map.put(k, v);
        }
        pub fn invalidate(self: *TC, k: [32]u8) void {
            _ = self.map.remove(k);
        }
    };

    const alloc = std.testing.allocator;
    var cache = TestCache.init(alloc);
    defer cache.deinit();

    const k_a: [32]u8 = .{1} ** 32;
    const k_b: [32]u8 = .{2} ** 32;

    try cache.put(k_a, 100);

    var tx = CacheTx(TestCache, [32]u8, u32).init(alloc, &cache);
    defer tx.deinit();

    // Replace A; insert B.
    try tx.recordPut(k_a, cache.get(k_a));
    try cache.put(k_a, 999);
    try tx.recordPut(k_b, cache.get(k_b));
    try cache.put(k_b, 888);

    try std.testing.expectEqual(@as(u32, 999), cache.get(k_a).?);
    try std.testing.expectEqual(@as(u32, 888), cache.get(k_b).?);

    // Rollback.
    tx.rollback();

    // A back to 100, B gone.
    try std.testing.expectEqual(@as(u32, 100), cache.get(k_a).?);
    try std.testing.expect(cache.get(k_b) == null);
}

test "CacheTx: commit makes rollback a no-op" {
    const TestCache = struct {
        const TC = @This();
        map: std.AutoHashMap([32]u8, u32),
        pub fn init(alloc: std.mem.Allocator) TC {
            return .{ .map = std.AutoHashMap([32]u8, u32).init(alloc) };
        }
        pub fn deinit(self: *TC) void {
            self.map.deinit();
        }
        pub fn get(self: *TC, k: [32]u8) ?u32 {
            return self.map.get(k);
        }
        pub fn put(self: *TC, k: [32]u8, v: u32) !void {
            try self.map.put(k, v);
        }
        pub fn invalidate(self: *TC, k: [32]u8) void {
            _ = self.map.remove(k);
        }
    };

    const alloc = std.testing.allocator;
    var cache = TestCache.init(alloc);
    defer cache.deinit();

    const k_a: [32]u8 = .{1} ** 32;
    var tx = CacheTx(TestCache, [32]u8, u32).init(alloc, &cache);
    defer tx.deinit();

    try tx.recordPut(k_a, null);
    try cache.put(k_a, 42);
    tx.commit();
    tx.rollback(); // no-op after commit

    try std.testing.expectEqual(@as(u32, 42), cache.get(k_a).?);
}
