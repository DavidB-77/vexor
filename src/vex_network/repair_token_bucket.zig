//! Repair-serve token bucket (DoS flood backstop)
//!
//! Mirrors Agave serve_repair.rs TokenBucket(MAX_BYTES_PER_SECOND): a byte budget
//! that refills by elapsed wall-clock time and is debited per repair RESPONSE. When
//! the budget is exhausted the response is DROPPED instead of served — a flood from a
//! hostile peer can saturate at most `rate` bytes/s of our serve loop, never more.
//!
//! DEFENSIVE / liveness-only: it gates ONLY outbound repair responses, never any
//! consensus path (no Bank / LtHash / vote / bank_hash touch). The default limit is
//! generous (100 MB/s == Agave's MAX_BYTES_PER_SECOND) so legitimate peers are never
//! throttled in practice; it only bites under extreme load. Monotonic-clock based.
//!
//! `tryConsume` is a pure function of (state, bytes, now_ns) so it KATs in isolation
//! (test-repair-ratelimit drives it directly, std-only — never drags tvu.zig). The
//! caller serializes access with a mutex (the serve path can run on the repair-drain
//! thread or the kernel-UDP path).

const std = @import("std");

pub const RepairTokenBucket = struct {
    /// Refill rate in bytes per second (capacity == 1s worth of bytes = rate).
    rate_bytes_per_sec: u64,
    /// Current available budget in bytes (saturates at capacity == rate).
    budget: f64,
    /// Last refill timestamp (monotonic ns). Only meaningful once `seeded` is true.
    last_ns: i128,
    /// Whether last_ns has been seeded by the first tryConsume call. A bool (not a
    /// last_ns==0 sentinel) so now_ns==0 is a valid timestamp (important for KATs /
    /// any clock whose epoch is 0).
    seeded: bool,

    pub const DEFAULT_MBPS: u64 = 100; // == Agave serve_repair MAX_BYTES_PER_SECOND

    pub fn init(rate_bytes_per_sec: u64) RepairTokenBucket {
        return .{
            .rate_bytes_per_sec = rate_bytes_per_sec,
            .budget = @floatFromInt(rate_bytes_per_sec), // start full
            .last_ns = 0,
            .seeded = false,
        };
    }

    /// Build from VEX_REPAIR_RATELIMIT_MBPS (MB/s; default 100). A value of 0 is
    /// treated as "limiter disabled" — capacity becomes effectively unbounded so
    /// tryConsume always admits (an operator escape hatch; default stays generous).
    pub fn initFromEnv() RepairTokenBucket {
        var mbps: u64 = DEFAULT_MBPS;
        if (std.posix.getenv("VEX_REPAIR_RATELIMIT_MBPS")) |s| {
            mbps = std.fmt.parseInt(u64, s, 10) catch DEFAULT_MBPS;
        }
        if (mbps == 0) return init(std.math.maxInt(u64)); // disabled → never drops
        return init(mbps *| 1_000_000);
    }

    /// Refill by elapsed time, then debit `bytes`. Returns true (and debits) if the
    /// budget covers `bytes`, false (no debit) if exhausted → caller DROPS the
    /// response. `now_ns` is a monotonic timestamp (std.time.nanoTimestamp / Instant).
    pub fn tryConsume(self: *RepairTokenBucket, bytes: u64, now_ns: i128) bool {
        const cap: f64 = @floatFromInt(self.rate_bytes_per_sec);
        if (!self.seeded) {
            self.last_ns = now_ns;
            self.seeded = true;
        } else if (now_ns > self.last_ns) {
            const elapsed_ns: f64 = @floatFromInt(now_ns - self.last_ns);
            self.budget += (elapsed_ns / 1_000_000_000.0) * @as(f64, @floatFromInt(self.rate_bytes_per_sec));
            if (self.budget > cap) self.budget = cap; // saturate at 1s capacity
            self.last_ns = now_ns;
        }
        const need: f64 = @floatFromInt(bytes);
        if (self.budget >= need) {
            self.budget -= need;
            return true;
        }
        return false;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// KATs (test-repair-ratelimit) — pure-logic, std-only, drive the bucket directly
// ═══════════════════════════════════════════════════════════════════════════════

test "RepairTokenBucket: starts full at capacity" {
    var b = RepairTokenBucket.init(1000);
    // First consume at a fixed instant: full budget == rate, so 1000 fits exactly.
    try std.testing.expect(b.tryConsume(1000, 1_000_000));
    // Now exhausted (no time elapsed): the very next byte is dropped.
    try std.testing.expect(!b.tryConsume(1, 1_000_000));
}

test "RepairTokenBucket: floods above the limit are dropped, first-K admitted" {
    // rate = 1000 B/s, capacity = 1000 B. At a FIXED instant (no refill) feed
    // N=20 requests of 100 B each (total 2000 B = 2x capacity) → first 10 admit,
    // remaining 10 are dropped and counted. Proves the byte budget, not a count.
    var b = RepairTokenBucket.init(1000);
    const now: i128 = 5_000_000_000;
    var admitted: usize = 0;
    var dropped: usize = 0;
    for (0..20) |_| {
        if (b.tryConsume(100, now)) admitted += 1 else dropped += 1;
    }
    try std.testing.expectEqual(@as(usize, 10), admitted); // 1000 / 100
    try std.testing.expectEqual(@as(usize, 10), dropped);
}

test "RepairTokenBucket: refills over elapsed (mock) time" {
    // Exhaust, then advance the mock clock by 0.5s → 500 B refilled (rate 1000 B/s).
    var b = RepairTokenBucket.init(1000);
    const t0: i128 = 0;
    try std.testing.expect(b.tryConsume(1000, t0)); // drain to 0
    try std.testing.expect(!b.tryConsume(1, t0)); // empty

    const t1: i128 = t0 + 500_000_000; // +0.5s
    // 500 B available now: 500 fits, 501 would not.
    try std.testing.expect(b.tryConsume(500, t1));
    try std.testing.expect(!b.tryConsume(1, t1));
}

test "RepairTokenBucket: refill saturates at capacity (no unbounded accrual)" {
    // Idle for 10s on a 1000 B/s bucket → would accrue 10000 B, but caps at 1000.
    var b = RepairTokenBucket.init(1000);
    try std.testing.expect(b.tryConsume(1000, 0)); // drain
    const t_late: i128 = 10_000_000_000; // +10s
    // Only one full capacity (1000) is available, not 10000.
    try std.testing.expect(b.tryConsume(1000, t_late));
    try std.testing.expect(!b.tryConsume(1, t_late));
}

test "RepairTokenBucket: a generous default never throttles a realistic peer" {
    // 100 MB/s default. A legit peer pulling 1 MB of repair in one instant fits
    // (capacity = 100 MB); only an extreme flood (>100 MB in <1s) is dropped.
    var b = RepairTokenBucket.init(RepairTokenBucket.DEFAULT_MBPS * 1_000_000);
    const now: i128 = 1;
    try std.testing.expect(b.tryConsume(1_000_000, now)); // 1 MB ok
    try std.testing.expect(b.tryConsume(50_000_000, now)); // +50 MB ok (51 MB used)
    // Pushing 60 MB more (111 MB total > 100 MB capacity) → dropped.
    try std.testing.expect(!b.tryConsume(60_000_000, now));
}

test "RepairTokenBucket: disabled (rate=max) admits everything" {
    var b = RepairTokenBucket.init(std.math.maxInt(u64)); // == initFromEnv with MBPS=0
    try std.testing.expect(b.tryConsume(1_000_000_000, 1));
    try std.testing.expect(b.tryConsume(1_000_000_000, 1)); // still admits, no real cap
}
