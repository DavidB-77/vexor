//! P5 MOAT #2 — bank_hash Divergence ALARM: MILESTONE M2, the LIVE always-on alarm.
//!
//! (Design and M2 spec are tracked in this project's internal design-docs
//! archive, not in this repo.)
//!
//! WHAT THIS IS: the runtime wrapper around M1's pure `classify()` engine
//! (src/vex_ledger/divergence_alarm.zig — the STABLE SEAM, imported unchanged). M2 adds
//! exactly three things and NOTHING on the bank_hash math path:
//!   1. A non-blocking 40-byte SPSC enqueue on the replay thread (the freeze-tap), drained
//!      by a dedicated low-priority ALARM THREAD. The replay thread NEVER does RPC, replay,
//!      allocation, or blocking — it only pushes {slot, bank_hash}. (design §1.1, §5.1)
//!   2. The alarm thread: drains the ring, tracks our frozen tip, lazily polls the public
//!      testnet-RPC oracle for ROOTED-LAG slots (≤1 call/2s, jittered), reads the P5#1
//!      FlightRecord for the slot's 4 bank_hash inputs, applies the §1.4 false-positive
//!      guards (rooted-both-sides, first-divergent walk-back, debounce, latch), and calls
//!      classify() to name the carrier class. (design §1.2–§1.4, §2)
//!   3. On a realized divergence it emits the [DIVERGENCE-ALARM] log marker + a durable
//!      bundle (SUMMARY.md / verdict.json) and — for an EXECUTION verdict — SPAWNS A CHILD
//!      PROCESS running tools/divergence-localize.sh (never in-process replay, so the live
//!      node is never blocked). VEX_DIVERGE_ALARM_PUSH is a parse+log stub (no network). (§3, §4)
//!
//! HARD INVARIANTS (spec §5.1, non-negotiable):
//!   - NO bank_hash-math change, NO new on-disk record type (pure CONSUMER of KIND_FLIGHT=12).
//!   - The producer-side enqueue NEVER blocks and can NEVER fail (drop-oldest overwrite ring).
//!   - Byte-identical replay behavior flag-OFF (comptime-dead under no -Dvex_ledger) AND
//!     flag-ON (VEX_DIVERGE_ALARM=1): the tap is a single ring push; the math is untouched.
//!
//! GATING:
//!   comptime  build_options.vex_ledger   → the whole feature is dead code in production.
//!   runtime   VEX_DIVERGE_ALARM=1         → arms the tap + spawns the thread; requires
//!             VEX_LEDGER_FLIGHT=1 (the alarm reads the FlightRecord). If VEX_DIVERGE_ALARM
//!             is set but VEX_LEDGER_FLIGHT is not, wiring logs a warning and stays dormant.
//!
//! This module is std-only (no validator/core import) so it builds and KAT-tests standalone;
//! the runtime FlightRecord read is done through an injected function pointer so the ring +
//! thread + oracle + classifier are all exercised without linking the ledger into the KATs.

const std = @import("std");
const classifier = @import("divergence_alarm.zig");

pub const Hash32 = classifier.Hash32;
pub const CarrierClass = classifier.CarrierClass;
pub const Verdict = classifier.Verdict;
pub const FlightInputs = classifier.FlightInputs;
pub const OracleInputs = classifier.OracleInputs;

// ═════════════════════════════════════════════════════════════════════════════
// 1. The freeze-tap SPSC ring — 40-byte {slot, bank_hash}, drop-OLDEST, never blocks.
// ═════════════════════════════════════════════════════════════════════════════

/// The 40-byte record the replay thread pushes at the freeze-tap. `extern` fixes the
/// layout at exactly 8 + 32 = 40 bytes (the spec's payload size).
pub const TapEntry = extern struct {
    slot: u64,
    bank_hash: Hash32,
};

comptime {
    std.debug.assert(@sizeOf(TapEntry) == 40);
}

/// Fixed 4096-entry single-producer/single-consumer overwrite ring.
///
/// CONTRACT (my directive, resolving spec GAP #1): the PRODUCER (replay thread) NEVER
/// blocks and NEVER fails — on a full ring it overwrites the OLDEST unread entry and bumps
/// a `dropped` counter. The consumer (alarm thread) detects when the producer has lapped it
/// and re-aligns its tail to the oldest still-present entry. Only head/tail are the cursors;
/// each is written by exactly one thread (producer=head, consumer=tail) so the SPSC
/// invariant holds; `dropped` is the producer's authoritative overwrite count. A per-read
/// re-check of head guards against a torn read if the producer laps during the copy.
pub const CAPACITY: u32 = 4096;

pub const AlarmRing = struct {
    entries: [CAPACITY]TapEntry = undefined,
    mask: u32 = CAPACITY - 1,
    head: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // producer cursor
    tail: std.atomic.Value(u32) = std.atomic.Value(u32).init(0), // consumer cursor
    pushed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    popped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    /// PRODUCER-ONLY. Infallible + non-blocking. If the ring is full this overwrites the
    /// oldest unread entry (drop-oldest) and increments `dropped`. This is the entire
    /// hot-path cost of the alarm: one load, one compare, one store.
    pub fn push(self: *Self, entry: TapEntry) void {
        const head = self.head.load(.monotonic); // producer owns head
        const tail = self.tail.load(.acquire); // observe consumer progress (advisory)
        if (head -% tail >= CAPACITY) {
            // Overwriting an unread slot: count the drop here (producer is authoritative).
            _ = self.dropped.fetchAdd(1, .monotonic);
        }
        self.entries[head & self.mask] = entry;
        self.head.store(head +% 1, .release); // publish the slot write
        _ = self.pushed.fetchAdd(1, .monotonic);
    }

    /// CONSUMER-ONLY. Returns false when empty. Re-aligns past any entries the producer
    /// lapped (those were already counted by the producer). Retries on a torn read.
    pub fn pop(self: *Self, out: *TapEntry) bool {
        while (true) {
            const tail = self.tail.load(.monotonic); // consumer owns tail
            const head = self.head.load(.acquire); // observe producer publish
            if (head == tail) return false; // empty
            var t = tail;
            if (head -% t > CAPACITY) {
                // Producer lapped us; skip to the oldest still-present entry.
                t = head -% CAPACITY;
            }
            const entry = self.entries[t & self.mask]; // copy out
            // Guard: if the producer lapped past `t` DURING the copy, the bytes may be torn.
            const head2 = self.head.load(.acquire);
            if (head2 -% t > CAPACITY) continue; // torn — retry with a fresh alignment
            out.* = entry;
            self.tail.store(t +% 1, .release);
            _ = self.popped.fetchAdd(1, .monotonic);
            return true;
        }
    }

    pub fn depth(self: *const Self) u32 {
        return self.head.load(.monotonic) -% self.tail.load(.monotonic);
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// 2. False-positive guards (design §1.4) — pure, testable helpers.
// ═════════════════════════════════════════════════════════════════════════════

/// Guard #1 (design §1.4.1): only compare a slot once it is rooted by BOTH sides. A slot we
/// replayed on a fork the cluster abandoned is a dropped fork, not a divergence.
pub fn rootedBothSides(our_rooted: bool, cluster_finalized: bool) bool {
    return our_rooted and cluster_finalized;
}

/// Guard #4 (design §1.4.4): a single stale oracle read must not fire. The debouncer only
/// promotes a divergence to FIRING after the SAME slot re-confirms divergent on a re-query.
pub const Debouncer = struct {
    /// The slot currently held pending a re-confirm (null = nothing pending).
    pending_slot: ?u64 = null,
    pending_class: CarrierClass = .convergent,

    pub const Decision = enum {
        /// Convergent / nothing to do.
        idle,
        /// First divergent sighting — held pending one re-query (do NOT fire yet).
        armed,
        /// Re-query re-confirmed the same divergent slot — FIRE now.
        fire,
    };

    /// Feed one classification outcome for `slot`. Returns whether to fire. `divergent` is
    /// (class != convergent). A divergent slot arms on first sight; a second divergent
    /// sighting of the SAME slot fires; a convergent sighting clears the pending latch.
    pub fn observe(self: *Debouncer, slot: u64, class: CarrierClass) Decision {
        const divergent = class != .convergent and class != .inconsistent;
        if (!divergent) {
            // A convergent re-read of the pending slot clears it (it was a stale read).
            if (self.pending_slot) |ps| {
                if (ps == slot) self.pending_slot = null;
            }
            return .idle;
        }
        if (self.pending_slot) |ps| {
            if (ps == slot) {
                // Second divergent sighting of the same slot → confirmed.
                self.pending_slot = null;
                return .fire;
            }
            // A different, earlier divergent slot supersedes (first-divergent wins).
        }
        self.pending_slot = slot;
        self.pending_class = class;
        return .armed;
    }
};

/// Guard #3 (design §1.4.3): first-divergent, not downstream. Once we have LATCHED an anchor
/// slot, no slot at or after it re-fires. The latch is the anchor of the divergence event.
pub const Latch = struct {
    anchor: ?u64 = null,

    /// Should `slot` be allowed to fire? Only if we have not latched, or `slot` is strictly
    /// BEFORE the current anchor (an earlier first-divergent slot re-anchors the event).
    pub fn allow(self: *const Latch, slot: u64) bool {
        if (self.anchor) |a| return slot < a;
        return true;
    }

    pub fn set(self: *Latch, slot: u64) void {
        self.anchor = slot;
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// 3. base58 decode (std-only, no core import) — for the oracle blockhash → 32 bytes.
// ═════════════════════════════════════════════════════════════════════════════

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode a base58 string into exactly 32 bytes. Returns null on any invalid char or a
/// decoded length ≠ 32 (best-effort: a malformed oracle response yields `unknown`, never a
/// false compare).
pub fn base58Decode32(s: []const u8) ?Hash32 {
    var buf: [64]u8 = [_]u8{0} ** 64;
    var buf_len: usize = 0;
    for (s) |c| {
        const digit = std.mem.indexOfScalar(u8, B58_ALPHABET, c) orelse return null;
        var carry: usize = @intCast(digit);
        var i: usize = 0;
        while (i < buf_len) : (i += 1) {
            carry += @as(usize, buf[i]) * 58;
            buf[i] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            if (buf_len >= buf.len) return null;
            buf[buf_len] = @intCast(carry & 0xff);
            buf_len += 1;
            carry >>= 8;
        }
    }
    // Leading '1's are leading zero bytes.
    for (s) |c| {
        if (c == '1') buf_len += 1 else break;
    }
    if (buf_len != 32) return null;
    var out: Hash32 = undefined;
    // buf is little-endian (least significant first); the wire hash is big-endian.
    var j: usize = 0;
    while (j < 32) : (j += 1) out[j] = buf[31 - j];
    return out;
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Config (env-parsed once at wiring).
// ═════════════════════════════════════════════════════════════════════════════

pub const AlarmConfig = struct {
    /// VEX_DIVERGE_ALARM_AUTOREPLAY=0 → detect+classify only (emit REPRO, skip child replay).
    autoreplay: bool = true,
    /// VEX_DIVERGE_ALARM_PUSH → notify stub (parsed + logged; no network in M2).
    push: bool = false,
    /// Public testnet RPC oracle (CLUSTER ORACLE HARD RULE — never Vexor localhost/oracle-node).
    oracle_url: []const u8 = "https://api.testnet.solana.com",
    /// Bundle output root.
    bundle_root: []const u8 = "/tmp/vexor-divergence-bundles",
    /// The M1 wrapper the alarm spawns as a child process on an EXECUTION verdict.
    /// Operators wire this up to their own local diagnostic tooling; none ships
    /// in this repo by default.
    localize_script: []const u8 = "",
    /// Rooted-lag: only compare a slot once it is this many slots behind our tip.
    rooted_lag: u64 = 32,

    pub fn fromEnv() AlarmConfig {
        var c = AlarmConfig{};
        if (std.posix.getenv("VEX_DIVERGE_ALARM_AUTOREPLAY")) |v| {
            c.autoreplay = !std.mem.eql(u8, std.mem.trim(u8, v, " \t\r\n"), "0");
        }
        c.push = std.posix.getenv("VEX_DIVERGE_ALARM_PUSH") != null;
        if (std.posix.getenv("VEX_DIVERGE_ALARM_ORACLE")) |v| c.oracle_url = v;
        if (std.posix.getenv("VEX_DIVERGE_ALARM_BUNDLE_DIR")) |v| c.bundle_root = v;
        if (std.posix.getenv("VEX_DIVERGE_ALARM_LOCALIZE")) |v| c.localize_script = v;
        return c;
    }
};

/// Injected FlightRecord reader — decouples the alarm thread from the ledger for testing.
/// Returns the slot's 4 bank_hash inputs, or null if the record is not present.
pub const FlightReadFn = *const fn (ctx: ?*anyopaque, slot: u64) ?FlightInputs;

/// Injected oracle client — returns the cluster canonical inputs for a rooted slot, or null
/// if the slot is not yet cluster-finalized (guard #1: skip un-rooted / dropped forks).
pub const OracleFetchFn = *const fn (ctx: ?*anyopaque, cfg: *const AlarmConfig, slot: u64) ?OracleInputs;

// ═════════════════════════════════════════════════════════════════════════════
// 5. The alarm engine — thread lifecycle + the detection loop.
// ═════════════════════════════════════════════════════════════════════════════

pub const DivergeAlarm = struct {
    allocator: std.mem.Allocator,
    ring: AlarmRing = .{},
    config: AlarmConfig,

    // Wiring (set before start()):
    flight_ctx: ?*anyopaque = null,
    flight_read: FlightReadFn,
    oracle_ctx: ?*anyopaque = null,
    oracle_fetch: OracleFetchFn,

    // Thread state:
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Detection state (alarm-thread-private):
    our_tip: u64 = 0,
    next_check: u64 = 0, // lowest slot not yet compared
    last_good: u64 = 0, // highest slot whose bank_hash matched the cluster (parent transitivity)
    debouncer: Debouncer = .{},
    latch: Latch = .{},
    fired_count: u64 = 0,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        config: AlarmConfig,
        flight_ctx: ?*anyopaque,
        flight_read: FlightReadFn,
        oracle_ctx: ?*anyopaque,
        oracle_fetch: OracleFetchFn,
    ) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .config = config,
            .flight_ctx = flight_ctx,
            .flight_read = flight_read,
            .oracle_ctx = oracle_ctx,
            .oracle_fetch = oracle_fetch,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// PRODUCER (replay thread). Non-blocking, infallible. This is the whole hot-path tap.
    pub fn enqueue(self: *Self, slot: u64, bank_hash: Hash32) void {
        self.ring.push(.{ .slot = slot, .bank_hash = bank_hash });
    }

    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, threadMain, .{self});
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn threadMain(self: *Self) void {
        // Low priority: the alarm must never CPU-preempt consensus. We do not hard-pin to a
        // core (a hard pin risks landing on a consensus core across box reconfigs); nice(19)
        // + the standing core-disjointness of the busy consensus cores keeps us cold. An
        // operator can pin explicitly via taskset on the process if desired.
        _ = std.os.linux.syscall3(.setpriority, 0, 0, @bitCast(@as(isize, 19)));
        std.log.warn("[DIVERGENCE-ALARM] thread ARMED (oracle={s} autoreplay={} push={})", .{
            self.config.oracle_url, self.config.autoreplay, self.config.push,
        });

        var prng = std.Random.DefaultPrng.init(0xD1_AE_A1_A2_00_00_00_01);
        const rand = prng.random();

        while (self.running.load(.acquire)) {
            // Drain the ring: advance our frozen tip.
            var e: TapEntry = undefined;
            var drained: usize = 0;
            while (self.ring.pop(&e)) {
                if (e.slot > self.our_tip) self.our_tip = e.slot;
                if (self.next_check == 0) self.next_check = e.slot; // first-ever slot
                drained += 1;
                if (drained >= 512) break; // bound one drain burst
            }

            // Lazily compare ONE rooted-lag slot per tick (≤1 oracle call / ~2s, jittered).
            self.stepCompare();

            // Jittered idle: ~2s ± 0.5s. On a fired+latched event we back off harder.
            const base_ms: u64 = if (self.latch.anchor != null) 5000 else 2000;
            const jitter_ms: u64 = rand.uintLessThan(u64, 1000);
            sleepMs(base_ms + jitter_ms);
        }
        std.log.warn("[DIVERGENCE-ALARM] thread STOPPED (fired={d} dropped={d})", .{
            self.fired_count, self.ring.dropped.load(.monotonic),
        });
    }

    /// Compare exactly the next eligible rooted-lag slot (bounded work per tick).
    fn stepCompare(self: *Self) void {
        if (self.next_check == 0) return; // nothing frozen yet
        if (self.our_tip < self.config.rooted_lag) return;
        const rooted_edge = self.our_tip - self.config.rooted_lag;
        if (self.next_check > rooted_edge) return; // nothing new is old enough yet

        const slot = self.next_check;

        // Read OUR 4 inputs from the FlightRecord (design §5.3 — the alarm is a consumer).
        const flight = self.flight_read(self.flight_ctx, slot) orelse {
            // No record (pruned / flight off for this slot) — cannot compare; advance.
            self.next_check += 1;
            return;
        };

        // Oracle: cluster canonical for a FINALIZED slot. null ⇒ not cluster-rooted yet /
        // dropped fork ⇒ guard #1 skip (do NOT advance; re-check next tick until finalized).
        const oracle = self.oracle_fetch(self.oracle_ctx, &self.config, slot) orelse return;

        // Parent transitivity (design §1.4.3 walk-back input): if the immediate parent was
        // our last known-good compared slot, the parent matched; otherwise leave it unknown
        // and let the classifier fall to the bank_hash elimination.
        var o = oracle;
        if (o.parent_matches == null and self.last_good + 1 == slot) o.parent_matches = true;

        const v = classifier.classify(flight, o);

        if (v.class == .convergent) {
            self.last_good = slot;
            self.next_check += 1;
            _ = self.debouncer.observe(slot, .convergent); // clears any stale pending
            return;
        }

        // Divergent. Debounce: first sighting arms, second confirms (guard #4).
        const decision = self.debouncer.observe(slot, v.class);
        if (decision == .armed) {
            // Hold this slot for a re-confirm on the next tick (do not advance next_check).
            return;
        }
        if (decision == .fire) {
            if (self.latch.allow(slot)) {
                self.latch.set(slot);
                self.fire(slot, flight, o, v);
            }
            self.next_check += 1;
        }
    }

    /// Emit the alarm: [DIVERGENCE-ALARM] marker + durable bundle + (EXECUTION) child spawn.
    fn fire(self: *Self, slot: u64, flight: FlightInputs, oracle: OracleInputs, v: Verdict) void {
        self.fired_count += 1;
        var short_buf: [16]u8 = undefined;
        std.log.err(
            "[DIVERGENCE-ALARM] slot={d} class={s} needs_account_diff={} reanchor_parent={} " ++
                "our_bank={s} first_divergent=true",
            .{ slot, v.class.asStr(), v.needs_account_diff, v.reanchor_parent, hexShortInto(&short_buf, flight.bank_hash) },
        );

        const bundle = self.writeBundle(slot, flight, oracle, v) catch |err| {
            std.log.err("[DIVERGENCE-ALARM] bundle write FAILED slot={d}: {any}", .{ slot, err });
            return;
        };
        defer self.allocator.free(bundle);
        std.log.err("[DIVERGENCE-ALARM] bundle={s}", .{bundle});

        if (self.config.push) {
            // PUSH STUB (spec §4.2): env parsed, intent logged — NO network in M2. The full
            // signed/trusted webhook story is post-M2.
            std.log.warn("[DIVERGENCE-ALARM] PUSH requested (stub) — would post {s}/SUMMARY.md", .{bundle});
        }

        if (v.needs_account_diff and self.config.autoreplay) {
            self.spawnLocalize(slot, bundle);
        } else if (v.needs_account_diff) {
            std.log.warn("[DIVERGENCE-ALARM] autoreplay OFF — see {s}/REPRO.sh to localize slot {d}", .{ bundle, slot });
        }
    }

    /// Write the durable bundle dir with SUMMARY.md + verdict.json + REPRO.sh (spec §4.1).
    fn writeBundle(self: *Self, slot: u64, flight: FlightInputs, oracle: OracleInputs, v: Verdict) ![]u8 {
        const ts = std.time.timestamp();
        const dir = try std.fmt.allocPrint(self.allocator, "{s}/divergence-alarm-{d}-{d}", .{ self.config.bundle_root, slot, ts });
        errdefer self.allocator.free(dir);
        std.fs.cwd().makePath(dir) catch |err| {
            std.log.err("[DIVERGENCE-ALARM] makePath {s}: {any}", .{ dir, err });
            return err;
        };

        // Render both hashes into DISTINCT buffers up front (never call hexInto twice on one
        // shared buffer inside a single format expression — that aliases and collides them).
        var our_hb: [64]u8 = undefined;
        var cluster_hb: [64]u8 = undefined;
        const our_hex = hexInto(&our_hb, flight.bank_hash);
        const cluster_hex = hexInto(&cluster_hb, oracle.bank_hash orelse ([_]u8{0} ** 32));

        // verdict.json
        {
            const json = try std.fmt.allocPrint(self.allocator,
                \\{{
                \\  "slot": {d},
                \\  "class": "{s}",
                \\  "first_divergent_slot": {d},
                \\  "our_bank_hash": "{s}",
                \\  "cluster_bank_hash": "{s}",
                \\  "inputs": {{
                \\    "parent": "{s}",
                \\    "poh": "{s}",
                \\    "sigs": "{s}",
                \\    "lthash": "{s}"
                \\  }},
                \\  "needs_account_diff": {},
                \\  "reanchor_parent": {},
                \\  "autoreplay": {}
                \\}}
                \\
            , .{
                slot,               v.class.asStr(),
                slot,               our_hex,
                cluster_hex,        matchStr(v.parent),
                matchStr(v.poh),    matchStr(v.sigs),
                matchStr(v.lthash), v.needs_account_diff,
                v.reanchor_parent,  self.config.autoreplay,
            });
            defer self.allocator.free(json);
            try writeFileInDir(dir, "verdict.json", json);
        }

        // SUMMARY.md
        {
            const md = try std.fmt.allocPrint(self.allocator,
                \\# DIVERGENCE-ALARM — slot {d}
                \\
                \\- **class**: {s}
                \\- **our bank_hash**: {s}
                \\- **parent**: {s}  **poh**: {s}  **sigs**: {s}  **lthash**: {s}
                \\- **needs account diff**: {}
                \\- **reanchor parent**: {}
                \\
                \\This is the LIVE analog of `[BANK-FROZEN]`. For an EXECUTION class the alarm
                \\spawned `divergence-localize.sh --slot {d}` to name the exact account+field+owner
                \\(see this dir's per-account outputs once the child completes), unless autoreplay
                \\was disabled — in which case run REPRO.sh during a node-down window.
                \\
            , .{
                slot,               v.class.asStr(),
                our_hex,            matchStr(v.parent),
                matchStr(v.poh),    matchStr(v.sigs),
                matchStr(v.lthash), v.needs_account_diff,
                v.reanchor_parent,  slot,
            });
            defer self.allocator.free(md);
            try writeFileInDir(dir, "SUMMARY.md", md);
        }

        // REPRO.sh — the exact offline re-replay the operator (or the child) runs.
        {
            const sh = try std.fmt.allocPrint(self.allocator,
                \\#!/usr/bin/env bash
                \\# Auto-generated by the divergence-alarm (M2). Localize slot {d} offline.
                \\set -euo pipefail
                \\exec nice -n 19 ionice -c3 taskset -c 28-31 \
                \\  {s} --slot {d} --oracle --out "$(cd "$(dirname "$0")" && pwd)"
                \\
            , .{ slot, self.config.localize_script, slot });
            defer self.allocator.free(sh);
            try writeFileInDir(dir, "REPRO.sh", sh);
        }

        return dir;
    }

    /// Spawn tools/divergence-localize.sh as a detached child (never in-process). The child
    /// runs core-pinned + niced; its lifetime is independent of the validator.
    fn spawnLocalize(self: *Self, slot: u64, bundle: []const u8) void {
        if (self.config.localize_script.len == 0) return; // no localize tool wired up
        var slot_buf: [24]u8 = undefined;
        const slot_str = std.fmt.bufPrint(&slot_buf, "{d}", .{slot}) catch return;
        const argv = [_][]const u8{
            "nice",                      "-n",     "19",     "ionice",   "-c3",   "taskset", "-c", "28-31",
            self.config.localize_script, "--slot", slot_str, "--oracle", "--out", bundle,
        };
        var child = std.process.Child.init(&argv, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.spawn() catch |err| {
            std.log.err("[DIVERGENCE-ALARM] localize spawn FAILED slot={d}: {any}", .{ slot, err });
            return;
        };
        std.log.err("[DIVERGENCE-ALARM] localize child spawned pid={d} slot={d} → {s}", .{ child.id, slot, bundle });
        // Detach: do NOT wait (the alarm thread must not block on the heavy replay).
    }
};

// ── small std-only helpers ───────────────────────────────────────────────────

fn sleepMs(ms: u64) void {
    std.Thread.sleep(ms * std.time.ns_per_ms);
}

fn matchStr(m: classifier.Match) []const u8 {
    return switch (m) {
        .match => "match",
        .differ => "differ",
        .unknown => "unknown",
    };
}

const HEX = "0123456789abcdef";

/// Full 64-char hex of a 32-byte hash into a CALLER-provided buffer. Caller-owned buffers
/// (never a shared static) so two hashes can be rendered in a SINGLE format expression
/// without aliasing — the bug that made verdict.json's our/cluster hashes collide.
fn hexInto(buf: *[64]u8, h: Hash32) []const u8 {
    for (h, 0..) |b, i| {
        buf[i * 2] = HEX[b >> 4];
        buf[i * 2 + 1] = HEX[b & 0xf];
    }
    return buf[0..64];
}

/// First-8-bytes hex (16 chars) into a caller buffer — the log-marker short form.
fn hexShortInto(buf: *[16]u8, h: Hash32) []const u8 {
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        buf[i * 2] = HEX[h[i] >> 4];
        buf[i * 2 + 1] = HEX[h[i] & 0xf];
    }
    return buf[0..16];
}

fn writeFileInDir(dir: []const u8, name: []const u8, contents: []const u8) !void {
    var d = try std.fs.cwd().openDir(dir, .{});
    defer d.close();
    var f = try d.createFile(name, .{});
    defer f.close();
    try f.writeAll(contents);
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Live oracle client (curl child from the ALARM thread ONLY — never replay thread).
// ═════════════════════════════════════════════════════════════════════════════
//
// Design GAP #2 resolved (my directive): no in-tree HTTP client is wired to a public
// endpoint, so shell out to `curl -s --max-time 10` from the alarm thread. Zero new deps.
// getBlock(slot, commitment=finalized, transactionDetails=signatures, rewards=false) →
//   .result.blockhash          (base58 PoH → 32 bytes)
//   Σ .result.signatures.len    (cluster signature accounting, coarse)
// A null return (404 / not finalized / parse fail) means "not comparable yet" = guard #1.

pub const CurlOracle = struct {
    allocator: std.mem.Allocator,

    pub fn fetch(ctx: ?*anyopaque, cfg: *const AlarmConfig, slot: u64) ?OracleInputs {
        const self: *CurlOracle = @ptrCast(@alignCast(ctx.?));
        // transactionDetails="none": we only need .blockhash (the PoH input). commitment
        // "finalized" enforces the rooted-both-sides guard #1 (unfinalized/dropped forks 404).
        const body = std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBlock\",\"params\":[{d}," ++
                "{{\"commitment\":\"finalized\",\"transactionDetails\":\"none\"," ++
                "\"rewards\":false,\"maxSupportedTransactionVersion\":0}}]}}",
            .{slot},
        ) catch return null;
        defer self.allocator.free(body);

        const argv = [_][]const u8{
            "curl", "-s",                             "--max-time", "10", "-X",           "POST",
            "-H",   "Content-Type: application/json", "-d",         body, cfg.oracle_url,
        };
        var child = std.process.Child.init(&argv, self.allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch return null;
        const out = child.stdout.?.readToEndAlloc(self.allocator, 8 * 1024 * 1024) catch {
            _ = child.wait() catch {};
            return null;
        };
        defer self.allocator.free(out);
        _ = child.wait() catch {};

        return parseGetBlock(out);
    }

    /// Minimal, allocation-free-ish JSON scrape of the getBlock result. Best-effort: any
    /// missing field yields `unknown` on that input, never a false compare.
    ///
    /// signature_count is DELIBERATELY left `unknown` (see `txCount` below): getBlock with
    /// transactionDetails="signatures" returns ONE (primary) signature per transaction, so a
    /// count of that array = the TRANSACTION count, which is NOT Agave's bank `signature_count`
    /// (the SUM of every tx's signatures.len — larger whenever any tx has >1 signer). Comparing
    /// the coarse count to Agave's summed count FALSE-FIRES SIG_ACCOUNTING on every ordinary
    /// multi-signer block (empirically: slot 421723201 → our 478 vs 474 tx-sigs). The design
    /// (§1.2) flags this compare as "coarse"; an exact sig sum needs transactionDetails="full"
    /// (deferred — heavy response). Until then we do not fire on signatures.
    fn parseGetBlock(json: []const u8) ?OracleInputs {
        // An RPC error (e.g. -32009 slot skipped) or missing result → not comparable.
        if (std.mem.indexOf(u8, json, "\"result\"") == null) return null;
        var o = OracleInputs{};
        if (extractString(json, "\"blockhash\":\"")) |bh| {
            o.poh_hash = base58Decode32(bh);
        }
        // NB: signature_count intentionally NOT populated — see doc comment above.
        return o;
    }

    /// Count of primary-signature strings in a getBlock "signatures" array = the block's
    /// TRANSACTION count (NOT Agave's signature_count). Exposed for diagnostics / future exact
    /// sig-sum work; NOT used by the classifier (would false-fire — see parseGetBlock).
    fn txCount(json: []const u8) ?u64 {
        const idx = std.mem.indexOf(u8, json, "\"signatures\":[") orelse return null;
        var count: u64 = 0;
        var k = idx + "\"signatures\":[".len;
        var depth: i32 = 1;
        while (k < json.len and depth > 0) : (k += 1) {
            switch (json[k]) {
                '[' => depth += 1,
                ']' => depth -= 1,
                '"' => {
                    count += 1;
                    k += 1;
                    while (k < json.len and json[k] != '"') : (k += 1) {}
                },
                else => {},
            }
        }
        return count;
    }

    fn extractString(json: []const u8, key: []const u8) ?[]const u8 {
        const idx = std.mem.indexOf(u8, json, key) orelse return null;
        const start = idx + key.len;
        const end_rel = std.mem.indexOfScalar(u8, json[start..], '"') orelse return null;
        return json[start .. start + end_rel];
    }
};

// ═════════════════════════════════════════════════════════════════════════════
// 7. Live FlightRecord reader adapter — bridges VexLedger → FlightInputs.
//    (Kept as a thin free function so the KATs can inject a fake instead.)
// ═════════════════════════════════════════════════════════════════════════════
//
// The concrete wiring lives in replay_stage.zig/main.zig (they own the VexLedger type and
// its blake3 digest of accounts_lt_hash). This module stays validator-free; the adapter is
// provided by the caller as a FlightReadFn. See main.zig `wireDivergeAlarm`.

// ═════════════════════════════════════════════════════════════════════════════
//                                    KATs
// ═════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

fn th(byte: u8) Hash32 {
    return [_]u8{byte} ** 32;
}

test "ring: enqueue/drain FIFO, empty→false" {
    var ring = AlarmRing{};
    var out: TapEntry = undefined;
    try testing.expect(!ring.pop(&out)); // empty

    var i: u64 = 0;
    while (i < 100) : (i += 1) ring.push(.{ .slot = 1000 + i, .bank_hash = th(@intCast(i & 0xff)) });
    try testing.expectEqual(@as(u32, 100), ring.depth());

    i = 0;
    while (i < 100) : (i += 1) {
        try testing.expect(ring.pop(&out));
        try testing.expectEqual(@as(u64, 1000 + i), out.slot);
    }
    try testing.expect(!ring.pop(&out));
    try testing.expectEqual(@as(u64, 0), ring.dropped.load(.monotonic));
}

test "ring: drop-OLDEST when full, dropped counter counts overwrites, survivors are newest" {
    var ring = AlarmRing{};
    // Push CAPACITY + 5 without draining → 5 oldest overwritten.
    var i: u64 = 0;
    const total: u64 = CAPACITY + 5;
    while (i < total) : (i += 1) ring.push(.{ .slot = i, .bank_hash = th(0) });
    try testing.expectEqual(@as(u64, 5), ring.dropped.load(.monotonic));
    // depth() = head-tail is the LOGICAL unconsumed count (incl. the 5 lapped-but-unrealigned
    // slots); the consumer realigns tail on the first pop, capping live survivors at CAPACITY.
    try testing.expectEqual(@as(u32, CAPACITY + 5), ring.depth());

    // The survivors are the NEWEST CAPACITY entries: slots 5 .. total-1, in FIFO order.
    var out: TapEntry = undefined;
    var expect: u64 = 5;
    var survivors: u64 = 0;
    while (ring.pop(&out)) : (expect += 1) {
        try testing.expectEqual(expect, out.slot);
        survivors += 1;
    }
    try testing.expectEqual(total, expect);
    try testing.expectEqual(@as(u64, CAPACITY), survivors);
}

test "ring: wraparound preserves FIFO over many push/pop cycles" {
    var ring = AlarmRing{};
    var next_push: u64 = 0;
    var next_expect: u64 = 0;
    var out: TapEntry = undefined;
    var round: u64 = 0;
    while (round < 50_000) : (round += 1) {
        var p: u32 = 0;
        while (p < 3) : (p += 1) {
            ring.push(.{ .slot = next_push, .bank_hash = th(0) });
            next_push += 1;
        }
        var q: u32 = 0;
        while (q < 3) : (q += 1) {
            if (ring.pop(&out)) {
                try testing.expectEqual(next_expect, out.slot);
                next_expect += 1;
            }
        }
    }
    while (ring.pop(&out)) {
        try testing.expectEqual(next_expect, out.slot);
        next_expect += 1;
    }
    try testing.expectEqual(next_push, next_expect); // conservation (never full here)
}

test "ring: threaded producer/consumer — never blocks, conservation of delivered+dropped" {
    var ring = AlarmRing{};
    const N: u64 = 500_000;
    const Consumer = struct {
        fn run(r: *AlarmRing, n: u64, done: *std.atomic.Value(bool), got: *u64) void {
            var out: TapEntry = undefined;
            var seen: u64 = 0;
            while (!done.load(.acquire) or r.depth() > 0) {
                if (r.pop(&out)) seen += 1 else std.atomic.spinLoopHint();
                if (seen >= n) break;
            }
            got.* = seen;
        }
    };
    var done = std.atomic.Value(bool).init(false);
    var got: u64 = 0;
    const t = try std.Thread.spawn(.{}, Consumer.run, .{ &ring, N, &done, &got });
    var i: u64 = 0;
    while (i < N) : (i += 1) ring.push(.{ .slot = i, .bank_hash = th(0) }); // NEVER blocks
    done.store(true, .release);
    t.join();
    // Every pushed entry is either delivered or dropped (drop-oldest); none double-counted.
    const delivered = ring.popped.load(.monotonic);
    const dropped = ring.dropped.load(.monotonic);
    try testing.expectEqual(N, ring.pushed.load(.monotonic));
    try testing.expect(delivered + dropped >= N - CAPACITY); // sound conservation bound
    try testing.expect(delivered <= N);
}

test "debounce: single stale divergent read does NOT fire; second confirm fires" {
    var d = Debouncer{};
    // First divergent sighting → armed, not fire.
    try testing.expectEqual(Debouncer.Decision.armed, d.observe(500, .execution));
    // A convergent re-read of the SAME slot clears it (it was stale).
    try testing.expectEqual(Debouncer.Decision.idle, d.observe(500, .convergent));
    try testing.expect(d.pending_slot == null);
    // Now a real, persistent divergence: arm then confirm.
    try testing.expectEqual(Debouncer.Decision.armed, d.observe(600, .execution));
    try testing.expectEqual(Debouncer.Decision.fire, d.observe(600, .execution));
}

test "rooted-both-sides guard: fires only when BOTH sides rooted" {
    try testing.expect(!rootedBothSides(false, false));
    try testing.expect(!rootedBothSides(true, false)); // our root but cluster not finalized
    try testing.expect(!rootedBothSides(false, true)); // cluster final but we haven't rooted
    try testing.expect(rootedBothSides(true, true));
}

test "latch: anchors on first-divergent; downstream slots do NOT re-fire; earlier re-anchors" {
    var l = Latch{};
    try testing.expect(l.allow(700)); // nothing latched yet
    l.set(700);
    try testing.expect(!l.allow(700)); // same slot
    try testing.expect(!l.allow(701)); // downstream inherits — must not re-fire
    try testing.expect(l.allow(699)); // an EARLIER first-divergent re-anchors
}

test "base58Decode32: round-trips a known 32-byte all-zero and rejects wrong length" {
    // 32 zero bytes base58-encode to a string of 32 '1's.
    const zeros = "11111111111111111111111111111111";
    const dec = base58Decode32(zeros) orelse return error.DecodeFailed;
    try testing.expectEqual(th(0), dec);
    // Too short → null.
    try testing.expect(base58Decode32("1111") == null);
    // Invalid char (0, O, I, l are not in the alphabet) → null.
    try testing.expect(base58Decode32("0OIl") == null);
}

test "getBlock parse: extracts blockhash (poh); does NOT populate sig_count (coarse=false-fire); RPC error → null" {
    const ok =
        \\{"jsonrpc":"2.0","result":{"blockhash":"11111111111111111111111111111111","previousBlockhash":"So11111111111111111111111111111111111111112","signatures":["aaa","bbb","ccc"]},"id":1}
    ;
    const o = CurlOracle.parseGetBlock(ok) orelse return error.ParseFailed;
    try testing.expectEqual(th(0), o.poh_hash.?);
    // signature_count MUST stay unknown — the coarse per-tx count is not Agave's summed count,
    // and populating it false-fires SIG_ACCOUNTING on any multi-signer block (the RUN-B bug).
    try testing.expect(o.signature_count == null);
    // txCount() still exposes the (diagnostic-only) transaction count = 3 primary sigs.
    try testing.expectEqual(@as(u64, 3), CurlOracle.txCount(ok).?);

    const err =
        \\{"jsonrpc":"2.0","error":{"code":-32009,"message":"Slot 5 was skipped"},"id":1}
    ;
    try testing.expect(CurlOracle.parseGetBlock(err) == null);
}

// ── classify() integration: a synthetic divergence flows tap→classify→verdict ──
//
// Reuses the M1 fixture shape (an all-match convergent pair) and flips one input, proving
// the M2 seam feeds classify() correctly and the debounce/latch pipeline fires exactly once.

fn fakeFlight(comptime bank: u8) FlightInputs {
    return .{
        .slot = 420_859_999,
        .bank_hash = th(bank),
        .parent_hash = th(0xAA),
        .signature_count = 128,
        .poh_hash = th(0xCC),
        .lthash_digest = th(0xDD),
    };
}

const FakeSource = struct {
    // A divergent EXECUTION slot: our bank_hash ≠ cluster's, but parent/poh/sigs match.
    fn read(_: ?*anyopaque, slot: u64) ?FlightInputs {
        if (slot == 421_724_293) return fakeFlight(0x77); // ours
        return fakeFlight(0xBB); // convergent elsewhere
    }
    fn oracle(_: ?*anyopaque, _: *const AlarmConfig, slot: u64) ?OracleInputs {
        // Cluster canonical: bank_hash 0xBB, matching poh/sigs (EXECUTION by elimination @ carrier).
        _ = slot;
        return .{ .parent_matches = true, .poh_hash = th(0xCC), .signature_count = 128, .bank_hash = th(0xBB) };
    }
};

test "integration: synthetic EXECUTION divergence classifies correctly through the M2 seam" {
    const flight = FakeSource.read(null, 421_724_293).?;
    const oracle = FakeSource.oracle(null, &AlarmConfig{}, 421_724_293).?;
    const v = classifier.classify(flight, oracle);
    try testing.expectEqual(CarrierClass.execution, v.class);
    try testing.expect(v.needs_account_diff);

    // And the debounce+latch pipeline fires exactly once for it.
    var d = Debouncer{};
    var l = Latch{};
    try testing.expectEqual(Debouncer.Decision.armed, d.observe(421_724_293, v.class));
    const dec = d.observe(421_724_293, v.class);
    try testing.expectEqual(Debouncer.Decision.fire, dec);
    try testing.expect(l.allow(421_724_293));
    l.set(421_724_293);
    try testing.expect(!l.allow(421_724_294)); // the very next (downstream) slot must NOT re-fire
}

test "integration: a convergent window never arms (flag-on but hash-neutral → zero fire)" {
    var d = Debouncer{};
    // Feed a run of convergent slots (the epoch-989 window AFTER the fix is canonical).
    var slot: u64 = 421_724_289;
    while (slot <= 421_724_293) : (slot += 1) {
        const flight = fakeFlight(0xBB);
        const oracle = OracleInputs{ .parent_matches = true, .poh_hash = th(0xCC), .signature_count = 128, .bank_hash = th(0xBB) };
        const v = classifier.classify(flight, oracle);
        try testing.expectEqual(CarrierClass.convergent, v.class);
        try testing.expectEqual(Debouncer.Decision.idle, d.observe(slot, v.class));
    }
    try testing.expect(d.pending_slot == null); // nothing pending → zero false positives
}
