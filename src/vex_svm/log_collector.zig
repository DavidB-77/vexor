//! Vexor LogCollector — program-runtime log capture for SB-1 executeOnBank.
//!
//! Mirrors Agave's svm-log-collector + stable_log, so that simulate()/executeOnBank
//! returns the canonical "Program ..." log lines downstream consumers (RPC
//! simulateTransaction, `solana logs`, explorers) expect — instead of the current
//! trace-spam-with-no-collector path where SimResult.logs is empty.
//!
//! Agave source references (4.1.0-beta.3):
//!   svm-log-collector/src/lib.rs:5         LOG_MESSAGES_BYTES_LIMIT = 10 * 1000
//!   svm-log-collector/src/lib.rs:26-42     LogCollector::log (byte-limit + "Log truncated")
//!   svm-log-collector/src/lib.rs:44-46     get_recorded_content
//!   program-runtime/src/stable_log.rs:20-31  program_invoke  "Program {} invoke [{}]"
//!   program-runtime/src/stable_log.rs:42-44  program_log     "Program log: {}"
//!   program-runtime/src/stable_log.rs:55-61  program_data    "Program data: {}"  (base64, space-joined)
//!   program-runtime/src/stable_log.rs:73-84  program_return  "Program return: {} {}"
//!   program-runtime/src/stable_log.rs:93-95  program_success "Program {} success"
//!   program-runtime/src/stable_log.rs:104-110 program_failure "Program {} failed: {}"
//!   program-runtime/src/vm.rs:343-349        program-consumed "Program {} consumed {} of {} compute units"
//!
//! Fidelity notes:
//!   * Every framing helper routes its formatted string through append(), exactly as
//!     Agave routes each helper through ic_logger_msg! -> LogCollector::log — so the
//!     byte limit applies uniformly to framing AND program-emitted lines.
//!   * append() reproduces Agave's log() precisely: the running byte total is advanced
//!     ONLY when a message is actually pushed; a dropped (over-limit) message does NOT
//!     advance the counter, so a later smaller message that still fits IS appended.
//!     The single "Log truncated" marker is emitted once (limit_warning guard). This is
//!     NOT a hard stop — it matches Agave for mixed-size streams.
//!
//! Program ids are taken as already-base58 STRINGS (caller encodes). This keeps the
//! module std-ONLY and self-verifiable without pulling in a Pubkey/base58 dependency.

const std = @import("std");

/// Agave svm-log-collector/src/lib.rs:5 — `const LOG_MESSAGES_BYTES_LIMIT: usize = 10 * 1000;`
pub const LOG_MESSAGES_BYTES_LIMIT: usize = 10 * 1000;

/// Agave svm-log-collector/src/lib.rs:36 — the single marker pushed on overflow.
pub const TRUNCATION_MARKER = "Log truncated";

pub const LogCollector = struct {
    allocator: std.mem.Allocator,
    /// Owned, heap-allocated message strings (this collector frees them in deinit).
    messages: std.ArrayListUnmanaged([]u8) = .{},
    /// Running total of bytes actually committed (Agave: `bytes_written`).
    bytes_written: usize = 0,
    /// `Some(limit)` in Agave; `null` here disables the byte limit entirely.
    bytes_limit: ?usize = LOG_MESSAGES_BYTES_LIMIT,
    /// One-shot guard so "Log truncated" is emitted at most once (Agave: `limit_warning`).
    limit_warning: bool = false,

    pub fn init(allocator: std.mem.Allocator) LogCollector {
        return .{ .allocator = allocator };
    }

    /// Like Agave's `new_ref_with_limit` — construct with an explicit (or no) byte limit.
    pub fn initWithLimit(allocator: std.mem.Allocator, bytes_limit: ?usize) LogCollector {
        return .{ .allocator = allocator, .bytes_limit = bytes_limit };
    }

    pub fn deinit(self: *LogCollector) void {
        for (self.messages.items) |m| self.allocator.free(m);
        self.messages.deinit(self.allocator);
        self.* = undefined;
    }

    /// Agave svm-log-collector/src/lib.rs:26-42 — LogCollector::log.
    ///
    /// `msg` is borrowed; the collector takes its OWN owned copy of any message it
    /// keeps (and of the marker). The caller retains ownership of `msg`.
    pub fn append(self: *LogCollector, msg: []const u8) !void {
        const limit = self.bytes_limit orelse {
            // No limit: always record.
            try self.push(msg);
            return;
        };

        // Agave: `let bytes_written = self.bytes_written.saturating_add(message.len());`
        const bytes_written = std.math.add(usize, self.bytes_written, msg.len) catch std.math.maxInt(usize);
        if (bytes_written >= limit) {
            // Over (or exactly at) the limit: emit the marker once, do NOT advance the
            // counter — a later smaller message can still fit and be appended.
            if (!self.limit_warning) {
                self.limit_warning = true;
                try self.push(TRUNCATION_MARKER);
            }
        } else {
            self.bytes_written = bytes_written;
            try self.push(msg);
        }
    }

    /// Internal: duplicate + store an owned copy. On allocation failure nothing is
    /// committed (the byte counter is advanced by the caller only on the success path).
    fn push(self: *LogCollector, msg: []const u8) !void {
        const owned = try self.allocator.dupe(u8, msg);
        errdefer self.allocator.free(owned);
        try self.messages.append(self.allocator, owned);
    }

    /// Agave svm-log-collector/src/lib.rs:44-46 — get_recorded_content.
    pub fn messagesSlice(self: *const LogCollector) []const []const u8 {
        return self.messages.items;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canonical framing helpers (Agave program-runtime/src/stable_log.rs + vm.rs).
    // Each formats into a stack buffer where bounded, else a heap temp, then routes
    // the result through append() so the byte limit applies uniformly.
    // ─────────────────────────────────────────────────────────────────────────

    /// "Program <id> invoke [<depth>]"  (stable_log.rs:20-31)
    pub fn programInvoke(self: *LogCollector, program_id_b58: []const u8, depth: usize) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program {s} invoke [{d}]", .{ program_id_b58, depth });
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program <id> success"  (stable_log.rs:93-95)
    pub fn programSuccess(self: *LogCollector, program_id_b58: []const u8) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program {s} success", .{program_id_b58});
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program <id> failed: <err>"  (stable_log.rs:104-110)
    pub fn programFailed(self: *LogCollector, program_id_b58: []const u8, err: []const u8) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program {s} failed: {s}", .{ program_id_b58, err });
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program log: <msg>"  (stable_log.rs:42-44)
    pub fn programLog(self: *LogCollector, msg: []const u8) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program log: {s}", .{msg});
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program data: <b64>"  (stable_log.rs:55-61)
    ///
    /// Agave joins multiple base64-encoded chunks with a single space; here the caller
    /// passes the already-encoded (and, if multiple, already space-joined) payload.
    pub fn programData(self: *LogCollector, b64: []const u8) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program data: {s}", .{b64});
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program return: <id> <b64>"  (stable_log.rs:73-84)
    pub fn programReturn(self: *LogCollector, program_id_b58: []const u8, b64: []const u8) !void {
        const s = try std.fmt.allocPrint(self.allocator, "Program return: {s} {s}", .{ program_id_b58, b64 });
        defer self.allocator.free(s);
        try self.append(s);
    }

    /// "Program <id> consumed <used> of <budget> compute units"  (vm.rs:343-349)
    pub fn programConsumed(self: *LogCollector, program_id_b58: []const u8, used: u64, budget: u64) !void {
        const s = try std.fmt.allocPrint(
            self.allocator,
            "Program {s} consumed {d} of {d} compute units",
            .{ program_id_b58, used, budget },
        );
        defer self.allocator.free(s);
        try self.append(s);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "framing strings are byte-exact vs Agave stable_log / vm" {
    var lc = LogCollector.init(testing.allocator);
    defer lc.deinit();

    const id = "11111111111111111111111111111111";
    try lc.programInvoke(id, 1);
    try lc.programLog("Instruction: Transfer");
    try lc.programData("aGVsbG8=");
    try lc.programReturn(id, "AQID");
    try lc.programConsumed(id, 1500, 200000);
    try lc.programSuccess(id);
    try lc.programFailed(id, "custom program error: 0x1");

    const m = lc.messagesSlice();
    try testing.expectEqual(@as(usize, 7), m.len);
    try testing.expectEqualStrings("Program 11111111111111111111111111111111 invoke [1]", m[0]);
    try testing.expectEqualStrings("Program log: Instruction: Transfer", m[1]);
    try testing.expectEqualStrings("Program data: aGVsbG8=", m[2]);
    try testing.expectEqualStrings("Program return: 11111111111111111111111111111111 AQID", m[3]);
    try testing.expectEqualStrings("Program 11111111111111111111111111111111 consumed 1500 of 200000 compute units", m[4]);
    try testing.expectEqualStrings("Program 11111111111111111111111111111111 success", m[5]);
    try testing.expectEqualStrings("Program 11111111111111111111111111111111 failed: custom program error: 0x1", m[6]);
}

test "byte-limit truncation mirrors Agave test_log_messages_bytes_limit" {
    // Agave svm-log-collector/src/lib.rs:108-122 — append "x" 2*LIMIT times, expect
    // exactly LIMIT messages: (LIMIT-1) "x" then one "Log truncated".
    var lc = LogCollector.init(testing.allocator);
    defer lc.deinit();

    var i: usize = 0;
    while (i < LOG_MESSAGES_BYTES_LIMIT * 2) : (i += 1) {
        try lc.append("x");
    }

    const m = lc.messagesSlice();
    try testing.expectEqual(@as(usize, LOG_MESSAGES_BYTES_LIMIT), m.len);
    for (m[0 .. LOG_MESSAGES_BYTES_LIMIT - 1]) |line| {
        try testing.expectEqualStrings("x", line);
    }
    try testing.expectEqualStrings(TRUNCATION_MARKER, m[LOG_MESSAGES_BYTES_LIMIT - 1]);
}

test "marker emitted once; later smaller message still fits (no hard stop)" {
    // Fidelity check for Agave's non-hard-stop semantics: bytes_written is advanced
    // only on a committed push, so after an over-limit drop a smaller message that
    // fits is still appended. Limit chosen small for a tight, deterministic case.
    var lc = LogCollector.initWithLimit(testing.allocator, 10);
    defer lc.deinit();

    try lc.append("abcd"); // bytes_written 0+4=4 < 10 -> kept
    try lc.append("ef"); // 4+2=6 < 10 -> kept
    try lc.append("ghijklmn"); // 6+8=14 >= 10 -> drop, push "Log truncated", counter stays 6
    try lc.append("xx"); // 6+2=8 < 10 -> kept (proves no hard stop)
    try lc.append("yyyy"); // 8+4=12 >= 10 -> drop, marker already shown, counter stays 8

    const m = lc.messagesSlice();
    try testing.expectEqual(@as(usize, 4), m.len);
    try testing.expectEqualStrings("abcd", m[0]);
    try testing.expectEqualStrings("ef", m[1]);
    try testing.expectEqualStrings(TRUNCATION_MARKER, m[2]);
    try testing.expectEqualStrings("xx", m[3]);
}

test "null bytes_limit disables truncation" {
    var lc = LogCollector.initWithLimit(testing.allocator, null);
    defer lc.deinit();
    var i: usize = 0;
    while (i < 100) : (i += 1) try lc.append("some longer message that would overflow a tiny limit");
    try testing.expectEqual(@as(usize, 100), lc.messagesSlice().len);
}
