//! agave_proto.zig — byte-exact protobuf (prost) wire-form emitter for Agave
//! rc.1 blockstore records (TransactionStatusMeta, Rewards/Reward/NumPartitions).
//!
//! Pure `std` only. NO other imports. Zig 0.15.2.
//!
//! This is byte-fidelity-critical: the goldens (KATs at the bottom) are the gate.
//! It must produce the EXACT same bytes as Rust prost would for the same record,
//! so a Vexor-written blockstore protobuf is indistinguishable from Agave's.
//!
//! The 5 prost canonicalization rules implemented here:
//!  1. FIELD ORDER = ascending tag number (never struct/declaration order).
//!  2. proto3 default-omit: scalar 0, empty string/bytes, false, enum 0,
//!     absent message/optional → emit NOTHING.
//!  3. key byte = varint of (field_number << 3) | wire_type.
//!     wire types: 0=varint, 1=64-bit, 2=len-delim, 5=32-bit.
//!  4. PACKED repeated scalars (repeated uint64): ONE wt2 key + ONE total-length
//!     varint + concatenated element varints.
//!  5. `optional` presence fields: Some(0) IS emitted; None omitted. int64 uses
//!     two's-complement varint (negative → 10 bytes), NOT zigzag.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ── Wire types ──────────────────────────────────────────────────────────────
pub const WT_VARINT: u3 = 0;
pub const WT_I64: u3 = 1;
pub const WT_LEN: u3 = 2;

// ── Writer: a prost encoder over an ArrayListUnmanaged(u8) ───────────────────
pub const Writer = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    allocator: Allocator,

    pub fn init(allocator: Allocator) Writer {
        return .{ .buf = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.allocator);
    }

    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }

    pub fn bytes(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    // ── LEB128 varint ────────────────────────────────────────────────────────
    pub fn writeVarint(self: *Writer, value: u64) !void {
        var v = value;
        while (true) {
            const low: u8 = @intCast(v & 0x7f);
            v >>= 7;
            if (v != 0) {
                try self.buf.append(self.allocator, low | 0x80);
            } else {
                try self.buf.append(self.allocator, low);
                break;
            }
        }
    }

    pub fn writeKey(self: *Writer, field: u32, wire_type: u3) !void {
        try self.writeVarint((@as(u64, field) << 3) | @as(u64, wire_type));
    }

    pub fn writeRaw(self: *Writer, slice: []const u8) !void {
        try self.buf.appendSlice(self.allocator, slice);
    }

    // ── proto3 scalar fields (default-omit) ────────────────────────────────────
    pub fn writeVarintField(self: *Writer, field: u32, value: u64) !void {
        if (value == 0) return; // proto3 default-omit
        try self.writeKey(field, WT_VARINT);
        try self.writeVarint(value);
    }

    /// `optional uint64`: None omitted, Some(v) emitted EVEN if v==0 (presence).
    pub fn writeOptionalVarintField(self: *Writer, field: u32, value: ?u64) !void {
        const v = value orelse return;
        try self.writeKey(field, WT_VARINT);
        try self.writeVarint(v);
    }

    /// int64 — two's-complement varint via bitcast (NOT zigzag). 0 omitted.
    pub fn writeInt64Field(self: *Writer, field: u32, value: i64) !void {
        if (value == 0) return;
        try self.writeKey(field, WT_VARINT);
        try self.writeVarint(@as(u64, @bitCast(value)));
    }

    pub fn writeBoolField(self: *Writer, field: u32, value: bool) !void {
        if (!value) return;
        try self.writeKey(field, WT_VARINT);
        try self.buf.append(self.allocator, 0x01);
    }

    pub fn writeStringField(self: *Writer, field: u32, value: []const u8) !void {
        if (value.len == 0) return;
        try self.writeKey(field, WT_LEN);
        try self.writeVarint(value.len);
        try self.writeRaw(value);
    }

    pub fn writeBytesField(self: *Writer, field: u32, value: []const u8) !void {
        // identical to string: empty → omit.
        try self.writeStringField(field, value);
    }

    /// PACKED repeated uint64: ONE wt2 key + ONE total-length varint + concat.
    pub fn writePackedU64Field(self: *Writer, field: u32, values: []const u64) !void {
        if (values.len == 0) return;
        // Total payload length = sum of each element's varint byte-length.
        var total: usize = 0;
        for (values) |x| total += varintLen(x);
        try self.writeKey(field, WT_LEN);
        try self.writeVarint(total);
        for (values) |x| try self.writeVarint(x);
    }

    /// length-delimited sub-message: key + len + pre-encoded submsg bytes.
    /// (Caller decides presence; this always emits — used for "present" elements.)
    pub fn writeMessageField(self: *Writer, field: u32, submsg: []const u8) !void {
        try self.writeKey(field, WT_LEN);
        try self.writeVarint(submsg.len);
        try self.writeRaw(submsg);
    }

    /// A single ELEMENT of a `repeated string`/`repeated bytes` field — ALWAYS
    /// emits key+len+bytes, even for an empty element (len 0). proto3 default-omit
    /// applies to SINGULAR scalars only; a repeated field's empty element is a real
    /// element prost emits as key+`00` (e.g. log_messages containing `sol_log("")`).
    pub fn writeRepeatedBytesElement(self: *Writer, field: u32, value: []const u8) !void {
        try self.writeKey(field, WT_LEN);
        try self.writeVarint(value.len);
        try self.writeRaw(value);
    }

    pub fn writeEnumField(self: *Writer, field: u32, value: u32) !void {
        if (value == 0) return; // enum default-omit
        try self.writeKey(field, WT_VARINT);
        try self.writeVarint(value);
    }
};

/// Number of bytes a LEB128-encoded varint of `value` occupies.
pub fn varintLen(value: u64) usize {
    var v = value;
    var n: usize = 1;
    while (v >= 0x80) : (v >>= 7) n += 1;
    return n;
}

// ── RewardType enum (prost numbering) ───────────────────────────────────────
pub const RewardType = enum(u32) {
    Unspecified = 0,
    Fee = 1,
    Rent = 2,
    Staking = 3,
    Voting = 4,
    DeactivatedStake = 5,
};

// ── Reward (storage.proto: Reward) ──────────────────────────────────────────
pub const Reward = struct {
    pubkey: []const u8 = "", // tag1 string
    lamports: i64 = 0, // tag2 int64 (two's-complement)
    post_balance: u64 = 0, // tag3 uint64
    reward_type: RewardType = .Unspecified, // tag4 enum
    commission: []const u8 = "", // tag5 string
    commission_bps: []const u8 = "", // tag6 string

    /// Encode this Reward as a sub-message; caller owns the returned slice.
    pub fn encode(self: Reward, allocator: Allocator) ![]u8 {
        var w = Writer.init(allocator);
        errdefer w.deinit();
        try self.encodeInto(&w);
        return w.toOwnedSlice();
    }

    pub fn encodeInto(self: Reward, w: *Writer) !void {
        try w.writeStringField(1, self.pubkey);
        try w.writeInt64Field(2, self.lamports);
        try w.writeVarintField(3, self.post_balance);
        try w.writeEnumField(4, @intFromEnum(self.reward_type));
        try w.writeStringField(5, self.commission);
        try w.writeStringField(6, self.commission_bps);
    }
};

// ── NumPartitions (storage.proto: NumPartitions) ────────────────────────────
pub const NumPartitions = struct {
    num_partitions: u64 = 0, // tag1 uint64

    pub fn encodeInto(self: NumPartitions, w: *Writer) !void {
        try w.writeVarintField(1, self.num_partitions);
    }
};

// ── Rewards (storage.proto: Rewards) ────────────────────────────────────────
pub const Rewards = struct {
    rewards: []const Reward = &.{}, // tag1 repeated Reward (non-packed msgs)
    num_partitions: ?u64 = null, // tag2 optional NumPartitions

    pub fn encode(self: Rewards, allocator: Allocator) ![]u8 {
        var w = Writer.init(allocator);
        errdefer w.deinit();
        try self.encodeInto(&w);
        return w.toOwnedSlice();
    }

    pub fn encodeInto(self: Rewards, w: *Writer) !void {
        // tag1: each Reward as its own length-delimited message.
        for (self.rewards) |r| {
            const sub = try r.encode(w.allocator);
            defer w.allocator.free(sub);
            try w.writeMessageField(1, sub);
        }
        // tag2: optional NumPartitions message.
        if (self.num_partitions) |np| {
            var nw = Writer.init(w.allocator);
            defer nw.deinit();
            const npart = NumPartitions{ .num_partitions = np };
            try npart.encodeInto(&nw);
            try w.writeMessageField(2, nw.bytes());
        }
    }
};

// ── TransactionStatusMeta (storage.proto: TransactionStatusMeta) ────────────
//
// Tag order (MUST emit ascending): 1..17. Tier-1 = Ok-status only.
pub const TransactionStatusMeta = struct {
    // tag1 err: nested TransactionError{bytes err=1} message, pre-encoded via
    // TransactionError.encodeProtoErrField. null == Ok-status (omitted, the
    // proto3 None case at convert.rs). Non-null == Err-status (Tier-2).
    err_proto: ?[]const u8 = null,
    fee: u64 = 0, // tag2 uint64
    pre_balances: []const u64 = &.{}, // tag3 repeated uint64 PACKED
    post_balances: []const u64 = &.{}, // tag4 repeated uint64 PACKED
    // tag5 inner_instructions: repeated message — pre-encoded element slices.
    inner_instructions: []const []const u8 = &.{},
    log_messages: []const []const u8 = &.{}, // tag6 repeated string
    // tag7 pre_token_balances, tag8 post_token_balances, tag9 rewards:
    //   repeated message — pre-encoded element slices.
    pre_token_balances: []const []const u8 = &.{},
    post_token_balances: []const []const u8 = &.{},
    rewards: []const []const u8 = &.{},
    inner_instructions_none: bool = false, // tag10 bool
    log_messages_none: bool = false, // tag11 bool
    // tag12 loaded_writable_addresses, tag13 loaded_readonly_addresses:
    //   repeated bytes (each a 32-byte pubkey).
    loaded_writable_addresses: []const []const u8 = &.{},
    loaded_readonly_addresses: []const []const u8 = &.{},
    return_data: ?[]const u8 = null, // tag14 optional message (pre-encoded)
    return_data_none: bool = false, // tag15 bool
    compute_units_consumed: ?u64 = null, // tag16 optional uint64
    cost_units: ?u64 = null, // tag17 optional uint64

    pub fn encode(self: TransactionStatusMeta, allocator: Allocator) ![]u8 {
        var w = Writer.init(allocator);
        errdefer w.deinit();
        try self.encodeInto(&w);
        return w.toOwnedSlice();
    }

    pub fn encodeInto(self: TransactionStatusMeta, w: *Writer) !void {
        // Strictly ascending tag order: 1,2,3,...,17.
        // tag1 err: present only for Err-status (pre-encoded nested message).
        if (self.err_proto) |e| try w.writeMessageField(1, e);
        try w.writeVarintField(2, self.fee);
        try w.writePackedU64Field(3, self.pre_balances);
        try w.writePackedU64Field(4, self.post_balances);
        for (self.inner_instructions) |sub| try w.writeMessageField(5, sub);
        // repeated string/bytes ELEMENTS never default-omit (an empty element is a
        // real element prost emits as key+len0) — use writeRepeatedBytesElement.
        for (self.log_messages) |s| try w.writeRepeatedBytesElement(6, s);
        for (self.pre_token_balances) |sub| try w.writeMessageField(7, sub);
        for (self.post_token_balances) |sub| try w.writeMessageField(8, sub);
        for (self.rewards) |sub| try w.writeMessageField(9, sub);
        try w.writeBoolField(10, self.inner_instructions_none);
        try w.writeBoolField(11, self.log_messages_none);
        for (self.loaded_writable_addresses) |pk| try w.writeRepeatedBytesElement(12, pk);
        for (self.loaded_readonly_addresses) |pk| try w.writeRepeatedBytesElement(13, pk);
        if (self.return_data) |rd| try w.writeMessageField(14, rd);
        try w.writeBoolField(15, self.return_data_none);
        try w.writeOptionalVarintField(16, self.compute_units_consumed);
        try w.writeOptionalVarintField(17, self.cost_units);
    }
};

// ── TransactionError bincode — Tier-2 Err-status (rc.1 byte-exact) ───────────
//
// The proto `TransactionStatusMeta.err` (tag1) is a nested message
// `TransactionError { bytes err = 1; }` whose bytes are `bincode::serialize` of
// the Rust `TransactionError` enum (Agave rc.1: storage-proto/src/convert.rs:473,
// confirmed_block.proto:55-82). bincode here is the FREE function = FIXINT (NOT
// varint): enum variant index = **u32 little-endian (4 bytes)**, length prefixes
// = u64 LE, Option = 1-byte tag — bincode-1.3.3 `.with_fixint_encoding()`.
// Indices = rc.1 declaration order (solana-transaction-error 3.2.0 /
// solana-instruction-error 2.3.0). Goldens = rc.1's own serialize test suite
// (storage-proto/src/lib.rs `test_seserialize_stored_transaction_error`).
//
// Only data-carrying variants need a payload; every other variant is a bare
// 4-byte u32 tag. Data-carrying: TransactionError {InstructionError=8,
// DuplicateInstruction=30, InsufficientFundsForRent=31,
// ProgramExecutionTemporarilyRestricted=35}; InstructionError {Custom=25}.

fn appendU32LE(a: Allocator, out: *std.ArrayListUnmanaged(u8), v: u32) !void {
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, v, .little);
    try out.appendSlice(a, &le);
}

/// rc.1 `InstructionError`. Only `Custom(u32)` (index 25) carries data; every
/// other variant is a bare index (e.g. `BorshIoError`=44 is a UNIT variant in
/// rc.1 — no `String` payload, unlike older Agave).
pub const InstructionError = union(enum) {
    /// Any data-less variant, by its rc.1 declaration index (0..53, except 25).
    unit: u32,
    /// `Custom(u32)` — index 25.
    custom: u32,

    fn appendBincode(self: InstructionError, a: Allocator, out: *std.ArrayListUnmanaged(u8)) !void {
        switch (self) {
            .unit => |idx| try appendU32LE(a, out, idx),
            .custom => |code| {
                try appendU32LE(a, out, 25);
                try appendU32LE(a, out, code);
            },
        }
    }
};

/// rc.1 `TransactionError`. Variants carrying data are explicit; all others use
/// `.unit = <rc.1 index>` (a bare 4-byte u32 tag).
pub const TransactionError = union(enum) {
    /// Any data-less variant, by its rc.1 declaration index
    /// (0..38, except 8, 30, 31, 35).
    unit: u32,
    /// `InstructionError(u8 ix_index, InstructionError)` — index 8.
    instruction_error: struct { ix_index: u8, err: InstructionError },
    /// `DuplicateInstruction(u8)` — index 30.
    duplicate_instruction: u8,
    /// `InsufficientFundsForRent { account_index: u8 }` — index 31 (struct
    /// variant; bincode serializes the field value only, no field name).
    insufficient_funds_for_rent: u8,
    /// `ProgramExecutionTemporarilyRestricted { account_index: u8 }` — index 35.
    program_execution_temporarily_restricted: u8,

    fn appendBincode(self: TransactionError, a: Allocator, out: *std.ArrayListUnmanaged(u8)) !void {
        switch (self) {
            .unit => |idx| try appendU32LE(a, out, idx),
            .instruction_error => |ie| {
                try appendU32LE(a, out, 8);
                try out.append(a, ie.ix_index);
                try ie.err.appendBincode(a, out); // nested InstructionError
            },
            .duplicate_instruction => |b| {
                try appendU32LE(a, out, 30);
                try out.append(a, b);
            },
            .insufficient_funds_for_rent => |b| {
                try appendU32LE(a, out, 31);
                try out.append(a, b);
            },
            .program_execution_temporarily_restricted => |b| {
                try appendU32LE(a, out, 35);
                try out.append(a, b);
            },
        }
    }

    /// `bincode::serialize(&self)` — the raw inner-`err`-field bytes. Owned.
    pub fn bincode(self: TransactionError, a: Allocator) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .{};
        errdefer out.deinit(a);
        try self.appendBincode(a, &out);
        return out.toOwnedSlice(a);
    }

    /// The full nested-message bytes for `TransactionStatusMeta.err` (tag1):
    /// `TransactionError { bytes err = 1 = bincode }`. Pass the result to
    /// `TransactionStatusMeta.err_proto` (or `writeMessageField(1, …)`). Owned.
    /// The bincode bytes are always ≥4 (the u32 tag) so the singular `bytes`
    /// field is always present (never proto3-default-omitted).
    pub fn encodeProtoErrField(self: TransactionError, a: Allocator) ![]u8 {
        const bc = try self.bincode(a);
        defer a.free(bc);
        var w = Writer.init(a);
        errdefer w.deinit();
        try w.writeBytesField(1, bc);
        return w.toOwnedSlice();
    }
};

// ── DECODER (inverse of the encoders) — for the --full-rpc-api read path ─────
//
// getBlock/getTransaction must DECODE the stored protobuf back into structs. This
// is the read-STRICT inverse of the encoders above: every read is bounds-checked
// (→ error.Truncated), a varint > 10 bytes or an unsupported wire type → Malformed.
// Repeated SUB-MESSAGE fields (inner_instructions / token_balances / rewards) are
// returned as RAW sub-message byte slices — symmetric with the encoder, which
// takes them pre-encoded (their nested bodies are Tier-2; the handler decodes
// further when those land). All returned slices are OWNED — call `deinit`.

pub const ProtoError = error{ Truncated, Malformed };

const ProtoReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn atEnd(self: *const ProtoReader) bool {
        return self.pos >= self.buf.len;
    }
    fn readVarint(self: *ProtoReader) ProtoError!u64 {
        var result: u64 = 0;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            if (self.pos >= self.buf.len) return ProtoError.Truncated;
            const b = self.buf[self.pos];
            self.pos += 1;
            result |= @as(u64, b & 0x7f) << @intCast(i * 7);
            if (b & 0x80 == 0) return result;
        }
        return ProtoError.Malformed; // varint > 10 bytes
    }
    const Key = struct { field: u32, wire: u3 };
    fn readKey(self: *ProtoReader) ProtoError!Key {
        const k = try self.readVarint();
        return .{ .field = @intCast(k >> 3), .wire = @intCast(k & 0x7) };
    }
    fn readLen(self: *ProtoReader) ProtoError![]const u8 {
        const n: usize = @intCast(try self.readVarint());
        if (self.pos + n > self.buf.len) return ProtoError.Truncated;
        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return s;
    }
    fn skip(self: *ProtoReader, wire: u3) ProtoError!void {
        switch (wire) {
            0 => _ = try self.readVarint(),
            1 => {
                if (self.pos + 8 > self.buf.len) return ProtoError.Truncated;
                self.pos += 8;
            },
            2 => _ = try self.readLen(),
            5 => {
                if (self.pos + 4 > self.buf.len) return ProtoError.Truncated;
                self.pos += 4;
            },
            else => return ProtoError.Malformed, // 3/4 = groups (deprecated), unsupported
        }
    }
};

fn freeSliceList(a: Allocator, list: [][]u8) void {
    for (list) |s| a.free(s);
    a.free(list);
}

pub const DecodedTransactionStatusMeta = struct {
    err_bytes: ?[]u8 = null, // inner bincode TransactionError bytes; null = Ok-status
    fee: u64 = 0,
    pre_balances: []u64 = &.{},
    post_balances: []u64 = &.{},
    inner_instructions: [][]u8 = &.{}, // raw sub-message bytes
    log_messages: [][]u8 = &.{},
    pre_token_balances: [][]u8 = &.{},
    post_token_balances: [][]u8 = &.{},
    rewards: [][]u8 = &.{},
    inner_instructions_none: bool = false,
    log_messages_none: bool = false,
    loaded_writable_addresses: [][]u8 = &.{},
    loaded_readonly_addresses: [][]u8 = &.{},
    return_data: ?[]u8 = null,
    return_data_none: bool = false,
    compute_units_consumed: ?u64 = null,
    cost_units: ?u64 = null,

    pub fn deinit(self: *DecodedTransactionStatusMeta, a: Allocator) void {
        if (self.err_bytes) |b| a.free(b);
        a.free(self.pre_balances);
        a.free(self.post_balances);
        freeSliceList(a, self.inner_instructions);
        freeSliceList(a, self.log_messages);
        freeSliceList(a, self.pre_token_balances);
        freeSliceList(a, self.post_token_balances);
        freeSliceList(a, self.rewards);
        freeSliceList(a, self.loaded_writable_addresses);
        freeSliceList(a, self.loaded_readonly_addresses);
        if (self.return_data) |b| a.free(b);
    }
};

/// Decode a stored TransactionStatusMeta protobuf. Read-strict. OWNED result.
pub fn decodeTransactionStatusMeta(a: Allocator, bytes: []const u8) !DecodedTransactionStatusMeta {
    var out = DecodedTransactionStatusMeta{};
    errdefer out.deinit(a);

    var pre = std.ArrayListUnmanaged(u64){};
    errdefer pre.deinit(a);
    var post = std.ArrayListUnmanaged(u64){};
    errdefer post.deinit(a);
    var inner = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &inner);
    var logs = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &logs);
    var pretb = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &pretb);
    var posttb = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &posttb);
    var rew = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &rew);
    var lwa = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &lwa);
    var lra = std.ArrayListUnmanaged([]u8){};
    errdefer freeArrayOfSlices(a, &lra);

    var r = ProtoReader{ .buf = bytes };
    while (!r.atEnd()) {
        const key = try r.readKey();
        switch (key.field) {
            1 => { // err: nested TransactionError{ bytes err=1 } → inner bincode bytes
                const sub = try r.readLen();
                var sr = ProtoReader{ .buf = sub };
                while (!sr.atEnd()) {
                    const sk = try sr.readKey();
                    if (sk.field == 1 and sk.wire == 2) {
                        const eb = try sr.readLen();
                        if (out.err_bytes) |old| a.free(old);
                        out.err_bytes = try a.dupe(u8, eb);
                    } else try sr.skip(sk.wire);
                }
            },
            2 => out.fee = try r.readVarint(),
            3 => try decodeRepeatedU64(a, &pre, &r, key.wire),
            4 => try decodeRepeatedU64(a, &post, &r, key.wire),
            5 => try inner.append(a, try a.dupe(u8, try r.readLen())),
            6 => try logs.append(a, try a.dupe(u8, try r.readLen())),
            7 => try pretb.append(a, try a.dupe(u8, try r.readLen())),
            8 => try posttb.append(a, try a.dupe(u8, try r.readLen())),
            9 => try rew.append(a, try a.dupe(u8, try r.readLen())),
            10 => out.inner_instructions_none = (try r.readVarint()) != 0,
            11 => out.log_messages_none = (try r.readVarint()) != 0,
            12 => try lwa.append(a, try a.dupe(u8, try r.readLen())),
            13 => try lra.append(a, try a.dupe(u8, try r.readLen())),
            14 => {
                if (out.return_data) |old| a.free(old);
                out.return_data = try a.dupe(u8, try r.readLen());
            },
            15 => out.return_data_none = (try r.readVarint()) != 0,
            16 => out.compute_units_consumed = try r.readVarint(),
            17 => out.cost_units = try r.readVarint(),
            else => try r.skip(key.wire), // unknown field → skip
        }
    }
    out.pre_balances = try pre.toOwnedSlice(a);
    out.post_balances = try post.toOwnedSlice(a);
    out.inner_instructions = try inner.toOwnedSlice(a);
    out.log_messages = try logs.toOwnedSlice(a);
    out.pre_token_balances = try pretb.toOwnedSlice(a);
    out.post_token_balances = try posttb.toOwnedSlice(a);
    out.rewards = try rew.toOwnedSlice(a);
    out.loaded_writable_addresses = try lwa.toOwnedSlice(a);
    out.loaded_readonly_addresses = try lra.toOwnedSlice(a);
    return out;
}

fn freeArrayOfSlices(a: Allocator, list: *std.ArrayListUnmanaged([]u8)) void {
    for (list.items) |s| a.free(s);
    list.deinit(a);
}

/// Decode a `repeated uint64` field — PACKED (wt2: a length-delimited blob of
/// concatenated varints) or a single unpacked element (wt0). Both are valid wire.
fn decodeRepeatedU64(a: Allocator, list: *std.ArrayListUnmanaged(u64), r: *ProtoReader, wire: u3) !void {
    if (wire == 2) {
        const blob = try r.readLen();
        var br = ProtoReader{ .buf = blob };
        while (!br.atEnd()) try list.append(a, try br.readVarint());
    } else if (wire == 0) {
        try list.append(a, try r.readVarint());
    } else return ProtoError.Malformed;
}

pub const DecodedReward = struct {
    pubkey: []u8 = &.{},
    lamports: i64 = 0,
    post_balance: u64 = 0,
    reward_type: u32 = 0,
    commission: []u8 = &.{},
    commission_bps: []u8 = &.{},
};
pub const DecodedRewards = struct {
    rewards: []DecodedReward = &.{},
    num_partitions: ?u64 = null,

    pub fn deinit(self: *DecodedRewards, a: Allocator) void {
        for (self.rewards) |rw| {
            a.free(rw.pubkey);
            a.free(rw.commission);
            a.free(rw.commission_bps);
        }
        a.free(self.rewards);
    }
};

fn decodeReward(a: Allocator, bytes: []const u8) !DecodedReward {
    var rw = DecodedReward{};
    errdefer {
        a.free(rw.pubkey);
        a.free(rw.commission);
        a.free(rw.commission_bps);
    }
    var r = ProtoReader{ .buf = bytes };
    while (!r.atEnd()) {
        const key = try r.readKey();
        switch (key.field) {
            1 => {
                a.free(rw.pubkey);
                rw.pubkey = try a.dupe(u8, try r.readLen());
            },
            2 => rw.lamports = @bitCast(try r.readVarint()), // int64 two's-complement
            3 => rw.post_balance = try r.readVarint(),
            4 => rw.reward_type = @intCast(try r.readVarint()),
            5 => {
                a.free(rw.commission);
                rw.commission = try a.dupe(u8, try r.readLen());
            },
            6 => {
                a.free(rw.commission_bps);
                rw.commission_bps = try a.dupe(u8, try r.readLen());
            },
            else => try r.skip(key.wire),
        }
    }
    return rw;
}

/// Decode a stored Rewards protobuf (repeated Reward + optional NumPartitions).
/// Read-strict. OWNED result. Carries num_partitions (rc.1 partitioned rewards).
pub fn decodeRewards(a: Allocator, bytes: []const u8) !DecodedRewards {
    var out = DecodedRewards{};
    errdefer out.deinit(a);
    var list = std.ArrayListUnmanaged(DecodedReward){};
    errdefer {
        for (list.items) |rw| {
            a.free(rw.pubkey);
            a.free(rw.commission);
            a.free(rw.commission_bps);
        }
        list.deinit(a);
    }
    var r = ProtoReader{ .buf = bytes };
    while (!r.atEnd()) {
        const key = try r.readKey();
        switch (key.field) {
            1 => { // repeated Reward message
                const rw = try decodeReward(a, try r.readLen());
                try list.append(a, rw);
            },
            2 => { // NumPartitions{ num_partitions=1 }
                const sub = try r.readLen();
                var sr = ProtoReader{ .buf = sub };
                while (!sr.atEnd()) {
                    const sk = try sr.readKey();
                    if (sk.field == 1 and sk.wire == 0) {
                        out.num_partitions = try sr.readVarint();
                    } else try sr.skip(sk.wire);
                }
            },
            else => try r.skip(key.wire),
        }
    }
    out.rewards = try list.toOwnedSlice(a);
    return out;
}

// ════════════════════════════════════════════════════════════════════════════
//  KATs — golden vectors. These are the gate. expectEqualSlices vs verified hex.
// ════════════════════════════════════════════════════════════════════════════

const testing = std.testing;

test "varintLen sanity" {
    try testing.expectEqual(@as(usize, 1), varintLen(0));
    try testing.expectEqual(@as(usize, 1), varintLen(0x7f));
    try testing.expectEqual(@as(usize, 2), varintLen(0x80));
    try testing.expectEqual(@as(usize, 2), varintLen(1234)); // 0x88 0x27 spans (16-bit)
    try testing.expectEqual(@as(usize, 10), varintLen(@as(u64, @bitCast(@as(i64, -1)))));
}

test "Vector A — TransactionStatusMeta fee/balances/none-flags/cu" {
    const meta = TransactionStatusMeta{
        .fee = 5000,
        .pre_balances = &.{ 100, 200 },
        .post_balances = &.{ 95, 205 },
        .inner_instructions_none = true,
        .log_messages_none = true,
        .return_data_none = true,
        .compute_units_consumed = 1234,
    };
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    const expected = [_]u8{
        0x10, 0x88, 0x27, 0x1a, 0x03, 0x64, 0xc8, 0x01,
        0x22, 0x03, 0x5f, 0xcd, 0x01, 0x50, 0x01, 0x58,
        0x01, 0x78, 0x01, 0x80, 0x01, 0xd2, 0x09,
    };
    try testing.expectEqualSlices(u8, &expected, got);
}

test "Vector B — Rewards with one Staking Reward + num_partitions" {
    const pk = "Stake11111111111111111111111111111111111111";
    const rewards = [_]Reward{
        .{
            .pubkey = pk,
            .lamports = 2500,
            .post_balance = 1000000,
            .reward_type = .Staking,
            .commission = "",
            .commission_bps = "",
        },
    };
    const r = Rewards{ .rewards = &rewards, .num_partitions = 64 };
    const got = try r.encode(testing.allocator);
    defer testing.allocator.free(got);

    var expected: std.ArrayListUnmanaged(u8) = .{};
    defer expected.deinit(testing.allocator);
    try expected.appendSlice(testing.allocator, &[_]u8{ 0x0a, 0x36, 0x0a, 0x2b });
    try expected.appendSlice(testing.allocator, pk);
    try expected.appendSlice(testing.allocator, &[_]u8{
        0x10, 0xc4, 0x13, 0x18, 0xc0, 0x84, 0x3d, 0x20, 0x03, 0x12, 0x02, 0x08, 0x40,
    });
    try testing.expectEqualSlices(u8, expected.items, got);
}

test "Vector C1 — compute_units_consumed=Some(0) emits presence" {
    const meta = TransactionStatusMeta{ .compute_units_consumed = 0 };
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x80, 0x01, 0x00 }, got);
}

test "Vector C2 — TransactionStatusMeta::default() is 0 bytes" {
    const meta = TransactionStatusMeta{};
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{}, got);
}

test "Vector C3 — Reward with negative lamports (10-byte two's-complement)" {
    const r = Reward{
        .pubkey = "",
        .lamports = -1000,
        .post_balance = 0,
        .reward_type = .Voting,
        .commission = "10",
        .commission_bps = "1000",
    };
    const got = try r.encode(testing.allocator);
    defer testing.allocator.free(got);
    const expected = [_]u8{
        0x10, 0x98, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, // tag2 -1000
        0x20, 0x04, // tag4 type=Voting(4)
        0x2a, 0x02, 0x31, 0x30, // tag5 "10"
        0x32, 0x04, 0x31, 0x30, 0x30, 0x30, // tag6 "1000"
    };
    try testing.expectEqualSlices(u8, &expected, got);
}

test "Vector C4 — Reward Unspecified type + post_balance, commissions omitted" {
    const r = Reward{
        .pubkey = "abc",
        .lamports = 123,
        .post_balance = 321,
        .reward_type = .Unspecified,
        .commission = "",
        .commission_bps = "",
    };
    const got = try r.encode(testing.allocator);
    defer testing.allocator.free(got);
    const expected = [_]u8{
        0x0a, 0x03, 0x61, 0x62, 0x63, // tag1 "abc"
        0x10, 0x7b, // tag2 123
        0x18, 0xc1, 0x02, // tag3 321
    };
    try testing.expectEqualSlices(u8, &expected, got);
}

test "Vector D — repeated empty log_messages element emits key+len0 (LIVE latent-bug fix)" {
    // log_messages = ["", "hi"]: prost emits tag6 len0 for the empty element
    // (NOT default-omitted) then tag6 "hi". Proves the repeated-element writer.
    const logs = [_][]const u8{ "", "hi" };
    const meta = TransactionStatusMeta{ .log_messages = &logs };
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    // 0x32=tag6 wt2; empty → 32 00 ; "hi" → 32 02 68 69.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x32, 0x00, 0x32, 0x02, 0x68, 0x69 }, got);
}

// ── Tier-2 Err-status bincode goldens (rc.1 serialize test suite) ────────────
// Vectors E1-E4 are byte-for-byte the rc.1 `test_seserialize_stored_transaction_error`
// assertions (storage-proto/src/lib.rs) — rc.1's OWN canonical serialize output.

test "Vector E1 — TransactionError::InsufficientFundsForFee bincode (unit, idx 4)" {
    const e = TransactionError{ .unit = 4 };
    const got = try e.bincode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 4, 0, 0, 0 }, got);
}

test "Vector E2 — InsufficientFundsForRent{account_index:42} bincode (struct, idx 31)" {
    const e = TransactionError{ .insufficient_funds_for_rent = 42 };
    const got = try e.bincode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 31, 0, 0, 0, 42 }, got);
}

test "Vector E3 — DuplicateInstruction(42) bincode (tuple, idx 30)" {
    const e = TransactionError{ .duplicate_instruction = 42 };
    const got = try e.bincode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{ 30, 0, 0, 0, 42 }, got);
}

test "Vector E4 — InstructionError(42, Custom(0xdeadbeef)) bincode (nested, idx 8→25)" {
    const e = TransactionError{ .instruction_error = .{ .ix_index = 42, .err = .{ .custom = 0xdeadbeef } } };
    const got = try e.bincode(testing.allocator);
    defer testing.allocator.free(got);
    // 8,0,0,0 | 42 | 25,0,0,0 | 0xdeadbeef LE = 239,190,173,222
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 0, 0, 0, 42, 25, 0, 0, 0, 239, 190, 173, 222 }, got);
}

test "Vector E5 — BorshIoError is a UNIT variant in rc.1 (idx 44, 4 bytes, no String)" {
    const e = InstructionError{ .unit = 44 };
    var out: std.ArrayListUnmanaged(u8) = .{};
    defer out.deinit(testing.allocator);
    try e.appendBincode(testing.allocator, &out);
    try testing.expectEqualSlices(u8, &[_]u8{ 44, 0, 0, 0 }, out.items);
}

test "Vector E6 — full proto nesting: TransactionStatusMeta.err for InstructionError(42,Custom)" {
    // encodeProtoErrField wraps the 13-byte bincode in TransactionError{bytes err=1}:
    //   inner  = 0A 0D <13 bincode bytes>           (tag1 wt2, len 13)
    const e = TransactionError{ .instruction_error = .{ .ix_index = 42, .err = .{ .custom = 0xdeadbeef } } };
    const inner = try e.encodeProtoErrField(testing.allocator);
    defer testing.allocator.free(inner);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x0a, 0x0d, 8, 0, 0, 0, 42, 25, 0, 0, 0, 239, 190, 173, 222,
    }, inner);

    // …and TransactionStatusMeta(err only) emits tag1 wrapping that 15-byte msg:
    //   0A 0F <inner 15 bytes>
    const meta = TransactionStatusMeta{ .err_proto = inner };
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x0a, 0x0f, 0x0a, 0x0d, 8, 0, 0, 0, 42, 25, 0, 0, 0, 239, 190, 173, 222,
    }, got);
}

test "Vector E7 — Ok-status (err_proto null) omits tag1 entirely" {
    const meta = TransactionStatusMeta{ .err_proto = null, .fee = 5000 };
    const got = try meta.encode(testing.allocator);
    defer testing.allocator.free(got);
    // No tag1; first field is tag2 (fee) = 0x10 0x88 0x27.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x10, 0x88, 0x27 }, got);
}

// ── DECODER round-trip + read-strictness KATs (--full-rpc-api read path) ─────

test "F1 — decodeTransactionStatusMeta round-trips (encode->decode == identity)" {
    const a = testing.allocator;
    const ii0 = [_]u8{ 0x08, 0x01 }; // opaque pre-encoded inner_instructions element
    const tb0 = [_]u8{ 0x12, 0x02, 0xAA, 0xBB }; // opaque token_balance element
    const pk1 = [_]u8{0x11} ** 32;
    const pk2 = [_]u8{0x22} ** 32;
    const logs = [_][]const u8{ "", "hello" }; // incl an empty element
    const rd = [_]u8{ 0xDE, 0xAD };
    const te = TransactionError{ .instruction_error = .{ .ix_index = 42, .err = .{ .custom = 0xdeadbeef } } };
    const err_proto = try te.encodeProtoErrField(a);
    defer a.free(err_proto);

    const meta = TransactionStatusMeta{
        .err_proto = err_proto,
        .fee = 5000,
        .pre_balances = &[_]u64{ 1, 2, 3 },
        .post_balances = &[_]u64{ 4, 5, 6 },
        .inner_instructions = &[_][]const u8{&ii0},
        .log_messages = &logs,
        .pre_token_balances = &[_][]const u8{&tb0},
        .loaded_writable_addresses = &[_][]const u8{&pk1},
        .loaded_readonly_addresses = &[_][]const u8{&pk2},
        .return_data = &rd,
        .compute_units_consumed = 1234,
        .cost_units = 0, // Some(0) presence must survive
    };
    const enc = try meta.encode(a);
    defer a.free(enc);
    var dec = try decodeTransactionStatusMeta(a, enc);
    defer dec.deinit(a);

    try testing.expectEqual(@as(u64, 5000), dec.fee);
    try testing.expectEqualSlices(u64, &[_]u64{ 1, 2, 3 }, dec.pre_balances);
    try testing.expectEqualSlices(u64, &[_]u64{ 4, 5, 6 }, dec.post_balances);
    try testing.expectEqual(@as(usize, 1), dec.inner_instructions.len);
    try testing.expectEqualSlices(u8, &ii0, dec.inner_instructions[0]);
    try testing.expectEqual(@as(usize, 2), dec.log_messages.len);
    try testing.expectEqualSlices(u8, "", dec.log_messages[0]);
    try testing.expectEqualSlices(u8, "hello", dec.log_messages[1]);
    try testing.expectEqualSlices(u8, &tb0, dec.pre_token_balances[0]);
    try testing.expectEqualSlices(u8, &pk1, dec.loaded_writable_addresses[0]);
    try testing.expectEqualSlices(u8, &pk2, dec.loaded_readonly_addresses[0]);
    try testing.expectEqualSlices(u8, &rd, dec.return_data.?);
    try testing.expectEqual(@as(?u64, 1234), dec.compute_units_consumed);
    try testing.expectEqual(@as(?u64, 0), dec.cost_units); // Some(0) preserved
    // err decodes to the inner bincode TransactionError bytes (Vector E4).
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 0, 0, 0, 42, 25, 0, 0, 0, 239, 190, 173, 222 }, dec.err_bytes.?);
}

test "F2 — decodeRewards round-trips rewards + num_partitions (partitioned epoch rewards)" {
    const a = testing.allocator;
    const rewards = [_]Reward{
        .{ .pubkey = "addr-one", .lamports = -5000, .post_balance = 100, .reward_type = .Staking, .commission = "5", .commission_bps = "500" },
        .{ .pubkey = "addr-two", .lamports = 7000, .post_balance = 200, .reward_type = .Voting },
    };
    const rw = Rewards{ .rewards = &rewards, .num_partitions = 42 };
    const enc = try rw.encode(a);
    defer a.free(enc);
    var dec = try decodeRewards(a, enc);
    defer dec.deinit(a);

    try testing.expectEqual(@as(usize, 2), dec.rewards.len);
    try testing.expectEqualSlices(u8, "addr-one", dec.rewards[0].pubkey);
    try testing.expectEqual(@as(i64, -5000), dec.rewards[0].lamports); // negative int64 round-trips
    try testing.expectEqual(@as(u64, 100), dec.rewards[0].post_balance);
    try testing.expectEqual(@as(u32, @intFromEnum(RewardType.Staking)), dec.rewards[0].reward_type);
    try testing.expectEqualSlices(u8, "5", dec.rewards[0].commission);
    try testing.expectEqualSlices(u8, "500", dec.rewards[0].commission_bps);
    try testing.expectEqualSlices(u8, "addr-two", dec.rewards[1].pubkey);
    try testing.expectEqual(@as(i64, 7000), dec.rewards[1].lamports);
    try testing.expectEqual(@as(u32, @intFromEnum(RewardType.Voting)), dec.rewards[1].reward_type);
    try testing.expectEqual(@as(?u64, 42), dec.num_partitions);
}

test "F3 — decoder read-strict: empty ok, truncated + malformed rejected" {
    const a = testing.allocator;
    // Empty input → all-default decode (Ok-status, no fields) — valid.
    var d0 = try decodeTransactionStatusMeta(a, &[_]u8{});
    defer d0.deinit(a);
    try testing.expectEqual(@as(u64, 0), d0.fee);
    try testing.expect(d0.err_bytes == null);
    try testing.expectEqual(@as(usize, 0), d0.pre_balances.len);

    // Length-delimited field claiming 5 bytes with only 2 present → Truncated.
    try testing.expectError(error.Truncated, decodeTransactionStatusMeta(a, &[_]u8{ 0x32, 0x05, 0x41, 0x42 }));
    // Varint with continuation bit then EOF → Truncated.
    try testing.expectError(error.Truncated, decodeTransactionStatusMeta(a, &[_]u8{0x80}));
    // 11-byte all-continuation varint → Malformed (varint > 10 bytes).
    try testing.expectError(error.Malformed, decodeTransactionStatusMeta(a, &([_]u8{0x80} ** 11)));
    // decodeRewards is equally strict.
    try testing.expectError(error.Truncated, decodeRewards(a, &[_]u8{ 0x0a, 0x09, 0x01 }));
}
