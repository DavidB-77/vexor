//! eBPF Bytecode Generator
//! Generates eBPF XDP program at runtime without needing clang/LLVM
//!
//! Inspired by high-performance Solana validator implementations.
//! See docs/AFXDP_PERFORMANCE_GUIDE.md for architecture details.

const std = @import("std");

// ═══════════════════════════════════════════════════════════════════════════════
// eBPF Instruction Encoding (Standard BPF instruction format)
// ═══════════════════════════════════════════════════════════════════════════════

// Register definitions
const r0: u8 = 0;
const r1: u8 = 1;
const r2: u8 = 2;
const r3: u8 = 3;
const r4: u8 = 4;
const r5: u8 = 5;

// Load instructions
fn ldxb(dst: u8, src: u8, off: i16) u64 {
    return @as(u64, 0x71) | (@as(u64, dst) << 8) | (@as(u64, src) << 12) | (@as(u64, @as(u16, @bitCast(off))) << 16);
}

fn ldxh(dst: u8, src: u8, off: i16) u64 {
    return @as(u64, 0x69) | (@as(u64, dst) << 8) | (@as(u64, src) << 12) | (@as(u64, @as(u16, @bitCast(off))) << 16);
}

fn ldxw(dst: u8, src: u8, off: i16) u64 {
    return @as(u64, 0x61) | (@as(u64, dst) << 8) | (@as(u64, src) << 12) | (@as(u64, @as(u16, @bitCast(off))) << 16);
}

fn lddw(dst: u8, imm: i32) u64 {
    // 0x18 = BPF_LD | BPF_IMM | BPF_DW
    // src_reg = 1 (0x10 in byte 1) = BPF_PSEUDO_MAP_FD - tells kernel this is a map FD
    // This is critical! Without BPF_PSEUDO_MAP_FD, the kernel treats it as a scalar value
    // Reference: Firedancer uses 0x1018 which has src_reg=1
    return @as(u64, 0x18) | (@as(u64, dst) << 8) | (@as(u64, 1) << 12) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

// ALU instructions
fn mov64_imm(dst: u8, imm: i32) u64 {
    return @as(u64, 0xb7) | (@as(u64, dst) << 8) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

fn mov64_reg(dst: u8, src: u8) u64 {
    return @as(u64, 0xbf) | (@as(u64, dst) << 8) | (@as(u64, src) << 12);
}

fn add64_imm(dst: u8, imm: i32) u64 {
    return @as(u64, 0x07) | (@as(u64, dst) << 8) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

fn add64_reg(dst: u8, src: u8) u64 {
    return @as(u64, 0x0f) | (@as(u64, dst) << 8) | (@as(u64, src) << 12);
}

fn and64_imm(dst: u8, imm: i32) u64 {
    return @as(u64, 0x57) | (@as(u64, dst) << 8) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

fn lsh64_imm(dst: u8, imm: i32) u64 {
    return @as(u64, 0x67) | (@as(u64, dst) << 8) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

// Jump instructions
fn ja(off: i16) u64 {
    return @as(u64, 0x05) | (@as(u64, @as(u16, @bitCast(off))) << 16);
}

fn jeq_imm(dst: u8, imm: i32, off: i16) u64 {
    return @as(u64, 0x15) | (@as(u64, dst) << 8) | (@as(u64, @as(u16, @bitCast(off))) << 16) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

fn jne_imm(dst: u8, imm: i32, off: i16) u64 {
    return @as(u64, 0x55) | (@as(u64, dst) << 8) | (@as(u64, @as(u16, @bitCast(off))) << 16) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

fn jgt_reg(dst: u8, src: u8, off: i16) u64 {
    return @as(u64, 0x2d) | (@as(u64, dst) << 8) | (@as(u64, src) << 12) | (@as(u64, @as(u16, @bitCast(off))) << 16);
}

fn jlt_imm(dst: u8, imm: i32, off: i16) u64 {
    return @as(u64, 0xa5) | (@as(u64, dst) << 8) | (@as(u64, @as(u16, @bitCast(off))) << 16) | (@as(u64, @as(u32, @bitCast(imm))) << 32);
}

// Call and exit
fn call_helper(helper_id: u32) u64 {
    return @as(u64, 0x85) | (@as(u64, helper_id) << 32);
}

const exit_insn: u64 = 0x95;

// XDP actions
const XDP_PASS: i32 = 2;

// BPF helper function IDs
const BPF_FUNC_redirect_map: u32 = 0x33; // 51

// ═══════════════════════════════════════════════════════════════════════════════
// XDP PROGRAM GENERATOR (Runtime bytecode generation)
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate XDP program bytecode at runtime
/// (the same approach Firedancer takes - no need for clang/LLVM!)
///
/// The generated program:
/// 1. Parses Ethernet/IP/UDP headers
/// 2. Checks if UDP destination port matches any in our list
/// 3. Redirects matching packets to AF_XDP socket, passes others to kernel
///
/// Returns: number of instructions written
pub fn generateXdpProgram(
    code_buf: []u64,
    xsks_map_fd: i32,
    listen_ports: []const u16,
) !usize {
    // Labels for jump targets (we'll fix them up later)
    const LBL_PASS: i16 = 1;
    const LBL_REDIRECT: i16 = 2;
    // Note: LBL_UDP_CHECK not needed since we fall through naturally

    if (listen_ports.len > 16) {
        return error.TooManyPorts;
    }
    if (code_buf.len < 128) {
        return error.BufferTooSmall;
    }

    var idx: usize = 0;

    // r1 = xdp_md* (passed by kernel)
    // r2 = xdp_md->data
    // r3 = xdp_md->data_end

    code_buf[idx] = ldxw(r2, r1, 0);
    idx += 1; // r2 = xdp_md->data
    code_buf[idx] = ldxw(r3, r1, 4);
    idx += 1; // r3 = xdp_md->data_end

    // Bounds check: need at least 34 bytes (14 eth + 20 ip)
    code_buf[idx] = mov64_reg(r5, r2);
    idx += 1;
    code_buf[idx] = add64_imm(r5, 34);
    idx += 1;
    code_buf[idx] = jgt_reg(r5, r3, LBL_PASS);
    idx += 1; // if r2+34 > r3 goto LBL_PASS

    // Check Ethernet type == IPv4 (0x0800, but in network byte order = 0x0008)
    code_buf[idx] = ldxh(r5, r2, 12);
    idx += 1; // r5 = eth_hdr->h_proto
    code_buf[idx] = jne_imm(r5, 0x0008, LBL_PASS);
    idx += 1; // if != IP4 goto LBL_PASS

    // Advance r2 past Ethernet header (14 bytes)
    code_buf[idx] = add64_imm(r2, 14);
    idx += 1;

    // Calculate IP header length and next header position
    code_buf[idx] = ldxb(r4, r2, 0);
    idx += 1; // r4 = ip_hdr->version_ihl
    code_buf[idx] = and64_imm(r4, 0x0f);
    idx += 1; // r4 = ihl (lower 4 bits)
    code_buf[idx] = lsh64_imm(r4, 2);
    idx += 1; // r4 = ihl * 4 (header length in bytes)
    code_buf[idx] = jlt_imm(r4, 20, LBL_PASS);
    idx += 1; // if r4 < 20 goto LBL_PASS (invalid)
    code_buf[idx] = add64_reg(r4, r2);
    idx += 1; // r4 = start of next header (UDP)

    // Check protocol == UDP (17)
    code_buf[idx] = ldxb(r5, r2, 9);
    idx += 1; // r5 = ip_hdr->protocol
    code_buf[idx] = jne_imm(r5, 17, LBL_PASS);
    idx += 1; // if != UDP goto LBL_PASS

    // Note: UDP check position is at current idx, but we don't need a separate label for it
    // since the control flow falls through naturally from the IP protocol check

    // Move r2 to UDP header
    code_buf[idx] = mov64_reg(r2, r4);
    idx += 1;

    // Bounds check: need 8 more bytes for UDP header
    code_buf[idx] = add64_imm(r4, 8);
    idx += 1;
    code_buf[idx] = jgt_reg(r4, r3, LBL_PASS);
    idx += 1; // if r4+8 > r3 goto LBL_PASS

    // Get UDP destination port
    code_buf[idx] = ldxh(r4, r2, 2);
    idx += 1; // r4 = udp_hdr->dest (network byte order)

    // Check each port (ports are in network byte order for comparison)
    for (listen_ports) |port| {
        if (port == 0) continue;
        // Convert port to network byte order for comparison
        const port_be = @byteSwap(port);
        code_buf[idx] = jeq_imm(r4, @as(i32, port_be), LBL_REDIRECT);
        idx += 1;
    }

    // LBL_PASS: return XDP_PASS
    const lbl_pass_pos = idx;
    code_buf[idx] = mov64_imm(r0, XDP_PASS);
    idx += 1;
    code_buf[idx] = exit_insn;
    idx += 1;

    // LBL_REDIRECT: redirect to AF_XDP socket with fallback
    const lbl_redirect_pos = idx;
    code_buf[idx] = ldxw(r2, r1, 16);
    idx += 1; // r2 = xdp_md->rx_queue_index
    code_buf[idx] = lddw(r1, xsks_map_fd);
    idx += 1; // r1 = xsks_map_fd (64-bit load, takes 2 slots)
    code_buf[idx] = 0;
    idx += 1; // Second half of lddw (upper 32 bits = 0)
    code_buf[idx] = mov64_imm(r3, 0);
    idx += 1; // r3 = flags = 0
    code_buf[idx] = call_helper(BPF_FUNC_redirect_map);
    idx += 1; // call bpf_redirect_map(r1, r2, r3) -> result in r0
    // Check if redirect failed (r0 < 0) and fallback to kernel
    code_buf[idx] = jlt_imm(r0, 0, LBL_PASS);
    idx += 1; // if r0 < 0, jump to LBL_PASS (fallback to kernel)
    code_buf[idx] = exit_insn; // Otherwise return r0 (successful XDP_REDIRECT)
    idx += 1;

    const code_cnt = idx;

    // Fix up jump labels
    // Jump instructions have format: opcode | dst<<8 | off<<16 | imm<<32
    // We need to replace placeholder labels with actual offsets
    var i: usize = 0;
    while (i < code_cnt) : (i += 1) {
        const insn = code_buf[i];
        const opcode = insn & 0xFF;

        // Check if this is a conditional jump (0x05, 0x15, 0x25, 0x2d, 0x35, 0x45, 0x55, 0x65, 0x75, 0xa5, 0xb5, 0xc5, 0xd5)
        // or unconditional jump (0x05)
        if ((opcode & 0x07) == 0x05) {
            const jmp_label = @as(i16, @bitCast(@as(u16, @truncate((insn >> 16) & 0xFFFF))));
            var jmp_target: ?usize = null;

            if (jmp_label == LBL_PASS) {
                jmp_target = lbl_pass_pos;
            } else if (jmp_label == LBL_REDIRECT) {
                jmp_target = lbl_redirect_pos;
            } else if (jmp_label == 0) {
                continue; // No fixup needed
            }

            if (jmp_target) |target| {
                // Calculate relative offset: target - current - 1
                const off: i16 = @intCast(@as(isize, @intCast(target)) - @as(isize, @intCast(i)) - 1);
                const off_u: u16 = @bitCast(off);
                // Replace the offset in the instruction
                code_buf[i] = (insn & 0xFFFFFFFF0000FFFF) | (@as(u64, off_u) << 16);
            }
        }
    }

    std.log.info("[eBPF Gen] Generated XDP program: {d} instructions for {d} ports", .{ code_cnt, listen_ports.len });
    return code_cnt;
}

/// Convert code buffer to bytes for BPF_PROG_LOAD
pub fn codeToBytes(code_buf: []const u64, byte_buf: []u8) ![]const u8 {
    const needed = code_buf.len * 8;
    if (byte_buf.len < needed) {
        return error.BufferTooSmall;
    }

    for (code_buf, 0..) |insn, i| {
        std.mem.writeInt(u64, byte_buf[i * 8 ..][0..8], insn, .little);
    }

    return byte_buf[0..needed];
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

test "generate basic xdp program" {
    var code_buf: [512]u64 = undefined;
    const ports = [_]u16{ 8001, 8002, 8003 };

    const count = try generateXdpProgram(&code_buf, 5, &ports);
    try std.testing.expect(count > 0);
    try std.testing.expect(count < 100);
}
