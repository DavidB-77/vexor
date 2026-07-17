// murmur3.zig — module 67 §G SPLIT extraction from vm_executable.zig.
// Manifest §501/§126: extract murmur3 (byte-exact) into vex_bpf/murmur3.zig so the
// LIVE elf_loader.zig no longer @imports it out of the API-rotted, DELETE-bound
// vm_executable.zig (whose sibling load() uses a Zig-0.14 alignedAlloc(u8, 8, ...)
// signature that no longer compiles under 0.15.2 — a latent defect in dead code
// that only bites when vm_executable's own test block is discovered). murmur3 is
// the syscall-name→ID hash: a wrong hash = syscall mis-dispatch (CONSENSUS). The
// fn body + its known-syscall-IDs test below are byte-exact retained lines from
// vm_executable.zig:433-447; only this `const std` header is added so the helper
// stands alone. The DELETE-bound vm_executable.zig is verbatim-carried this module
// (its now-duplicate murmur3 + rotted load() strip out when the dormant vm_* chain
// is deleted in the post-migration refactor); vm_syscalls.zig:1047 still consumes
// vm_executable.murmur3 (inert, DELETE-bound). Only the elf_loader.zig:14 consumer
// is repointed here.
const std = @import("std");

// ── Murmur3_32 hash (syscall name → ID) ──────────────────────────────────────
// cf. sig/src/vm/syscalls/lib.zig:Syscall.Registry  /  std.hash.Murmur3_32
pub fn murmur3(key: []const u8) u32 {
    return std.hash.Murmur3_32.hashWithSeed(key, 0);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test "murmur3: known syscall IDs" {
    // Verified against Agave rbpf
    try std.testing.expectEqual(@as(u32, 0x207559bd), murmur3("sol_log_"));
    try std.testing.expectEqual(@as(u32, 0x11f49d86), murmur3("sol_sha256"));
    try std.testing.expectEqual(@as(u32, 0xd7449092), murmur3("sol_invoke_signed_rust"));
    try std.testing.expectEqual(@as(u32, 0x83f00e8f), murmur3("sol_alloc_free_"));
}
