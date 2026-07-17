// Minimal vex_svm stub used ONLY by `zig build test-accounts`.
//
// The real `vex_svm` module imports `vex_store`, which claims the same source
// files (sig_overlay.zig, recorder.zig, etc.) that the test's root module
// (rooted at src/vex_store/accounts.zig) also reaches. Zig refuses to compile
// when the same file belongs to two modules. This stub breaks the chain by
// providing only the symbols accounts.zig actually references — with no
// vex_store dependency.
//
// Accessed by accounts.zig:
//   line 796  @import("vex_svm").native.program_ids.vote          [32]u8 constant
//   line 802  @import("vex_svm").native.vote.deserializeVoteState fn(data) ?VoteState
//   line 1190 @import("vex_svm").bank.Bank.accountLtHash          fn(...) LtHashValue
//
// All test-relevant code paths use owners that do NOT match program_ids.vote,
// so the deserialize branch is not exercised; the stub returns null. The Bank
// stub is only reached from writeAccountAtSlot which the carrier #2 tests do
// not call, but the signature must still type-check.

const std = @import("std");
const crypto = @import("vex_crypto");

pub const native = struct {
    pub const program_ids = struct {
        // Sentinel value — the carrier #2 tests use non-vote owners, so this
        // comparison always returns false in test execution. Bytes are
        // intentionally not the real Vote111 pubkey to make accidental matches
        // immediately visible if a test starts using vote owners.
        pub const vote: [32]u8 = [_]u8{0xDE} ** 32;
    };

    pub const vote = struct {
        pub const VoteState = struct {
            last_timestamp: LastTimestamp,
            pub const LastTimestamp = struct {
                slot: u64,
                timestamp: i64,
            };
        };

        pub fn deserializeVoteState(data: []const u8) ?VoteState {
            _ = data;
            return null;
        }
    };

    // Referenced by the canonical top_votes chokepoint
    // (AccountsDb.refreshTopVoteForWrite, accounts.zig). The carrier-#2 tests
    // use non-vote owners, so the VOTE_PROGRAM_ID compare always returns false
    // and the deserialize branch is never reached; the sentinel id + null
    // deserializer keep the path type-checked but inert in test execution.
    pub const vote_program = struct {
        pub const VOTE_PROGRAM_ID: [32]u8 = [_]u8{0xDE} ** 32;
    };

    pub const vote_state_serde = struct {
        pub const VoteState = struct {
            last_timestamp: LastTimestamp,
            pub const LastTimestamp = struct {
                slot: u64,
                timestamp: i64,
            };
            pub fn lastVotedSlot(self: *const VoteState) ?u64 {
                _ = self;
                return null;
            }
        };

        pub fn deserializeVoteState(data: []const u8) ?VoteState {
            _ = data;
            return null;
        }
    };
};

pub const bank = struct {
    pub const Bank = struct {
        pub fn accountLtHash(
            pubkey: *const [32]u8,
            owner: *const [32]u8,
            lamports: u64,
            executable: bool,
            data: []const u8,
        ) crypto.lthash.LtHashValue {
            _ = pubkey;
            _ = owner;
            _ = lamports;
            _ = executable;
            _ = data;
            return crypto.lthash.LtHashValue.init();
        }
    };
};
