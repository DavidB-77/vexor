//! zksdk module root for the ZK ElGamal proof port (task #11, 2026-06-19).
//! Re-exports the ported proof primitives + proof-data types. @prov:zksdk.module-map
//!
//! FOUNDATION subset is live now (ed25519 MSM shim + Merlin + ElGamal + Pedersen, KAT-validated).
//! Sigma-proof / range-proof / proof-data exports are appended as each module is ported + audited.

const builtin = @import("builtin");

comptime {
    if (builtin.is_test) {
        _ = @import("elgamal.zig");
        _ = @import("merlin.zig");
        _ = @import("pedersen.zig");
        _ = @import("sigma_proofs/pubkey_validity.zig");
        _ = @import("sigma_proofs/zero_ciphertext.zig");
        _ = @import("sigma_proofs/ciphertext_commitment.zig");
        _ = @import("sigma_proofs/ciphertext_ciphertext.zig");
        _ = @import("sigma_proofs/percentage_with_cap.zig");
        _ = @import("sigma_proofs/grouped_ciphertext/2_handles.zig");
        _ = @import("sigma_proofs/grouped_ciphertext/3_handles.zig");
        _ = @import("range_proof/ipp.zig");
        _ = @import("range_proof/bulletproofs.zig");
    }
}

pub const elgamal = @import("elgamal.zig");
pub const pedersen = @import("pedersen.zig");
pub const merlin = @import("merlin.zig");

pub const Strobe128 = merlin.Strobe128;
pub const Transcript = merlin.Transcript;

pub const ElGamalCiphertext = elgamal.Ciphertext;
pub const ElGamalKeypair = elgamal.Keypair;
pub const ElGamalPubkey = elgamal.Pubkey;
pub const GroupedElGamalCiphertext = elgamal.GroupedElGamalCiphertext;

// ── appended as ported (sigma proofs / range proofs / proof-data) ──
// sigma proofs
const ciphertext_ciphertext = @import("sigma_proofs/ciphertext_ciphertext.zig");
const ciphertext_commitment = @import("sigma_proofs/ciphertext_commitment.zig");
const percentage = @import("sigma_proofs/percentage_with_cap.zig");
const pubkey_validity = @import("sigma_proofs/pubkey_validity.zig");
const zero_ciphertext = @import("sigma_proofs/zero_ciphertext.zig");

pub const CiphertextCiphertextData = ciphertext_ciphertext.Data;
pub const CiphertextCommitmentData = ciphertext_commitment.Data;
pub const PercentageWithCapData = percentage.Data;
pub const PubkeyProofData = pubkey_validity.Data;
pub const ZeroCiphertextData = zero_ciphertext.Data;

// grouped ciphertext validity
const grouped_cipher_2_handles = @import("sigma_proofs/grouped_ciphertext/2_handles.zig");
const grouped_cipher_3_handles = @import("sigma_proofs/grouped_ciphertext/3_handles.zig");

pub const GroupedCiphertext2HandlesData = grouped_cipher_2_handles.Data;
pub const BatchedGroupedCiphertext2HandlesData = grouped_cipher_2_handles.BatchedData;
pub const GroupedCiphertext3HandlesData = grouped_cipher_3_handles.Data;
pub const BatchedGroupedCiphertext3HandlesData = grouped_cipher_3_handles.BatchedData;

// range proof
pub const bulletproofs = @import("range_proof/bulletproofs.zig");

pub const RangeProofU64Data = bulletproofs.Data(64);
pub const RangeProofU128Data = bulletproofs.Data(128);
pub const RangeProofU256Data = bulletproofs.Data(256);
