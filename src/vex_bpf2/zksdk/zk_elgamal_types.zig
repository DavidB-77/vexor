//! `runtime.program.zk_elgamal` analog — ProofType + CU constants for the ZK ElGamal proof port.
//! @prov:zksdk.module-map — full Sig/Agave port + CU-constant cross-check trail in PROVENANCE.md.
//!
//! ProofContextStateMeta / ProofContextState / ID live in the handler (they need vex's Pubkey type)
//! and are added when the handler is ported. The proof modules only need ProofType from here.

/// @prov:zksdk.module-map — the on-chain proof_type discriminator stored in context-state accounts.
pub const ProofType = enum(u8) {
    /// Empty proof type used to distinguish if a proof context account is initialized.
    uninitialized,
    zero_ciphertext,
    ciphertext_ciphertext_equality,
    ciphertext_commitment_equality,
    pubkey_validity,
    percentage_with_cap,
    batched_range_proof_u64,
    batched_range_proof_u128,
    batched_range_proof_u256,
    grouped_ciphertext2_handles_validity,
    batched_grouped_ciphertext2_handles_validity,
    grouped_ciphertext3_handles_validity,
    batched_grouped_ciphertext3_handles_validity,
    _,

    pub const BincodeSize = u8;
};

// @prov:zksdk.cu-costs — charged BEFORE verification in the handler.
pub const CLOSE_CONTEXT_STATE_COMPUTE_UNITS: u64 = 3_300;
pub const VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS: u64 = 6_000;
pub const VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS: u64 = 8_000;
pub const VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS: u64 = 6_400;
pub const VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS: u64 = 2_600;
pub const VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS: u64 = 6_500;
pub const VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS: u64 = 111_000;
pub const VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS: u64 = 200_000;
pub const VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS: u64 = 368_000;
pub const VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 6_400;
pub const VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 13_000;
pub const VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 8_100;
pub const VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS: u64 = 16_400;
