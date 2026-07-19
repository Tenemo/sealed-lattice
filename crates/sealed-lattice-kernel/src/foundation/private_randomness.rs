pub const PROOF_APPLICATION_SLOT_SCHEMA_IDENTIFIER: u16 = 0x0109;
pub const PRIVATE_RANDOM_BLOCK_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0400;
pub const PERSISTENT_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0401;
pub const ACTION_RANDOMNESS_DERIVATION_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0402;
pub const ORDINARY_PROOF_COIN_INPUT_SCHEMA_IDENTIFIER: u16 = 0x0403;
pub const RANDOM_CURSOR_SCHEMA_IDENTIFIER: u16 = 0x1804;
pub const SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_IDENTIFIER: u16 = 0x120d;

pub const ACTION_RANDOMNESS_ROOT_BYTE_LENGTH: usize = 64;
pub const PRIVATE_RANDOMNESS_ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
pub const PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH: usize = 64;
pub const PRIVATE_PROOF_SALT_PURPOSE: u16 = 0xfffe;

const FOUNDATION_SCHEMA_VERSION: u16 = 1;
const SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_SCHEMA_VERSION: u16 = 3;
const ACTION_RANDOMNESS_KEY_MATERIAL_BYTE_LENGTH: usize = 192;
const ACTION_RANDOMNESS_COMMITMENT_PREIMAGE_BYTE_LENGTH: usize = 64;
const PRIVATE_RANDOMNESS_STREAM_KEY_BYTE_LENGTH: usize = 64;
const PROOF_COIN_KEY_BYTE_LENGTH: usize = 64;
const PRIVATE_RANDOMNESS_BLOCK_BIT_LENGTH: u16 = 512;

const SUITE_DISTRIBUTION_FAMILY: u16 = 0x0116;
const SETUP_SOURCE_FAMILY: u16 = 0x1201;
const SETUP_MAILBOX_FAMILY: u16 = 0x0200;
const VSS_EXPANSION_FAMILY: u16 = 0x2120;
const TARGET_FLOODING_FAMILY: u16 = 0x1630;
const ORDINARY_BALLOT_PROOF_FAMILY: u16 =
    ProofFamilyIdentifiers::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER;
const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: u16 =
    ProofFamilyIdentifiers::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;

const ACTION_RANDOMNESS_KEY_HIERARCHY_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/private-randomness/action-key-hierarchy/v1";
const ACTION_RANDOMNESS_COMMITMENT_DOMAIN: &str =
    "sealed-lattice/private-randomness/action-root-commitment/v1";
const SETUP_ACTION_RANDOMNESS_AUTHORIZATION_DOMAIN: &str =
    "sealed-lattice/setup/state/action-randomness/v1";
const PRIVATE_RANDOMNESS_BLOCK_CUSTOMIZATION: &[u8] = b"sealed-lattice/private-randomness/v1";
const SETUP_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/setup/reset-safe-attempt/v1";
const PERSISTENT_PROOF_PREPARATION_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/proof/persistent-preparation/v1";
const PERSISTENT_PROOF_WITNESS_ATTEMPT_CUSTOMIZATION: &[u8] =
    b"sealed-lattice/proof/persistent-canonical-witness-attempt/v1";
const ORDINARY_PROOF_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/proof/ordinary-attempt/v1";
const TARGET_RELEASE_ATTEMPT_CUSTOMIZATION: &[u8] = b"sealed-lattice/target-release/attempt/v1";
const APPLICATION_SLOT_HASH_DOMAIN: &str = "sealed-lattice/proof/application-slot/v1";
const SETUP_STRUCTURED_COMMITMENT_OPENING_CONTEXT_HASH_DOMAIN: &str =
    "sealed-lattice/setup/structured-commitment-opening-context/v3";

const RESET_SAFE_PROOF_FAMILIES: [u16; 8] = [
    ProofFamilyIdentifiers::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    ProofFamilyIdentifiers::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
];
const PUBLIC_ONLY_PROOF_FAMILIES: [u16; 3] =
    ProofFamilyIdentifiers::PUBLIC_ONLY_FAMILY_SCHEMA_IDENTIFIERS;

mod domain;
mod material;
mod proof_coins;
mod stream;
mod validation;

pub use domain::PrivateRandomnessDomain;
pub(crate) use material::PersistentProofWitnessCoinBinding;
pub use material::{
    ActionPrivateRandomness, ActionRandomnessDerivationInput, ActionRandomnessRoot,
    SetupStructuredCommitmentOpeningContext,
};
pub use proof_coins::{
    OrdinaryProofCoinInput, PersistentProofCoinInput, PrivateRandomnessAttemptIdentifier,
    ProofApplicationSlot,
};
pub use stream::{PrivateRandomBlockInput, PrivateRandomCursor, PrivateRandomnessStream};

/// Non-serialized accounting for the distinct canonical KMAC inputs used by
/// one action. Byte-identical resume and replay inputs are counted once by the
/// action owner before constructing this row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PrivateRandomnessKmacInputClassAccounting {
    action_key_hierarchy_derivation_count: u64,
    attempt_identifier_derivation_count: u64,
    private_stream_block_count: u64,
    committed_material_inner_derivation_count: u64,
}

impl PrivateRandomnessKmacInputClassAccounting {
    pub(crate) fn checked_new(
        action_key_hierarchy_derivation_count: u64,
        attempt_identifier_derivation_count: u64,
        private_stream_block_count: u64,
        committed_material_inner_derivation_count: u64,
    ) -> Option<Self> {
        action_key_hierarchy_derivation_count
            .checked_add(attempt_identifier_derivation_count)?
            .checked_add(private_stream_block_count)?
            .checked_add(committed_material_inner_derivation_count)?;
        Some(Self {
            action_key_hierarchy_derivation_count,
            attempt_identifier_derivation_count,
            private_stream_block_count,
            committed_material_inner_derivation_count,
        })
    }

    pub(crate) fn checked_add(self, right: Self) -> Option<Self> {
        Self::checked_new(
            self.action_key_hierarchy_derivation_count
                .checked_add(right.action_key_hierarchy_derivation_count)?,
            self.attempt_identifier_derivation_count
                .checked_add(right.attempt_identifier_derivation_count)?,
            self.private_stream_block_count
                .checked_add(right.private_stream_block_count)?,
            self.committed_material_inner_derivation_count
                .checked_add(right.committed_material_inner_derivation_count)?,
        )
    }
}

/// Maximum distinct block inputs consumed by one byte-oriented stream. A
/// resumed stream can rederive its buffered block, but that byte-identical
/// counter input is not a second distinct input.
pub(crate) fn private_randomness_stream_block_count_for_byte_length(
    byte_length: u64,
) -> Option<u64> {
    let block_byte_length = u64::try_from(PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH).ok()?;
    Some(byte_length.div_ceil(block_byte_length))
}

/// Maximum distinct block inputs consumed by one bit-oriented stream. Bits
/// are packed continuously before the 64-byte stream-block boundary is
/// applied, so this does not introduce a byte-rounding term per coefficient.
pub(crate) fn private_randomness_stream_block_count_for_bit_length(bit_length: u64) -> Option<u64> {
    let block_bit_length = u64::try_from(PRIVATE_RANDOMNESS_BLOCK_BYTE_LENGTH)
        .ok()?
        .checked_mul(8)?;
    Some(bit_length.div_ceil(block_bit_length))
}

/// Maximum distinct block inputs consumed by consecutive modular outputs in
/// one stream under the production rejection-sampling rule.
pub(crate) fn private_randomness_stream_block_count_for_modulo_outputs(
    output_count: u64,
    modulus: u64,
    maximum_candidate_draws_per_output: u32,
) -> Option<u64> {
    if modulus <= 1 || maximum_candidate_draws_per_output == 0 {
        return None;
    }
    let significant_bit_length = u64::BITS - modulus.leading_zeros();
    let sample_byte_length = u64::from(significant_bit_length).div_ceil(8);
    private_randomness_stream_block_count_for_rejection_sampling(
        output_count,
        sample_byte_length,
        maximum_candidate_draws_per_output,
    )
}

/// Maximum distinct block inputs for a fixed-width rejection sampler whose
/// candidate width is derived by an owning protocol module.
pub(crate) fn private_randomness_stream_block_count_for_rejection_sampling(
    output_count: u64,
    sample_byte_length: u64,
    maximum_candidate_draws_per_output: u32,
) -> Option<u64> {
    if sample_byte_length == 0 || maximum_candidate_draws_per_output == 0 {
        return None;
    }
    let consumed_byte_length = output_count
        .checked_mul(u64::from(maximum_candidate_draws_per_output))?
        .checked_mul(sample_byte_length)?;
    private_randomness_stream_block_count_for_byte_length(consumed_byte_length)
}

/// Distinct proof-attempt identifier derivations for one application slot.
/// Public-only proof families have no private attempt input. The target proof
/// has the same two persistent proof derivations as the other reset-safe
/// families; its separately keyed release attempt belongs to target flooding.
pub(crate) fn proof_attempt_identifier_derivation_count(
    application_statement_schema_identifier: u16,
) -> Option<u64> {
    if RESET_SAFE_PROOF_FAMILIES.contains(&application_statement_schema_identifier) {
        Some(2)
    } else if application_statement_schema_identifier == ORDINARY_BALLOT_PROOF_FAMILY {
        Some(1)
    } else if PUBLIC_ONLY_PROOF_FAMILIES.contains(&application_statement_schema_identifier) {
        Some(0)
    } else {
        None
    }
}

fn schema_error(
    refusal_reason: super::RefusalReason,
    message: &'static str,
) -> super::FoundationSchemaError {
    super::FoundationSchemaError::new(refusal_reason, message)
}

#[cfg(test)]
#[path = "private_randomness/tests.rs"]
mod tests;
use super::proof_application::ProofApplicationSlotCeilings as ProofFamilyIdentifiers;
