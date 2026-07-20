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

/// Distinct proof-attempt identifier derivations for one application slot.
/// Public-only proof families have no private attempt input. The target proof
/// has the same two persistent proof derivations as the other reset-safe
/// families; its separately keyed release attempt belongs to target flooding.
#[cfg(test)]
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
