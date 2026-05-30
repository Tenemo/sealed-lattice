use serde_json::{Map, Value, json};

use crate::{
    ballot_privacy::component::ParsedSparseComponentProofStatement,
    bgv::profile::{DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{
        canonical_json, canonical_json_matches_bytes, derive_protocol_hash,
        derive_protocol_hash_for_ascii_string_payload, hash512, to_hex,
    },
    transcript_core::decode_hex,
};

use super::protocol_constants::{
    BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION, BALLOT_PRIVACY_FIELD_MODULUS,
    BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT, BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT,
    BALLOT_PRIVACY_MINIMUM_OPTION_COUNT, BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT,
    BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT,
};
use super::{
    PolynomialVector, SHARE_COMMITMENT_MODULE_RANK, SHARE_COMMITMENT_OPENING_DIMENSION,
    check_aggregate_derivation_witness_relation, is_protocol_hash, required_json_field,
    required_string_field, sparse_matrix_from_sparse_component_statement, string_field,
    structural_refusal, structural_rejection,
    verify_aggregate_derivation_relation_subproof_for_component,
};

const BRIDGE_PROOF_PROFILE_ID: &str = "EncryptedAggregateBridge-v1";
const BRIDGE_PROOF_BACKEND: &str = "SealedLatticeBridgeRelation";
const BGV_ENCRYPTION_PROOF_SUBRELATION: &str =
    "SealedLatticePassiveCollectiveCiphertextEquationRelation";
const BGV_ENCRYPTION_KEY_MATERIAL_KIND: &str = "passive-transcript-derived-collective-public-key";
// Deliberate proof gaps for this milestone (not bugs): the bridge ciphertext is intentionally
// NOT threshold-decryptable and NOT claim-bearing; surfaced as false in the target contract.
const DEVELOPMENT_KEY_ONLY: bool = false;
const THRESHOLD_DECRYPTABLE: bool = false;
const CLAIM_BEARING_BRIDGE_ENCRYPTION: bool = false;
// Status-string markers below: intentional proof-gap labels that downgrade the claim,
// not verification failures. *_DEFERRED / *_MISSING / *_PRECONDITION mark known open gaps.
const BRIDGE_PROOF_PENDING_STATUS: &str = "BridgeProofBackendPending";
const SHARED_WITNESS_BINDING_PENDING_STATUS: &str = "SharedWitnessBindingProofPending";
const AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS: &str =
    "AggregateToPlaintextBindingProofPending";
const BGV_ENCRYPTION_PROOF_PENDING_STATUS: &str = "BoundedEncryptionProofPending";
const RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS: &str = "RnsCrtConsistencyProofPending";
const BRIDGE_PROOF_CHECKED_STATUS: &str = "BridgeProofRelationChecked";
const SHARED_WITNESS_BINDING_CHECKED_STATUS: &str = "SharedWitnessBindingRelationChecked";
const AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS: &str =
    "AggregateToPlaintextModularBindingChecked";
const BGV_ENCRYPTION_PROOF_CHECKED_STATUS: &str = "BgvCiphertextEquationChecked";
const RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS: &str = "RnsCrtConsistencyRelationChecked";
const SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS: &str =
    "SharedWitnessZeroKnowledgeResponseDistributionChecked";
const BGV_RANDOMNESS_BOUND_PROOF_MISSING_STATUS: &str = "BgvRandomnessBoundProofMissing";
const BGV_RANDOMNESS_BOUND_PROOF_STATUS: &str = "BgvRandomnessErrorSupportPolynomialChecked";
const BRIDGE_CLAIM_CLOSURE_STATUS: &str = "BridgeProofClaimClosureMissing";
const BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG: &str = "fresh-csprng";
const BRIDGE_RANDOMNESS_SOURCE_DEVELOPMENT_DETERMINISTIC: &str =
    "development-deterministic-fixture";
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsProfileFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537InverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForEncryptedAggregateBridgeClaim";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForAggregateBridgeClaimClosure";
const PLAINTEXT_CANONICAL_LIFT_PROOF_MISSING_STATUS: &str = "PlaintextCanonicalLiftProofMissing";
const AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS: &str =
    "AggregateDerivationFullVerificationPreconditionNotBound";
// Soundness-bit budget. 64 challenge bits per check x 2 checks = 128-bit challenge entropy.
// Rejection-sampling (limit 64 attempts) costs a 6-bit-per-check grinding discount.
const SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK: u64 = 64;
const BRIDGE_SHARED_WITNESS_CHECK_COUNT: usize = 2;
const BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT: usize = 64;
const SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK: u64 = 6;
const BRIDGE_SHARED_WITNESS_CHALLENGE_ENTROPY_BITS: u64 =
    SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
// The batch-encoding relation mod 65537 (PLAINTEXT_MODULUS) is the soundness bottleneck;
// its 32-bit unadjusted floor lands at the 20-bit effective binding floor after grinding.
const BRIDGE_SHARED_WITNESS_WEAKEST_RELATION_MODULUS: u64 = PLAINTEXT_MODULUS;
const BRIDGE_SHARED_WITNESS_UNADJUSTED_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR: u64 = 32;
const BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR: u64 = 20;
const BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT: u64 = 2;

mod boundedness;
mod dimensions;
mod evaluation;
mod generation;
mod shared_witness;
mod statement;
mod target_contract;
mod validation;
mod verification;

#[cfg(test)]
mod tests;

use evaluation::evaluate_aggregate_bridge_relation;
use generation::generate_aggregate_bridge_encryption;
use verification::verify_aggregate_bridge_encryption;

pub(crate) fn generate_aggregate_bridge_encryption_from_command_request(request: &Value) -> Value {
    match generate_aggregate_bridge_encryption(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "generateAggregateBridgeEncryption",
            vec![structural_refusal(error.message, None)],
        ),
    }
}

pub(crate) fn verify_aggregate_bridge_encryption_from_command_request(request: &Value) -> Value {
    match verify_aggregate_bridge_encryption(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "verifyAggregateBridgeEncryption",
            vec![structural_refusal(error.message, None)],
        ),
    }
}

pub(crate) fn evaluate_aggregate_bridge_relation_from_command_request(request: &Value) -> Value {
    match evaluate_aggregate_bridge_relation(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "evaluateAggregateBridgeRelation",
            vec![structural_refusal(error.message, None)],
        ),
    }
}
