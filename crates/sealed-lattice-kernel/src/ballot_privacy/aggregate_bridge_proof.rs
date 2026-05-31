use serde_json::{Map, Value, json};

use crate::{
    ballot_privacy::component::ParsedSparseComponentProofStatement,
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
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
// Deliberate proof gaps for this implementation stage (not bugs): bridge
// ciphertexts use the decryptable BGV convention, but target-threshold
// decryption and final bridge acceptance are not certified by this proof.
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
const DECRYPTABLE_BGV_CIPHERTEXT_CONVENTION_STATUS: &str = "DecryptableBgvCiphertextConvention";
const TARGET_THRESHOLD_DECRYPTION_PROTOCOL_PENDING_STATUS: &str =
    "TargetThresholdDecryptionProtocolPending";
const BRIDGE_CLAIM_CLOSURE_STATUS: &str = "BridgeProofClaimClosureMissing";
const BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG: &str = "fresh-csprng";
const BRIDGE_RANDOMNESS_SOURCE_DEVELOPMENT_DETERMINISTIC: &str =
    "development-deterministic-fixture";
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsProfileFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForEncryptedAggregateBridgeClaim";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForAggregateBridgeClaimClosure";
const PLAINTEXT_CANONICAL_LIFT_PROOF_MISSING_STATUS: &str = "PlaintextCanonicalLiftProofMissing";
const AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS: &str =
    "AggregateDerivationFullVerificationPreconditionNotBound";
// Soundness-bit budget. 64 challenge bits per check x 2 checks = 128-bit challenge entropy.
// Rejection-sampling (limit 64 attempts) costs a 6-bit-per-check grinding discount.
// The weakest checked relation is the integer-lifted plaintext/batch link reduced modulo the
// first two BGV data primes, not the 65537 plaintext field.
const SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK: u64 = 64;
const BRIDGE_SHARED_WITNESS_CHECK_COUNT: usize = 2;
const BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT: usize = 64;
const SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK: u64 = 6;
const BRIDGE_SHARED_WITNESS_CHALLENGE_ENTROPY_BITS: u64 =
    SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
const BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI: [u64; 2] = [DATA_PRIMES[0], DATA_PRIMES[1]];
const BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT: u128 =
    (DATA_PRIMES[0] as u128) * (DATA_PRIMES[1] as u128);
const BRIDGE_SHARED_WITNESS_PROOF_MODULUS_PRODUCT_BITS_FLOOR: u64 = 93;
const BRIDGE_FULL_MATRIX_UNION_BOUND_BITS: u64 = 9;
const BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS: u64 = 0;
const BRIDGE_PROOF_SYSTEM_LOSS_BITS: u64 = 0;
const BRIDGE_CHALLENGE_BIAS_BITS: u64 = 0;
const BRIDGE_TARGET_BINDING_SOUNDNESS_BITS: u64 = 128;
const BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS: u64 =
    SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK
        * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
const BRIDGE_SHARED_WITNESS_UNADJUSTED_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR: u64 =
    BRIDGE_SHARED_WITNESS_PROOF_MODULUS_PRODUCT_BITS_FLOOR
        * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
const BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR: u64 =
    BRIDGE_SHARED_WITNESS_UNADJUSTED_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR
        - BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS
        - BRIDGE_FULL_MATRIX_UNION_BOUND_BITS
        - BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS
        - BRIDGE_PROOF_SYSTEM_LOSS_BITS
        - BRIDGE_CHALLENGE_BIAS_BITS;
const BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_BELOW_TARGET: bool =
    BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR
        < BRIDGE_TARGET_BINDING_SOUNDNESS_BITS;
const BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT: u64 = 2;

fn bridge_batch_integer_lift_proof_modulus_product_decimal() -> String {
    BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT.to_string()
}

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

pub(crate) fn verify_aggregate_bridge_encryption_for_evaluator(
    request: &Value,
) -> CanonicalResult<Value> {
    verify_aggregate_bridge_encryption(request)
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
