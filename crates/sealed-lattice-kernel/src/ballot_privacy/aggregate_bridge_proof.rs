use serde_json::{Map, Value, json};

use crate::{
    ballot_privacy::component::ParsedSparseComponentProofStatement,
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, derive_protocol_hash, hash512, to_hex},
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
const BGV_ENCRYPTION_PROOF_SUBRELATION: &str = "SealedLatticeDevelopmentCiphertextEquationRelation";
const BRIDGE_PROOF_PENDING_STATUS: &str = "BridgeProofBackendPending";
const SHARED_WITNESS_BINDING_PENDING_STATUS: &str = "SharedWitnessBindingProofPending";
const AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS: &str =
    "AggregateToPlaintextBindingProofPending";
const BGV_ENCRYPTION_PROOF_PENDING_STATUS: &str = "BoundedEncryptionProofPending";
const RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS: &str = "RnsCrtConsistencyProofPending";
const BRIDGE_PROOF_CHECKED_STATUS: &str = "BridgeProofRelationChecked";
const SHARED_WITNESS_BINDING_CHECKED_STATUS: &str = "SharedWitnessBindingRelationChecked";
const AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS: &str =
    "AggregateToPlaintextBindingProofChecked";
const BGV_ENCRYPTION_PROOF_CHECKED_STATUS: &str = "BgvCiphertextEquationChecked";
const RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS: &str = "RnsCrtConsistencyRelationChecked";
const SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS: &str =
    "SharedWitnessZeroKnowledgeResponseDistributionChecked";
const BGV_RANDOMNESS_BOUND_PROOF_MISSING_STATUS: &str = "BgvRandomnessBoundProofMissing";
const BGV_RANDOMNESS_BOUND_PROOF_STATUS: &str = "BgvRandomnessErrorSupportPolynomialChecked";
const BRIDGE_CLAIM_CLOSURE_STATUS: &str = "BridgeProofClaimClosureMissing";
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsProfileFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537InverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForEncryptedAggregateBridgeClaim";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForAggregateBridgeClaimClosure";
const PLAINTEXT_ROOT_PROOF_BINDING_CHECKED_STATUS: &str = "PlaintextRootProofBindingChecked";
const SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK: u64 = 64;
const BRIDGE_SHARED_WITNESS_CHECK_COUNT: usize = 2;
const BRIDGE_SHARED_WITNESS_SOUNDNESS_BITS: u64 =
    SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
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
