use serde_json::{Map, Value, json};

use crate::{
    ballot_privacy::component::{
        ParsedSparseComponentProofStatement, derive_share_commitment_message_matrix,
        derive_share_commitment_randomness_matrix,
    },
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
    BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT, SHARE_COMMITMENT_MODULUS,
};
use super::{
    PolynomialRing, PolynomialVector, SHARE_COMMITMENT_MODULE_DEGREE, SHARE_COMMITMENT_MODULE_RANK,
    SHARE_COMMITMENT_OPENING_DIMENSION, check_aggregate_derivation_witness_relation,
    is_protocol_hash, required_json_field, required_string_field,
    sparse_matrix_from_sparse_component_statement, string_field, structural_refusal,
    structural_rejection, verify_aggregate_derivation_proof_from_command_request,
    verify_aggregate_derivation_relation_subproof_for_component,
};

const BRIDGE_PROOF_PROFILE_ID: &str = "EncryptedAggregateBridge-v1";
const BRIDGE_PROOF_BACKEND: &str = "SealedLatticeBridgeRelation";
const BGV_ENCRYPTION_PROOF_SUBRELATION: &str =
    "SealedLatticePassiveCollectiveCiphertextEquationRelation";
const BGV_ENCRYPTION_KEY_MATERIAL_KIND: &str = "passive-transcript-derived-collective-public-key";
const DEVELOPMENT_KEY_ONLY: bool = false;
const THRESHOLD_DECRYPTABLE: bool = true;
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
const PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS: &str =
    "ProofFriendlyPlaintextCoefficientBindingRelationChecked";
const PROOF_FRIENDLY_PLAINTEXT_LIFT_BINDING_STATUS: &str =
    "ProofFriendlyPlaintextCoefficientLiftBindingChecked";
const PLAINTEXT_COEFFICIENT_BINDING_SCHEME: &str =
    "ChunkedAdditiveModuleSisPlaintextCoefficientCommitment";
const PLAINTEXT_BINDING_OPENING_INFINITY_NORM_BOUND: i64 = 1_024;
const DECRYPTABLE_BGV_CIPHERTEXT_CONVENTION_STATUS: &str = "DecryptableBgvCiphertextConvention";
const TARGET_THRESHOLD_DECRYPTABILITY_CERTIFIED_STATUS: &str =
    "TargetThresholdDecryptabilityCompatibilityCertified";
const BRIDGE_CLAIM_MISSING_STATUS: &str = "BridgeProofClaimClosureMissing";
const BRIDGE_CLAIM_VERIFIED_STATUS: &str = "BridgeProofClaimClosureVerified";
const BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG: &str = "fresh-csprng";
const BRIDGE_RANDOMNESS_SOURCE_DEVELOPMENT_DETERMINISTIC: &str =
    "development-deterministic-fixture";
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsProfileFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537IntegerLiftedInverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForEncryptedAggregateBridgeClaim";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForAggregateBridgeClaimClosure";
const PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS: &str = "PlaintextCanonicalLiftProofChecked";
const AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS: &str =
    "AggregateDerivationFullVerificationPreconditionNotBound";
const AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS: &str =
    "AggregateDerivationFullVerificationChecked";
// Soundness-bit budget. The Fiat-Shamir challenge is sampled directly into the weakest
// active relation's 46-bit effective modulus, so the global bridge binding budget is not
// derived from the two-prime batch-lift product. Five checks leave a 159-bit floor after
// rejection-attempt grinding, a 2^32 Fiat-Shamir query bound, and the full-matrix union bound.
const BRIDGE_SHARED_WITNESS_CHECK_COUNT: usize = 5;
const BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT: usize = 64;
const SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK: u64 = 6;
const BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI: [u64; 2] = [DATA_PRIMES[0], DATA_PRIMES[1]];
const BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT: u128 =
    (DATA_PRIMES[0] as u128) * (DATA_PRIMES[1] as u128);
const BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT_BITS_FLOOR: u64 = 93;
const SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK: u64 = BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK;
const BRIDGE_WEAKEST_ACTIVE_RELATION: &str = "AggregateReductionFieldRelation";
const BRIDGE_WEAKEST_ACTIVE_RELATION_EFFECTIVE_MODULUS: u128 =
    1_u128 << BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK;
const BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK: u64 = 46;
const BRIDGE_WEAKEST_ACTIVE_RELATION_MODEL: &str =
    "aggregate-proof-ring-effective-binding-floor-v1";
const BRIDGE_FULL_MATRIX_UNION_BOUND_BITS: u64 = 9;
const BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS: u64 = 32;
const BRIDGE_PROOF_SYSTEM_LOSS_BITS: u64 = 0;
const BRIDGE_CHALLENGE_BIAS_BITS: u64 = 0;
const BRIDGE_CHALLENGE_BIAS_ACCOUNTING_MODEL: &str =
    "direct-rejection-sampling-into-effective-weakest-relation-modulus-v1";
const BRIDGE_RANDOM_ORACLE_ACCOUNTING_MODEL: &str =
    "classical-random-oracle-query-loss-with-explicit-bound-v1";
const BRIDGE_QROM_ACCOUNTING_STATUS: &str = "QromAccountingNotProvidedForHandoff";
const BRIDGE_TARGET_BINDING_SOUNDNESS_BITS: u64 = 128;
const BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS: u64 =
    SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK
        * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
const BRIDGE_SHARED_WITNESS_RAW_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR: u64 =
    BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK * BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64;
const BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR: u64 =
    BRIDGE_SHARED_WITNESS_RAW_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR
        - BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS
        - BRIDGE_FULL_MATRIX_UNION_BOUND_BITS
        - BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS
        - BRIDGE_PROOF_SYSTEM_LOSS_BITS
        - BRIDGE_CHALLENGE_BIAS_BITS;
const BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_BELOW_TARGET: bool =
    BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR
        < BRIDGE_TARGET_BINDING_SOUNDNESS_BITS;
const BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT: u64 = 2;

#[derive(Clone, Copy)]
struct BridgeClaimStatus {
    claim_bearing_bridge_encryption: bool,
    scoped_bridge_relation_closure: bool,
    bridge_claim_closure_verified: bool,
    bridge_claim_verification_status: &'static str,
}

fn bridge_claim_status(
    aggregate_derivation_verification_scope: &str,
    prover_randomness_source: &str,
    encryption_randomness_seed_source: &str,
) -> BridgeClaimStatus {
    let bridge_claim_verified = aggregate_derivation_verification_scope
        == AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS
        && prover_randomness_source == BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG
        && encryption_randomness_seed_source == BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG
        && !BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_BELOW_TARGET;

    if bridge_claim_verified {
        return BridgeClaimStatus {
            claim_bearing_bridge_encryption: true,
            scoped_bridge_relation_closure: true,
            bridge_claim_closure_verified: true,
            bridge_claim_verification_status: BRIDGE_CLAIM_VERIFIED_STATUS,
        };
    }

    BridgeClaimStatus {
        claim_bearing_bridge_encryption: false,
        scoped_bridge_relation_closure: false,
        bridge_claim_closure_verified: false,
        bridge_claim_verification_status: BRIDGE_CLAIM_MISSING_STATUS,
    }
}

fn bridge_batch_integer_lift_proof_modulus_product_decimal() -> String {
    BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT.to_string()
}

fn bridge_weakest_active_relation_effective_modulus_decimal() -> String {
    BRIDGE_WEAKEST_ACTIVE_RELATION_EFFECTIVE_MODULUS.to_string()
}

mod boundedness;
mod dimensions;
mod evaluation;
mod generation;
mod plaintext_binding;
mod plaintext_lift;
mod plaintext_root_relation;
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

fn aggregate_derivation_verification_scope_from_request(
    request: &Value,
    component: &Value,
    operation: &str,
) -> CanonicalResult<&'static str> {
    let scope = requested_aggregate_derivation_verification_scope(request, operation)?;
    if scope == AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS {
        return Ok(scope);
    }

    let mut verification_request = json!({
        "component": component,
        "countedBallotPackages": request["countedBallotPackages"],
        "closeRecord": request["closeRecord"],
        "contributorActionContext": request["contributorActionContext"],
    });
    if let Some(casual_micro_roster_acknowledged) = request.get("casualMicroRosterAcknowledged") {
        verification_request["casualMicroRosterAcknowledged"] =
            casual_micro_roster_acknowledged.clone();
    }
    let verification =
        verify_aggregate_derivation_proof_from_command_request(&verification_request);
    if verification.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "{operation} aggregate-derivation precondition verification failed: {}",
                verification
            ),
        ));
    }
    let labels = verification
        .get("statusLabels")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "aggregate-derivation verification did not return status labels",
            )
        })?;
    if !labels
        .iter()
        .any(|label| label.as_str() == Some("AggregateDerivationRelationChecked"))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregate-derivation verification did not check the relation",
        ));
    }
    if !labels
        .iter()
        .any(|label| label.as_str() == Some("AggregateDerivationFullVerificationChecked"))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregate-derivation verification did not bind the full close/counting context",
        ));
    }
    if !labels
        .iter()
        .any(|label| label.as_str() == Some("AggregateDerivationProofVerified"))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregate-derivation verification did not accept the scoped aggregate proof",
        ));
    }

    Ok(scope)
}

fn requested_aggregate_derivation_verification_scope(
    request: &Value,
    operation: &str,
) -> CanonicalResult<&'static str> {
    let has_counted_ballot_packages = request.get("countedBallotPackages").is_some();
    let has_close_record = request.get("closeRecord").is_some();
    let has_contributor_action_context = request.get("contributorActionContext").is_some();
    let has_full_verification_context =
        has_counted_ballot_packages || has_close_record || has_contributor_action_context;
    if !has_full_verification_context {
        return Ok(AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS);
    }
    if !has_counted_ballot_packages || !has_close_record || !has_contributor_action_context {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{operation} requires countedBallotPackages, closeRecord, and contributorActionContext together to bind full aggregate-derivation verification"
            ),
        ));
    }

    Ok(AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS)
}

fn validate_aggregate_derivation_verification_scope(
    aggregate_derivation_verification_scope: &str,
) -> CanonicalResult<()> {
    if aggregate_derivation_verification_scope
        != AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS
        && aggregate_derivation_verification_scope
            != AGGREGATE_DERIVATION_FULL_VERIFICATION_CHECKED_STATUS
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregate-derivation verification scope is not supported by the bridge profile",
        ));
    }

    Ok(())
}
