use super::boundedness::{
    BridgeBgvRandomnessBoundCommitmentInput, bridge_bgv_randomness_bound_commitment,
    bridge_bgv_randomness_bound_commitment_digest, validate_bridge_bgv_randomness_bound_commitment,
};
use super::validation::{
    read_u64_object_field, read_usize_object_field, reject_forbidden_public_bridge_fields,
    require_equal_string, require_equal_u64,
};
use super::*;
use num_bigint::{BigInt, Sign};
use num_traits::{One, ToPrimitive};

pub(super) struct BridgeSharedWitnessProverInput<'value> {
    pub(super) setup_package: &'value Value,
    pub(super) bridge_encryption: &'value Value,
    pub(super) proof_input: &'value Value,
    pub(super) bridge_proof_statement_digest: &'value str,
    pub(super) contributor_identity: &'value str,
    pub(super) aggregate_derivation_statement_digest: &'value str,
    pub(super) aggregate_integer_share_vector: &'value [u64],
    pub(super) aggregate_opening_randomness: &'value [i64],
    pub(super) aggregate_reduced_coordinates: &'value [u64],
    pub(super) aggregate_quotient_vector: &'value [u64],
    pub(super) trace: &'value crate::bgv::commands::M9BridgeCiphertextRelationTrace,
    pub(super) prover_randomness_hex: &'value str,
}

pub(super) struct BridgeSharedWitnessProofVerification {
    pub(super) challenge_hex: String,
    pub(super) shared_response_scalar_count: u64,
}

struct BridgeAggregateRelationCommitmentContext {
    parsed_statement: ParsedSparseComponentProofStatement,
    target_vector: PolynomialVector,
}

const BRIDGE_SHARED_WITNESS_PROOF_MODEL: &str =
    "fiat-shamir-linear-shared-response-rejection-sampled-v1";
const BRIDGE_SHARED_WITNESS_RESPONSE_ENCODING: &str = "signed-i256-little-endian-hex-v1";
const BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_MODEL: &str =
    "uniform-240-bit-mask-common-output-rejection-sampled-v1";
const BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_STATUS: &str =
    "SharedWitnessResponseDistributionBoundsChecked";
const BRIDGE_SHARED_WITNESS_RESPONSE_DISTRIBUTION_STATUS: &str =
    "SharedWitnessResponseDistributionRejectionSampled";
const BRIDGE_SHARED_WITNESS_MASK_BIT_LENGTH: usize = 240;
const BRIDGE_SHARED_WITNESS_RESPONSE_REJECTION_SLACK_BIT_LENGTH: usize = 112;
const BRIDGE_SHARED_WITNESS_MASK_RANDOM_BIT_LENGTH: usize =
    BRIDGE_SHARED_WITNESS_MASK_BIT_LENGTH + 1;
const BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH: usize = 32;
const BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE: usize = 31;
const BRIDGE_SHARED_WITNESS_MASK_COORDINATES_PER_DIGEST: usize = 2;
const BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT: usize = 64;

pub(super) fn generate_bridge_shared_witness_proof(
    input: BridgeSharedWitnessProverInput<'_>,
) -> CanonicalResult<Value> {
    let aggregate_integer_witness = u64_slice_to_bigint_vec(input.aggregate_integer_share_vector);
    let aggregate_opening_witness = i64_slice_to_bigint_vec(input.aggregate_opening_randomness);
    let aggregate_reduced_witness = u64_slice_to_bigint_vec(input.aggregate_reduced_coordinates);
    let aggregate_quotient_witness = u64_slice_to_bigint_vec(input.aggregate_quotient_vector);
    let plaintext_coefficient_witness =
        u64_slice_to_bigint_vec(&input.trace.plaintext_coefficients_mod_plaintext);
    let randomizer_witness =
        i64_slice_to_bigint_vec(&input.trace.encryption_randomness_coefficients);
    let perturbation_zero_witness =
        i64_slice_to_bigint_vec(&input.trace.encryption_error_zero_coefficients);
    let perturbation_one_witness =
        i64_slice_to_bigint_vec(&input.trace.encryption_error_one_coefficients);
    let aggregate_relation_context =
        bridge_aggregate_relation_commitment_context(input.proof_input)?;
    let mut checks = Vec::with_capacity(BRIDGE_SHARED_WITNESS_CHECK_COUNT);
    let mut challenge_hex = String::new();
    let mask_absolute_bound = bridge_shared_witness_mask_absolute_bound_exclusive();
    let response_shift_bound = bridge_shared_witness_response_shift_bound_exclusive();

    for check_index in 0..BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        let mut accepted_check = None;
        for rejection_attempt_index in 0..BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT {
            let aggregate_integer_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "aggregate-share",
                aggregate_integer_witness.len(),
                &mask_absolute_bound,
            );
            let aggregate_opening_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "aggregate-opening",
                aggregate_opening_witness.len(),
                &mask_absolute_bound,
            );
            let aggregate_reduced_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "aggregate-reduced",
                aggregate_reduced_witness.len(),
                &mask_absolute_bound,
            );
            let aggregate_quotient_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "aggregate-quotient",
                aggregate_quotient_witness.len(),
                &mask_absolute_bound,
            );
            let plaintext_coefficient_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "batch-coefficient",
                plaintext_coefficient_witness.len(),
                &mask_absolute_bound,
            );
            let randomizer_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "cipher-randomizer",
                randomizer_witness.len(),
                &mask_absolute_bound,
            );
            let perturbation_zero_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "bounded-perturbation-zero",
                perturbation_zero_witness.len(),
                &mask_absolute_bound,
            );
            let perturbation_one_mask = sample_bridge_mask_vector(
                input.bridge_proof_statement_digest,
                input.prover_randomness_hex,
                check_index,
                rejection_attempt_index,
                "bounded-perturbation-one",
                perturbation_one_witness.len(),
                &mask_absolute_bound,
            );
            let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
                &aggregate_relation_context,
                &aggregate_integer_mask,
                &aggregate_opening_mask,
                &aggregate_reduced_mask,
                &aggregate_quotient_mask,
                0,
            )?;
            let batch_commitment_digest =
                crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                    &aggregate_reduced_mask,
                    &plaintext_coefficient_mask,
                )?;
            let bgv_commitment_digest =
                crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                    input.setup_package,
                    input.contributor_identity,
                    input.aggregate_derivation_statement_digest,
                    input.bridge_encryption,
                    0,
                    &plaintext_coefficient_mask,
                    &randomizer_mask,
                    &perturbation_zero_mask,
                    &perturbation_one_mask,
                )?;
            let bgv_randomness_bound_commitment =
                bridge_bgv_randomness_bound_commitment(BridgeBgvRandomnessBoundCommitmentInput {
                    bridge_proof_statement_digest: input.bridge_proof_statement_digest,
                    check_index,
                    randomizer_masks: &randomizer_mask,
                    randomizer_witness: &randomizer_witness,
                    perturbation_zero_masks: &perturbation_zero_mask,
                    perturbation_zero_witness: &perturbation_zero_witness,
                    perturbation_one_masks: &perturbation_one_mask,
                    perturbation_one_witness: &perturbation_one_witness,
                })?;
            let bgv_randomness_bound_commitment_digest =
                bridge_bgv_randomness_bound_commitment_digest(&bgv_randomness_bound_commitment)?;
            let challenge_scalar = bridge_shared_witness_challenge_scalar(
                input.bridge_proof_statement_digest,
                check_index,
                &aggregate_commitment_digest,
                &batch_commitment_digest,
                &bgv_commitment_digest,
                &bgv_randomness_bound_commitment_digest,
            );
            let challenge = BigInt::from(challenge_scalar);
            let aggregate_share_response = response_vector(
                &aggregate_integer_mask,
                &challenge,
                &response_shift_bound,
                &aggregate_integer_witness,
            )?;
            let aggregate_opening_response = response_vector(
                &aggregate_opening_mask,
                &challenge,
                &response_shift_bound,
                &aggregate_opening_witness,
            )?;
            let aggregate_reduced_response = response_vector(
                &aggregate_reduced_mask,
                &challenge,
                &response_shift_bound,
                &aggregate_reduced_witness,
            )?;
            let aggregate_quotient_response = response_vector(
                &aggregate_quotient_mask,
                &challenge,
                &response_shift_bound,
                &aggregate_quotient_witness,
            )?;
            let batch_coefficient_response = response_vector(
                &plaintext_coefficient_mask,
                &challenge,
                &response_shift_bound,
                &plaintext_coefficient_witness,
            )?;
            let cipher_randomizer_response = response_vector(
                &randomizer_mask,
                &challenge,
                &response_shift_bound,
                &randomizer_witness,
            )?;
            let bounded_perturbation_zero_response = response_vector(
                &perturbation_zero_mask,
                &challenge,
                &response_shift_bound,
                &perturbation_zero_witness,
            )?;
            let bounded_perturbation_one_response = response_vector(
                &perturbation_one_mask,
                &challenge,
                &response_shift_bound,
                &perturbation_one_witness,
            )?;
            if validate_all_response_vector_bounds(
                &aggregate_share_response,
                &aggregate_opening_response,
                &aggregate_reduced_response,
                &aggregate_quotient_response,
                &batch_coefficient_response,
                &cipher_randomizer_response,
                &bounded_perturbation_zero_response,
                &bounded_perturbation_one_response,
            )
            .is_err()
            {
                continue;
            }
            let check_challenge_hex = bridge_challenge_hex(challenge_scalar);
            let check = json!({
                "checkIndex": check_index,
                "rejectionAttemptIndex": rejection_attempt_index,
                "challengeScalarHex": check_challenge_hex,
                "aggregateRelationCommitmentDigest": aggregate_commitment_digest,
                "batchEncodingCommitmentDigest": batch_commitment_digest,
                "bgvCiphertextCommitmentDigest": bgv_commitment_digest,
                "bgvRandomnessBoundCommitment": bgv_randomness_bound_commitment,
                "bgvRandomnessBoundCommitmentDigest": bgv_randomness_bound_commitment_digest,
                "aggregateShareResponseHex": signed_i256_vector_hex(&aggregate_share_response)?,
                "aggregateOpeningResponseHex": signed_i256_vector_hex(&aggregate_opening_response)?,
                "aggregateReducedResponseHex": signed_i256_vector_hex(&aggregate_reduced_response)?,
                "aggregateQuotientResponseHex": signed_i256_vector_hex(&aggregate_quotient_response)?,
                "batchCoefficientResponseHex": signed_i256_vector_hex(&batch_coefficient_response)?,
                "cipherRandomizerResponseHex": signed_i256_vector_hex(&cipher_randomizer_response)?,
                "boundedPerturbationZeroResponseHex": signed_i256_vector_hex(&bounded_perturbation_zero_response)?,
                "boundedPerturbationOneResponseHex": signed_i256_vector_hex(&bounded_perturbation_one_response)?,
            });
            challenge_hex.push_str(&check_challenge_hex);
            accepted_check = Some(check);
            break;
        }
        let check = accepted_check.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge shared-witness rejection sampler did not find an in-bound response transcript",
            )
        })?;
        checks.push(check);
    }

    let shared_response_scalar_count = shared_response_scalar_count(
        aggregate_integer_witness.len(),
        aggregate_opening_witness.len(),
        aggregate_reduced_witness.len(),
        aggregate_quotient_witness.len(),
    )?;

    Ok(json!({
        "objectType": "AggregateBridgeSharedWitnessProof",
        "objectVersion": 1,
        "proofModel": BRIDGE_SHARED_WITNESS_PROOF_MODEL,
        "bridgeProofStatementDigest": input.bridge_proof_statement_digest,
        "relationCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT,
        "challengeHex": challenge_hex,
        "sharedResponseScalarCount": shared_response_scalar_count,
        "sameHiddenAggregateCoordinatesLinked": true,
        "responseBoundModel": BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_MODEL,
        "maskAbsoluteBoundExclusive": bridge_shared_witness_mask_absolute_bound_exclusive_decimal(),
        "responseAbsoluteBoundExclusive": bridge_shared_witness_response_absolute_bound_exclusive_decimal(),
        "responseShiftBoundExclusive": bridge_shared_witness_response_shift_bound_exclusive_decimal(),
        "responseBoundStatus": BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_STATUS,
        "responseDistributionStatus": BRIDGE_SHARED_WITNESS_RESPONSE_DISTRIBUTION_STATUS,
        "rejectionAttemptLimit": BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT,
        "checks": checks,
        "responseEncoding": BRIDGE_SHARED_WITNESS_RESPONSE_ENCODING,
    }))
}

pub(super) fn bridge_shared_witness_proof_digest(
    shared_witness_proof: &Value,
) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-shared-witness-proof-digest-v1",
            "bridgeSharedWitnessProof": shared_witness_proof,
        }),
    )
}

pub(super) fn bridge_shared_witness_zero_knowledge_status(
    bridge_proof_statement_digest: &str,
    shared_witness_proof_digest: &str,
) -> Value {
    json!({
        "objectType": "AggregateBridgeSharedWitnessZeroKnowledgeStatus",
        "objectVersion": 1,
        "statusModel": "shared-witness-zero-knowledge-response-distribution-status-v1",
        "bridgeProofStatementDigest": bridge_proof_statement_digest,
        "bridgeSharedWitnessProofDigest": shared_witness_proof_digest,
        "responseBoundModel": BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_MODEL,
        "maskAbsoluteBoundExclusive": bridge_shared_witness_mask_absolute_bound_exclusive_decimal(),
        "responseAbsoluteBoundExclusive": bridge_shared_witness_response_absolute_bound_exclusive_decimal(),
        "responseShiftBoundExclusive": bridge_shared_witness_response_shift_bound_exclusive_decimal(),
        "responseBoundStatus": BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_STATUS,
        "responseDistributionStatus": BRIDGE_SHARED_WITNESS_RESPONSE_DISTRIBUTION_STATUS,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "simulatorProofChecked": true,
        "bridgeClaimClosureAccepted": false,
    })
}

pub(super) fn bridge_shared_witness_zero_knowledge_status_digest(
    status_evidence: &Value,
) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-shared-witness-zero-knowledge-status-v1",
            "sharedWitnessZeroKnowledgeStatusEvidence": status_evidence,
        }),
    )
}

pub(super) fn validate_bridge_shared_witness_zero_knowledge_status(
    proof_value: &Value,
    bridge_proof_statement_digest: &str,
    shared_witness_proof_digest: &str,
) -> CanonicalResult<String> {
    let status_evidence = required_json_field(
        proof_value,
        "sharedWitnessZeroKnowledgeStatusEvidence",
        "bridgeProof",
    )?;
    reject_forbidden_public_bridge_fields(
        status_evidence,
        "bridgeProof.sharedWitnessZeroKnowledgeStatusEvidence",
    )?;
    let expected_status = bridge_shared_witness_zero_knowledge_status(
        bridge_proof_statement_digest,
        shared_witness_proof_digest,
    );
    if status_evidence != &expected_status {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge shared-witness zero-knowledge status evidence does not match the proof-bound public inputs",
        ));
    }

    let status_digest = bridge_shared_witness_zero_knowledge_status_digest(status_evidence)?;
    require_equal_string(
        proof_value,
        "sharedWitnessZeroKnowledgeStatusDigest",
        &status_digest,
        "shared-witness zero-knowledge status digest",
    )?;

    Ok(status_digest)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_bridge_shared_witness_proof(
    proof_value: &Value,
    component: &Value,
    setup_package: &Value,
    bridge_encryption: &Value,
    bridge_proof_statement_digest: &str,
    contributor_identity: &str,
    aggregate_derivation_statement_digest: &str,
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<BridgeSharedWitnessProofVerification> {
    let proof_input = required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let shared_proof = required_json_field(proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
    reject_forbidden_public_bridge_fields(shared_proof, "bridgeProof.bridgeSharedWitnessProof")?;
    if string_field(shared_proof, "objectType") != Some("AggregateBridgeSharedWitnessProof")
        || read_u64_object_field(shared_proof, "objectVersion", "bridgeSharedWitnessProof")? != 1
        || string_field(shared_proof, "proofModel") != Some(BRIDGE_SHARED_WITNESS_PROOF_MODEL)
        || string_field(shared_proof, "responseEncoding")
            != Some(BRIDGE_SHARED_WITNESS_RESPONSE_ENCODING)
        || string_field(shared_proof, "responseBoundModel")
            != Some(BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_MODEL)
        || string_field(shared_proof, "responseBoundStatus")
            != Some(BRIDGE_SHARED_WITNESS_RESPONSE_BOUND_STATUS)
        || string_field(shared_proof, "responseDistributionStatus")
            != Some(BRIDGE_SHARED_WITNESS_RESPONSE_DISTRIBUTION_STATUS)
        || shared_proof
            .get("sameHiddenAggregateCoordinatesLinked")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge shared-witness proof shell is not the supported verifier relation",
        ));
    }
    require_equal_string(
        shared_proof,
        "bridgeProofStatementDigest",
        bridge_proof_statement_digest,
        "shared-witness proof statement digest",
    )?;
    require_equal_string(
        shared_proof,
        "maskAbsoluteBoundExclusive",
        &bridge_shared_witness_mask_absolute_bound_exclusive_decimal(),
        "shared-witness mask absolute bound",
    )?;
    require_equal_string(
        shared_proof,
        "responseAbsoluteBoundExclusive",
        &bridge_shared_witness_response_absolute_bound_exclusive_decimal(),
        "shared-witness response absolute bound",
    )?;
    require_equal_string(
        shared_proof,
        "responseShiftBoundExclusive",
        &bridge_shared_witness_response_shift_bound_exclusive_decimal(),
        "shared-witness response shift bound",
    )?;
    require_equal_u64(
        shared_proof,
        "rejectionAttemptLimit",
        BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT as u64,
        "shared-witness rejection attempt limit",
    )?;
    let relation_check_count = read_usize_object_field(
        shared_proof,
        "relationCheckCount",
        "bridgeSharedWitnessProof",
    )?;
    if relation_check_count != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof has an unsupported check count",
        ));
    }
    let expected_aggregate_count =
        usize::try_from(aggregate_reduced_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate reduced coordinate count does not fit usize",
            )
        })?;
    let expected_quotient_count =
        usize::try_from(aggregate_quotient_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate quotient coordinate count does not fit usize",
            )
        })?;
    let expected_shared_response_scalar_count = shared_response_scalar_count(
        expected_aggregate_count,
        SHARE_COMMITMENT_OPENING_DIMENSION,
        expected_aggregate_count,
        expected_quotient_count,
    )?;
    require_equal_u64(
        shared_proof,
        "sharedResponseScalarCount",
        expected_shared_response_scalar_count,
        "shared-witness proof scalar count",
    )?;
    let checks = shared_proof
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bridgeSharedWitnessProof.checks must be an array",
            )
        })?;
    if checks.len() != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof check array has the wrong length",
        ));
    }
    let aggregate_relation_context = bridge_aggregate_relation_commitment_context(proof_input)?;
    let mut challenge_hex = String::new();
    for (check_index, check) in checks.iter().enumerate() {
        require_equal_u64(
            check,
            "checkIndex",
            check_index as u64,
            "shared-witness proof check index",
        )?;
        let rejection_attempt_index = read_usize_object_field(
            check,
            "rejectionAttemptIndex",
            "bridgeSharedWitnessProof.check",
        )?;
        if rejection_attempt_index >= BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge shared-witness rejection attempt index is outside the supported range",
            ));
        }
        let challenge_scalar_hex = required_string_field(
            check,
            "challengeScalarHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let challenge_scalar = parse_bridge_challenge_scalar(challenge_scalar_hex)?;
        let aggregate_share_response = read_signed_i256_hex_vector(
            check,
            "aggregateShareResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_opening_response = read_signed_i256_hex_vector(
            check,
            "aggregateOpeningResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_reduced_response = read_signed_i256_hex_vector(
            check,
            "aggregateReducedResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_quotient_response = read_signed_i256_hex_vector(
            check,
            "aggregateQuotientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let batch_coefficient_response = read_signed_i256_hex_vector(
            check,
            "batchCoefficientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let cipher_randomizer_response = read_signed_i256_hex_vector(
            check,
            "cipherRandomizerResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_zero_response = read_signed_i256_hex_vector(
            check,
            "boundedPerturbationZeroResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_one_response = read_signed_i256_hex_vector(
            check,
            "boundedPerturbationOneResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        validate_response_lengths(
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            &batch_coefficient_response,
            &cipher_randomizer_response,
            &bounded_perturbation_zero_response,
            &bounded_perturbation_one_response,
            expected_aggregate_count,
            expected_quotient_count,
        )?;
        let response_bound = bridge_shared_witness_response_absolute_bound_exclusive();
        for (role, responses) in [
            ("aggregate share", aggregate_share_response.as_slice()),
            ("aggregate opening", aggregate_opening_response.as_slice()),
            ("aggregate reduced", aggregate_reduced_response.as_slice()),
            ("aggregate quotient", aggregate_quotient_response.as_slice()),
            ("batch coefficient", batch_coefficient_response.as_slice()),
            ("cipher randomizer", cipher_randomizer_response.as_slice()),
            (
                "bounded perturbation zero",
                bounded_perturbation_zero_response.as_slice(),
            ),
            (
                "bounded perturbation one",
                bounded_perturbation_one_response.as_slice(),
            ),
        ] {
            validate_response_vector_bounds_with_bound(role, responses, &response_bound)?;
        }
        let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
            &aggregate_relation_context,
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            challenge_scalar,
        )?;
        let batch_commitment_digest =
            crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                &aggregate_reduced_response,
                &batch_coefficient_response,
            )?;
        let bgv_commitment_digest =
            crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                setup_package,
                contributor_identity,
                aggregate_derivation_statement_digest,
                bridge_encryption,
                challenge_scalar,
                &batch_coefficient_response,
                &cipher_randomizer_response,
                &bounded_perturbation_zero_response,
                &bounded_perturbation_one_response,
            )?;
        let bgv_randomness_bound_commitment_digest =
            validate_bridge_bgv_randomness_bound_commitment(
                check,
                bridge_proof_statement_digest,
                check_index,
                challenge_scalar,
                &cipher_randomizer_response,
                &bounded_perturbation_zero_response,
                &bounded_perturbation_one_response,
            )?;
        require_equal_string(
            check,
            "aggregateRelationCommitmentDigest",
            &aggregate_commitment_digest,
            "shared-witness aggregate relation commitment digest",
        )?;
        require_equal_string(
            check,
            "batchEncodingCommitmentDigest",
            &batch_commitment_digest,
            "shared-witness batch encoding commitment digest",
        )?;
        require_equal_string(
            check,
            "bgvCiphertextCommitmentDigest",
            &bgv_commitment_digest,
            "shared-witness BGV ciphertext commitment digest",
        )?;
        let recomputed_challenge_scalar = bridge_shared_witness_challenge_scalar(
            bridge_proof_statement_digest,
            check_index,
            &aggregate_commitment_digest,
            &batch_commitment_digest,
            &bgv_commitment_digest,
            &bgv_randomness_bound_commitment_digest,
        );
        if challenge_scalar != recomputed_challenge_scalar {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge shared-witness proof challenge does not match the Fiat-Shamir transcript",
            ));
        }
        challenge_hex.push_str(challenge_scalar_hex);
    }
    require_equal_string(
        shared_proof,
        "challengeHex",
        &challenge_hex,
        "shared-witness proof challenge transcript",
    )?;

    Ok(BridgeSharedWitnessProofVerification {
        challenge_hex,
        shared_response_scalar_count: expected_shared_response_scalar_count,
    })
}

fn bridge_aggregate_relation_commitment_context(
    proof_input: &Value,
) -> CanonicalResult<BridgeAggregateRelationCommitmentContext> {
    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parsed_statement = sparse_matrix_from_sparse_component_statement(proof_statement)
        .map_err(|error| CanonicalError::new(CanonicalErrorCode::InvalidFixture, error.message))?;
    let ring = parsed_statement.source_statement_matrix.ring();
    let target_vector =
        PolynomialVector::new(ring, parsed_statement.target_vector_coefficients.clone())?;

    Ok(BridgeAggregateRelationCommitmentContext {
        parsed_statement,
        target_vector,
    })
}

fn aggregate_relation_commitment_digest_from_responses(
    context: &BridgeAggregateRelationCommitmentContext,
    aggregate_share_response: &[BigInt],
    aggregate_opening_response: &[BigInt],
    aggregate_reduced_response: &[BigInt],
    aggregate_quotient_response: &[BigInt],
    challenge_scalar: u64,
) -> CanonicalResult<String> {
    let ring = context.parsed_statement.source_statement_matrix.ring();
    let modulus_bigint = BigInt::from(ring.modulus());
    let response_entries = aggregate_share_response
        .iter()
        .chain(aggregate_opening_response.iter())
        .chain(aggregate_reduced_response.iter())
        .chain(aggregate_quotient_response.iter())
        .map(|response| constant_response_polynomial(response, ring.degree(), &modulus_bigint))
        .collect::<Vec<_>>();
    let response_vector = PolynomialVector::new(ring, response_entries)?;
    let response_image = context
        .parsed_statement
        .source_statement_matrix
        .multiply_vector(&response_vector)?;
    let challenge_residue =
        u64::try_from(u128::from(challenge_scalar) % u128::from(ring.modulus())).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge challenge residue does not fit u64",
            )
        })?;
    let scaled_target_entries = context
        .target_vector
        .entries()
        .iter()
        .map(|entry| ring.scale(challenge_residue, entry))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let scaled_target = PolynomialVector::new(ring, scaled_target_entries)?;
    let commitment_vector = response_image.add(&scaled_target)?;

    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-relation-commitment-v1",
            "commitmentVector": canonical_polynomial_vector_response(commitment_vector.entries()),
        }),
    )
}

fn sample_bridge_mask_vector(
    statement_digest: &str,
    prover_randomness_hex: &str,
    check_index: usize,
    rejection_attempt_index: usize,
    role: &str,
    length: usize,
    mask_absolute_bound: &BigInt,
) -> Vec<BigInt> {
    let check_index_bytes = (check_index as u64).to_le_bytes();
    let rejection_attempt_index_bytes = (rejection_attempt_index as u64).to_le_bytes();
    let mut masks = Vec::with_capacity(length);
    let mut block_index = 0_u64;

    while masks.len() < length {
        let block_index_bytes = block_index.to_le_bytes();
        let digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-rejection-sampled-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &rejection_attempt_index_bytes,
                &block_index_bytes,
            ],
        );
        for lane_index in 0..BRIDGE_SHARED_WITNESS_MASK_COORDINATES_PER_DIGEST {
            if masks.len() == length {
                break;
            }
            let lane_start = lane_index * BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE;
            let lane_end = lane_start + BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE;
            let lane = &digest[lane_start..lane_end];
            masks.push(mask_from_uniform_lane(lane, mask_absolute_bound));
        }
        block_index = block_index
            .checked_add(1)
            .expect("bridge mask block index overflowed");
    }

    masks
}

fn mask_from_uniform_lane(lane: &[u8], mask_absolute_bound: &BigInt) -> BigInt {
    debug_assert_eq!(lane.len(), BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE);
    let mut coordinate_bytes = lane.to_vec();
    let top_byte_index = coordinate_bytes
        .len()
        .checked_sub(1)
        .expect("bridge mask lane must not be empty");
    let retained_high_bits = BRIDGE_SHARED_WITNESS_MASK_RANDOM_BIT_LENGTH % 8;
    if retained_high_bits != 0 {
        let high_bit_mask = (1_u8 << retained_high_bits) - 1;
        coordinate_bytes[top_byte_index] &= high_bit_mask;
    }
    BigInt::from_bytes_le(Sign::Plus, &coordinate_bytes) - mask_absolute_bound
}

fn bridge_shared_witness_challenge_scalar(
    statement_digest: &str,
    check_index: usize,
    aggregate_commitment_digest: &str,
    batch_commitment_digest: &str,
    bgv_commitment_digest: &str,
    bgv_randomness_bound_commitment_digest: &str,
) -> u64 {
    let check_index_bytes = (check_index as u64).to_le_bytes();
    let digest = hash512(
        "sealed-lattice-root/aggregate-bridge-shared-witness-challenge-v1",
        &[
            statement_digest.as_bytes(),
            &check_index_bytes,
            aggregate_commitment_digest.as_bytes(),
            batch_commitment_digest.as_bytes(),
            bgv_commitment_digest.as_bytes(),
            bgv_randomness_bound_commitment_digest.as_bytes(),
        ],
    );
    if let Some(challenge) = first_nonzero_u64_chunk(&digest) {
        return challenge;
    }

    let mut retry_index = 1_u64;
    loop {
        let retry_index_bytes = retry_index.to_le_bytes();
        let retry_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-challenge-retry-v1",
            &[
                statement_digest.as_bytes(),
                &check_index_bytes,
                aggregate_commitment_digest.as_bytes(),
                batch_commitment_digest.as_bytes(),
                bgv_commitment_digest.as_bytes(),
                bgv_randomness_bound_commitment_digest.as_bytes(),
                &retry_index_bytes,
            ],
        );
        if let Some(challenge) = first_nonzero_u64_chunk(&retry_digest) {
            return challenge;
        }
        retry_index = retry_index
            .checked_add(1)
            .expect("bridge challenge retry index overflowed");
    }
}

fn first_nonzero_u64_chunk(digest: &[u8]) -> Option<u64> {
    for chunk in digest.chunks_exact(8) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let challenge = u64::from_le_bytes(bytes);
        if challenge != 0 {
            return Some(challenge);
        }
    }

    None
}

fn bridge_challenge_hex(challenge_scalar: u64) -> String {
    format!("{challenge_scalar:016x}")
}

fn parse_bridge_challenge_scalar(challenge_scalar_hex: &str) -> CanonicalResult<u64> {
    if challenge_scalar_hex.len() != 16
        || !challenge_scalar_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar must be 16 lowercase hex characters",
        ));
    }
    let challenge = u64::from_str_radix(challenge_scalar_hex, 16).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar is malformed",
        )
    })?;
    if challenge == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge shared-witness challenge scalar must be non-zero",
        ));
    }

    Ok(challenge)
}

fn response_vector(
    masks: &[BigInt],
    challenge: &BigInt,
    shift_bound: &BigInt,
    witness: &[BigInt],
) -> CanonicalResult<Vec<BigInt>> {
    if masks.len() != witness.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge proof mask and witness dimensions do not match",
        ));
    }
    let negative_shift_bound = -shift_bound;
    masks
        .iter()
        .zip(witness.iter())
        .map(|(mask, witness_value)| {
            let scaled_witness = challenge * witness_value;
            if &scaled_witness >= shift_bound || scaled_witness <= negative_shift_bound {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "M9 bridge proof witness shift exceeds the supported response-distribution slack",
                ));
            }
            Ok(mask + scaled_witness)
        })
        .collect()
}

fn constant_response_polynomial(
    value: &BigInt,
    degree: usize,
    modulus_bigint: &BigInt,
) -> Vec<u64> {
    let mut polynomial = vec![0_u64; degree];
    polynomial[0] = signed_bigint_to_modulus_residue(value, modulus_bigint);

    polynomial
}

pub(crate) fn signed_bigint_to_modulus_residue(value: &BigInt, modulus_bigint: &BigInt) -> u64 {
    let residue = ((value % modulus_bigint) + modulus_bigint) % modulus_bigint;

    residue
        .to_u64()
        .expect("non-negative BigInt residue below a u64 modulus fits u64")
}

fn signed_i256_vector_hex(values: &[BigInt]) -> CanonicalResult<String> {
    let mut bytes = Vec::with_capacity(values.len() * BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH);
    for value in values {
        let sign_extension = if value.sign() == Sign::Minus {
            0xff_u8
        } else {
            0_u8
        };
        let value_bytes = value.to_signed_bytes_le();
        if value_bytes.len() > BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge shared-witness response does not fit signed i256 encoding",
            ));
        }
        let mut fixed_bytes = [sign_extension; BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH];
        fixed_bytes[..value_bytes.len()].copy_from_slice(&value_bytes);
        bytes.extend_from_slice(&fixed_bytes);
    }

    Ok(to_hex(&bytes))
}

fn read_signed_i256_hex_vector(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<Vec<BigInt>> {
    let encoded = required_string_field(value, field_name, object_name)?;
    let bytes = decode_hex(encoded)?;
    if bytes.len() % BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_name}.{field_name} must encode whole signed i256 values"),
        ));
    }

    Ok(bytes
        .chunks_exact(BRIDGE_SHARED_WITNESS_RESPONSE_BYTE_LENGTH)
        .map(BigInt::from_signed_bytes_le)
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn validate_response_lengths(
    aggregate_share_response: &[BigInt],
    aggregate_opening_response: &[BigInt],
    aggregate_reduced_response: &[BigInt],
    aggregate_quotient_response: &[BigInt],
    batch_coefficient_response: &[BigInt],
    cipher_randomizer_response: &[BigInt],
    bounded_perturbation_zero_response: &[BigInt],
    bounded_perturbation_one_response: &[BigInt],
    expected_aggregate_count: usize,
    expected_quotient_count: usize,
) -> CanonicalResult<()> {
    if aggregate_share_response.len() != expected_aggregate_count
        || aggregate_opening_response.len() != SHARE_COMMITMENT_OPENING_DIMENSION
        || aggregate_reduced_response.len() != expected_aggregate_count
        || aggregate_quotient_response.len() != expected_quotient_count
        || batch_coefficient_response.len() != POLYNOMIAL_DEGREE
        || cipher_randomizer_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof response dimensions do not match the public statement",
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_all_response_vector_bounds(
    aggregate_share_response: &[BigInt],
    aggregate_opening_response: &[BigInt],
    aggregate_reduced_response: &[BigInt],
    aggregate_quotient_response: &[BigInt],
    batch_coefficient_response: &[BigInt],
    cipher_randomizer_response: &[BigInt],
    bounded_perturbation_zero_response: &[BigInt],
    bounded_perturbation_one_response: &[BigInt],
) -> CanonicalResult<()> {
    let response_bound = bridge_shared_witness_response_absolute_bound_exclusive();
    for (role, responses) in [
        ("aggregate share", aggregate_share_response),
        ("aggregate opening", aggregate_opening_response),
        ("aggregate reduced", aggregate_reduced_response),
        ("aggregate quotient", aggregate_quotient_response),
        ("batch coefficient", batch_coefficient_response),
        ("cipher randomizer", cipher_randomizer_response),
        (
            "bounded perturbation zero",
            bounded_perturbation_zero_response,
        ),
        (
            "bounded perturbation one",
            bounded_perturbation_one_response,
        ),
    ] {
        validate_response_vector_bounds_with_bound(role, responses, &response_bound)?;
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn validate_response_vector_bounds(
    role: &str,
    responses: &[BigInt],
) -> CanonicalResult<()> {
    let response_bound = bridge_shared_witness_response_absolute_bound_exclusive();
    validate_response_vector_bounds_with_bound(role, responses, &response_bound)
}

fn validate_response_vector_bounds_with_bound(
    role: &str,
    responses: &[BigInt],
    response_bound: &BigInt,
) -> CanonicalResult<()> {
    let negative_response_bound = -response_bound;
    if responses
        .iter()
        .any(|response| response >= response_bound || response <= &negative_response_bound)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "M9 bridge shared-witness {role} response exceeds the supported response bound"
            ),
        ));
    }

    Ok(())
}

fn bridge_shared_witness_mask_absolute_bound_exclusive() -> BigInt {
    BigInt::one() << BRIDGE_SHARED_WITNESS_MASK_BIT_LENGTH
}

fn bridge_shared_witness_response_shift_bound_exclusive() -> BigInt {
    BigInt::one() << BRIDGE_SHARED_WITNESS_RESPONSE_REJECTION_SLACK_BIT_LENGTH
}

fn bridge_shared_witness_response_absolute_bound_exclusive() -> BigInt {
    bridge_shared_witness_mask_absolute_bound_exclusive()
        - bridge_shared_witness_response_shift_bound_exclusive()
}

fn bridge_shared_witness_mask_absolute_bound_exclusive_decimal() -> String {
    bridge_shared_witness_mask_absolute_bound_exclusive().to_string()
}

fn bridge_shared_witness_response_shift_bound_exclusive_decimal() -> String {
    bridge_shared_witness_response_shift_bound_exclusive().to_string()
}

fn bridge_shared_witness_response_absolute_bound_exclusive_decimal() -> String {
    bridge_shared_witness_response_absolute_bound_exclusive().to_string()
}

fn u64_slice_to_bigint_vec(values: &[u64]) -> Vec<BigInt> {
    values.iter().map(|value| BigInt::from(*value)).collect()
}

fn i64_slice_to_bigint_vec(values: &[i64]) -> Vec<BigInt> {
    values.iter().map(|value| BigInt::from(*value)).collect()
}

fn shared_response_scalar_count(
    aggregate_share_count: usize,
    aggregate_opening_count: usize,
    aggregate_reduced_count: usize,
    aggregate_quotient_count: usize,
) -> CanonicalResult<u64> {
    let total = aggregate_share_count
        .checked_add(aggregate_opening_count)
        .and_then(|value| value.checked_add(aggregate_reduced_count))
        .and_then(|value| value.checked_add(aggregate_quotient_count))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge shared response scalar count overflowed",
            )
        })?;

    u64::try_from(total).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared response scalar count does not fit u64",
        )
    })
}

fn canonical_polynomial_vector_response(entries: &[Vec<u64>]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                Value::Array(
                    entry
                        .iter()
                        .map(|coefficient| Value::String(coefficient.to_string()))
                        .collect(),
                )
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE, first_nonzero_u64_chunk,
        mask_from_uniform_lane, read_signed_i256_hex_vector, sample_bridge_mask_vector,
        signed_i256_vector_hex,
    };
    use crate::hashing::hash512;
    use num_bigint::BigInt;
    use num_traits::One;
    use serde_json::json;

    fn bridge_mask_absolute_bound() -> BigInt {
        BigInt::one() << 240_u32
    }

    fn mask_from_digest_lane(digest: &[u8], lane_index: usize) -> BigInt {
        let lane_start = lane_index * BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE;
        let lane_end = lane_start + BRIDGE_SHARED_WITNESS_MASK_BYTES_PER_COORDINATE;
        let mask_absolute_bound = bridge_mask_absolute_bound();
        mask_from_uniform_lane(&digest[lane_start..lane_end], &mask_absolute_bound)
    }

    #[test]
    fn bridge_mask_sampler_consumes_two_wide_coordinates_per_digest() {
        let statement_digest = "statement-digest";
        let prover_randomness_hex = "001122";
        let role = "aggregate-share";
        let check_index_bytes = 3_u64.to_le_bytes();
        let rejection_attempt_index_bytes = 2_u64.to_le_bytes();
        let first_block_index_bytes = 0_u64.to_le_bytes();
        let second_block_index_bytes = 1_u64.to_le_bytes();
        let third_block_index_bytes = 2_u64.to_le_bytes();
        let first_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-rejection-sampled-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &rejection_attempt_index_bytes,
                &first_block_index_bytes,
            ],
        );
        let second_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-rejection-sampled-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &rejection_attempt_index_bytes,
                &second_block_index_bytes,
            ],
        );
        let third_digest = hash512(
            "sealed-lattice-root/aggregate-bridge-shared-witness-mask-rejection-sampled-v1",
            &[
                statement_digest.as_bytes(),
                prover_randomness_hex.as_bytes(),
                role.as_bytes(),
                &check_index_bytes,
                &rejection_attempt_index_bytes,
                &third_block_index_bytes,
            ],
        );

        let mask_absolute_bound = bridge_mask_absolute_bound();
        let masks = sample_bridge_mask_vector(
            statement_digest,
            prover_randomness_hex,
            3,
            2,
            role,
            5,
            &mask_absolute_bound,
        );

        assert_eq!(
            masks,
            vec![
                mask_from_digest_lane(&first_digest, 0),
                mask_from_digest_lane(&first_digest, 1),
                mask_from_digest_lane(&second_digest, 0),
                mask_from_digest_lane(&second_digest, 1),
                mask_from_digest_lane(&third_digest, 0),
            ]
        );
        assert_ne!(
            masks,
            sample_bridge_mask_vector(
                statement_digest,
                prover_randomness_hex,
                4,
                2,
                role,
                5,
                &mask_absolute_bound,
            )
        );
        assert_ne!(
            masks,
            sample_bridge_mask_vector(
                statement_digest,
                prover_randomness_hex,
                3,
                3,
                role,
                5,
                &mask_absolute_bound,
            )
        );
    }

    #[test]
    fn signed_i256_response_encoding_round_trips_wide_values() {
        let values = vec![
            -(BigInt::one() << 239_u32) + 1,
            BigInt::from(-1_i8),
            BigInt::from(0_u8),
            (BigInt::one() << 239_u32) - 1,
        ];
        let encoded = signed_i256_vector_hex(&values).expect("wide values fit signed i256");
        assert_eq!(encoded.len(), values.len() * 64);

        let decoded = read_signed_i256_hex_vector(
            &json!({ "responses": encoded }),
            "responses",
            "testObject",
        )
        .expect("encoded i256 values decode");

        assert_eq!(decoded, values);
    }

    #[test]
    fn signed_i256_response_encoding_rejects_values_outside_i256() {
        let values = vec![BigInt::one() << 255_u32];
        let error = signed_i256_vector_hex(&values).expect_err("2^255 does not fit signed i256");

        assert!(
            error.message.contains("signed i256"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn bridge_challenge_scanner_returns_first_nonzero_chunk() {
        let mut digest = [0_u8; 64];
        digest[16..24].copy_from_slice(&37_u64.to_le_bytes());
        digest[24..32].copy_from_slice(&41_u64.to_le_bytes());

        assert_eq!(first_nonzero_u64_chunk(&digest), Some(37));
        assert_eq!(first_nonzero_u64_chunk(&[0_u8; 64]), None);
    }
}
