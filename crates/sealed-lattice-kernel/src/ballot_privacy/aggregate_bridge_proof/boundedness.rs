use super::validation::{
    read_u64_object_field, reject_forbidden_public_bridge_fields, require_equal_string,
};
use super::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

const BGV_RANDOMNESS_BOUND_STATUS_MODEL: &str = "development-bgv-randomness-bound-proof-status-v1";
const BGV_RANDOMNESS_BOUND_PROOF_MODEL: &str = "fiat-shamir-same-response-support-polynomial-v1";
const BGV_RANDOMNESS_SUPPORT: &str = "balanced-ternary-coefficients-minus-one-to-one";
const BGV_ERROR_SUPPORT: &str = "centered-binomial-eta2-coefficients-minus-two-to-two";
const BGV_BOUND_SUPPORT_CHECK_MODEL: &str = "coefficientwise-support-expansion-v1";
const BGV_BOUND_SUPPORT_SOUNDNESS_MODEL: &str = "coefficientwise-support-polynomial-fiat-shamir-v1";
const BGV_BOUND_SUPPORT_CHALLENGE_DISTRIBUTION: &str =
    "same-direct-weakest-relation-challenge-as-shared-witness-v1";
// Vanishing polynomials whose roots are exactly the legal support: x(x-1)(x+1) vanishes on
// the ternary {-1,0,1} randomizer support; x(x-2)(x-1)(x+1)(x+2) on the CBD-eta2 {-2..2} errors.
const RANDOMIZER_SUPPORT_POLYNOMIAL: &str = "x*(x-1)*(x+1)";
const ERROR_SUPPORT_POLYNOMIAL: &str = "x*(x-2)*(x-1)*(x+1)*(x+2)";
const RANDOMIZER_EXPANSION_COEFFICIENT_COUNT: usize = 3;
const ERROR_EXPANSION_COEFFICIENT_COUNT: usize = 5;
const BGV_BOUND_SUPPORT_MODULUS_COUNT: usize = 1;
const BGV_BOUND_SUPPORT_MAXIMUM_POLYNOMIAL_DEGREE: u64 = 5;
const BGV_BOUND_SUPPORT_POLYNOMIAL_DEGREE_LOSS_BITS: u64 = 3;
const BGV_BOUND_SUPPORT_COEFFICIENT_UNION_BOUND_BITS: u64 = 17;
const BGV_BOUND_SUPPORT_EFFECTIVE_SOUNDNESS_BITS_FLOOR: u64 =
    BRIDGE_SHARED_WITNESS_RAW_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR
        - BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS
        - BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS
        - BRIDGE_FULL_MATRIX_UNION_BOUND_BITS
        - BGV_BOUND_SUPPORT_POLYNOMIAL_DEGREE_LOSS_BITS
        - BGV_BOUND_SUPPORT_COEFFICIENT_UNION_BOUND_BITS;
// 6 bytes = 48 bits holds any residue mod a <2^48 data prime; boundedness is checked
// in the weakest-relation proof field while the BGV ciphertext equation still covers the full RNS basis.
const BGV_BOUND_SUPPORT_RESIDUE_BYTE_LENGTH: usize = 6;

pub(super) struct BridgeBgvRandomnessBoundCommitmentInput<'value> {
    pub(super) bridge_proof_statement_hash: &'value str,
    pub(super) check_index: usize,
    pub(super) randomizer_masks: &'value [BigInt],
    pub(super) randomizer_witness: &'value [BigInt],
    pub(super) perturbation_zero_masks: &'value [BigInt],
    pub(super) perturbation_zero_witness: &'value [BigInt],
    pub(super) perturbation_one_masks: &'value [BigInt],
    pub(super) perturbation_one_witness: &'value [BigInt],
}

pub(super) fn bridge_bgv_randomness_bound_status(
    bridge_proof_statement_hash: &str,
    bridge_shared_witness_proof_hash: &str,
    encrypted_aggregate_share_ciphertext_root: &str,
    collective_public_key_root: &str,
    collective_public_key_coefficient_root: &str,
    bgv_public_key_root: &str,
) -> Value {
    let polynomial_degree =
        u64::try_from(POLYNOMIAL_DEGREE).expect("polynomial degree fits in u64");
    let error_coefficient_count = polynomial_degree
        .checked_mul(BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT)
        .expect("BGV ciphertext component count times degree fits in u64");

    json!({
        "objectType": "AggregateBridgeBgvRandomnessBoundProofStatus",
        "objectVersion": 1,
        "statusModel": BGV_RANDOMNESS_BOUND_STATUS_MODEL,
        "proofModel": BGV_RANDOMNESS_BOUND_PROOF_MODEL,
        "bridgeProofStatementHash": bridge_proof_statement_hash,
        "bridgeSharedWitnessProofHash": bridge_shared_witness_proof_hash,
        "encryptedAggregateShareCiphertextRoot": encrypted_aggregate_share_ciphertext_root,
        "collectivePublicKeyRoot": collective_public_key_root,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "bgvPublicKeyRoot": bgv_public_key_root,
        "randomizerCoefficientCount": polynomial_degree,
        "errorPolynomialCount": BRIDGE_BGV_CIPHERTEXT_COMPONENT_COUNT,
        "errorCoefficientCount": error_coefficient_count,
        "randomizerSupport": BGV_RANDOMNESS_SUPPORT,
        "errorSupport": BGV_ERROR_SUPPORT,
        "randomizerSupportPolynomial": RANDOMIZER_SUPPORT_POLYNOMIAL,
        "errorSupportPolynomial": ERROR_SUPPORT_POLYNOMIAL,
        "supportCheckModel": BGV_BOUND_SUPPORT_CHECK_MODEL,
        "supportSoundnessModel": BGV_BOUND_SUPPORT_SOUNDNESS_MODEL,
        "supportChallengeDistribution": BGV_BOUND_SUPPORT_CHALLENGE_DISTRIBUTION,
        "supportModulusCount": BGV_BOUND_SUPPORT_MODULUS_COUNT,
        "supportRelationModuli": support_moduli(),
        "supportCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64,
        "supportCoefficientChecksPerSharedWitnessCheck": error_coefficient_count
            .checked_add(polynomial_degree)
            .expect("support coefficient count fits in u64"),
        "supportMaximumPolynomialDegree": BGV_BOUND_SUPPORT_MAXIMUM_POLYNOMIAL_DEGREE,
        "supportPolynomialDegreeLossBits": BGV_BOUND_SUPPORT_POLYNOMIAL_DEGREE_LOSS_BITS,
        "supportCoefficientUnionBoundBits": BGV_BOUND_SUPPORT_COEFFICIENT_UNION_BOUND_BITS,
        "supportRejectionRetryLossBits": BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS,
        "supportRandomOracleQueryBoundBits": BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS,
        "supportFullMatrixUnionBoundBits": BRIDGE_FULL_MATRIX_UNION_BOUND_BITS,
        "supportCancellationProbabilityModel": "per-coefficient-degree-bound-no-cross-coefficient-batching-v1",
        "supportEffectiveSoundnessBitsFloor": BGV_BOUND_SUPPORT_EFFECTIVE_SOUNDNESS_BITS_FLOOR,
        "supportSoundnessIncludedInBridgeReport": true,
        "supportSoundnessTargetMet": BGV_BOUND_SUPPORT_EFFECTIVE_SOUNDNESS_BITS_FLOOR
            >= BRIDGE_TARGET_BINDING_SOUNDNESS_BITS,
        "sameSharedWitnessResponseTranscript": true,
        "verifierBoundednessProofChecked": true,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "bridgeClaimClosureAccepted": false,
    })
}

pub(super) fn bridge_bgv_randomness_bound_status_hash(
    status_evidence: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-bgv-randomness-bound-status-v1",
            "bgvRandomnessBoundProofStatusEvidence": status_evidence,
        }),
    )
}

pub(super) fn validate_bridge_bgv_randomness_bound_status(
    proof_value: &Value,
    bridge_proof_statement_hash: &str,
    bridge_shared_witness_proof_hash: &str,
    bridge_encryption: &Value,
) -> CanonicalResult<String> {
    let status_evidence = required_json_field(
        proof_value,
        "bgvRandomnessBoundProofStatusEvidence",
        "bridgeProof",
    )?;
    reject_forbidden_public_bridge_fields(
        status_evidence,
        "bridgeProof.bgvRandomnessBoundProofStatusEvidence",
    )?;

    let expected_status = bridge_bgv_randomness_bound_status(
        bridge_proof_statement_hash,
        bridge_shared_witness_proof_hash,
        required_string_field(
            bridge_encryption,
            "encryptedAggregateShareCiphertextRoot",
            "bridgeEncryption",
        )?,
        required_string_field(
            bridge_encryption,
            "collectivePublicKeyRoot",
            "bridgeEncryption",
        )?,
        required_string_field(
            bridge_encryption,
            "collectivePublicKeyCoefficientRoot",
            "bridgeEncryption",
        )?,
        required_string_field(bridge_encryption, "bgvPublicKeyRoot", "bridgeEncryption")?,
    );
    if status_evidence != &expected_status {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge BGV randomness-bound status evidence does not match the proof-bound public inputs",
        ));
    }

    let status_hash = bridge_bgv_randomness_bound_status_hash(status_evidence)?;
    require_equal_string(
        proof_value,
        "bgvRandomnessBoundProofStatusHash",
        &status_hash,
        "BGV randomness-bound status hash",
    )?;

    Ok(status_hash)
}

pub(super) fn bridge_bgv_randomness_bound_commitment(
    input: BridgeBgvRandomnessBoundCommitmentInput<'_>,
) -> CanonicalResult<Value> {
    validate_bgv_boundedness_witness_dimensions(
        input.randomizer_masks,
        input.randomizer_witness,
        input.perturbation_zero_masks,
        input.perturbation_zero_witness,
        input.perturbation_one_masks,
        input.perturbation_one_witness,
    )?;
    let randomizer_expansion_commitments_by_modulus = support_moduli()
        .iter()
        .map(|modulus| {
            support_expansion_commitment_for_role(
                *modulus,
                BgvSupportKind::Randomizer,
                input.randomizer_masks,
                input.randomizer_witness,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_zero_expansion_commitments_by_modulus = support_moduli()
        .iter()
        .map(|modulus| {
            support_expansion_commitment_for_role(
                *modulus,
                BgvSupportKind::Error,
                input.perturbation_zero_masks,
                input.perturbation_zero_witness,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_one_expansion_commitments_by_modulus = support_moduli()
        .iter()
        .map(|modulus| {
            support_expansion_commitment_for_role(
                *modulus,
                BgvSupportKind::Error,
                input.perturbation_one_masks,
                input.perturbation_one_witness,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "AggregateBridgeBgvRandomnessBoundCommitment",
        "objectVersion": 1,
        "proofModel": BGV_RANDOMNESS_BOUND_PROOF_MODEL,
        "bridgeProofStatementHash": input.bridge_proof_statement_hash,
        "checkIndex": input.check_index,
        "supportCheckModel": BGV_BOUND_SUPPORT_CHECK_MODEL,
        "supportModuli": support_moduli(),
        "randomizerSupport": BGV_RANDOMNESS_SUPPORT,
        "errorSupport": BGV_ERROR_SUPPORT,
        "randomizerSupportPolynomial": RANDOMIZER_SUPPORT_POLYNOMIAL,
        "errorSupportPolynomial": ERROR_SUPPORT_POLYNOMIAL,
        "randomizerExpansionCommitmentsByModulus": randomizer_expansion_commitments_by_modulus,
        "errorZeroExpansionCommitmentsByModulus": error_zero_expansion_commitments_by_modulus,
        "errorOneExpansionCommitmentsByModulus": error_one_expansion_commitments_by_modulus,
    }))
}

pub(super) fn bridge_bgv_randomness_bound_commitment_hash(
    commitment: &Value,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-bgv-randomness-bound-commitment-v1",
            "bgvRandomnessBoundCommitment": commitment,
        }),
    )
}

pub(super) fn validate_bridge_bgv_randomness_bound_commitment(
    check: &Value,
    bridge_proof_statement_hash: &str,
    check_index: usize,
    challenge_scalar: u128,
    randomizer_response: &[BigInt],
    perturbation_zero_response: &[BigInt],
    perturbation_one_response: &[BigInt],
) -> CanonicalResult<String> {
    let commitment = required_json_field(
        check,
        "bgvRandomnessBoundCommitment",
        "bridgeSharedWitnessProof.check",
    )?;
    reject_forbidden_public_bridge_fields(
        commitment,
        "bridgeSharedWitnessProof.check.bgvRandomnessBoundCommitment",
    )?;
    validate_bgv_bound_commitment_shell(commitment, bridge_proof_statement_hash, check_index)?;
    let randomizer_commitments = read_expansion_commitments_by_modulus(
        commitment,
        "randomizerExpansionCommitmentsByModulus",
        RANDOMIZER_EXPANSION_COEFFICIENT_COUNT,
    )?;
    let error_zero_commitments = read_expansion_commitments_by_modulus(
        commitment,
        "errorZeroExpansionCommitmentsByModulus",
        ERROR_EXPANSION_COEFFICIENT_COUNT,
    )?;
    let error_one_commitments = read_expansion_commitments_by_modulus(
        commitment,
        "errorOneExpansionCommitmentsByModulus",
        ERROR_EXPANSION_COEFFICIENT_COUNT,
    )?;
    validate_bgv_support_response_dimensions(
        randomizer_response,
        perturbation_zero_response,
        perturbation_one_response,
    )?;

    for (modulus_index, modulus) in support_moduli().iter().enumerate() {
        validate_support_polynomial_for_role(
            "cipher-randomizer",
            *modulus,
            BgvSupportKind::Randomizer,
            challenge_scalar,
            randomizer_response,
            &randomizer_commitments[modulus_index],
        )?;
        validate_support_polynomial_for_role(
            "bounded-perturbation-zero",
            *modulus,
            BgvSupportKind::Error,
            challenge_scalar,
            perturbation_zero_response,
            &error_zero_commitments[modulus_index],
        )?;
        validate_support_polynomial_for_role(
            "bounded-perturbation-one",
            *modulus,
            BgvSupportKind::Error,
            challenge_scalar,
            perturbation_one_response,
            &error_one_commitments[modulus_index],
        )?;
    }

    let commitment_hash = bridge_bgv_randomness_bound_commitment_hash(commitment)?;
    require_equal_string(
        check,
        "bgvRandomnessBoundCommitmentHash",
        &commitment_hash,
        "BGV randomness-bound commitment hash",
    )?;

    Ok(commitment_hash)
}

#[derive(Clone, Copy)]
enum BgvSupportKind {
    Randomizer,
    Error,
}

fn validate_bgv_boundedness_witness_dimensions(
    randomizer_masks: &[BigInt],
    randomizer_witness: &[BigInt],
    perturbation_zero_masks: &[BigInt],
    perturbation_zero_witness: &[BigInt],
    perturbation_one_masks: &[BigInt],
    perturbation_one_witness: &[BigInt],
) -> CanonicalResult<()> {
    if randomizer_masks.len() != POLYNOMIAL_DEGREE
        || randomizer_witness.len() != POLYNOMIAL_DEGREE
        || perturbation_zero_masks.len() != POLYNOMIAL_DEGREE
        || perturbation_zero_witness.len() != POLYNOMIAL_DEGREE
        || perturbation_one_masks.len() != POLYNOMIAL_DEGREE
        || perturbation_one_witness.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge BGV boundedness witness dimensions do not match the BGV profile",
        ));
    }

    Ok(())
}

fn validate_bgv_support_response_dimensions(
    randomizer_response: &[BigInt],
    perturbation_zero_response: &[BigInt],
    perturbation_one_response: &[BigInt],
) -> CanonicalResult<()> {
    if randomizer_response.len() != POLYNOMIAL_DEGREE
        || perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge BGV boundedness response dimensions do not match the BGV profile",
        ));
    }

    Ok(())
}

fn support_expansion_commitment_for_role(
    modulus: u64,
    support_kind: BgvSupportKind,
    masks: &[BigInt],
    witness: &[BigInt],
) -> CanonicalResult<String> {
    let coefficient_count = support_kind.expansion_coefficient_count();
    let mut commitment_bytes = Vec::with_capacity(masks.len() * coefficient_count * 8);
    let modulus_bigint = BigInt::from(modulus);
    for (mask, witness_value) in masks.iter().zip(witness.iter()) {
        let mask_residue = bigint_to_modulus_residue(mask, &modulus_bigint);
        let witness_residue = bigint_to_modulus_residue(witness_value, &modulus_bigint);
        let expansion =
            support_expansion_coefficients(support_kind, mask_residue, witness_residue, modulus)?;
        for expansion_coefficient in expansion {
            commitment_bytes.extend_from_slice(
                &expansion_coefficient.to_le_bytes()[..BGV_BOUND_SUPPORT_RESIDUE_BYTE_LENGTH],
            );
        }
    }

    Ok(to_hex(&commitment_bytes))
}

fn validate_support_polynomial_for_role(
    role: &str,
    modulus: u64,
    support_kind: BgvSupportKind,
    challenge_scalar: u128,
    responses: &[BigInt],
    expansion_commitments: &[u64],
) -> CanonicalResult<()> {
    let expansion_coefficient_count = support_kind.expansion_coefficient_count();
    if expansion_commitments.len() != responses.len() * expansion_coefficient_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge BGV boundedness expansion commitment length is invalid",
        ));
    }
    let challenge_residue =
        u64::try_from(challenge_scalar % u128::from(modulus)).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge BGV boundedness challenge residue does not fit u64",
            )
        })?;
    let modulus_bigint = BigInt::from(modulus);
    for (coefficient_index, (response, expansion)) in responses
        .iter()
        .zip(expansion_commitments.chunks_exact(expansion_coefficient_count))
        .enumerate()
    {
        let response_residue = bigint_to_modulus_residue(response, &modulus_bigint);
        let support_value =
            support_polynomial_value(support_kind, response_residue, challenge_residue, modulus);
        let mut expanded_support_value = 0_u64;
        let mut challenge_power = 1_u64;
        for commitment in expansion {
            expanded_support_value = add_mod_u64(
                expanded_support_value,
                mul_mod_u64(*commitment, challenge_power, modulus),
                modulus,
            );
            challenge_power = mul_mod_u64(challenge_power, challenge_residue, modulus);
        }
        if support_value != expanded_support_value {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted aggregate bridge BGV boundedness support polynomial check failed for {role} coefficient {coefficient_index}"
                ),
            ));
        }
    }

    Ok(())
}

fn validate_bgv_bound_commitment_shell(
    commitment: &Value,
    bridge_proof_statement_hash: &str,
    check_index: usize,
) -> CanonicalResult<()> {
    if string_field(commitment, "objectType") != Some("AggregateBridgeBgvRandomnessBoundCommitment")
        || read_u64_object_field(commitment, "objectVersion", "bgvRandomnessBoundCommitment")? != 1
        || string_field(commitment, "proofModel") != Some(BGV_RANDOMNESS_BOUND_PROOF_MODEL)
        || string_field(commitment, "randomizerSupport") != Some(BGV_RANDOMNESS_SUPPORT)
        || string_field(commitment, "errorSupport") != Some(BGV_ERROR_SUPPORT)
        || string_field(commitment, "supportCheckModel") != Some(BGV_BOUND_SUPPORT_CHECK_MODEL)
        || string_field(commitment, "randomizerSupportPolynomial")
            != Some(RANDOMIZER_SUPPORT_POLYNOMIAL)
        || string_field(commitment, "errorSupportPolynomial") != Some(ERROR_SUPPORT_POLYNOMIAL)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge BGV boundedness commitment shell is not supported",
        ));
    }
    // Only coefficientwise checks are sound here: a single out-of-support coefficient must not
    // be maskable by weighted batching, so any weightModel field is rejected.
    if commitment.get("weightModel").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge BGV boundedness commitment must use coefficientwise support checks, not weighted batching",
        ));
    }
    require_equal_string(
        commitment,
        "bridgeProofStatementHash",
        bridge_proof_statement_hash,
        "BGV boundedness statement hash",
    )?;
    if read_u64_object_field(commitment, "checkIndex", "bgvRandomnessBoundCommitment")?
        != check_index as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge BGV boundedness commitment check index does not match the shared-witness check",
        ));
    }
    let support_modulus_values = commitment
        .get("supportModuli")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bgvRandomnessBoundCommitment.supportModuli must be an array",
            )
        })?;
    if support_modulus_values.len() != BGV_BOUND_SUPPORT_MODULUS_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted aggregate bridge BGV boundedness support modulus count is invalid",
        ));
    }
    for (modulus_value, expected_modulus) in support_modulus_values.iter().zip(support_moduli()) {
        if modulus_value.as_u64() != Some(*expected_modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted aggregate bridge BGV boundedness support modulus list does not match the BGV profile",
            ));
        }
    }

    Ok(())
}

fn read_expansion_commitments_by_modulus(
    value: &Value,
    field_name: &str,
    coefficient_count: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let by_modulus = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("bgvRandomnessBoundCommitment.{field_name} must be an array"),
            )
        })?;
    if by_modulus.len() != BGV_BOUND_SUPPORT_MODULUS_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("bgvRandomnessBoundCommitment.{field_name} has an invalid modulus count"),
        ));
    }
    by_modulus
        .iter()
        .zip(support_moduli())
        .map(|(commitments_for_modulus, modulus)| {
            let commitments_hex = commitments_for_modulus
                .as_str()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "bgvRandomnessBoundCommitment.{field_name} entries must be fixed-width hex strings"
                        ),
                    )
                })?;
            decode_support_expansion_commitments_hex(commitments_hex, coefficient_count, *modulus, field_name)
        })
        .collect()
}

fn decode_support_expansion_commitments_hex(
    commitments_hex: &str,
    coefficient_count: usize,
    modulus: u64,
    field_name: &str,
) -> CanonicalResult<Vec<u64>> {
    let expected_byte_length = POLYNOMIAL_DEGREE
        .checked_mul(coefficient_count)
        .and_then(|count| count.checked_mul(BGV_BOUND_SUPPORT_RESIDUE_BYTE_LENGTH))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge BGV boundedness expansion commitment byte length overflowed",
            )
        })?;
    if commitments_hex.len() != expected_byte_length * 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("bgvRandomnessBoundCommitment.{field_name} has an invalid encoded byte length"),
        ));
    }
    let commitment_bytes = decode_hex(commitments_hex)?;
    if commitment_bytes.len() != expected_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("bgvRandomnessBoundCommitment.{field_name} has an invalid byte length"),
        ));
    }
    commitment_bytes
        .chunks_exact(BGV_BOUND_SUPPORT_RESIDUE_BYTE_LENGTH)
        .map(|chunk| {
            let mut bytes = [0_u8; 8];
            bytes[..BGV_BOUND_SUPPORT_RESIDUE_BYTE_LENGTH].copy_from_slice(chunk);
            let value = u64::from_le_bytes(bytes);
            if value >= modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    format!(
                        "bgvRandomnessBoundCommitment.{field_name} entry is outside its modulus"
                    ),
                ));
            }

            Ok(value)
        })
        .collect()
}

fn support_moduli() -> &'static [u64] {
    &DATA_PRIMES[..BGV_BOUND_SUPPORT_MODULUS_COUNT]
}

impl BgvSupportKind {
    fn expansion_coefficient_count(self) -> usize {
        match self {
            Self::Randomizer => RANDOMIZER_EXPANSION_COEFFICIENT_COUNT,
            Self::Error => ERROR_EXPANSION_COEFFICIENT_COUNT,
        }
    }
}

// Coefficients (in powers of the challenge c) of support(mask + c*witness): the response is the
// homomorphic opening mask + c*witness. Literals 3 / 5,10,15,4 are the binomial-expansion terms
// of x^3-x and x^5-5x^3+4x; the verifier recombines these as sum(commitment * c^k).
fn support_expansion_coefficients(
    support_kind: BgvSupportKind,
    mask: u64,
    witness: u64,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mask_power = powers(mask, 5, modulus);
    let witness_power = powers(witness, 5, modulus);
    Ok(match support_kind {
        BgvSupportKind::Randomizer => vec![
            mask_power[3],
            mul_small_mod(3, mul_mod_u64(mask_power[2], witness, modulus), modulus),
            sub_mod_u64(
                mul_small_mod(3, mul_mod_u64(mask, witness_power[2], modulus), modulus),
                mask,
                modulus,
            ),
        ],
        BgvSupportKind::Error => vec![
            mask_power[5],
            mul_small_mod(5, mul_mod_u64(mask_power[4], witness, modulus), modulus),
            sub_mod_u64(
                mul_small_mod(
                    10,
                    mul_mod_u64(mask_power[3], witness_power[2], modulus),
                    modulus,
                ),
                mul_small_mod(5, mask_power[3], modulus),
                modulus,
            ),
            sub_mod_u64(
                mul_small_mod(
                    10,
                    mul_mod_u64(mask_power[2], witness_power[3], modulus),
                    modulus,
                ),
                mul_small_mod(15, mul_mod_u64(mask_power[2], witness, modulus), modulus),
                modulus,
            ),
            add_mod_u64(
                sub_mod_u64(
                    mul_small_mod(5, mul_mod_u64(mask, witness_power[4], modulus), modulus),
                    mul_small_mod(15, mul_mod_u64(mask, witness_power[2], modulus), modulus),
                    modulus,
                ),
                mul_small_mod(4, mask, modulus),
                modulus,
            ),
        ],
    })
}

// Degree-homogenized support polynomial evaluated at the response (value) with c as the
// homogenizing variable: x^3-x -> x^3 - x*c^2, x^5-5x^3+4x -> x^5 - 5x^3*c^2 + 4x*c^4. Equals the
// recombined sum(commitment * c^k), certifying each coefficient lies in support.
fn support_polynomial_value(
    support_kind: BgvSupportKind,
    value: u64,
    homogenizing_value: u64,
    modulus: u64,
) -> u64 {
    let value_power = powers(value, 5, modulus);
    let homogenizing_power = powers(homogenizing_value, 5, modulus);
    match support_kind {
        BgvSupportKind::Randomizer => sub_mod_u64(
            value_power[3],
            mul_mod_u64(value, homogenizing_power[2], modulus),
            modulus,
        ),
        BgvSupportKind::Error => add_mod_u64(
            sub_mod_u64(
                value_power[5],
                mul_mod_u64(
                    mul_small_mod(5, value_power[3], modulus),
                    homogenizing_power[2],
                    modulus,
                ),
                modulus,
            ),
            mul_mod_u64(
                mul_small_mod(4, value, modulus),
                homogenizing_power[4],
                modulus,
            ),
            modulus,
        ),
    }
}

fn powers(value: u64, highest_power: usize, modulus: u64) -> Vec<u64> {
    let mut powers = vec![1_u64; highest_power + 1];
    for power_index in 1..=highest_power {
        powers[power_index] = mul_mod_u64(powers[power_index - 1], value, modulus);
    }

    powers
}

fn bigint_to_modulus_residue(value: &BigInt, modulus_bigint: &BigInt) -> u64 {
    let residue = ((value % modulus_bigint) + modulus_bigint) % modulus_bigint;
    residue
        .to_u64()
        .expect("non-negative BigInt residue below a u64 modulus fits u64")
}

fn add_mod_u64(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn sub_mod_u64(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        (u128::from(left) + u128::from(modulus) - u128::from(right)) as u64
    }
}

fn mul_mod_u64(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn mul_small_mod(scalar: u64, value: u64, modulus: u64) -> u64 {
    mul_mod_u64(scalar % modulus, value, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ValidSupportCommitmentCheck {
        check: Value,
        randomizer_response: Vec<BigInt>,
        perturbation_zero_response: Vec<BigInt>,
        perturbation_one_response: Vec<BigInt>,
    }

    fn valid_support_commitment_check(
        challenge: u128,
    ) -> CanonicalResult<ValidSupportCommitmentCheck> {
        let randomizer_masks = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let perturbation_zero_masks = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let perturbation_one_masks = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let mut randomizer_witness = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let mut perturbation_zero_witness = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let mut perturbation_one_witness = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        randomizer_witness[0] = BigInt::from(1_u8);
        perturbation_zero_witness[0] = BigInt::from(-2_i8);
        perturbation_one_witness[0] = BigInt::from(2_u8);

        let randomizer_response = randomizer_witness
            .iter()
            .map(|witness| BigInt::from(challenge) * witness)
            .collect::<Vec<_>>();
        let perturbation_zero_response = perturbation_zero_witness
            .iter()
            .map(|witness| BigInt::from(challenge) * witness)
            .collect::<Vec<_>>();
        let perturbation_one_response = perturbation_one_witness
            .iter()
            .map(|witness| BigInt::from(challenge) * witness)
            .collect::<Vec<_>>();
        let commitment =
            bridge_bgv_randomness_bound_commitment(BridgeBgvRandomnessBoundCommitmentInput {
                bridge_proof_statement_hash: "a".repeat(128).as_str(),
                check_index: 0,
                randomizer_masks: &randomizer_masks,
                randomizer_witness: &randomizer_witness,
                perturbation_zero_masks: &perturbation_zero_masks,
                perturbation_zero_witness: &perturbation_zero_witness,
                perturbation_one_masks: &perturbation_one_masks,
                perturbation_one_witness: &perturbation_one_witness,
            })?;
        let commitment_hash = bridge_bgv_randomness_bound_commitment_hash(&commitment)?;
        let check = json!({
            "bgvRandomnessBoundCommitment": commitment,
            "bgvRandomnessBoundCommitmentHash": commitment_hash,
        });

        Ok(ValidSupportCommitmentCheck {
            check,
            randomizer_response,
            perturbation_zero_response,
            perturbation_one_response,
        })
    }

    #[test]
    fn boundedness_support_checks_use_the_weakest_relation_field_with_compact_residue_encoding() {
        assert_eq!(support_moduli(), &DATA_PRIMES[..1]);
        assert_eq!(BGV_BOUND_SUPPORT_MODULUS_COUNT, 1);
        assert!(
            support_moduli()
                .iter()
                .all(|modulus| *modulus < (1_u64 << 48))
        );
    }

    #[test]
    fn randomizer_support_expansion_matches_challenged_response() {
        let modulus = support_moduli()[0];
        let modulus_bigint = BigInt::from(modulus);
        for mask in [-7_i64, -1, 0, 3, 19] {
            for witness in [-1_i64, 0, 1] {
                for challenge in [1_u64, 17, u64::MAX] {
                    let mask_residue =
                        bigint_to_modulus_residue(&BigInt::from(mask), &modulus_bigint);
                    let witness_residue =
                        bigint_to_modulus_residue(&BigInt::from(witness), &modulus_bigint);
                    let challenge_residue = challenge % modulus;
                    let response = add_mod_u64(
                        mask_residue,
                        mul_mod_u64(challenge_residue, witness_residue, modulus),
                        modulus,
                    );
                    let expansion = support_expansion_coefficients(
                        BgvSupportKind::Randomizer,
                        mask_residue,
                        witness_residue,
                        modulus,
                    )
                    .expect("expansion should build");
                    let mut expanded = 0_u64;
                    let mut challenge_power = 1_u64;
                    for coefficient in expansion {
                        expanded = add_mod_u64(
                            expanded,
                            mul_mod_u64(coefficient, challenge_power, modulus),
                            modulus,
                        );
                        challenge_power = mul_mod_u64(challenge_power, challenge_residue, modulus);
                    }

                    assert_eq!(
                        support_polynomial_value(
                            BgvSupportKind::Randomizer,
                            response,
                            challenge_residue,
                            modulus
                        ),
                        expanded
                    );
                }
            }
        }
    }

    #[test]
    fn error_support_expansion_matches_challenged_response() {
        let modulus = support_moduli()[0];
        let modulus_bigint = BigInt::from(modulus);
        for mask in [-11_i64, -2, 0, 5, 23] {
            for witness in [-2_i64, -1, 0, 1, 2] {
                for challenge in [1_u64, 29, u64::MAX] {
                    let mask_residue =
                        bigint_to_modulus_residue(&BigInt::from(mask), &modulus_bigint);
                    let witness_residue =
                        bigint_to_modulus_residue(&BigInt::from(witness), &modulus_bigint);
                    let challenge_residue = challenge % modulus;
                    let response = add_mod_u64(
                        mask_residue,
                        mul_mod_u64(challenge_residue, witness_residue, modulus),
                        modulus,
                    );
                    let expansion = support_expansion_coefficients(
                        BgvSupportKind::Error,
                        mask_residue,
                        witness_residue,
                        modulus,
                    )
                    .expect("expansion should build");
                    let mut expanded = 0_u64;
                    let mut challenge_power = 1_u64;
                    for coefficient in expansion {
                        expanded = add_mod_u64(
                            expanded,
                            mul_mod_u64(coefficient, challenge_power, modulus),
                            modulus,
                        );
                        challenge_power = mul_mod_u64(challenge_power, challenge_residue, modulus);
                    }

                    assert_eq!(
                        support_polynomial_value(
                            BgvSupportKind::Error,
                            response,
                            challenge_residue,
                            modulus
                        ),
                        expanded
                    );
                }
            }
        }
    }

    #[test]
    fn support_check_rejects_coefficientwise_invalid_randomizer() {
        let modulus = support_moduli()[0];
        let challenge = 17_u128;
        let masks = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let mut witnesses = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        witnesses[0] = BigInt::from(2_i8);
        witnesses[1] = BigInt::from(-2_i8);
        let responses = witnesses
            .iter()
            .map(|witness| BigInt::from(challenge) * witness)
            .collect::<Vec<_>>();
        let commitments_hex = support_expansion_commitment_for_role(
            modulus,
            BgvSupportKind::Randomizer,
            &masks,
            &witnesses,
        )
        .expect("commitment should build");
        let commitments = decode_support_expansion_commitments_hex(
            &commitments_hex,
            BgvSupportKind::Randomizer.expansion_coefficient_count(),
            modulus,
            "testRandomizerCommitments",
        )
        .expect("commitment should decode");

        let error = validate_support_polynomial_for_role(
            "cipher-randomizer",
            modulus,
            BgvSupportKind::Randomizer,
            challenge,
            &responses,
            &commitments,
        )
        .expect_err("non-support coefficients must not cancel across the batch");

        assert!(
            error.message.contains("coefficient 0"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn support_check_rejects_invalid_error_coefficients_without_batch_cancellation() {
        let modulus = support_moduli()[0];
        let challenge = 19_u128;
        let masks = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        let mut witnesses = vec![BigInt::from(0_u8); POLYNOMIAL_DEGREE];
        witnesses[3] = BigInt::from(3_i8);
        witnesses[4] = BigInt::from(-3_i8);
        let responses = witnesses
            .iter()
            .map(|witness| BigInt::from(challenge) * witness)
            .collect::<Vec<_>>();
        let commitments_hex = support_expansion_commitment_for_role(
            modulus,
            BgvSupportKind::Error,
            &masks,
            &witnesses,
        )
        .expect("commitment should build");
        let commitments = decode_support_expansion_commitments_hex(
            &commitments_hex,
            BgvSupportKind::Error.expansion_coefficient_count(),
            modulus,
            "testErrorCommitments",
        )
        .expect("commitment should decode");

        let error = validate_support_polynomial_for_role(
            "bounded-perturbation-zero",
            modulus,
            BgvSupportKind::Error,
            challenge,
            &responses,
            &commitments,
        )
        .expect_err("out-of-support error coefficients must reject coefficientwise");

        assert!(
            error.message.contains("coefficient 3"),
            "unexpected error: {}",
            error.message
        );
    }

    #[test]
    fn support_commitment_rejects_challenge_role_and_modulus_mutations() {
        let challenge = 17_u128;
        let ValidSupportCommitmentCheck {
            check,
            randomizer_response,
            perturbation_zero_response,
            perturbation_one_response,
        } = valid_support_commitment_check(challenge).expect("valid support commitment check");
        validate_bridge_bgv_randomness_bound_commitment(
            &check,
            &"a".repeat(128),
            0,
            challenge,
            &randomizer_response,
            &perturbation_zero_response,
            &perturbation_one_response,
        )
        .expect("valid support commitment should verify");

        let challenge_error = validate_bridge_bgv_randomness_bound_commitment(
            &check,
            &"a".repeat(128),
            0,
            challenge + 1,
            &randomizer_response,
            &perturbation_zero_response,
            &perturbation_one_response,
        )
        .expect_err("mutated support challenge must reject");
        assert!(
            challenge_error
                .message
                .contains("support polynomial check failed"),
            "unexpected error: {}",
            challenge_error.message
        );

        let mut role_mutated_check = check.clone();
        role_mutated_check["bgvRandomnessBoundCommitment"]["supportCheckModel"] =
            Value::String("weighted-batch-support-check-v1".to_string());
        let role_error = validate_bridge_bgv_randomness_bound_commitment(
            &role_mutated_check,
            &"a".repeat(128),
            0,
            challenge,
            &randomizer_response,
            &perturbation_zero_response,
            &perturbation_one_response,
        )
        .expect_err("mutated support role/model must reject");
        assert!(
            role_error.message.contains("commitment shell"),
            "unexpected error: {}",
            role_error.message
        );

        let mut modulus_mutated_check = check.clone();
        modulus_mutated_check["bgvRandomnessBoundCommitment"]["supportModuli"][0] =
            json!(support_moduli()[0] - 2);
        let modulus_error = validate_bridge_bgv_randomness_bound_commitment(
            &modulus_mutated_check,
            &"a".repeat(128),
            0,
            challenge,
            &randomizer_response,
            &perturbation_zero_response,
            &perturbation_one_response,
        )
        .expect_err("mutated support modulus must reject");
        assert!(
            modulus_error.message.contains("support modulus list"),
            "unexpected error: {}",
            modulus_error.message
        );
    }

    #[test]
    fn support_commitment_rejects_replayed_expansion_bytes() {
        let challenge = 23_u128;
        let ValidSupportCommitmentCheck {
            mut check,
            randomizer_response,
            perturbation_zero_response,
            perturbation_one_response,
        } = valid_support_commitment_check(challenge).expect("valid support commitment check");
        let randomizer_commitment =
            check["bgvRandomnessBoundCommitment"]["randomizerExpansionCommitmentsByModulus"][0]
                .clone();
        check["bgvRandomnessBoundCommitment"]["errorZeroExpansionCommitmentsByModulus"][0] =
            randomizer_commitment;
        check["bgvRandomnessBoundCommitmentHash"] = Value::String(
            bridge_bgv_randomness_bound_commitment_hash(&check["bgvRandomnessBoundCommitment"])
                .expect("mutated commitment hash should derive"),
        );

        let error = validate_bridge_bgv_randomness_bound_commitment(
            &check,
            &"a".repeat(128),
            0,
            challenge,
            &randomizer_response,
            &perturbation_zero_response,
            &perturbation_one_response,
        )
        .expect_err("replayed support expansion bytes must reject");

        assert!(
            error.message.contains("invalid encoded byte length")
                || error.message.contains("support polynomial check failed"),
            "unexpected error: {}",
            error.message
        );
    }
}
