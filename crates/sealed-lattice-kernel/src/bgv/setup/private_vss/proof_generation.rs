use super::*;

use crate::hashing::derive_canonical_object_hash;

const PROOF_RANDOMNESS_SEED_BYTES: usize = 64;
const PROOF_RANDOMNESS_NONCE_BYTES: usize = 64;

pub(crate) fn generate_private_vss_share_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_context = object_field(
        request,
        "setupContext",
        "setupContext",
        "setupContextMissing",
        "setupContext must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if let Err(refusal) = verify_setup_context(setup_context)? {
        return Err(private_vss_refusal_to_error(refusal));
    }
    let public_matrix_seed_hash = hash_string_field(
        request,
        "publicMatrixSeedHash",
        "publicMatrixSeedHash",
        "publicMatrixSeedHashMissing",
        "publicMatrixSeedHash must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let private_envelope_aad_hash = hash_string_field(
        request,
        "privateEnvelopeAadHash",
        "privateEnvelopeAadHash",
        "privateEnvelopeAadHashMissing",
        "privateEnvelopeAadHash must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    validate_hash_string(private_envelope_aad_hash, "privateEnvelopeAadHash")?;

    let source_trustee_record = object_field(
        request,
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCoefficientCommitmentRecord",
        "sourceTrusteeCommitmentRecordMissing",
        "sourceTrusteeCoefficientCommitmentRecord must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let source_trustee_binding = verify_source_trustee_commitment_record(
        source_trustee_record,
        setup_context,
        public_matrix_seed_hash,
    )?
    .map_err(private_vss_refusal_to_error)?;
    let material_records = array_field(
        request,
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCoefficientCommitmentMaterialRecords",
        "sourceTrusteeCommitmentMaterialMissing",
        "sourceTrusteeCoefficientCommitmentMaterialRecords must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let coefficient_commitments = verify_coefficient_commitment_material_records(
        material_records,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_binding,
    )?
    .map_err(private_vss_refusal_to_error)?;

    let recipient_identity = string_field(
        request,
        "recipientIdentity",
        "recipientIdentity",
        "recipientIdentityMissing",
        "recipientIdentity must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let recipient_roster_position = u64_field(
        request,
        "recipientRosterPosition",
        "recipientRosterPosition",
        "recipientRosterPositionMissing",
        "recipientRosterPosition must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let roster = super::accepted_setup::accepted_roster_from_setup_context(setup_context);
    if recipient_roster_position >= roster.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "recipientRosterPosition is outside the setup roster",
        ));
    }
    let rns_limb_index = usize_field(
        request,
        "rnsLimbIndex",
        "rnsLimbIndex",
        "rnsLimbIndexMissing",
        "rnsLimbIndex must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let rns_prime = u64_field(
        request,
        "rnsPrime",
        "rnsPrime",
        "rnsPrimeMissing",
        "rnsPrime must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let ring_degree = usize_field(
        request,
        "ringDegree",
        "ringDegree",
        "ringDegreeMissing",
        "ringDegree must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "ringDegree is outside the selected setup parameters",
        ));
    }
    let share_values = u64_vector_field(
        request,
        "shareValues",
        "shareValues",
        "shareValuesMissing",
        "shareValues must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if share_values.len() != ring_degree || share_values.iter().any(|value| *value >= rns_prime) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "shareValues must be canonical Q_share residues with length ringDegree",
        ));
    }
    let coefficient_commitment_roots = hash_vector_field(
        request,
        "coefficientCommitmentRoots",
        "coefficientCommitmentRoots",
        "coefficientCommitmentRootsMissing",
        "coefficientCommitmentRoots must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    if coefficient_commitment_roots.len() != roster.decryption_threshold as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientCommitmentRoots must bind every setup Shamir coefficient",
        ));
    }
    let mut coefficient_commitment_values =
        Vec::with_capacity(roster.decryption_threshold as usize);
    for (shamir_coefficient_index, commitment_root) in
        coefficient_commitment_roots.iter().enumerate()
    {
        let shamir_coefficient_index = shamir_coefficient_index as u64;
        if source_trustee_binding
            .coefficient_commitment_roots
            .get(&(rns_limb_index, shamir_coefficient_index))
            .map(String::as_str)
            != Some(commitment_root.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "coefficientCommitmentRoots must match the public source trustee commitment record",
            ));
        }
        let Some(material_binding) =
            coefficient_commitments.get(&(rns_limb_index, shamir_coefficient_index))
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sourceTrusteeCoefficientCommitmentMaterialRecords must include the requested proof limb",
            ));
        };
        if material_binding.commitment_root != *commitment_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "coefficient commitment material root must match coefficientCommitmentRoots",
            ));
        }
        coefficient_commitment_values.push(material_binding.commitment.clone());
    }

    let coefficient_messages_by_shamir_index = u64_matrix_field(
        request,
        "coefficientMessagesByShamirIndex",
        "coefficientMessagesByShamirIndex",
        "coefficientMessagesMissing",
        "coefficientMessagesByShamirIndex must be provided for private VSS proof generation",
    )?;
    let opening_randomness_by_shamir_index = i128_matrix3_field(
        request,
        "openingRandomnessByShamirIndex",
        "openingRandomnessByShamirIndex",
        "openingRandomnessMissing",
        "openingRandomnessByShamirIndex must be provided for private VSS proof generation",
    )?;
    let carry_witnesses = derive_private_vss_carry_witnesses(
        rns_prime,
        recipient_roster_position,
        ring_degree,
        roster.decryption_threshold as usize,
        &share_values,
        &coefficient_messages_by_shamir_index,
    )?;
    let proof_randomness_seed_hex = string_field(
        request,
        "proofRandomnessSeedHex",
        "proofRandomnessSeedHex",
        "proofRandomnessSeedMissing",
        "proofRandomnessSeedHex must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let proof_randomness_nonce_hex = string_field(
        request,
        "proofRandomnessNonceHex",
        "proofRandomnessNonceHex",
        "proofRandomnessNonceMissing",
        "proofRandomnessNonceHex must be provided for private VSS proof generation",
    )
    .map_err(private_vss_refusal_to_error)?;
    let share_values_hash = derive_canonical_object_hash(&json!({
        "objectType": "PrivateVssShareValueVector",
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shareValues": share_values,
    }))?;
    let bound_proof_randomness_seed_hex = statement_bound_private_vss_proof_randomness_seed_hex(
        setup_context,
        public_matrix_seed_hash,
        private_envelope_aad_hash,
        &source_trustee_binding.source_trustee_identity,
        source_trustee_binding.source_trustee_roster_position,
        &source_trustee_binding.source_trustee_commitment_root,
        recipient_identity,
        recipient_roster_position,
        rns_limb_index,
        rns_prime,
        ring_degree,
        &coefficient_commitment_roots,
        &share_values_hash,
        proof_randomness_seed_hex,
        proof_randomness_nonce_hex,
    )?;
    let proof_record =
        private_vss_share_succinct_proof_record(PrivateVssShareSuccinctProofGenerationInput {
            setup_context,
            public_matrix_seed_hash,
            private_envelope_aad_hash,
            source_trustee_identity: &source_trustee_binding.source_trustee_identity,
            source_trustee_roster_position: source_trustee_binding.source_trustee_roster_position,
            recipient_identity,
            recipient_roster_position,
            source_trustee_commitment_root: &source_trustee_binding.source_trustee_commitment_root,
            rns_limb_index,
            rns_prime,
            ring_degree,
            coefficient_commitment_roots: &coefficient_commitment_roots,
            share_values: &share_values,
            share_values_hash: &share_values_hash,
            coefficient_commitments: &coefficient_commitment_values,
            witness: &PrivateVssShareSuccinctProofWitness {
                coefficient_messages_by_shamir_index,
                opening_randomness_by_shamir_index,
                carry_witnesses,
            },
            proof_randomness_seed_hex: &bound_proof_randomness_seed_hex,
        })?;

    Ok(json!({
        "operation": "generatePrivateVssShareProof",
        "sourceTrusteeIdentity": source_trustee_binding.source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_binding.source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "shareValuesHash": share_values_hash,
        "privateVssShareProof": proof_record,
    }))
}

#[allow(clippy::too_many_arguments)]
fn statement_bound_private_vss_proof_randomness_seed_hex(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    private_envelope_aad_hash: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    source_trustee_commitment_root: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    coefficient_commitment_roots: &[String],
    share_values_hash: &str,
    proof_randomness_seed_hex: &str,
    proof_randomness_nonce_hex: &str,
) -> CanonicalResult<String> {
    validate_exact_randomness_hex(
        proof_randomness_seed_hex,
        PROOF_RANDOMNESS_SEED_BYTES,
        "proofRandomnessSeedHex",
    )?;
    validate_exact_randomness_hex(
        proof_randomness_nonce_hex,
        PROOF_RANDOMNESS_NONCE_BYTES,
        "proofRandomnessNonceHex",
    )?;

    derive_canonical_object_hash(&json!({
        "objectType": "PrivateVssShareProofRandomnessBinding",
        "proofFamily": "vss-opening-carry",
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "privateEnvelopeAadHash": private_envelope_aad_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "shareValuesHash": share_values_hash,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
    }))
}

fn u64_matrix_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let rows = array_field(value, field_name, object_path, reason_code, message)
        .map_err(private_vss_refusal_to_error)?;
    rows.iter()
        .enumerate()
        .map(|(row_index, row)| {
            row.as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{object_path}.{row_index} must be an array"),
                    )
                })?
                .iter()
                .enumerate()
                .map(|(column_index, item)| {
                    item.as_u64().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "{object_path}.{row_index}.{column_index} must be an unsigned integer"
                            ),
                        )
                    })
                })
                .collect()
        })
        .collect()
}

fn i128_matrix3_field(
    value: &Value,
    field_name: &str,
    object_path: &str,
    reason_code: &'static str,
    message: impl Into<String>,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    let outer_rows = array_field(value, field_name, object_path, reason_code, message)
        .map_err(private_vss_refusal_to_error)?;
    outer_rows
        .iter()
        .enumerate()
        .map(|(outer_index, middle_value)| {
            let middle_rows = middle_value.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_path}.{outer_index} must be an array"),
                )
            })?;
            middle_rows
                .iter()
                .enumerate()
                .map(|(middle_index, inner_value)| {
                    let inner_values = inner_value.as_array().ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!("{object_path}.{outer_index}.{middle_index} must be an array"),
                        )
                    })?;
                    inner_values
                        .iter()
                        .enumerate()
                        .map(|(inner_index, item)| {
                            decimal_i128_value(item).ok_or_else(|| {
                                CanonicalError::new(
                                    CanonicalErrorCode::InvalidFixture,
                                    format!(
                                        "{object_path}.{outer_index}.{middle_index}.{inner_index} must be a signed integer or decimal string"
                                    ),
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn derive_private_vss_carry_witnesses(
    rns_prime: u64,
    recipient_roster_position: u64,
    ring_degree: usize,
    decryption_threshold: usize,
    share_values: &[u64],
    coefficient_messages_by_shamir_index: &[Vec<u64>],
) -> CanonicalResult<Vec<i128>> {
    if coefficient_messages_by_shamir_index.len() != decryption_threshold {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientMessagesByShamirIndex must contain every setup Shamir coefficient",
        ));
    }
    if coefficient_messages_by_shamir_index.iter().any(|messages| {
        messages.len() != ring_degree || messages.iter().any(|value| *value >= rns_prime)
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "coefficientMessagesByShamirIndex entries must be canonical Q_share residues with length ringDegree",
        ));
    }
    let trustee_point = canonical_trustee_point(
        usize::try_from(recipient_roster_position).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "recipientRosterPosition does not fit usize",
            )
        })?,
        rns_prime,
    )?;
    let mut trustee_point_powers = Vec::with_capacity(coefficient_messages_by_shamir_index.len());
    let mut trustee_point_power = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for _ in coefficient_messages_by_shamir_index {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power = trustee_point_power
            .checked_mul(trustee_point_wide)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "private VSS trustee point power overflowed during proof generation",
                )
            })?;
    }
    let modulus_wide = u128::from(rns_prime);
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let unreduced_value = coefficient_messages_by_shamir_index
            .iter()
            .zip(trustee_point_powers.iter())
            .try_fold(0_u128, |accumulated_value, (messages, trustee_power)| {
                let term = u128::from(messages[coefficient_position])
                    .checked_mul(*trustee_power)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            "private VSS unreduced Shamir term overflowed during proof generation",
                        )
                    })?;
                accumulated_value.checked_add(term).ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "private VSS unreduced Shamir evaluation overflowed during proof generation",
                    )
                })
            })?;
        let reduced_value = u64::try_from(unreduced_value % modulus_wide).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "private VSS reduced share value does not fit u64",
            )
        })?;
        // The carry is fully determined by the coefficient messages and the prime (not an independent input); this check rejects messages that do not reduce to the published share.
        if share_values.get(coefficient_position) != Some(&reduced_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "shareValues do not match the private coefficient witness at coefficient {coefficient_position}"
                ),
            ));
        }
        let carry = unreduced_value / modulus_wide;
        carry_witnesses.push(i128::try_from(carry).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "private VSS carry witness does not fit i128",
            )
        })?);
    }

    Ok(carry_witnesses)
}
