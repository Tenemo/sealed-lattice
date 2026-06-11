use super::*;

struct ParsedEvaluationKeyShareLnpProof {
    challenge: u64,
    key_switch_relation_commitments: Vec<Vec<Vec<BigInt>>>,
    secret_commitment_relation_commitments: Vec<SetupCommitmentValue>,
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    error_response_by_digit: Vec<Vec<i128>>,
    relinearization_source_response_by_digit: Vec<Vec<i128>>,
    carry_response_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
    tbox_proof_bytes: Vec<u8>,
    tbox_commitment_prefix_hash: String,
    parameter_profile_hash_hex: String,
}

pub(in crate::bgv::setup) fn verify_evaluation_key_share_lnp_relation_proof(
    input: EvaluationKeyShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<EvaluationKeyShareLnpProofVerification> {
    validate_evaluation_key_share_statement_material(&input)?;
    let component_b_by_digit = component_b_vectors_from_record(
        input.proof_family,
        input.proof_record,
        input.transported_key_switch_component_material,
    )?;
    let statement_value = evaluation_key_share_lnp_statement_value(&input, &component_b_by_digit)?;
    let statement_hash =
        evaluation_key_share_lnp_statement_hash(input.proof_family, &statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let parsed_proof = parse_evaluation_key_share_lnp_relation_proof(
        input.proof_family,
        input.proof_bytes,
        &statement_hash,
        input.constant_commitments,
        &component_b_by_digit,
    )?;
    let expected_parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;
    if parsed_proof.parameter_profile_hash_hex != expected_parameter_profile_hash {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof is not bound to the accepted tbox parameter profile",
        ));
    }
    let encoded_commitments = encode_evaluation_key_share_relation_commitments(
        &parsed_proof.key_switch_relation_commitments,
        &parsed_proof.secret_commitment_relation_commitments,
    )?;
    let layout = input.proof_family.tbox_layout();
    let expected_tbox_prefix_binding_seed =
        super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
            &layout,
            &statement_hash_hex,
            &expected_parameter_profile_hash,
            &encoded_commitments,
        )?;
    let expected_tbox_prefix = encode_evaluation_key_share_lnp_tbox_prefix(
        input.proof_family,
        &layout,
        &expected_tbox_prefix_binding_seed,
    )?;
    let expected_tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &expected_tbox_prefix,
        )?;
    if parsed_proof.tbox_commitment_prefix_hash != expected_tbox_commitment_prefix_hash {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP tbox commitment prefix is not bound to the statement and relation commitments",
        ));
    }
    let relation_commitment_hash_hex = evaluation_key_share_lnp_relation_commitment_hash(
        input.proof_family,
        &statement_hash_hex,
        &expected_parameter_profile_hash,
        &parsed_proof.tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let recomputed_challenge = evaluation_key_share_lnp_relation_challenge(
        input.proof_family,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    if parsed_proof.challenge != recomputed_challenge {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP scalar challenge does not match its relation transcript",
        ));
    }
    let tbox_summary = super::setup_proof::verify_setup_proof_lnp_tbox_proof_bytes(
        &layout,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
        &parsed_proof.tbox_proof_bytes,
    )?;
    verify_evaluation_key_share_response_bounds(
        input.proof_family,
        input.proof_record,
        parsed_proof.challenge,
        &component_b_by_digit,
        &parsed_proof,
    )?;
    verify_evaluation_key_secret_commitment_responses(
        input.public_matrix_seed_hash,
        input.constant_commitments,
        parsed_proof.challenge,
        &parsed_proof.secret_commitment_relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.negative_indicator_response_coefficients,
        &parsed_proof.randomness_response_by_limb,
    )?;
    verify_evaluation_key_share_key_switch_responses(
        input.proof_family,
        input.proof_record,
        &component_b_by_digit,
        parsed_proof.challenge,
        &parsed_proof.key_switch_relation_commitments,
        &parsed_proof.secret_response_coefficients,
        &parsed_proof.error_response_by_digit,
        &parsed_proof.relinearization_source_response_by_digit,
        &parsed_proof.carry_response_by_digit_by_limb,
    )?;

    Ok(EvaluationKeyShareLnpProofVerification {
        proof_size_bytes: input.proof_bytes.len(),
        statement_hash_hex,
        relation_commitment_hash_hex,
        tbox_commitment_prefix_hash: parsed_proof.tbox_commitment_prefix_hash,
        z34_seed_material_hash: tbox_summary.z34_seed_material_hash,
        z34_challenge_seed_hash: tbox_summary.z34_challenge_seed_hash,
        z34_challenge_tail_hash: tbox_summary.z34_challenge_tail_hash,
        z34_challenge_row_domain_hash: tbox_summary.z34_challenge_row_domain_hash,
        z34_challenge_z3_row_set_hash: tbox_summary.z34_challenge_z3_row_set_hash,
        z34_challenge_z4_row_set_hash: tbox_summary.z34_challenge_z4_row_set_hash,
        tbox_lower_protocol_challenge_hash: tbox_summary.tbox_lower_protocol_challenge_hash,
        z34_z3_check_window_hash: tbox_summary.z34_z3_check_window_hash,
        z34_z4_check_window_hash: tbox_summary.z34_z4_check_window_hash,
        z34_z3_l2_squared_decimal: tbox_summary.z3_l2_squared.to_string(),
        z34_z4_infinity_norm_decimal: tbox_summary.z4_infinity_norm.to_string(),
        challenge: parsed_proof.challenge,
    })
}

pub(super) fn validate_evaluation_key_share_statement_material(
    input: &EvaluationKeyShareLnpProofVerificationInput<'_>,
) -> CanonicalResult<()> {
    if input.constant_commitments.len() != DATA_PRIMES.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof requires one same-secret constant commitment per Q_share limb",
        ));
    }
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    if ring_degree == 0 || ring_degree > POLYNOMIAL_DEGREE {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof ringDegree is outside the selected profile",
        ));
    }
    for (rns_limb_index, commitment) in input.constant_commitments.iter().enumerate() {
        if commitment.source_rns_limb_index != rns_limb_index
            || commitment.source_message_modulus != DATA_PRIMES[rns_limb_index]
            || commitment.shamir_coefficient_index != 0
            || commitment.ring_degree != ring_degree
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key proof same-secret commitments must follow Q_share order and proof ringDegree",
            ));
        }
    }
    if input.proof_record.get("setupProofBinding") != Some(input.setup_proof_binding) {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof setupProofBinding must match the accepted setup-proof profile",
        ));
    }
    let expected_tbox_parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;
    if input
        .proof_record
        .get(input.proof_family.tbox_parameter_profile_hash_field())
        .and_then(Value::as_str)
        != Some(expected_tbox_parameter_profile_hash.as_str())
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof tbox parameter profile hash does not match the accepted profile",
        ));
    }
    if input.proof_record.get("sameSecretStatementRoot")
        != input
            .same_secret_statement_record
            .get("sameSecretStatementRoot")
        || input.proof_record.get("trusteeSecretCommitmentRoot")
            != input
                .same_secret_statement_record
                .get("trusteeSecretCommitmentRoot")
        || input.proof_record.get("trusteeIdentity")
            != input.same_secret_statement_record.get("trusteeIdentity")
        || input.proof_record.get("trusteeRosterPosition")
            != input
                .same_secret_statement_record
                .get("trusteeRosterPosition")
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key proof record must bind the accepted same-secret statement",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        input.setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;

    Ok(())
}

fn parse_evaluation_key_share_lnp_relation_proof(
    proof_family: EvaluationKeyShareProofFamily,
    proof_bytes: &[u8],
    expected_statement_hash: &[u8; 64],
    expected_commitments: &[SetupCommitmentValue],
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<ParsedEvaluationKeyShareLnpProof> {
    let mut cursor = 0_usize;
    let magic = read_fixed::<8>(proof_bytes, &mut cursor)?;
    if &magic != proof_family.proof_magic() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof has the wrong format marker",
        ));
    }
    let statement_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    if &statement_hash != expected_statement_hash {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof is not bound to this statement",
        ));
    }
    let parameter_profile_hash = read_fixed::<64>(proof_bytes, &mut cursor)?;
    let parameter_profile_hash_hex = to_hex(&parameter_profile_hash);
    let challenge = read_u64(proof_bytes, &mut cursor)?;
    if challenge == 0 || challenge > evaluation_key_share_scalar_challenge_maximum()? {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP scalar challenge is outside the expected range",
        ));
    }
    let tbox_proof_byte_count =
        usize::try_from(read_u64(proof_bytes, &mut cursor)?).map_err(|_| {
            invalid_evaluation_key_share_proof(
                "evaluation-key LNP tbox proof byte count does not fit usize",
            )
        })?;
    if tbox_proof_byte_count == 0 {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof must include tbox proof bytes",
        ));
    }
    let tbox_proof_bytes = read_bytes(proof_bytes, &mut cursor, tbox_proof_byte_count)?;
    let layout = proof_family.tbox_layout();
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let digit_count = component_b_by_digit.len();
    let limb_count = component_b_by_digit
        .first()
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no digits"))?;
    let ring_degree = component_b_by_digit
        .first()
        .and_then(|digit| digit.first())
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no limbs"))?;
    let key_switch_relation_commitments = read_signed_big_int_matrix3(
        proof_bytes,
        &mut cursor,
        digit_count,
        limb_count,
        ring_degree,
    )?;
    let secret_commitment_relation_commitments = expected_commitments
        .iter()
        .map(|expected_commitment| {
            read_evaluation_key_share_relation_commitment(
                proof_bytes,
                &mut cursor,
                expected_commitment,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let secret_response_coefficients = read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
    let negative_indicator_response_coefficients =
        read_i128_vector(proof_bytes, &mut cursor, ring_degree)?;
    let randomness_response_by_limb = expected_commitments
        .iter()
        .map(|expected_commitment| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|_| {
                    read_i128_vector(proof_bytes, &mut cursor, expected_commitment.ring_degree)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let error_response_by_digit =
        read_i128_matrix(proof_bytes, &mut cursor, digit_count, ring_degree)?;
    let relinearization_source_response_by_digit =
        if proof_family == EvaluationKeyShareProofFamily::Relinearization {
            read_i128_matrix(proof_bytes, &mut cursor, digit_count, ring_degree)?
        } else {
            Vec::new()
        };
    let carry_response_by_digit_by_limb = read_i128_matrix3(
        proof_bytes,
        &mut cursor,
        digit_count,
        limb_count,
        ring_degree,
    )?;
    if cursor != proof_bytes.len() {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key LNP proof has trailing bytes",
        ));
    }

    Ok(ParsedEvaluationKeyShareLnpProof {
        challenge,
        key_switch_relation_commitments,
        secret_commitment_relation_commitments,
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        error_response_by_digit,
        relinearization_source_response_by_digit,
        carry_response_by_digit_by_limb,
        tbox_proof_bytes,
        tbox_commitment_prefix_hash,
        parameter_profile_hash_hex,
    })
}

fn read_evaluation_key_share_relation_commitment(
    proof_bytes: &[u8],
    cursor: &mut usize,
    expected_commitment: &SetupCommitmentValue,
) -> CanonicalResult<SetupCommitmentValue> {
    let mut limbs = Vec::with_capacity(expected_commitment.limbs.len());
    for expected_limb in &expected_commitment.limbs {
        let mut rows = Vec::with_capacity(expected_limb.rows.len());
        for expected_row in &expected_limb.rows {
            let mut row = Vec::with_capacity(expected_row.len());
            for _ in expected_row {
                let coefficient = read_u64(proof_bytes, cursor)?;
                if coefficient >= expected_limb.modulus {
                    return Err(invalid_evaluation_key_share_proof(
                        "evaluation-key relation commitment coefficient is not canonical",
                    ));
                }
                row.push(coefficient);
            }
            rows.push(row);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index: expected_limb.commitment_modulus_index,
            modulus: expected_limb.modulus,
            rows,
        });
    }

    Ok(SetupCommitmentValue {
        source_rns_limb_index: expected_commitment.source_rns_limb_index,
        source_message_modulus: expected_commitment.source_message_modulus,
        shamir_coefficient_index: expected_commitment.shamir_coefficient_index,
        ring_degree: expected_commitment.ring_degree,
        limbs,
    })
}

fn verify_evaluation_key_share_response_bounds(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    challenge: u64,
    component_b_by_digit: &[Vec<Vec<u64>>],
    parsed_proof: &ParsedEvaluationKeyShareLnpProof,
) -> CanonicalResult<()> {
    let ring_degree = component_b_by_digit
        .first()
        .and_then(|digit| digit.first())
        .map(Vec::len)
        .ok_or_else(|| invalid_evaluation_key_share_proof("evaluation-key proof has no limbs"))?;
    let secret_response_bound = evaluation_key_share_secret_response_bound(challenge)?;
    verify_i128_vector_bound(
        &parsed_proof.secret_response_coefficients,
        secret_response_bound,
        "evaluation-key secret response",
    )?;
    verify_i128_vector_bound(
        &parsed_proof.negative_indicator_response_coefficients,
        secret_response_bound,
        "evaluation-key negative-indicator response",
    )?;
    let randomness_response_bound = evaluation_key_share_randomness_response_bound(challenge)?;
    for randomness_responses in &parsed_proof.randomness_response_by_limb {
        for column in randomness_responses {
            verify_i128_vector_bound(
                column,
                randomness_response_bound,
                "evaluation-key opening-randomness response",
            )?;
        }
    }
    let error_response_bound = evaluation_key_share_error_response_bound(challenge)?;
    for error_response in &parsed_proof.error_response_by_digit {
        verify_i128_vector_bound(
            error_response,
            error_response_bound,
            "evaluation-key error response",
        )?;
    }
    if proof_family == EvaluationKeyShareProofFamily::Relinearization {
        let source_response_bound = evaluation_key_share_relinearization_source_response_bound(
            challenge,
            proof_record,
            ring_degree,
        )?;
        for source_response in &parsed_proof.relinearization_source_response_by_digit {
            verify_i128_vector_bound(
                source_response,
                source_response_bound,
                "relinearization source response",
            )?;
        }
    }
    let carry_response_bound = evaluation_key_share_carry_response_bound(challenge, ring_degree)?;
    for carry_by_limb in &parsed_proof.carry_response_by_digit_by_limb {
        for carry_response in carry_by_limb {
            verify_i128_vector_bound(
                carry_response,
                carry_response_bound,
                "evaluation-key carry response",
            )?;
        }
    }

    Ok(())
}

fn verify_evaluation_key_secret_commitment_responses(
    public_matrix_seed_hash: &str,
    constant_commitments: &[SetupCommitmentValue],
    challenge: u64,
    relation_commitments: &[SetupCommitmentValue],
    secret_response_coefficients: &[i128],
    negative_indicator_response_coefficients: &[i128],
    randomness_response_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    if relation_commitments.len() != constant_commitments.len()
        || randomness_response_by_limb.len() != constant_commitments.len()
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key commitment response limb count does not match the statement",
        ));
    }
    for (limb_index, ((constant_commitment, relation_commitment), randomness_response)) in
        constant_commitments
            .iter()
            .zip(relation_commitments.iter())
            .zip(randomness_response_by_limb.iter())
            .enumerate()
    {
        let expected_response_commitment = linear_combination_setup_commitments(&[
            (relation_commitment, 1),
            (constant_commitment, u128::from(challenge)),
        ])?;
        let response_message_coefficients = secret_response_coefficients
            .iter()
            .zip(negative_indicator_response_coefficients.iter())
            .map(|(secret_response, negative_indicator_response)| {
                lifted_secret_message_response_big_int(
                    *secret_response,
                    *negative_indicator_response,
                    constant_commitment.source_message_modulus,
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let response_randomness_bound = evaluation_key_share_randomness_response_bound(challenge)?;
        verify_setup_big_signed_lifted_commitment_opening(
            public_matrix_seed_hash,
            &expected_response_commitment,
            &response_message_coefficients,
            randomness_response,
            response_randomness_bound,
        )
        .map_err(|_| {
            invalid_evaluation_key_share_proof(format!(
                "evaluation-key proof VSS commitment response failed for Q_share limb {limb_index}"
            ))
        })?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_evaluation_key_share_key_switch_responses(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    component_b_by_digit: &[Vec<Vec<u64>>],
    challenge: u64,
    relation_commitments: &[Vec<Vec<BigInt>>],
    secret_response_coefficients: &[i128],
    error_response_by_digit: &[Vec<i128>],
    relinearization_source_response_by_digit: &[Vec<i128>],
    carry_response_by_digit_by_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<()> {
    let level = value_usize(proof_record, "level")?;
    let ring_degree = value_usize(proof_record, "ringDegree")?;
    let key_switch_domain = string_field(proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(proof_record, "keySwitchSeedHex")?;
    if proof_family == EvaluationKeyShareProofFamily::Relinearization
        && relinearization_record_uses_same_secret_source(proof_record)
    {
        for (digit_index, source_response) in
            relinearization_source_response_by_digit.iter().enumerate()
        {
            if source_response != secret_response_coefficients {
                return Err(invalid_evaluation_key_share_proof(format!(
                    "relinearization round-one source response must match the same-secret response at digit {digit_index}"
                )));
            }
        }
    }
    let galois_element = proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    for (digit_index, component_b_by_limb) in component_b_by_digit.iter().enumerate() {
        let error_response = error_response_by_digit.get(digit_index).ok_or_else(|| {
            invalid_evaluation_key_share_proof(
                "evaluation-key error response digit count does not match component vectors",
            )
        })?;
        let source_response = match proof_family {
            EvaluationKeyShareProofFamily::Relinearization => relinearization_source_response_by_digit
                .get(digit_index)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "relinearization source response digit count does not match component vectors",
                    )
                })?
                .clone(),
            EvaluationKeyShareProofFamily::Galois => automorphism_i128(
                secret_response_coefficients,
                galois_element.ok_or_else(|| {
                    invalid_evaluation_key_share_proof("Galois proof must include rotation")
                })?,
            )?,
        };
        for (rns_limb_index, component_b) in component_b_by_limb.iter().enumerate() {
            let modulus = DATA_PRIMES[rns_limb_index];
            let public_sample = deterministic_key_switch_public_sample(
                key_switch_domain,
                key_switch_seed_hex,
                digit_index,
                modulus,
                ring_degree,
            );
            let public_sample_secret_product = negacyclic_public_sample_secret_product_big_int(
                &public_sample,
                secret_response_coefficients,
            )?;
            let carry_response = carry_response_by_digit_by_limb
                .get(digit_index)
                .and_then(|limbs| limbs.get(rns_limb_index))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key carry response shape does not match component vectors",
                    )
                })?;
            let relation_commitment = relation_commitments
                .get(digit_index)
                .and_then(|limbs| limbs.get(rns_limb_index))
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key relation commitment shape does not match component vectors",
                    )
                })?;
            if component_b.len() != ring_degree
                || public_sample_secret_product.len() != ring_degree
                || error_response.len() != ring_degree
                || source_response.len() != ring_degree
                || carry_response.len() != ring_degree
                || relation_commitment.len() != ring_degree
            {
                return Err(invalid_evaluation_key_share_proof(
                    "evaluation-key key-switch response width does not match ringDegree",
                ));
            }
            for coefficient_index in 0..ring_degree {
                let mut left_side =
                    BigInt::from(challenge) * BigInt::from(component_b[coefficient_index]);
                left_side += public_sample_secret_product[coefficient_index].clone();
                left_side -= BigInt::from(PLAINTEXT_MODULUS_I64)
                    * BigInt::from(error_response[coefficient_index]);
                let source_term = if rns_limb_index == digit_index {
                    source_response[coefficient_index]
                } else {
                    0
                };
                left_side -= BigInt::from(source_term);
                left_side -=
                    BigInt::from(modulus) * BigInt::from(carry_response[coefficient_index]);
                if left_side != relation_commitment[coefficient_index] {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "evaluation-key key-switch relation failed at level {level}, digit {digit_index}, limb {rns_limb_index}, coefficient {coefficient_index}"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn evaluation_key_share_scalar_challenge_maximum() -> CanonicalResult<u64> {
    let challenge_bits =
        u32::try_from(EVALUATION_KEY_SHARE_SCALAR_CHALLENGE_BITS).map_err(|_| {
            invalid_evaluation_key_share_proof(
                "evaluation-key challenge bit count does not fit u32",
            )
        })?;
    1_u64
        .checked_shl(challenge_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key challenge bound overflowed")
        })
}

fn evaluation_key_share_secret_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_SECRET_MASK_BITS,
        challenge,
        EVALUATION_KEY_SHARE_SECRET_INFINITY_BOUND,
        "evaluation-key secret response",
    )
}

fn evaluation_key_share_error_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_ERROR_MASK_BITS,
        challenge,
        EVALUATION_KEY_SHARE_ERROR_INFINITY_BOUND,
        "evaluation-key error response",
    )
}

fn evaluation_key_share_randomness_response_bound(challenge: u64) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_RANDOMNESS_MASK_BITS,
        challenge,
        SETUP_COMMITMENT_RANDOMNESS_INFINITY_BOUND,
        "evaluation-key opening-randomness response",
    )
}

fn evaluation_key_share_relinearization_source_response_bound(
    challenge: u64,
    proof_record: &Value,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_SOURCE_MASK_BITS,
        challenge,
        relinearization_source_witness_bound(proof_record, ring_degree)?,
        "relinearization source response",
    )
}

pub(super) fn relinearization_source_witness_bound(
    proof_record: &Value,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    let ring_degree = i128::try_from(ring_degree).map_err(|_| {
        invalid_evaluation_key_share_proof("evaluation-key ringDegree does not fit i128")
    })?;
    if relinearization_record_uses_same_secret_source(proof_record) {
        return Ok(ring_degree);
    }

    ring_degree
        .checked_mul(EVALUATION_KEY_SHARE_ROUND_TWO_AGGREGATE_SOURCE_PARTICIPANT_BOUND)
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("round-two relinearization source bound overflowed")
        })
}

fn evaluation_key_share_carry_response_bound(
    challenge: u64,
    ring_degree: usize,
) -> CanonicalResult<i128> {
    let witness_bound = i128::try_from(ring_degree)
        .map_err(|_| {
            invalid_evaluation_key_share_proof("evaluation-key ringDegree does not fit i128")
        })?
        .checked_mul(2)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            invalid_evaluation_key_share_proof("evaluation-key carry bound overflowed")
        })?;
    evaluation_key_share_response_bound(
        EVALUATION_KEY_SHARE_CARRY_MASK_BITS,
        challenge,
        witness_bound,
        "evaluation-key carry response",
    )
}

fn evaluation_key_share_response_bound(
    mask_bits: usize,
    challenge: u64,
    witness_infinity_bound: i128,
    label: &str,
) -> CanonicalResult<i128> {
    let mask_bound = mask_magnitude_bound(mask_bits, label)?;
    let challenge_term = i128::from(challenge)
        .checked_mul(witness_infinity_bound)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} bound overflowed")))?;
    mask_bound
        .checked_add(challenge_term)
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} bound overflowed")))
}

fn mask_magnitude_bound(mask_bits: usize, label: &str) -> CanonicalResult<i128> {
    let mask_bits = u32::try_from(mask_bits).map_err(|_| {
        invalid_evaluation_key_share_proof(format!("{label} mask bit count overflowed"))
    })?;
    1_i128
        .checked_shl(mask_bits)
        .and_then(|bound| bound.checked_sub(1))
        .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} mask bound overflowed")))
}

fn verify_i128_vector_bound(values: &[i128], bound: i128, label: &str) -> CanonicalResult<()> {
    for value in values {
        let magnitude = value
            .checked_abs()
            .ok_or_else(|| invalid_evaluation_key_share_proof(format!("{label} overflowed")))?;
        if magnitude > bound {
            return Err(invalid_evaluation_key_share_proof(format!(
                "{label} exceeds the accepted no-wrap bound"
            )));
        }
    }

    Ok(())
}
