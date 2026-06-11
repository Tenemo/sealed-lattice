use super::*;

pub(crate) fn generate_evaluation_key_share_lnp_proof_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "proofFamily",
            "publicMatrixSeedHash",
            "proofRecord",
            "sameSecretStatementRecord",
            "constantCommitments",
            "setupProofBinding",
            "transportedKeySwitchComponentMaterial",
            "secretCoefficients",
            "openingRandomnessByLimb",
            "errorCoefficientsByDigit",
            "relinearizationSourceCoefficientsByDigit",
            "roundOneAggregateSourceCoefficientsByDigit",
            "proofRandomnessSource",
            "proofRandomnessSeedHex",
        ],
        "generateEvaluationKeyShareLnpProof",
    )?;

    let proof_family = evaluation_key_share_proof_family_from_request(request)?;
    let public_matrix_seed_hash = string_field(request, "publicMatrixSeedHash")?;
    validate_lowercase_hash(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let proof_record = object_field(request, "proofRecord")?;
    let same_secret_statement_record = object_field(request, "sameSecretStatementRecord")?;
    let setup_proof_binding = object_field(request, "setupProofBinding")?;
    let constant_commitments = setup_commitment_values_field(request, "constantCommitments")?;
    let transported_key_switch_component_material = request
        .get("transportedKeySwitchComponentMaterial")
        .map(|material| {
            if material.is_object() {
                Ok(material)
            } else {
                Err(invalid_evaluation_key_share_proof(
                    "transportedKeySwitchComponentMaterial must be an object",
                ))
            }
        })
        .transpose()?;
    let component_b_by_digit = component_b_vectors_from_record(
        proof_family,
        proof_record,
        transported_key_switch_component_material,
    )?;
    let secret_coefficients = i64_vector_field(request, "secretCoefficients")?;
    let opening_randomness_by_limb = i128_matrix3_field(request, "openingRandomnessByLimb")?;
    let error_coefficients_by_digit = i64_matrix_field(request, "errorCoefficientsByDigit")?;
    let relinearization_source_coefficients_by_digit = match (
        proof_family,
        request.get("relinearizationSourceCoefficientsByDigit"),
    ) {
        (EvaluationKeyShareProofFamily::Relinearization, Some(_)) => {
            i128_matrix_field(request, "relinearizationSourceCoefficientsByDigit")?
        }
        (EvaluationKeyShareProofFamily::Relinearization, None) => {
            return Err(invalid_evaluation_key_share_proof(
                "relinearizationSourceCoefficientsByDigit is required for relinearization proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Galois, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "relinearizationSourceCoefficientsByDigit must not be provided for Galois proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Galois, None) => Vec::new(),
    };
    let round_one_aggregate_source_coefficients_by_digit = match (
        proof_family,
        relinearization_record_uses_same_secret_source(proof_record),
        request.get("roundOneAggregateSourceCoefficientsByDigit"),
    ) {
        (EvaluationKeyShareProofFamily::Relinearization, false, Some(_)) => {
            i128_matrix_field(request, "roundOneAggregateSourceCoefficientsByDigit")?
        }
        (EvaluationKeyShareProofFamily::Relinearization, false, None) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit is required for relinearization round-two proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Relinearization, true, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit must not be provided for relinearization round-one proof generation",
            ));
        }
        (EvaluationKeyShareProofFamily::Relinearization, true, None)
        | (EvaluationKeyShareProofFamily::Galois, _, None) => Vec::new(),
        (EvaluationKeyShareProofFamily::Galois, _, Some(_)) => {
            return Err(invalid_evaluation_key_share_proof(
                "roundOneAggregateSourceCoefficientsByDigit must not be provided for Galois proof generation",
            ));
        }
    };
    let proof_randomness_source = proof_randomness_source(request)?;
    let proof_randomness_seed_hex = string_field(request, "proofRandomnessSeedHex")?;
    validate_proof_randomness_seed(proof_randomness_seed_hex, "proofRandomnessSeedHex")?;

    let witness = EvaluationKeyShareLnpProofWitness {
        secret_coefficients,
        opening_randomness_by_limb,
        error_coefficients_by_digit,
        relinearization_source_coefficients_by_digit,
        round_one_aggregate_source_coefficients_by_digit,
    };
    let generation_input = EvaluationKeyShareLnpProofGenerationInput {
        proof_family,
        public_matrix_seed_hash,
        proof_record,
        same_secret_statement_record,
        constant_commitments: &constant_commitments,
        component_b_by_digit: &component_b_by_digit,
        setup_proof_binding,
        transported_key_switch_component_material,
        witness: &witness,
        proof_randomness_seed_hex,
    };
    let proof_bytes = generate_evaluation_key_share_lnp_relation_proof(generation_input)?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    let proof_bytes_hash =
        evaluation_key_share_lnp_relation_proof_bytes_hash(proof_family, &proof_bytes);

    let mut response = json!({
        "ok": true,
        "operation": "generateEvaluationKeyShareLnpProof",
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": proof_family.proof_family(),
        "proofVerificationStatus": proof_family.proof_verification_status(),
        "proofModelStatus": proof_family.proof_model_status(),
        "statementHash": verification.statement_hash_hex,
        "relationCommitmentHash": verification.relation_commitment_hash_hex,
        "tboxCommitmentPrefixHash": verification.tbox_commitment_prefix_hash,
        "z34SeedMaterialHash": verification.z34_seed_material_hash,
        "z34ChallengeSeedHash": verification.z34_challenge_seed_hash,
        "z34ChallengeTailHash": verification.z34_challenge_tail_hash,
        "z34ChallengeRowDomainHash": verification.z34_challenge_row_domain_hash,
        "z34ChallengeZ3RowSetHash": verification.z34_challenge_z3_row_set_hash,
        "z34ChallengeZ4RowSetHash": verification.z34_challenge_z4_row_set_hash,
        "tboxLowerProtocolChallengeHash": verification.tbox_lower_protocol_challenge_hash,
        "z34Z3CheckWindowHash": verification.z34_z3_check_window_hash,
        "z34Z4CheckWindowHash": verification.z34_z4_check_window_hash,
        "z34Z3L2SquaredDecimal": verification.z34_z3_l2_squared_decimal,
        "z34Z4InfinityNormDecimal": verification.z34_z4_infinity_norm_decimal,
        "challenge": verification.challenge.to_string(),
        "proofSizeBytes": verification.proof_size_bytes,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesHex": to_hex(&proof_bytes),
        "proofRandomness": {
            "source": proof_randomness_source,
            "seedBytes": 64,
            "retention": "proof randomness seed material is consumed for proof generation and is not returned"
        }
    });
    response[proof_family.tbox_parameter_profile_hash_field()] =
        json!(proof_family.tbox_parameter_profile_hash()?);

    Ok(response)
}

pub(in crate::bgv::setup) fn generate_evaluation_key_share_lnp_relation_proof(
    input: EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let (proof_bytes, _verification) =
        generate_evaluation_key_share_lnp_relation_proof_with_metadata(input)?;

    Ok(proof_bytes)
}

pub(in crate::bgv::setup) fn generate_evaluation_key_share_lnp_relation_proof_with_metadata(
    input: EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<(Vec<u8>, EvaluationKeyShareLnpProofVerification)> {
    validate_evaluation_key_share_generation_material(&input)?;
    let statement_input = EvaluationKeyShareLnpProofVerificationInput {
        proof_family: input.proof_family,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        proof_record: input.proof_record,
        same_secret_statement_record: input.same_secret_statement_record,
        constant_commitments: input.constant_commitments,
        setup_proof_binding: input.setup_proof_binding,
        transported_key_switch_component_material: input.transported_key_switch_component_material,
        proof_bytes: &[],
    };
    let statement_value =
        evaluation_key_share_lnp_statement_value(&statement_input, input.component_b_by_digit)?;
    let statement_hash =
        evaluation_key_share_lnp_statement_hash(input.proof_family, &statement_value)?;
    let statement_hash_hex = to_hex(&statement_hash);
    let layout = input.proof_family.tbox_layout();
    let parameter_profile_hash = input.proof_family.tbox_parameter_profile_hash()?;

    let masks = sample_evaluation_key_share_masks(&input)?;
    let key_switch_relation_commitments =
        key_switch_relation_commitments_from_masks(&input, &masks)?;
    let secret_commitment_relation_commitments =
        secret_commitment_relation_commitments_from_masks(&input, &masks)?;
    let encoded_commitments = encode_evaluation_key_share_relation_commitments(
        &key_switch_relation_commitments,
        &secret_commitment_relation_commitments,
    )?;
    let tbox_prefix_binding_seed = super::setup_proof::setup_proof_lnp_tbox_prefix_binding_seed(
        &layout,
        &statement_hash_hex,
        &parameter_profile_hash,
        &encoded_commitments,
    )?;
    let mut tbox_proof_bytes = encode_evaluation_key_share_lnp_tbox_prefix(
        input.proof_family,
        &layout,
        &tbox_prefix_binding_seed,
    )?;
    let tbox_commitment_prefix_hash =
        super::setup_proof::setup_proof_lnp_tbox_commitment_prefix_hash(
            &layout,
            &tbox_proof_bytes,
        )?;
    let relation_commitment_hash_hex = evaluation_key_share_lnp_relation_commitment_hash(
        input.proof_family,
        &statement_hash_hex,
        &parameter_profile_hash,
        &tbox_commitment_prefix_hash,
        &encoded_commitments,
    );
    let challenge = evaluation_key_share_lnp_relation_challenge(
        input.proof_family,
        &statement_hash_hex,
        &relation_commitment_hash_hex,
    )?;
    let tbox_summary =
        super::setup_proof::append_setup_proof_lnp_tbox_generated_suffix_with_summary(
            &mut tbox_proof_bytes,
            &layout,
            &statement_hash_hex,
            &relation_commitment_hash_hex,
        )?;

    let responses = evaluation_key_share_responses(&input, &masks, challenge)?;
    let mut proof_bytes = Vec::new();
    proof_bytes.extend_from_slice(input.proof_family.proof_magic());
    proof_bytes.extend_from_slice(&statement_hash);
    proof_bytes.extend_from_slice(&hash_hex_to_fixed_bytes(&parameter_profile_hash)?);
    proof_bytes.extend_from_slice(&challenge.to_le_bytes());
    let tbox_proof_size = u64::try_from(tbox_proof_bytes.len()).map_err(|_| {
        invalid_evaluation_key_share_proof("evaluation-key LNP tbox proof size does not fit u64")
    })?;
    proof_bytes.extend_from_slice(&tbox_proof_size.to_le_bytes());
    proof_bytes.extend_from_slice(&tbox_proof_bytes);
    write_signed_big_int_matrix3(&mut proof_bytes, &key_switch_relation_commitments)?;
    write_setup_commitments(&mut proof_bytes, &secret_commitment_relation_commitments);
    write_i128_vector(&mut proof_bytes, &responses.secret_response_coefficients);
    write_i128_vector(
        &mut proof_bytes,
        &responses.negative_indicator_response_coefficients,
    );
    write_i128_matrix3(&mut proof_bytes, &responses.randomness_response_by_limb);
    write_i128_matrix(&mut proof_bytes, &responses.error_response_by_digit);
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
        write_i128_matrix(
            &mut proof_bytes,
            &responses.relinearization_source_response_by_digit,
        );
    }
    write_i128_matrix3(&mut proof_bytes, &responses.carry_response_by_digit_by_limb);

    let proof_size_bytes = proof_bytes.len();
    let verification = EvaluationKeyShareLnpProofVerification {
        proof_size_bytes,
        statement_hash_hex,
        relation_commitment_hash_hex,
        tbox_commitment_prefix_hash,
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
        challenge,
    };

    Ok((proof_bytes, verification))
}

fn validate_evaluation_key_share_generation_material(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<()> {
    let verification_input = EvaluationKeyShareLnpProofVerificationInput {
        proof_family: input.proof_family,
        public_matrix_seed_hash: input.public_matrix_seed_hash,
        proof_record: input.proof_record,
        same_secret_statement_record: input.same_secret_statement_record,
        constant_commitments: input.constant_commitments,
        setup_proof_binding: input.setup_proof_binding,
        transported_key_switch_component_material: input.transported_key_switch_component_material,
        proof_bytes: &[],
    };
    validate_evaluation_key_share_statement_material(&verification_input)?;
    let parsed_component_b = component_b_vectors_from_record(
        input.proof_family,
        input.proof_record,
        input.transported_key_switch_component_material,
    )?;
    if parsed_component_b != input.component_b_by_digit {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key generation component vectors must match the proof record",
        ));
    }
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    if input.witness.secret_coefficients.len() != ring_degree
        || input.witness.opening_randomness_by_limb.len() != DATA_PRIMES.len()
        || input.witness.error_coefficients_by_digit.len() != input.component_b_by_digit.len()
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key witness shape does not match proof statement",
        ));
    }
    if input
        .witness
        .secret_coefficients
        .iter()
        .any(|coefficient| !(-1..=1).contains(coefficient))
    {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key secret witness must be ternary",
        ));
    }
    for limb_randomness in &input.witness.opening_randomness_by_limb {
        if limb_randomness.len() != SETUP_COMMITMENT_RANDOMNESS_WIDTH
            || limb_randomness
                .iter()
                .any(|column| column.len() != ring_degree)
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key opening-randomness witness shape does not match proof statement",
            ));
        }
    }
    for error in &input.witness.error_coefficients_by_digit {
        if error.len() != ring_degree
            || error
                .iter()
                .any(|coefficient| !(-2..=2).contains(coefficient))
        {
            return Err(invalid_evaluation_key_share_proof(
                "evaluation-key error witness must be centered-binomial support with the proof ringDegree",
            ));
        }
    }
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization
        && (input
            .witness
            .relinearization_source_coefficients_by_digit
            .len()
            != input.component_b_by_digit.len()
            || input
                .witness
                .relinearization_source_coefficients_by_digit
                .iter()
                .any(|source| source.len() != ring_degree))
    {
        return Err(invalid_evaluation_key_share_proof(
            "relinearization source witness shape does not match proof statement",
        ));
    }
    if input.proof_family == EvaluationKeyShareProofFamily::Relinearization {
        let is_round_one = relinearization_record_uses_same_secret_source(input.proof_record);
        if is_round_one {
            if !input
                .witness
                .round_one_aggregate_source_coefficients_by_digit
                .is_empty()
            {
                return Err(invalid_evaluation_key_share_proof(
                    "round-one relinearization proof generation must not include round-one aggregate source witness material",
                ));
            }
        } else if input
            .witness
            .round_one_aggregate_source_coefficients_by_digit
            .len()
            != input.component_b_by_digit.len()
            || input
                .witness
                .round_one_aggregate_source_coefficients_by_digit
                .iter()
                .any(|source| source.len() != ring_degree)
        {
            return Err(invalid_evaluation_key_share_proof(
                "round-one aggregate source witness shape does not match proof statement",
            ));
        }
        let source_bound = relinearization_source_witness_bound(input.proof_record, ring_degree)?;
        let secret_coefficients = input
            .witness
            .secret_coefficients
            .iter()
            .map(|coefficient| i128::from(*coefficient))
            .collect::<Vec<_>>();
        for (digit_index, source_coefficients) in input
            .witness
            .relinearization_source_coefficients_by_digit
            .iter()
            .enumerate()
        {
            if is_round_one {
                if source_coefficients != &secret_coefficients {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "round-one relinearization source witness must equal the same-secret witness at digit {digit_index}"
                    )));
                }
            } else {
                let expected_source = negacyclic_i128_product_lifted(
                    &secret_coefficients,
                    &input
                        .witness
                        .round_one_aggregate_source_coefficients_by_digit[digit_index],
                )?;
                if source_coefficients != &expected_source {
                    return Err(invalid_evaluation_key_share_proof(format!(
                        "round-two relinearization source witness must equal the trustee secret times the accepted round-one aggregate source at digit {digit_index}"
                    )));
                }
            }
            if source_coefficients
                .iter()
                .any(|coefficient| match coefficient.checked_abs() {
                    Some(magnitude) => magnitude > source_bound,
                    None => true,
                })
            {
                return Err(invalid_evaluation_key_share_proof(
                    "relinearization source witness exceeds the accepted no-wrap source bound",
                ));
            }
        }
    } else if !input
        .witness
        .relinearization_source_coefficients_by_digit
        .is_empty()
    {
        return Err(invalid_evaluation_key_share_proof(
            "Galois proof generation must not include relinearization source witness material",
        ));
    } else if !input
        .witness
        .round_one_aggregate_source_coefficients_by_digit
        .is_empty()
    {
        return Err(invalid_evaluation_key_share_proof(
            "Galois proof generation must not include round-one aggregate source witness material",
        ));
    }

    Ok(())
}

struct EvaluationKeyShareResponses {
    secret_response_coefficients: Vec<i128>,
    negative_indicator_response_coefficients: Vec<i128>,
    randomness_response_by_limb: Vec<Vec<Vec<i128>>>,
    error_response_by_digit: Vec<Vec<i128>>,
    relinearization_source_response_by_digit: Vec<Vec<i128>>,
    carry_response_by_digit_by_limb: Vec<Vec<Vec<i128>>>,
}

fn key_switch_relation_commitments_from_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
) -> CanonicalResult<Vec<Vec<Vec<BigInt>>>> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let galois_element = input
        .proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    let galois_source_masks = if input.proof_family == EvaluationKeyShareProofFamily::Galois {
        automorphism_i128(
            &masks.secret_masks,
            galois_element.ok_or_else(|| {
                invalid_evaluation_key_share_proof("Galois proof must include rotation")
            })?,
        )?
    } else {
        Vec::new()
    };
    input
        .component_b_by_digit
        .iter()
        .enumerate()
        .map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(|(rns_limb_index, _component_b)| {
                    let modulus = DATA_PRIMES[rns_limb_index];
                    let public_sample = deterministic_key_switch_public_sample(
                        key_switch_domain,
                        key_switch_seed_hex,
                        digit_index,
                        modulus,
                        ring_degree,
                    );
                    let public_sample_secret_product =
                        negacyclic_public_sample_secret_product_big_int(
                            &public_sample,
                            &masks.secret_masks,
                        )?;
                    let source_masks = match input.proof_family {
                        EvaluationKeyShareProofFamily::Relinearization => {
                            masks.relinearization_source_masks_by_digit[digit_index].clone()
                        }
                        EvaluationKeyShareProofFamily::Galois => galois_source_masks.clone(),
                    };
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            let mut value = public_sample_secret_product[coefficient_index].clone();
                            value -= BigInt::from(PLAINTEXT_MODULUS_I64)
                                * BigInt::from(
                                    masks.error_masks_by_digit[digit_index][coefficient_index],
                                );
                            if rns_limb_index == digit_index {
                                value -= BigInt::from(source_masks[coefficient_index]);
                            }
                            value -= BigInt::from(modulus)
                                * BigInt::from(
                                    masks.carry_masks_by_digit_by_limb[digit_index][rns_limb_index]
                                        [coefficient_index],
                                );
                            Ok(value)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

fn secret_commitment_relation_commitments_from_masks(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
) -> CanonicalResult<Vec<SetupCommitmentValue>> {
    input
        .constant_commitments
        .iter()
        .enumerate()
        .map(|(rns_limb_index, commitment)| {
            let message_coefficients = masks
                .secret_masks
                .iter()
                .zip(masks.negative_indicator_masks.iter())
                .map(|(secret_mask, negative_indicator_mask)| {
                    lifted_secret_message_response_big_int(
                        *secret_mask,
                        *negative_indicator_mask,
                        commitment.source_message_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            compute_setup_big_signed_lifted_commitment(
                input.public_matrix_seed_hash,
                rns_limb_index,
                commitment.source_message_modulus,
                0,
                &message_coefficients,
                &masks.randomness_masks_by_limb[rns_limb_index],
                commitment.ring_degree,
            )
        })
        .collect()
}

fn evaluation_key_share_responses(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
    masks: &EvaluationKeyShareMasks,
    challenge: u64,
) -> CanonicalResult<EvaluationKeyShareResponses> {
    let challenge_i128 = i128::from(challenge);
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let secret_response_coefficients = masks
        .secret_masks
        .iter()
        .zip(input.witness.secret_coefficients.iter())
        .map(|(mask, witness)| {
            mask.checked_add(
                challenge_i128
                    .checked_mul(i128::from(*witness))
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key secret response overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| {
                invalid_evaluation_key_share_proof("evaluation-key secret response overflowed")
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let negative_indicator_response_coefficients =
        masks
            .negative_indicator_masks
            .iter()
            .zip(input.witness.secret_coefficients.iter())
            .map(|(mask, secret)| {
                let negative_indicator = if *secret < 0 { 1_i128 } else { 0_i128 };
                mask.checked_add(challenge_i128.checked_mul(negative_indicator).ok_or_else(
                    || {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key negative-indicator response overflowed",
                        )
                    },
                )?)
                .ok_or_else(|| {
                    invalid_evaluation_key_share_proof(
                        "evaluation-key negative-indicator response overflowed",
                    )
                })
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
    let randomness_response_by_limb = masks
        .randomness_masks_by_limb
        .iter()
        .zip(input.witness.opening_randomness_by_limb.iter())
        .map(|(mask_columns, witness_columns)| {
            mask_columns
                .iter()
                .zip(witness_columns.iter())
                .map(|(mask_column, witness_column)| {
                    mask_column
                        .iter()
                        .zip(witness_column.iter())
                        .map(|(mask, witness)| {
                            mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(
                                || {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key randomness response overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key randomness response overflowed",
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<Vec<i128>>>>>()?;
    let error_response_by_digit = masks
        .error_masks_by_digit
        .iter()
        .zip(input.witness.error_coefficients_by_digit.iter())
        .map(|(mask_error, witness_error)| {
            mask_error
                .iter()
                .zip(witness_error.iter())
                .map(|(mask, witness)| {
                    mask.checked_add(
                        challenge_i128
                            .checked_mul(i128::from(*witness))
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key error response overflowed",
                                )
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_evaluation_key_share_proof(
                            "evaluation-key error response overflowed",
                        )
                    })
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<i128>>>>()?;
    let relinearization_source_response_by_digit = if input.proof_family
        == EvaluationKeyShareProofFamily::Relinearization
    {
        masks
            .relinearization_source_masks_by_digit
            .iter()
            .zip(
                input
                    .witness
                    .relinearization_source_coefficients_by_digit
                    .iter(),
            )
            .map(|(mask_source, witness_source)| {
                mask_source
                    .iter()
                    .zip(witness_source.iter())
                    .map(|(mask, witness)| {
                        mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(|| {
                            invalid_evaluation_key_share_proof(
                                "relinearization source response overflowed",
                            )
                        })?)
                        .ok_or_else(|| {
                            invalid_evaluation_key_share_proof(
                                "relinearization source response overflowed",
                            )
                        })
                    })
                    .collect()
            })
            .collect::<CanonicalResult<Vec<Vec<i128>>>>()?
    } else {
        Vec::new()
    };
    let carry_witnesses = key_switch_carry_witnesses(input)?;
    let carry_response_by_digit_by_limb = masks
        .carry_masks_by_digit_by_limb
        .iter()
        .zip(carry_witnesses.iter())
        .map(|(mask_by_limb, witness_by_limb)| {
            mask_by_limb
                .iter()
                .zip(witness_by_limb.iter())
                .map(|(mask_carry, witness_carry)| {
                    mask_carry
                        .iter()
                        .zip(witness_carry.iter())
                        .map(|(mask, witness)| {
                            mask.checked_add(challenge_i128.checked_mul(*witness).ok_or_else(
                                || {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry response overflowed",
                                    )
                                },
                            )?)
                            .ok_or_else(|| {
                                invalid_evaluation_key_share_proof(
                                    "evaluation-key carry response overflowed",
                                )
                            })
                        })
                        .collect()
                })
                .collect()
        })
        .collect::<CanonicalResult<Vec<Vec<Vec<i128>>>>>()?;
    if secret_response_coefficients.len() != ring_degree {
        return Err(invalid_evaluation_key_share_proof(
            "evaluation-key response width does not match ringDegree",
        ));
    }

    Ok(EvaluationKeyShareResponses {
        secret_response_coefficients,
        negative_indicator_response_coefficients,
        randomness_response_by_limb,
        error_response_by_digit,
        relinearization_source_response_by_digit,
        carry_response_by_digit_by_limb,
    })
}

fn key_switch_carry_witnesses(
    input: &EvaluationKeyShareLnpProofGenerationInput<'_>,
) -> CanonicalResult<Vec<Vec<Vec<i128>>>> {
    let ring_degree = value_usize(input.proof_record, "ringDegree")?;
    let key_switch_domain = string_field(input.proof_record, "keySwitchDomain")?;
    let key_switch_seed_hex = string_field(input.proof_record, "keySwitchSeedHex")?;
    let galois_element = input
        .proof_record
        .get("rotation")
        .and_then(Value::as_u64)
        .map(|rotation| {
            usize::try_from(rotation).map_err(|_| {
                invalid_evaluation_key_share_proof("Galois rotation does not fit usize")
            })
        })
        .transpose()?;
    let secret_witness = input
        .witness
        .secret_coefficients
        .iter()
        .map(|coefficient| i128::from(*coefficient))
        .collect::<Vec<_>>();
    let galois_source = if input.proof_family == EvaluationKeyShareProofFamily::Galois {
        automorphism_i128(
            &secret_witness,
            galois_element.ok_or_else(|| {
                invalid_evaluation_key_share_proof("Galois proof must include rotation")
            })?,
        )?
    } else {
        Vec::new()
    };
    input
        .component_b_by_digit
        .iter()
        .enumerate()
        .map(|(digit_index, component_b_by_limb)| {
            component_b_by_limb
                .iter()
                .enumerate()
                .map(|(rns_limb_index, component_b)| {
                    let modulus = DATA_PRIMES[rns_limb_index];
                    let public_sample = deterministic_key_switch_public_sample(
                        key_switch_domain,
                        key_switch_seed_hex,
                        digit_index,
                        modulus,
                        ring_degree,
                    );
                    let public_sample_secret_product =
                        negacyclic_public_sample_secret_product_lifted(
                            &public_sample,
                            &secret_witness,
                        )?;
                    let source = match input.proof_family {
                        EvaluationKeyShareProofFamily::Relinearization => input
                            .witness
                            .relinearization_source_coefficients_by_digit[digit_index]
                            .clone(),
                        EvaluationKeyShareProofFamily::Galois => galois_source.clone(),
                    };
                    (0..ring_degree)
                        .map(|coefficient_index| {
                            let mut numerator = i128::from(component_b[coefficient_index]);
                            numerator = numerator
                                .checked_add(public_sample_secret_product[coefficient_index])
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry numerator overflowed",
                                    )
                                })?;
                            numerator = numerator
                                .checked_sub(
                                    i128::from(PLAINTEXT_MODULUS_I64)
                                        .checked_mul(i128::from(
                                            input.witness.error_coefficients_by_digit[digit_index]
                                                [coefficient_index],
                                        ))
                                        .ok_or_else(|| {
                                            invalid_evaluation_key_share_proof(
                                                "evaluation-key carry error scaling overflowed",
                                            )
                                        })?,
                                )
                                .ok_or_else(|| {
                                    invalid_evaluation_key_share_proof(
                                        "evaluation-key carry numerator overflowed",
                                    )
                                })?;
                            if rns_limb_index == digit_index {
                                numerator = numerator
                                    .checked_sub(source[coefficient_index])
                                    .ok_or_else(|| {
                                        invalid_evaluation_key_share_proof(
                                            "evaluation-key carry source subtraction overflowed",
                                        )
                                    })?;
                            }
                            let modulus_i128 = i128::from(modulus);
                            if numerator % modulus_i128 != 0 {
                                return Err(invalid_evaluation_key_share_proof(
                                    "evaluation-key witness does not satisfy the lifted key-switch relation",
                                ));
                            }
                            Ok(numerator / modulus_i128)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
