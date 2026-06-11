use super::*;

static VERIFIED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_CHUNKS: OnceLock<
    Mutex<BTreeMap<String, VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry>>,
> = OnceLock::new();

#[derive(Debug, Clone)]
struct VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry {
    path: PathBuf,
    total_byte_length: u64,
}
pub(super) fn verify_relinearization_key_share_lnp_proof_record(
    record: &Value,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    proof_root_field_name: &str,
    supplied_proof_root: &str,
) -> CanonicalResult<()> {
    let trustee_roster_position = value_u64(record, "trusteeRosterPosition")?;
    let same_secret_record = proof_context
        .same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearization proof must reference an accepted same-secret statement",
            )
        })?;
    verify_evaluation_key_lnp_proof_record_common_fields(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
    )?;
    let share_root_field_name = match proof_root_field_name {
        "roundOneProofRoot" => "roundOneShareRoot",
        "roundTwoProofRoot" => "roundTwoShareRoot",
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearization proof root field must identify round one or round two",
            ));
        }
    };
    if record
        .get("keySwitchComponentVectorRoot")
        .and_then(Value::as_str)
        != Some(value_string(record, share_root_field_name)?)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "relinearization proof share root must match the verified key-switch component vector root",
        ));
    }
    let proof_bytes = evaluation_key_share_lnp_proof_bytes_from_record(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
        proof_context.request,
    )?;
    verify_evaluation_key_lnp_proof_bytes_metadata(
        EvaluationKeyShareProofFamily::Relinearization,
        record,
        &proof_bytes,
    )?;
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        proof_context.setup_package,
        trustee_roster_position,
        proof_context.transported_constant_commitments,
    )?;
    let setup_proof_binding = record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization proof setupProofBinding is required",
        )
    })?;
    let public_matrix_seed_hash = proof_context
        .setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before relinearization proof verification",
            )
        })?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Relinearization,
            public_matrix_seed_hash,
            proof_record: record,
            same_secret_statement_record: same_secret_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material: proof_context
                .transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    verify_evaluation_key_lnp_proof_transcript_metadata(record, &verification)?;
    let expected_proof_root = relinearization_key_share_proof_root(record, proof_root_field_name)?;
    if supplied_proof_root != expected_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization proof root does not match the canonical proof record",
        ));
    }

    Ok(())
}

pub(super) fn verify_galois_key_share_lnp_proof_record(
    proof_record: &Value,
    batch: &Value,
    proof_context: &EvaluationKeyProofVerificationContext<'_>,
    root_entry: &Value,
    expected_schedule_entry: &Value,
) -> CanonicalResult<String> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof record must be an object",
        ));
    }
    if let Some(unexpected_field) = unexpected_galois_key_share_proof_field(proof_record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("Galois key share proof contains unexpected field {unexpected_field}"),
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(GALOIS_KEY_SHARE_PROOF_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof objectType must be GaloisKeyShareProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof objectVersion must be 1",
        ));
    }
    for field_name in [
        "setupProfileId",
        "setupProofProfileId",
        "proofFamily",
        "proofVerificationStatus",
        "proofModelStatus",
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
        "trusteeIdentity",
        "trusteeRosterPosition",
        "evaluatorKeyScheduleRoot",
        "sameSecretConsistencyRoot",
        "sameSecretProofSetRoot",
        "sameSecretProofFamilyBindingRoot",
        "publicKeyShareLnpProofSetRoot",
        "sameSecretStatementRoot",
        "trusteeSecretCommitmentRoot",
        "sameSecretProofRoot",
        "galoisKeyCrpRoot",
        "requiredGaloisSetHash",
    ] {
        if proof_record.get(field_name) != batch.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("Galois key share proof {field_name} must match the parent batch"),
            ));
        }
    }
    if proof_record.get("rotation") != expected_schedule_entry.get("rotation")
        || proof_record.get("level") != expected_schedule_entry.get("level")
        || proof_record.get("rotation") != root_entry.get("rotation")
        || proof_record.get("level") != root_entry.get("level")
        || proof_record.get("galoisKeyShareRoot") != root_entry.get("galoisKeyShareRoot")
        || proof_record.get("keySwitchComponentVectorRoot") != root_entry.get("galoisKeyShareRoot")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "Galois key share proof must bind the scheduled rotation, level, and share root",
        ));
    }
    verify_evaluation_key_lnp_proof_record_common_fields(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
    )?;
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    let same_secret_record = proof_context
        .same_secret_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share proof must reference an accepted same-secret statement",
            )
        })?;
    let proof_bytes = evaluation_key_share_lnp_proof_bytes_from_record(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
        proof_context.request,
    )?;
    verify_evaluation_key_lnp_proof_bytes_metadata(
        EvaluationKeyShareProofFamily::Galois,
        proof_record,
        &proof_bytes,
    )?;
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        proof_context.setup_package,
        trustee_roster_position,
        proof_context.transported_constant_commitments,
    )?;
    let setup_proof_binding = proof_record.get("setupProofBinding").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "Galois key share proof setupProofBinding is required",
        )
    })?;
    let public_matrix_seed_hash = proof_context
        .setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before Galois proof verification",
            )
        })?;
    let verification = verify_evaluation_key_share_lnp_relation_proof(
        EvaluationKeyShareLnpProofVerificationInput {
            proof_family: EvaluationKeyShareProofFamily::Galois,
            public_matrix_seed_hash,
            proof_record,
            same_secret_statement_record: same_secret_record,
            constant_commitments: &constant_commitments,
            setup_proof_binding,
            transported_key_switch_component_material: proof_context
                .transported_key_switch_component_material,
            proof_bytes: &proof_bytes,
        },
    )?;
    verify_evaluation_key_lnp_proof_transcript_metadata(proof_record, &verification)?;
    let supplied_proof_root = value_string(proof_record, "galoisKeyShareProofRoot")?;
    let expected_proof_root = galois_key_share_proof_root(proof_record)?;
    if supplied_proof_root != expected_proof_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "galoisKeyShareProofRoot does not match the canonical Galois proof record",
        ));
    }

    Ok(supplied_proof_root.to_string())
}

fn verify_evaluation_key_lnp_proof_record_common_fields(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
) -> CanonicalResult<()> {
    let expected_setup_proof_binding = setup_proof_record_binding_value()?;
    if proof_record.get("setupProofBinding") != Some(&expected_setup_proof_binding) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof setupProofBinding must match the accepted setup-proof profile",
        ));
    }
    super::setup_proof::verify_setup_proof_record_binding(
        &expected_setup_proof_binding,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        &setup_proof_profile_hash()?,
    )?;
    let (expected_profile_id, tbox_profile_field_name, expected_tbox_hash) = match proof_family {
        EvaluationKeyShareProofFamily::Relinearization => (
            "sealed-lattice-relinearization-key-share-proof-lnp-v1",
            "relinearizationKeyShareTboxParameterProfileHash",
            super::setup_proof::relinearization_key_share_lnp_tbox_parameter_profile_hash()?,
        ),
        EvaluationKeyShareProofFamily::Galois => (
            "sealed-lattice-galois-key-share-proof-lnp-v1",
            "galoisKeyShareTboxParameterProfileHash",
            super::setup_proof::galois_key_share_lnp_tbox_parameter_profile_hash()?,
        ),
    };
    if proof_record.get("proofProfileId").and_then(Value::as_str) != Some(expected_profile_id)
        || proof_record
            .get(tbox_profile_field_name)
            .and_then(Value::as_str)
            != Some(expected_tbox_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "evaluation-key proof profile fields must match the accepted verifier",
        ));
    }
    let material_encoding = proof_record
        .get("keySwitchMaterialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "evaluation-key proof keySwitchMaterialEncoding is required",
            )
        })?;
    match material_encoding {
        "embedded-full-key-switch-component-vectors" => {
            if proof_record.get("keySwitchComponentVectors").is_none()
                || proof_record.get("keySwitchComponentMaterialRoot").is_some()
                || proof_record
                    .get("keySwitchComponentChunkSizeBytes")
                    .is_some()
                || proof_record.get("keySwitchComponentChunkCount").is_some()
                || proof_record
                    .get("keySwitchComponentTotalByteLength")
                    .is_some()
                || proof_record
                    .get("keySwitchComponentFullObjectHash")
                    .is_some()
                || proof_record.get("keySwitchComponentChunkRoot").is_some()
                || proof_record.get("keySwitchComponentChunkHashes").is_some()
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "embedded evaluation-key proof material must include component vectors and no component transport reference",
                ));
            }
        }
        EVALUATION_KEY_SHARE_COMPONENT_MATERIAL_ENCODING => {
            if proof_record.get("keySwitchComponentVectors").is_some() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "binary evaluation-key proof material must not embed keySwitchComponentVectors",
                ));
            }
            for field_name in [
                "keySwitchComponentMaterialRoot",
                "keySwitchComponentChunkSizeBytes",
                "keySwitchComponentChunkCount",
                "keySwitchComponentTotalByteLength",
                "keySwitchComponentFullObjectHash",
                "keySwitchComponentChunkRoot",
                "keySwitchComponentChunkHashes",
            ] {
                if proof_record.get(field_name).is_none() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!("binary evaluation-key proof material requires {field_name}"),
                    ));
                }
            }
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "evaluation-key proof keySwitchMaterialEncoding is not accepted",
            ));
        }
    }
    validate_hash_string(
        value_string(proof_record, "keySwitchComponentVectorRoot")?,
        "evaluationKeyShareProof.keySwitchComponentVectorRoot",
    )?;
    if let Some(material_root) = proof_record
        .get("keySwitchComponentMaterialRoot")
        .and_then(Value::as_str)
    {
        validate_hash_string(
            material_root,
            "evaluationKeyShareProof.keySwitchComponentMaterialRoot",
        )?;
    }

    Ok(())
}

fn verify_evaluation_key_lnp_proof_bytes_metadata(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key LNP proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofSizeBytes must match supplied proof bytes",
        ));
    }
    if value_string(proof_record, "proofBytesHash")?
        != evaluation_key_share_lnp_relation_proof_bytes_hash(proof_family, proof_bytes)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofBytesHash must match supplied proof bytes",
        ));
    }

    Ok(())
}

fn verify_evaluation_key_lnp_proof_transcript_metadata(
    proof_record: &Value,
    verification: &super::evaluation_key_share_proof::EvaluationKeyShareLnpProofVerification,
) -> CanonicalResult<()> {
    let verified_proof_size = u64::try_from(verification.proof_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key verified proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(verification.statement_hash_hex.as_str())
        || proof_record
            .get("relationCommitmentHash")
            .and_then(Value::as_str)
            != Some(verification.relation_commitment_hash_hex.as_str())
        || proof_record
            .get("tboxCommitmentPrefixHash")
            .and_then(Value::as_str)
            != Some(verification.tbox_commitment_prefix_hash.as_str())
        || value_decimal_u64(proof_record, "challenge")? != verification.challenge
        || proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(verified_proof_size)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof transcript metadata must match verified proof bytes",
        ));
    }
    verify_lnp_tbox_z34_metadata_fields(
        proof_record,
        LnpTboxZ34MetadataExpectation {
            z34_seed_material_hash: &verification.z34_seed_material_hash,
            z34_challenge_seed_hash: &verification.z34_challenge_seed_hash,
            z34_challenge_tail_hash: &verification.z34_challenge_tail_hash,
            z34_challenge_row_domain_hash: &verification.z34_challenge_row_domain_hash,
            z34_challenge_z3_row_set_hash: &verification.z34_challenge_z3_row_set_hash,
            z34_challenge_z4_row_set_hash: &verification.z34_challenge_z4_row_set_hash,
            tbox_lower_protocol_challenge_hash: &verification.tbox_lower_protocol_challenge_hash,
            z34_z3_check_window_hash: &verification.z34_z3_check_window_hash,
            z34_z4_check_window_hash: &verification.z34_z4_check_window_hash,
            z34_z3_l2_squared_decimal: &verification.z34_z3_l2_squared_decimal,
            z34_z4_infinity_norm_decimal: &verification.z34_z4_infinity_norm_decimal,
            proof_label: "evaluation-key LNP proof",
        },
    )?;

    Ok(())
}

pub(super) struct LnpTboxZ34MetadataExpectation<'a> {
    pub(super) z34_seed_material_hash: &'a str,
    pub(super) z34_challenge_seed_hash: &'a str,
    pub(super) z34_challenge_tail_hash: &'a str,
    pub(super) z34_challenge_row_domain_hash: &'a str,
    pub(super) z34_challenge_z3_row_set_hash: &'a str,
    pub(super) z34_challenge_z4_row_set_hash: &'a str,
    pub(super) tbox_lower_protocol_challenge_hash: &'a str,
    pub(super) z34_z3_check_window_hash: &'a str,
    pub(super) z34_z4_check_window_hash: &'a str,
    pub(super) z34_z3_l2_squared_decimal: &'a str,
    pub(super) z34_z4_infinity_norm_decimal: &'a str,
    pub(super) proof_label: &'a str,
}

pub(super) fn verify_lnp_tbox_z34_metadata_fields(
    proof_record: &Value,
    expectation: LnpTboxZ34MetadataExpectation<'_>,
) -> CanonicalResult<()> {
    for (field_name, expected_hash) in [
        ("z34SeedMaterialHash", expectation.z34_seed_material_hash),
        ("z34ChallengeSeedHash", expectation.z34_challenge_seed_hash),
        ("z34ChallengeTailHash", expectation.z34_challenge_tail_hash),
        (
            "z34ChallengeRowDomainHash",
            expectation.z34_challenge_row_domain_hash,
        ),
        (
            "z34ChallengeZ3RowSetHash",
            expectation.z34_challenge_z3_row_set_hash,
        ),
        (
            "z34ChallengeZ4RowSetHash",
            expectation.z34_challenge_z4_row_set_hash,
        ),
        (
            "tboxLowerProtocolChallengeHash",
            expectation.tbox_lower_protocol_challenge_hash,
        ),
        ("z34Z3CheckWindowHash", expectation.z34_z3_check_window_hash),
        ("z34Z4CheckWindowHash", expectation.z34_z4_check_window_hash),
    ] {
        if value_string(proof_record, field_name)? != expected_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{} {field_name} must match verified tbox proof bytes",
                    expectation.proof_label
                ),
            ));
        }
    }
    for (field_name, expected_decimal) in [
        (
            "z34Z3L2SquaredDecimal",
            expectation.z34_z3_l2_squared_decimal,
        ),
        (
            "z34Z4InfinityNormDecimal",
            expectation.z34_z4_infinity_norm_decimal,
        ),
    ] {
        if value_string(proof_record, field_name)? != expected_decimal {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{} {field_name} must match verified tbox proof bytes",
                    expectation.proof_label
                ),
            ));
        }
    }

    Ok(())
}

fn relinearization_key_share_proof_root(
    record: &Value,
    proof_root_field_name: &str,
) -> CanonicalResult<String> {
    let mut root_input = record.clone();
    let object = root_input
        .as_object_mut()
        .expect("relinearization proof record object was checked");
    object.remove(proof_root_field_name);
    match proof_root_field_name {
        "roundOneProofRoot" => {
            object.remove("roundOneRecordRoot");
        }
        "roundTwoProofRoot" => {
            object.remove("roundTwoRecordRoot");
        }
        _ => {}
    }
    derive_protocol_hash("RelinearizationKeyShareProofRoot", &root_input)
}

pub(super) fn relinearization_source_square_binding_root(
    record: &Value,
    round: &str,
    share_root: &str,
) -> CanonicalResult<String> {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round(round)?;
    derive_protocol_hash(
        "RelinearizationSourceSquareBindingRoot",
        &json!({
            "objectType": "RelinearizationSourceSquareBinding",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": "relinearization-key-share",
            "sourceRelation": source_relation,
            "sourceRelationStatus": source_relation_status,
            "round": round,
            "evaluatorKeyScheduleRoot": value_string(record, "evaluatorKeyScheduleRoot")?,
            "sameSecretProofSetRoot": value_string(record, "sameSecretProofSetRoot")?,
            "sameSecretProofFamilyBindingRoot": value_string(record, "sameSecretProofFamilyBindingRoot")?,
            "publicKeyShareLnpProofSetRoot": value_string(record, "publicKeyShareLnpProofSetRoot")?,
            "relinearizationCrpRoot": value_string(record, "relinearizationCrpRoot")?,
            "trusteeIdentity": value_string(record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(record, "trusteeRosterPosition")?,
            "level": value_u64(record, "level")?,
            "sameSecretStatementRoot": value_string(record, "sameSecretStatementRoot")?,
            "trusteeSecretCommitmentRoot": value_string(record, "trusteeSecretCommitmentRoot")?,
            "sameSecretProofRoot": value_string(record, "sameSecretProofRoot")?,
            "shareRoot": share_root,
            "keySwitchComponentVectorRoot": value_string(record, "keySwitchComponentVectorRoot")?,
            "statementHash": value_string(record, "statementHash")?,
            "relationCommitmentHash": value_string(record, "relationCommitmentHash")?,
            "proofBytesHash": value_string(record, "proofBytesHash")?,
        }),
    )
}

pub(super) fn relinearization_source_square_aggregate_root(
    round: &str,
    evaluator_key_schedule_root: &str,
    level: u64,
    source_square_binding_roots: &[Value],
    round_one_source_square_aggregate_root: Option<&str>,
) -> CanonicalResult<String> {
    let (source_relation, source_relation_status) =
        relinearization_source_relation_for_round(round)?;
    let mut aggregate = json!({
        "objectType": "RelinearizationSourceSquareAggregate",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "relinearization-key-share",
        "sourceRelation": source_relation,
        "sourceRelationStatus": source_relation_status,
        "round": round,
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
        "level": level,
        "sourceSquareBindingRoots": source_square_binding_roots,
    });
    if let Some(round_one_source_square_aggregate_root) = round_one_source_square_aggregate_root {
        aggregate["roundOneSourceSquareAggregateRoot"] =
            json!(round_one_source_square_aggregate_root);
    }

    derive_protocol_hash("RelinearizationSourceSquareAggregateRoot", &aggregate)
}

fn relinearization_source_relation_for_round(
    round: &str,
) -> CanonicalResult<(&'static str, &'static str)> {
    match round {
        "round-one" => Ok((
            "same-secret-for-relinearization-round-one-source",
            "verified-by-round-one-same-secret-source-response",
        )),
        "round-two" => Ok((
            "same-secret-times-round-one-aggregate-for-relinearization-source",
            "verifier-checked-round-two-source-square-aggregate-binding",
        )),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization source relation round is outside the accepted schedule",
        )),
    }
}

fn galois_key_share_proof_root(proof_record: &Value) -> CanonicalResult<String> {
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("Galois proof record object was checked")
        .remove("galoisKeyShareProofRoot");
    derive_protocol_hash("GaloisKeyShareProofRoot", &root_input)
}

fn evaluation_key_share_lnp_proof_bytes_from_record(
    proof_family: EvaluationKeyShareProofFamily,
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof requires proofBytesHex or transported proof material",
        ));
    }
    if value_string(proof_record, "proofBytesEncoding")? != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "evaluationKeyShareProof.proofMaterialRoot",
    )?;
    let chunks = transported_evaluation_key_share_proof_material_chunks(
        request,
        proof_material_root,
        proof_family,
    )?;
    let transport_hashes = setup_proof_material_transport_hashes(
        proof_family.proof_family(),
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_evaluation_key_share_lnp_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        setup_proof_material_reference_root(SetupProofMaterialReferenceInput {
            setup_profile_id: COLLECTIVE_BGV_SETUP_PROFILE_ID,
            proof_family: proof_family.proof_family(),
            trustee_identity: value_string(proof_record, "trusteeIdentity")?,
            trustee_roster_position: value_u64(proof_record, "trusteeRosterPosition")?,
            statement_hash_hex: value_string(proof_record, "statementHash")?,
            relation_commitment_hash_hex: value_string(proof_record, "relationCommitmentHash")?,
            tbox_commitment_prefix_hash: value_string(proof_record, "tboxCommitmentPrefixHash")?,
            proof_size_bytes: value_u64(proof_record, "proofSizeBytes")?,
            proof_bytes_hash: value_string(proof_record, "proofBytesHash")?,
            transport_hashes: &transport_hashes,
        })?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }
    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "evaluation-key transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

fn verified_evaluation_key_share_proof_material_chunks()
-> &'static Mutex<BTreeMap<String, VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry>> {
    VERIFIED_EVALUATION_KEY_SHARE_PROOF_MATERIAL_CHUNKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn register_verified_evaluation_key_share_proof_material_chunks(
    proof_material_root: &str,
    chunks: Vec<Vec<u8>>,
) -> CanonicalResult<()> {
    validate_hash_string(
        proof_material_root,
        "verifiedEvaluationKeyShareProofMaterial.proofMaterialRoot",
    )?;
    let store_entry =
        write_verified_evaluation_key_share_proof_material_chunks(proof_material_root, &chunks)?;
    let mut stored_chunks = verified_evaluation_key_share_proof_material_chunks()
        .lock()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verified evaluation-key proof material store is unavailable",
            )
        })?;
    if let Some(existing_chunks) = stored_chunks.get(proof_material_root)
        && (existing_chunks.path != store_entry.path
            || existing_chunks.total_byte_length != store_entry.total_byte_length)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "verified evaluation-key proof material root is already bound to different material storage",
        ));
    }
    stored_chunks.insert(proof_material_root.to_string(), store_entry);

    Ok(())
}

fn stored_verified_evaluation_key_share_proof_material_chunks(
    proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let stored_chunks = verified_evaluation_key_share_proof_material_chunks()
        .lock()
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verified evaluation-key proof material store is unavailable",
            )
        })?;
    let store_entry = stored_chunks
        .get(proof_material_root)
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material requires chunks or a live verified material handle",
            )
        })?;
    drop(stored_chunks);

    read_verified_evaluation_key_share_proof_material_chunks(&store_entry)
}

#[cfg(test)]
fn verified_evaluation_key_share_proof_material_store_directory() -> PathBuf {
    PathBuf::from("temp")
        .join("test-checkpoints")
        .join("terminal-accepted-setup-material-store")
        .join("evaluation-key-proof-material")
}

#[cfg(test)]
fn write_verified_evaluation_key_share_proof_material_chunks(
    proof_material_root: &str,
    chunks: &[Vec<u8>],
) -> CanonicalResult<VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry> {
    let total_byte_length = chunks.iter().try_fold(0_u64, |total, chunk| {
        total
            .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "verified evaluation-key proof material chunk length does not fit u64",
                )
            })?)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "verified evaluation-key proof material byte length overflowed",
                )
            })
    })?;
    let directory = verified_evaluation_key_share_proof_material_store_directory();
    fs::create_dir_all(&directory).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("verified evaluation-key proof material store could not be created: {error}"),
        )
    })?;
    let path = directory.join(format!("{proof_material_root}.bin"));
    if path.exists() {
        let observed_byte_length = fs::metadata(&path)
            .map_err(|error| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "verified evaluation-key proof material store entry could not be read: {error}",
                    ),
                )
            })?
            .len();
        if observed_byte_length != total_byte_length {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verified evaluation-key proof material store entry length does not match the registered chunks",
            ));
        }
    } else {
        let mut file = File::create(&path).map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "verified evaluation-key proof material store entry could not be created: {error}",
                ),
            )
        })?;
        for chunk in chunks {
            file.write_all(chunk).map_err(|error| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "verified evaluation-key proof material store entry could not be written: {error}",
                    ),
                )
            })?;
        }
    }

    Ok(VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry {
        path,
        total_byte_length,
    })
}

fn read_verified_evaluation_key_share_proof_material_chunks(
    store_entry: &VerifiedEvaluationKeyShareProofMaterialChunkStoreEntry,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_size = usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key proof material chunk size does not fit usize",
        )
    })?;
    let mut remaining_byte_length = store_entry.total_byte_length;
    let mut file = File::open(&store_entry.path).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "verified evaluation-key proof material store entry could not be opened: {error}"
            ),
        )
    })?;
    let mut chunks = Vec::new();
    while remaining_byte_length > 0 {
        let next_chunk_length =
            usize::try_from(remaining_byte_length.min(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES))
                .map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key proof material chunk length does not fit usize",
                    )
                })?;
        let mut chunk = vec![0_u8; next_chunk_length.min(chunk_size)];
        file.read_exact(&mut chunk).map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "verified evaluation-key proof material store entry could not be read: {error}"
                ),
            )
        })?;
        remaining_byte_length -= u64::try_from(chunk.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "evaluation-key proof material chunk length does not fit u64",
            )
        })?;
        chunks.push(chunk);
    }

    Ok(chunks)
}

fn verify_evaluation_key_share_lnp_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
        || value_u64(proof_record, "proofChunkCount")?
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "evaluation-key proof material chunk count does not fit u64",
                )
            })?
        || value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length
        || value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length
        || value_string(proof_record, "proofFullObjectHash")? != transport_hashes.full_object_hash
        || value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proof transport reference does not match transported chunks",
        ));
    }
    let chunk_hash_values = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "evaluation-key LNP proofChunkHashes must list every transported proof chunk",
            )
        })?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key LNP proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "evaluation-key LNP proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_evaluation_key_share_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
    proof_family: EvaluationKeyShareProofFamily,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedEvaluationKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial was required by transported evaluation-key LNP proof records",
            )
        })?;
    let material_set_proof_family = material_set.get("proofFamily").and_then(Value::as_str);
    let material_set_family_matches = material_set_proof_family == Some("evaluation-key-share")
        || material_set_proof_family == Some(proof_family.proof_family());
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE)
        || material_set.get("setupProfileId").and_then(Value::as_str)
            != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
        || material_set
            .get("setupProofProfileId")
            .and_then(Value::as_str)
            != Some(SETUP_PROOF_PROFILE_ID)
        || !material_set_family_matches
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial header does not match the evaluation-key proof family",
        ));
    }
    let proof_materials = material_set
        .get("proofMaterials")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial.proofMaterials must list proof material objects",
            )
        })?;
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        if proof_material.get("objectType").and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE)
            || proof_material.get("setupProfileId").and_then(Value::as_str)
                != Some(COLLECTIVE_BGV_SETUP_PROFILE_ID)
            || proof_material
                .get("setupProofProfileId")
                .and_then(Value::as_str)
                != Some(SETUP_PROOF_PROFILE_ID)
            || proof_material
                .get("proofBytesEncoding")
                .and_then(Value::as_str)
                != Some(SETUP_PROOF_MATERIAL_ENCODING)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material header is invalid",
            ));
        }
        let proof_material_family = proof_material
            .get("proofFamily")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported evaluation-key proof material proofFamily is required",
                )
            })?;
        if proof_material_family != proof_family.proof_family() {
            if proof_material_family == "relinearization-key-share"
                || proof_material_family == "galois-key-share"
            {
                continue;
            }
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material proofFamily is invalid",
            ));
        }
        if value_string(proof_material, "proofMaterialRoot")? != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if let Some(chunk_values) = proof_material.get("chunks") {
            let chunk_values = chunk_values.as_array().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported evaluation-key proof material chunks must be an array",
                )
            })?;
            chunk_values
                .iter()
                .map(|chunk| {
                    let bytes_hex = value_string(chunk, "bytesHex")?;
                    decode_hex(bytes_hex)
                })
                .collect::<CanonicalResult<Vec<_>>>()?
        } else {
            stored_verified_evaluation_key_share_proof_material_chunks(
                expected_proof_material_root,
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            proof_family.proof_family(),
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        if value_u64(proof_material, "proofChunkSizeBytes")?
            != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
            || value_u64(proof_material, "proofChunkCount")?
                != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "evaluation-key proof material chunk count does not fit u64",
                    )
                })?
            || value_u64(proof_material, "proofTotalByteLength")?
                != transport_hashes.total_byte_length
            || value_string(proof_material, "proofFullObjectHash")?
                != transport_hashes.full_object_hash
            || value_string(proof_material, "proofChunkRoot")? != transport_hashes.chunk_root
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported evaluation-key proof material hashes do not match chunks",
            ));
        }
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn unexpected_galois_key_share_proof_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "proofProfileId",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "evaluatorKeyScheduleRoot",
            "sameSecretConsistencyRoot",
            "sameSecretProofSetRoot",
            "sameSecretProofFamilyBindingRoot",
            "publicKeyShareLnpProofSetRoot",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofRoot",
            "galoisKeyCrpRoot",
            "requiredGaloisSetHash",
            "rotation",
            "level",
            "galoisKeyShareRoot",
            "setupProofBinding",
            "keySwitchMaterialEncoding",
            "keySwitchDomain",
            "keySwitchSeedHex",
            "ringDegree",
            "keySwitchComponentVectorRoot",
            "keySwitchComponentVectors",
            "keySwitchComponentMaterialRoot",
            "keySwitchComponentChunkSizeBytes",
            "keySwitchComponentChunkCount",
            "keySwitchComponentTotalByteLength",
            "keySwitchComponentFullObjectHash",
            "keySwitchComponentChunkRoot",
            "keySwitchComponentChunkHashes",
            "galoisKeyShareTboxParameterProfileHash",
            "statementHash",
            "relationCommitmentHash",
            "tboxCommitmentPrefixHash",
            "z34SeedMaterialHash",
            "z34ChallengeSeedHash",
            "z34ChallengeTailHash",
            "z34ChallengeRowDomainHash",
            "z34ChallengeZ3RowSetHash",
            "z34ChallengeZ4RowSetHash",
            "tboxLowerProtocolChallengeHash",
            "z34Z3CheckWindowHash",
            "z34Z4CheckWindowHash",
            "z34Z3L2SquaredDecimal",
            "z34Z4InfinityNormDecimal",
            "challenge",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesHex",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "galoisKeyShareProofRoot",
        ],
    )
}
