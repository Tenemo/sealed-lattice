use super::*;

use crate::hashing::derive_canonical_object_hash;

// Share-record containers for the trustee evaluation-key proof path. The
// records carry the public key-switch component material (the runtime key
// shares); the parent container and accepted setup package supply the ceremony
// and schedule bindings. The per-trustee succinct argument over every record
// is verified by
// verify_trustee_evaluation_key_proofs, which rebuilds each statement from
// these records, so the records themselves carry no proof fields.

pub(super) fn verify_relinearization_key_share_rounds(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let Some(rounds) = setup_package.get("relinearizationKeyShareRounds") else {
        return Ok(Some(setup_refusals(
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
        )));
    };
    if !rounds.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "relinearizationKeyShareRoundsNotObject",
            "relinearizationKeyShareRounds must be an object",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }
    if rounds.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(Some(setup_refusals(
            vec!["relinearizationKeyShareRounds".to_string()],
            Vec::new(),
        )));
    }
    if rounds.get("objectType").and_then(Value::as_str)
        != Some(RELINEARIZATION_KEY_SHARE_ROUNDS_OBJECT_TYPE)
    {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "relinearizationKeyShareRoundsTypeMismatch",
            "relinearizationKeyShareRounds.objectType must be RelinearizationKeyShareRounds",
            "setupPackage.relinearizationKeyShareRounds.objectType",
        )?));
    }
    let roster = super::accepted_roster_from_package(setup_package)?;
    let expected_levels = scheduled_relinearization_levels()?;
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let round_one_roots = array_value(rounds, "roundOneKeySwitchComponentMaterialRoots")?;
    let round_two_roots = array_value(rounds, "roundTwoKeySwitchComponentMaterialRoots")?;
    let expected_record_count = expected_levels.len() * roster.participant_count as usize;
    if round_one_roots.len() != expected_record_count
        || round_two_roots.len() != expected_record_count
    {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "relinearizationKeyShareRoundCountMismatch",
            "relinearization round-one and round-two records must contain one record per trustee and scheduled level",
            "setupPackage.relinearizationKeyShareRounds",
        )?));
    }

    for root in round_one_roots {
        if let Err(error) = verify_evaluation_key_component_material_root(root) {
            return Ok(Some(evaluation_key_material_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "evaluationKeyMaterialVerificationFailed",
                error.message,
                "setupPackage.relinearizationKeyShareRounds.roundOneKeySwitchComponentMaterialRoots",
            )?));
        }
    }

    for root in round_two_roots {
        if let Err(error) = verify_evaluation_key_component_material_root(root) {
            return Ok(Some(evaluation_key_material_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "evaluationKeyMaterialVerificationFailed",
                error.message,
                "setupPackage.relinearizationKeyShareRounds.roundTwoKeySwitchComponentMaterialRoots",
            )?));
        }
    }
    for trustee_roster_position in 0..roster.participant_count {
        verify_evaluation_key_record_trustee(&expected_trustees, trustee_roster_position)?;
    }
    Ok(None)
}

pub(super) fn verify_galois_key_share_batches(
    setup_package: &Value,
    trustee_registrations: &setup_intent::SetupIntentTrusteeRegistrationMap,
) -> CanonicalResult<Option<Refusals>> {
    let roster = super::accepted_roster_from_package(setup_package)?;
    let Some(batches) = setup_package.get("galoisKeyShareBatches") else {
        return Ok(Some(setup_refusals(
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
        )));
    };
    let Some(batches) = batches.as_array() else {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "galoisKeyShareBatchesNotArray",
            "galoisKeyShareBatches must be an array of trustee batches",
            "setupPackage.galoisKeyShareBatches",
        )?));
    };
    if batches.is_empty() {
        return Ok(Some(setup_refusals(
            vec!["galoisKeyShareBatches".to_string()],
            Vec::new(),
        )));
    }
    if batches.len() != roster.participant_count as usize {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::WrongTypeOrLength,
            "galoisKeyShareBatchCountMismatch",
            "galoisKeyShareBatches must contain one batch per trustee",
            "setupPackage.galoisKeyShareBatches",
        )?));
    }
    let expected_trustees = expected_trustees_from_setup_intent(trustee_registrations);
    let expected_schedule = expected_required_galois_key_schedule()?;
    for (trustee_roster_position, batch) in batches.iter().enumerate() {
        verify_evaluation_key_record_trustee(
            &expected_trustees,
            u64::try_from(trustee_roster_position).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "Galois key share batch position does not fit u64",
                )
            })?,
        )?;
        if let Err(error) = verify_galois_key_share_batch(batch, &expected_schedule) {
            return Ok(Some(evaluation_key_material_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
                "evaluationKeyMaterialVerificationFailed",
                error.message,
                "setupPackage.galoisKeyShareBatches",
            )?));
        }
    }

    Ok(None)
}

pub(super) fn galois_key_share_material_for_schedule(
    batch: &Value,
    schedule_index: usize,
) -> CanonicalResult<&str> {
    array_value(batch, "keySwitchComponentMaterialRoots")?
        .get(schedule_index)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batch does not contain a required scheduled material root",
            )
        })
}

pub(in crate::bgv::setup) struct EvaluationKeyProofCommonBinding {
    pub(super) evaluator_key_schedule_root: String,
    pub(super) public_matrix_seed_hash: String,
    pub(super) ring_degree: usize,
    trustee_identities: BTreeMap<u64, String>,
}

fn derive_evaluator_key_schedule_root(setup_package: &Value) -> CanonicalResult<String> {
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before evaluation-key share verification",
        )
    })?;
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluation-key share verification",
        )
    })?;
    derive_canonical_object_hash(&json!({
        "objectType": "EvaluatorKeySchedule",
        "setupContextHash": setup_context_hash(setup_context)?,
        "publicMatrixSeedHash": value_string(common_randomness, "publicMatrixSeedHash")?,
        "publicKeyShareSetRoot": derive_public_key_share_set_root(setup_package)?,
        "relinearizationLevelSchedule": expected_relinearization_level_schedule(),
        "requiredGaloisKeySchedule": expected_required_galois_key_schedule()?,
    }))
}

pub(in crate::bgv::setup) fn evaluation_key_proof_common_binding(
    setup_package: &Value,
) -> CanonicalResult<EvaluationKeyProofCommonBinding> {
    let common_randomness = setup_package.get("commonRandomness").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "commonRandomness was required before evaluation-key share verification",
        )
    })?;
    let trustee_identities = expected_trustees_from_setup_intent(
        &setup_intent::setup_intent_trustee_registrations_from_package(setup_package)?,
    );
    let vss_share_linkage_statement = setup_package.get("vssShareLinkageStatement").ok_or_else(
        || {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssShareLinkageStatement was required before evaluation-key share verification",
            )
        },
    )?;
    Ok(EvaluationKeyProofCommonBinding {
        evaluator_key_schedule_root: derive_evaluator_key_schedule_root(setup_package)?,
        public_matrix_seed_hash: value_string(common_randomness, "publicMatrixSeedHash")?
            .to_string(),
        ring_degree: usize::try_from(value_u64(vss_share_linkage_statement, "ringDegree")?)
            .map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "verified VSS ringDegree does not fit usize",
                )
            })?,
        trustee_identities,
    })
}

fn authoritative_trustee_identity(
    binding: &EvaluationKeyProofCommonBinding,
    trustee_roster_position: u64,
) -> CanonicalResult<&str> {
    binding
        .trustee_identities
        .get(&trustee_roster_position)
        .map(String::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "evaluation-key share trusteeRosterPosition must reference an accepted trustee",
            )
        })
}

// The scheduled relinearization key levels, read from the frozen evaluator
// schedule: one truncated key per round at the selected working level.
pub(in crate::bgv::setup) fn scheduled_relinearization_levels() -> CanonicalResult<Vec<u64>> {
    expected_relinearization_level_schedule()
        .as_array()
        .expect("relinearization level schedule is an array")
        .iter()
        .map(|entry| {
            entry.get("level").and_then(Value::as_u64).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "relinearization level schedule entry is missing its level",
                )
            })
        })
        .collect()
}

// Binds the shared public sampler directly to accepted common randomness and
// the exact schedule slot. The component-material sampler expands this seed per
// gadget digit and RNS limb.
pub(in crate::bgv::setup) fn expected_relinearization_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "RelinearizationKeySwitchPublicSampleSeed",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "publicMatrixSeedHash": binding.public_matrix_seed_hash.as_str(),
        "round": round,
        "level": level,
    }))
}

pub(in crate::bgv::setup) fn expected_galois_key_switch_seed(
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "GaloisKeySwitchPublicSampleSeed",
        "evaluatorKeyScheduleRoot": binding.evaluator_key_schedule_root.as_str(),
        "publicMatrixSeedHash": binding.public_matrix_seed_hash.as_str(),
        "rotation": rotation,
        "level": level,
    }))
}

pub(super) fn verify_relinearization_key_switch_sample_binding(
    material_root: &str,
    binding: &EvaluationKeyProofCommonBinding,
    round: &str,
    level: u64,
    trustee_roster_position: u64,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    let key_switch_seed_hex = expected_relinearization_key_switch_seed(binding, round, level)?;
    component_b_vectors_from_root(
        EvaluationKeyShareProofFamily::Relinearization,
        material_root,
        usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearization key-switch level does not fit usize",
            )
        })?,
        binding.ring_degree,
        EvaluationKeyShareDerivedMaterialBinding {
            trustee_identity: authoritative_trustee_identity(binding, trustee_roster_position)?,
            trustee_roster_position,
            key_switch_domain: "relinearization",
            key_switch_seed_hex: &key_switch_seed_hex,
        },
        accepted_setup_session,
    )
}

pub(super) fn verify_galois_key_switch_sample_binding(
    material_root: &str,
    binding: &EvaluationKeyProofCommonBinding,
    rotation: u64,
    level: u64,
    trustee_roster_position: u64,
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<DecodedEvaluationKeyShareComponentMaterial> {
    let key_switch_domain = format!("galois-{rotation}");
    let key_switch_seed_hex = expected_galois_key_switch_seed(binding, rotation, level)?;
    component_b_vectors_from_root(
        EvaluationKeyShareProofFamily::Galois,
        material_root,
        usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key-switch level does not fit usize",
            )
        })?,
        binding.ring_degree,
        EvaluationKeyShareDerivedMaterialBinding {
            trustee_identity: authoritative_trustee_identity(binding, trustee_roster_position)?,
            trustee_roster_position,
            key_switch_domain: &key_switch_domain,
            key_switch_seed_hex: &key_switch_seed_hex,
        },
        accepted_setup_session,
    )
}

// A share record binds the canonical streamed component material by root. The
// material is decoded and verified when the trustee proof statement is rebuilt.
fn verify_evaluation_key_component_material_root(root: &Value) -> CanonicalResult<()> {
    validate_hash_string(
        root.as_str().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "evaluation-key component material root must be a string",
            )
        })?,
        "evaluationKeyShareComponentMaterialRoot",
    )?;

    Ok(())
}

fn verify_galois_key_share_batch(batch: &Value, expected_schedule: &Value) -> CanonicalResult<()> {
    verify_evaluation_key_record_object(batch, GALOIS_KEY_SHARE_BATCH_OBJECT_TYPE)?;
    let expected_entries = expected_schedule.as_array().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "expected Galois key schedule must be an array",
        )
    })?;
    let material_roots = array_value(batch, "keySwitchComponentMaterialRoots")?;
    if material_roots.len() != expected_entries.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Galois key share batch must contain one material root per required schedule entry",
        ));
    }
    for material_root in material_roots {
        verify_evaluation_key_component_material_root(material_root)?;
    }

    Ok(())
}

fn verify_evaluation_key_record_object(
    record: &Value,
    expected_object_type: &str,
) -> CanonicalResult<()> {
    if !record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "evaluation-key share record must be an object",
        ));
    }
    if record.get("objectType").and_then(Value::as_str) != Some(expected_object_type) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("evaluation-key share objectType must be {expected_object_type}"),
        ));
    }
    Ok(())
}

fn verify_evaluation_key_record_trustee(
    expected_trustees: &BTreeMap<u64, String>,
    trustee_roster_position: u64,
) -> CanonicalResult<()> {
    if !expected_trustees.contains_key(&trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "evaluation-key share trusteeRosterPosition must reference an accepted trustee",
        ));
    }

    Ok(())
}
