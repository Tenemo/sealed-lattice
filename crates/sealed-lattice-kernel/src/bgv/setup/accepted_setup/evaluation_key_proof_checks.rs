use super::*;

use super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
use crate::bgv::setup::commitment::setup_commitment_root;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretLinkageStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
    decode_trustee_evaluation_key_proof_from_source,
    trustee_evaluation_key_proof_material_bytes_hash, verify_evaluation_key_share,
};
use crate::hashing::to_hex;

// Verification of the per-trustee succinct evaluation-key arguments: every
// trustee's single proof covers its whole frozen key schedule, and the
// verifier rebuilds each statement from the transported share records, the
// recomputed round-one public aggregates, the accepted same-secret constant
// commitments, and the ceremony context. No proof material inside the share
// records is trusted; everything verification-relevant is recomputed here.

#[cfg(test)]
fn trustee_evaluation_key_verify_progress(message: impl FnOnce() -> String) {
    if std::env::var("SEALED_LATTICE_TRUSTEE_PROOF_VERIFY_PROGRESS").as_deref() == Ok("1") {
        println!("sealed-lattice-trustee-proof-verify-progress {}", message());
    }
}

#[cfg(not(test))]
fn trustee_evaluation_key_verify_progress(_message: impl FnOnce() -> String) {}

pub(super) fn verify_trustee_evaluation_key_proofs(
    setup_package: &Value,
    request: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Option<Value>> {
    let rounds_present = setup_package
        .get("relinearizationKeyShareRounds")
        .and_then(Value::as_object)
        .is_some_and(|rounds| !rounds.is_empty());
    let batches_present = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .is_some_and(|batches| !batches.is_empty());
    let proof_set = setup_package.get("trusteeEvaluationKeyProofs");
    if !rounds_present || !batches_present {
        return match proof_set {
            None => Ok(None),
            Some(proof_set) if proof_set.as_object().is_some_and(serde_json::Map::is_empty) => {
                Ok(None)
            }
            Some(_) => Ok(Some(evaluation_key_material_refusal(
                "trusteeEvaluationKeyProofsWithoutShareRecords",
                "trusteeEvaluationKeyProofs requires the relinearization rounds and Galois batches it proves",
                "setupPackage.trusteeEvaluationKeyProofs",
            )?)),
        };
    }
    let Some(proof_set) = proof_set else {
        if trustee_evaluation_key_proofs_have_terminal_dependents(setup_package) {
            return Ok(Some(evaluation_key_material_refusal(
                "trusteeEvaluationKeyProofsMissing",
                "trusteeEvaluationKeyProofs must be present before terminal evaluation-key material can be accepted",
                "setupPackage.trusteeEvaluationKeyProofs",
            )?));
        }

        return Ok(Some(verification_response(
            Some("trusteeEvaluationKeyProofs"),
            vec!["trusteeEvaluationKeyProofs".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !proof_set.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            "trusteeEvaluationKeyProofsNotObject",
            "trusteeEvaluationKeyProofs must be a root-bound object",
            "setupPackage.trusteeEvaluationKeyProofs",
        )?));
    }
    if let Err(error) = verify_trustee_evaluation_key_proof_set(
        setup_package,
        request,
        proof_set,
        verified_same_secret_bridge,
        proof_binding_session,
    ) {
        return Ok(Some(evaluation_key_material_refusal(
            "trusteeEvaluationKeyProofVerificationFailed",
            error.message,
            "setupPackage.trusteeEvaluationKeyProofs",
        )?));
    }

    Ok(None)
}

fn trustee_evaluation_key_proofs_have_terminal_dependents(setup_package: &Value) -> bool {
    setup_package.get("evaluationKeys").is_some()
}

fn verify_trustee_evaluation_key_proof_set(
    setup_package: &Value,
    request: &Value,
    proof_set: &Value,
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<()> {
    if proof_set.get("objectType").and_then(Value::as_str)
        != Some(TRUSTEE_EVALUATION_KEY_PROOF_SET_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trusteeEvaluationKeyProofs objectType must match the accepted parameters",
        ));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before trustee evaluation-key proof verification",
        )
    })?;
    let roster = super::accepted_roster_from_package(setup_package);
    verify_context_fields_match(proof_set, setup_context, "trusteeEvaluationKeyProofs")?;
    for (field_name, expected_value) in [("proofFamily", TRUSTEE_EVALUATION_KEY_PROOF_FAMILY)] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("trusteeEvaluationKeyProofs.{field_name} must be {expected_value}"),
            ));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("trusteeEvaluationKeyProofs.{field_name} must be {expected_value}"),
            ));
        }
    }
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before trustee evaluation-key proof verification",
            )
        })?;
    let key_switch_decomposition_hash = accepted_key_switch_decomposition_hash()?;
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitments| commitments.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "the verified VSS coefficient commitment root was required before trustee evaluation-key proof verification",
            )
        })?;
    for (field_name, expected_value) in [
        (
            "evaluatorKeyScheduleRoot",
            binding.evaluator_key_schedule_root.as_str(),
        ),
        (
            "requiredGaloisSetHash",
            binding.required_galois_set_hash.as_str(),
        ),
        (
            "keySwitchDecompositionHash",
            key_switch_decomposition_hash.as_str(),
        ),
        (
            "vssCoefficientCommitmentRoot",
            vss_coefficient_commitment_root,
        ),
        (
            "publicKeyShareSetRoot",
            binding.public_key_share_set_root.as_str(),
        ),
        (
            "publicKeyShareSuccinctProofSetRoot",
            binding.public_key_share_succinct_proof_set_root.as_str(),
        ),
        (
            "relinearizationCrpRoot",
            binding.relinearization_crp_root.as_str(),
        ),
        ("galoisKeyCrpRoot", binding.galois_key_crp_root.as_str()),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "trusteeEvaluationKeyProofs.{field_name} must match the accepted setup binding"
                ),
            ));
        }
    }
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .expect("relinearization rounds were checked before trustee proof verification");
    if proof_set
        .get("relinearizationKeyShareRoundsRoot")
        .and_then(Value::as_str)
        != rounds
            .get("relinearizationKeyShareRoundsRoot")
            .and_then(Value::as_str)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "trusteeEvaluationKeyProofs.relinearizationKeyShareRoundsRoot must bind the verified share-record container",
        ));
    }
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .expect("Galois batches were checked before trustee proof verification");
    let supplied_batch_roots = array_value(proof_set, "galoisKeyShareBatchRoots")?;
    if supplied_batch_roots.len() != batches.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "trusteeEvaluationKeyProofs.galoisKeyShareBatchRoots must list every verified Galois batch",
        ));
    }
    let mut batch_roots_by_roster_position = BTreeMap::new();
    for batch in batches {
        batch_roots_by_roster_position.insert(
            value_u64(batch, "trusteeRosterPosition")?,
            value_string(batch, "galoisKeyShareBatchRoot")?,
        );
    }
    for supplied_batch_root in supplied_batch_roots {
        let trustee_roster_position = value_u64(supplied_batch_root, "trusteeRosterPosition")?;
        if batch_roots_by_roster_position.get(&trustee_roster_position)
            != Some(&value_string(
                supplied_batch_root,
                "galoisKeyShareBatchRoot",
            )?)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "trusteeEvaluationKeyProofs.galoisKeyShareBatchRoots must match the verified Galois batches",
            ));
        }
    }

    let proof_records = array_value(proof_set, "proofRecords")?;
    if proof_records.len() != roster.participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "trusteeEvaluationKeyProofs.proofRecords must contain one proof per trustee",
        ));
    }
    // Index-equals-position enforces a single canonical ordering and full dense
    // coverage 0..n. Do this before rebuilding heavyweight aggregate inputs so
    // malformed containers fail without paying proof-verification costs.
    for (record_position, proof_record) in proof_records.iter().enumerate() {
        let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
        if trustee_roster_position != record_position as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "trustee evaluation-key proof records must be ordered by roster position",
            ));
        }
    }
    let supplied_root = value_string(proof_set, "trusteeEvaluationKeyProofSetRoot")?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("trustee evaluation-key proof set object was checked")
        .remove("trusteeEvaluationKeyProofSetRoot");
    trustee_evaluation_key_verify_progress(|| "proof-set-root-start".to_string());
    let expected_root = derive_canonical_object_hash(&root_input)?;
    trustee_evaluation_key_verify_progress(|| "proof-set-root-finish".to_string());
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trusteeEvaluationKeyProofSetRoot does not match the canonical trustee proof container",
        ));
    }

    trustee_evaluation_key_verify_progress(|| "shared-inputs-start".to_string());
    let transported_key_switch_component_material =
        transported_evaluation_key_share_component_material_from_request(request)?;
    let transported_key_switch_component_material = request
        .get("transportedEvaluationKeyShareComponentMaterial")
        .or(transported_key_switch_component_material.as_ref());
    let round_one_aggregate_diagonals_by_level = round_one_public_aggregate_diagonals_from_package(
        setup_package,
        transported_key_switch_component_material,
    )?;
    trustee_evaluation_key_verify_progress(|| "shared-inputs-finish".to_string());

    let verify_record = |record_position: usize, proof_record: &Value| -> CanonicalResult<()> {
        let trustee_roster_position = record_position as u64;
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} statement-start")
        });
        let statement =
            trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
                setup_package,
                transported_key_switch_component_material,
                verified_same_secret_bridge,
                round_one_aggregate_diagonals_by_level: &round_one_aggregate_diagonals_by_level,
                trustee_roster_position,
            })?;
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} statement-finish")
        });
        verify_trustee_evaluation_key_proof_record(
            proof_record,
            setup_context,
            &statement,
            request,
            proof_binding_session,
        )
    };
    // Resolve or consume each proof completely before the next record so the
    // accepted-setup verifier has a hard one-proof byte bound on every target.
    for (record_position, proof_record) in proof_records.iter().enumerate() {
        verify_record(record_position, proof_record)?;
    }

    Ok(())
}

fn verify_trustee_evaluation_key_proof_record(
    proof_record: &Value,
    setup_context: &Value,
    statement: &TrusteeEvaluationKeyStatement,
    request: &Value,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trustee evaluation-key proof record must be an object",
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str)
        != Some(TRUSTEE_EVALUATION_KEY_PROOF_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trustee evaluation-key proof objectType must match the accepted parameters",
        ));
    }
    verify_context_fields_match(proof_record, setup_context, "trusteeEvaluationKeyProof")?;
    for (field_name, expected_value) in [("proofFamily", TRUSTEE_EVALUATION_KEY_PROOF_FAMILY)] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("trustee evaluation-key proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    let source_constant_commitment_root = statement
        .context
        .binding_roots
        .iter()
        .find(|(label, _)| label == "sourceConstantCoefficientCommitmentRoot")
        .map(|(_, root)| root.as_str())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "trustee evaluation-key statement is missing its source constant commitment root",
            )
        })?;
    for (field_name, expected_value) in [
        (
            "trusteeIdentity",
            statement.context.trustee_identity.as_str(),
        ),
        (
            "sourceConstantCoefficientCommitmentRoot",
            source_constant_commitment_root,
        ),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!(
                    "trustee evaluation-key proof {field_name} must match the accepted trustee secret binding"
                ),
            ));
        }
    }
    let expected_statement_hash = to_hex(&statement.statement_hash());
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(expected_statement_hash.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "trustee evaluation-key proof statementHash must match the statement rebuilt from the verified share records",
        ));
    }
    let supplied_root = value_string(proof_record, "trusteeEvaluationKeyProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("trustee evaluation-key proof record object was checked")
        .remove("trusteeEvaluationKeyProofRoot");
    trustee_evaluation_key_verify_progress(|| {
        format!("trustee={trustee_roster_position} record-root-start")
    });
    let expected_root = derive_canonical_object_hash(&root_input)?;
    trustee_evaluation_key_verify_progress(|| {
        format!("trustee={trustee_roster_position} record-root-finish")
    });
    if supplied_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trusteeEvaluationKeyProofRoot does not match the canonical trustee proof record",
        ));
    }

    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    let verification_binding_hash =
        trustee_evaluation_key_proof_verification_binding_hash(proof_record, statement)?;
    if !crate::bgv::setup::consume_accepted_setup_proof_binding(
        proof_binding_session.session_handle,
        &proof_binding_session.capability,
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        proof_material_root,
        &verification_binding_hash,
    )? {
        let proof_bytes = trustee_evaluation_key_proof_bytes_from_record(proof_record, request)?;
        if value_string(proof_record, "proofBytesHash")?
            != trustee_evaluation_key_proof_material_bytes_hash(proof_bytes.as_ref())?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "trustee evaluation-key proofBytesHash must match supplied proof bytes",
            ));
        }
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} proof-verify-start")
        });
        if crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::statement_is_key_bearing(
            statement,
        ) {
            // Key-bearing statements verify only against the key-switch atom
            // schedule container; every other proof format fails its magic check.
            crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule::verify_key_bearing_trustee_evaluation_keys(
                statement,
                proof_bytes.as_ref(),
            )?;
        } else {
            let proof =
                decode_trustee_evaluation_key_proof_from_source(statement, proof_bytes.as_ref())?;
            verify_evaluation_key_share(statement, &proof)?;
        }
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} proof-verify-finish")
        });
    }

    Ok(())
}

pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_verification_binding_hash(
    proof_record: &Value,
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<String> {
    let mut proof_record_root_input = proof_record.clone();
    proof_record_root_input
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "trustee evaluation-key proof record must be an object",
            )
        })?
        .remove("trusteeEvaluationKeyProofRoot");
    derive_canonical_object_hash(&json!({
        "objectType": "AcceptedSetupTrusteeEvaluationKeyProofVerificationBinding",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "proofMaterialRoot": trustee_evaluation_key_proof_material_root(proof_record)?,
        "statementHash": to_hex(&statement.statement_hash()),
        "proofRecordRoot": derive_canonical_object_hash(&proof_record_root_input)?,
    }))
}

// The accepted key-switch decomposition hash the proof context binds:
// recomputed from the repo-owned decomposition parameters, never read from the
// package.
pub(in crate::bgv::setup) fn accepted_key_switch_decomposition_hash() -> CanonicalResult<String> {
    derive_canonical_object_hash(
        &crate::bgv::setup::certificates::key_switch_decomposition_parameters()?,
    )
}

pub(in crate::bgv::setup) struct TrusteeEvaluationKeyStatementInputs<'a> {
    pub(in crate::bgv::setup) setup_package: &'a Value,
    pub(in crate::bgv::setup) transported_key_switch_component_material: Option<&'a Value>,
    pub(in crate::bgv::setup) verified_same_secret_bridge:
        Option<&'a VerifiedSameSecretBridgeMaterial>,
    pub(in crate::bgv::setup) round_one_aggregate_diagonals_by_level:
        &'a BTreeMap<u64, Vec<Vec<u64>>>,
    pub(in crate::bgv::setup) trustee_roster_position: u64,
}

// Rebuild one trustee's batched evaluation-key statement from the package
// share records: relinearization round-one keys in scheduled-level order,
// round-two keys with the recomputed public aggregate diagonals, then Galois
// keys in frozen schedule order, linked to the same-secret commitments.
// The proof generator assembles the identical statement, so a proof only
// verifies against the exact records, aggregates, and ceremony context.
pub(in crate::bgv::setup) fn trustee_evaluation_key_statement_from_package(
    inputs: &TrusteeEvaluationKeyStatementInputs<'_>,
) -> CanonicalResult<TrusteeEvaluationKeyStatement> {
    let setup_package = inputs.setup_package;
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required for trustee evaluation-key statement assembly",
        )
    })?;
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required for trustee evaluation-key statement assembly",
            )
        })?;
    let scheduled_levels = scheduled_relinearization_levels()?;
    let mut keys = Vec::new();
    let mut ring_degree = None;
    for level in &scheduled_levels {
        let record = relinearization_record_for_trustee_and_level(
            rounds,
            "roundOneRecords",
            inputs.trustee_roster_position,
            *level,
        )?;
        keys.push(evaluation_key_descriptor_from_record(
            EvaluationKeyShareKind::RelinearizationRoundOne,
            EvaluationKeyShareProofFamily::Relinearization,
            record,
            inputs.transported_key_switch_component_material,
            Vec::new(),
            &mut ring_degree,
        )?);
    }
    for level in &scheduled_levels {
        let record = relinearization_record_for_trustee_and_level(
            rounds,
            "roundTwoRecords",
            inputs.trustee_roster_position,
            *level,
        )?;
        let aggregate_diagonal = inputs
            .round_one_aggregate_diagonals_by_level
            .get(level)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "round-one public aggregate diagonal is missing for a scheduled level",
                )
            })?
            .clone();
        keys.push(evaluation_key_descriptor_from_record(
            EvaluationKeyShareKind::RelinearizationRoundTwo,
            EvaluationKeyShareProofFamily::Relinearization,
            record,
            inputs.transported_key_switch_component_material,
            aggregate_diagonal,
            &mut ring_degree,
        )?);
    }
    let batches = setup_package
        .get("galoisKeyShareBatches")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "galoisKeyShareBatches was required for trustee evaluation-key statement assembly",
            )
        })?;
    let batch = batches
        .iter()
        .find(|batch| {
            batch.get("trusteeRosterPosition").and_then(Value::as_u64)
                == Some(inputs.trustee_roster_position)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batches do not cover the trustee roster position",
            )
        })?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    for schedule_entry in expected_schedule
        .as_array()
        .expect("required Galois key schedule is an array")
    {
        let rotation = value_u64(schedule_entry, "rotation")?;
        let level = value_u64(schedule_entry, "level")?;
        let material_record = galois_key_share_material_for_schedule(batch, rotation, level)?;
        let galois_element = usize::try_from(rotation).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois rotation does not fit usize",
            )
        })?;
        keys.push(evaluation_key_descriptor_from_record(
            EvaluationKeyShareKind::GaloisRotation { galois_element },
            EvaluationKeyShareProofFamily::Galois,
            material_record,
            inputs.transported_key_switch_component_material,
            Vec::new(),
            &mut ring_degree,
        )?);
    }
    let ring_degree = ring_degree.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trustee evaluation-key statement requires at least one share record",
        )
    })?;

    // The trustee's key schedule is proven against a bridge whose proof has
    // already been verified against the canonical source VSS commitments.
    let verified_same_secret_bridge =
        inputs.verified_same_secret_bridge.ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret bridge material was required for trustee evaluation-key proof verification",
            )
        })?;
    let bridge_binding = verified_same_secret_bridge
        .statement_for_roster_position(inputs.trustee_roster_position)?;
    // Link the key proof to the canonical source-limb-zero BDLOP
    // constant commitment. The verified bridge proves the full source set and
    // all target constants share one signed ternary secret; the key atom needs
    // only one source opening to establish the same short secret.
    let public_matrix_seed_hash = bridge_binding
        .source_linkage
        .public_matrix_seed_hash
        .clone();
    let source_constant_commitment = bridge_binding
        .source_linkage
        .commitments
        .first()
        .cloned()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verified same-secret bridge source linkage was empty",
            )
        })?;
    let source_constant_commitment_root = setup_commitment_root(&source_constant_commitment)?;
    let same_secret_linkage = Some(SameSecretLinkageStatement {
        public_matrix_seed_hash,
        commitments: vec![source_constant_commitment],
    });
    let context = SuccinctSetupProofContext {
        proof_family: TRUSTEE_EVALUATION_KEY_PROOF_FAMILY.to_string(),
        ceremony_id: value_string(setup_context, "ceremonyId")?.to_string(),
        manifest_hash: value_string(setup_context, "manifestHash")?.to_string(),
        roster_hash: value_string(setup_context, "rosterHash")?.to_string(),
        trustee_identity: bridge_binding.trustee_identity.clone(),
        trustee_roster_position: inputs.trustee_roster_position,
        setup_epoch: value_string(setup_context, "setupEpoch")?.to_string(),
        binding_roots: vec![
            (
                "requiredGaloisSetHash".to_string(),
                binding.required_galois_set_hash.clone(),
            ),
            (
                "evaluatorKeyScheduleRoot".to_string(),
                binding.evaluator_key_schedule_root.clone(),
            ),
            (
                "keySwitchDecompositionHash".to_string(),
                accepted_key_switch_decomposition_hash()?,
            ),
            (
                "sourceConstantCoefficientCommitmentRoot".to_string(),
                source_constant_commitment_root,
            ),
        ],
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        keys,
        vss_share_linkage: None,
        same_secret_bridge: None,
        same_secret_linkage,
        private_vss_share: None,
        target_decryption_share: None,
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn evaluation_key_descriptor_from_record(
    kind: EvaluationKeyShareKind,
    proof_family: EvaluationKeyShareProofFamily,
    record: &Value,
    transported_key_switch_component_material: Option<&Value>,
    round_one_aggregate_diagonal: Vec<Vec<u64>>,
    ring_degree: &mut Option<usize>,
) -> CanonicalResult<EvaluationKeyShareDescriptor> {
    let level = usize::try_from(value_u64(record, "level")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key share level does not fit usize",
        )
    })?;
    let record_ring_degree = usize::try_from(value_u64(record, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key share ring degree does not fit usize",
        )
    })?;
    match ring_degree {
        Some(existing_ring_degree) if *existing_ring_degree != record_ring_degree => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "evaluation-key share records must agree on one ring degree",
            ));
        }
        Some(_) => {}
        None => *ring_degree = Some(record_ring_degree),
    }
    let component_b_by_digit = component_b_vectors_from_record(
        proof_family,
        record,
        transported_key_switch_component_material,
    )?;

    Ok(EvaluationKeyShareDescriptor {
        kind,
        level,
        key_switch_domain: value_string(record, "keySwitchDomain")?.to_string(),
        key_switch_seed_hex: value_string(record, "keySwitchSeedHex")?.to_string(),
        component_b_by_digit,
        round_one_aggregate_diagonal,
    })
}

fn relinearization_record_for_trustee_and_level<'a>(
    rounds: &'a Value,
    record_field_name: &str,
    trustee_roster_position: u64,
    level: u64,
) -> CanonicalResult<&'a Value> {
    array_value(rounds, record_field_name)?
        .iter()
        .find(|record| {
            record.get("trusteeRosterPosition").and_then(Value::as_u64)
                == Some(trustee_roster_position)
                && record.get("level").and_then(Value::as_u64) == Some(level)
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "relinearization {record_field_name} do not cover a scheduled trustee and level"
                ),
            )
        })
}

// Two-round collective relinearization: round one publishes gadget shares of s, and round two proves each trustee's source equals s times the public sum of round-one diagonals, so the assembled key switches s^2 back to s.
// The public round-one aggregate diagonal per scheduled level: for digit j,
// the sum over every trustee of its round-one component b_{j,j} mod q_j. Each
// trustee's round-two source multiplies its secret by this public aggregate,
// and the verifier recomputes it here from the same records the statements
// are rebuilt from, so a substituted aggregate cannot verify.
pub(in crate::bgv::setup) fn round_one_public_aggregate_diagonals_from_package(
    setup_package: &Value,
    transported_key_switch_component_material: Option<&Value>,
) -> CanonicalResult<BTreeMap<u64, Vec<Vec<u64>>>> {
    let roster = super::accepted_roster_from_package(setup_package);
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required for round-one aggregate recomputation",
            )
        })?;
    let round_one_records = array_value(rounds, "roundOneRecords")?;
    let mut aggregates_by_level = BTreeMap::<u64, (Vec<Vec<u64>>, u64)>::new();
    for record in round_one_records {
        let level = value_u64(record, "level")?;
        let digit_count = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "relinearization level does not fit usize",
            )
        })? + 1;
        let components = component_b_vectors_from_record(
            EvaluationKeyShareProofFamily::Relinearization,
            record,
            transported_key_switch_component_material,
        )?;
        let ring_degree = components
            .first()
            .and_then(|by_limb| by_limb.first())
            .map(Vec::len)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "round-one component material does not cover the aggregate diagonal",
                )
            })?;
        let (aggregate, contribution_count) = aggregates_by_level
            .entry(level)
            .or_insert_with(|| (vec![vec![0_u64; ring_degree]; digit_count], 0));
        // Exactly one contribution per trustee prevents under or over-counting the collective round-one aggregate that every round-two proof multiplies against; only the (digit j, limb j) diagonal contributes, reduced mod q_j.
        for digit_index in 0..digit_count {
            let modulus = DATA_PRIMES[digit_index];
            let diagonal = components
                .get(digit_index)
                .and_then(|by_limb| by_limb.get(digit_index))
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "round-one component material does not cover the aggregate diagonal",
                    )
                })?;
            for (accumulated, value) in aggregate[digit_index].iter_mut().zip(diagonal.iter()) {
                *accumulated =
                    crate::bgv::modular_arithmetic::add_mod_fast(*accumulated, *value, modulus);
            }
        }
        *contribution_count += 1;
    }
    let mut aggregate_diagonals_by_level = BTreeMap::new();
    for (level, (aggregate, contribution_count)) in aggregates_by_level {
        if contribution_count != roster.participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "round-one aggregate requires one component contribution per trustee",
            ));
        }
        aggregate_diagonals_by_level.insert(level, aggregate);
    }

    Ok(aggregate_diagonals_by_level)
}

fn trustee_evaluation_key_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(
        proof_material_root,
        "trusteeEvaluationKeyProof.proofMaterialRoot",
    )?;
    let proof_bytes =
        transported_trustee_evaluation_key_proof_material_bytes(request, proof_material_root)?;
    let expected_material_root = trustee_evaluation_key_proof_material_root(proof_record)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trustee evaluation-key proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    Ok(proof_bytes)
}

pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_material_root(
    proof_record: &Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "TrusteeEvaluationKeyProofMaterialReference",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
        "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
        "statementHash": value_string(proof_record, "statementHash")?,
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
    }))
}

fn transported_trustee_evaluation_key_proof_material_bytes(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SetupProofMaterialBytes> {
    let material_set = request
        .get("transportedEvaluationKeyShareProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial was required by transported trustee evaluation-key proof records",
            )
        })?;
    let material_set_proof_family = material_set.get("proofFamily").and_then(Value::as_str);
    let material_set_family_matches = material_set_proof_family == Some("evaluation-key-share")
        || material_set_proof_family == Some(TRUSTEE_EVALUATION_KEY_PROOF_FAMILY);
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_SET_OBJECT_TYPE)
        || !material_set_family_matches
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial header does not match the trustee evaluation-key proof family",
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
    let mut matching_bytes = None;
    for proof_material in proof_materials {
        if proof_material.get("objectType").and_then(Value::as_str)
            != Some(EVALUATION_KEY_SHARE_PROOF_TRANSPORT_OBJECT_TYPE)
            || proof_material.get("proofFamily").and_then(Value::as_str)
                != Some(TRUSTEE_EVALUATION_KEY_PROOF_FAMILY)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported trustee evaluation-key proof material header is invalid",
            ));
        }
        if value_string(proof_material, "proofMaterialRoot")? != expected_proof_material_root {
            continue;
        }
        if matching_bytes.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedEvaluationKeyShareProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let proof_bytes = verified_setup_proof_material_bytes_from_request(
            request,
            TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            expected_proof_material_root,
            proof_material,
            "transportedEvaluationKeyShareProofMaterial.proofMaterials",
        )?;
        matching_bytes = Some(proof_bytes);
    }

    matching_bytes.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedEvaluationKeyShareProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}
