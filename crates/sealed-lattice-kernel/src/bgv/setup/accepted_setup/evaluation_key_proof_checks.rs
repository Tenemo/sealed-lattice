use super::*;

use super::same_secret_bridge_verification::VerifiedSameSecretBridgeMaterial;
use crate::bgv::setup::commitment::setup_commitment_root;
use crate::bgv::setup::setup_proof::take_verified_setup_proof_material_bytes;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretLinkageStatement,
    SetupProofStatement, SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
    decode_trustee_evaluation_key_proof_from_source,
    trustee_evaluation_key_proof_material_bytes_hash, verify_evaluation_key_share,
};
use crate::hashing::to_hex;

// Verification of the per-trustee succinct evaluation-key arguments: every
// trustee's single proof covers its whole frozen key schedule, and the
// verifier rebuilds each statement from the authenticated share records, the
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
    verified_same_secret_bridge: Option<&VerifiedSameSecretBridgeMaterial>,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<Option<Refusals>> {
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
                crate::foundation::RefusalReason::MissingPrerequisite,
                "trusteeEvaluationKeyProofsWithoutShareRecords",
                "trusteeEvaluationKeyProofs requires the relinearization rounds and Galois batches it proves",
                "setupPackage.trusteeEvaluationKeyProofs",
            )?)),
        };
    }
    let Some(proof_set) = proof_set else {
        return Ok(Some(setup_refusals(
            vec!["trusteeEvaluationKeyProofs".to_string()],
            Vec::new(),
        )));
    };
    if !proof_set.is_object() {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::MalformedEncoding,
            "trusteeEvaluationKeyProofsNotObject",
            "trusteeEvaluationKeyProofs must be a root-bound object",
            "setupPackage.trusteeEvaluationKeyProofs",
        )?));
    }
    if let Err(error) = verify_trustee_evaluation_key_proof_set(
        setup_package,
        proof_set,
        verified_same_secret_bridge,
        proof_binding_session,
    ) {
        return Ok(Some(evaluation_key_material_refusal(
            crate::foundation::RefusalReason::InvalidProof,
            "trusteeEvaluationKeyProofVerificationFailed",
            error.message,
            "setupPackage.trusteeEvaluationKeyProofs",
        )?));
    }

    Ok(None)
}

fn verify_trustee_evaluation_key_proof_set(
    setup_package: &Value,
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
    let roster = super::accepted_roster_from_package(setup_package)?;
    let proof_records = array_value(proof_set, "proofRecords")?;
    if proof_records.len() != roster.participant_count as usize {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "trusteeEvaluationKeyProofs.proofRecords must contain one proof per trustee",
        ));
    }
    trustee_evaluation_key_verify_progress(|| "shared-inputs-start".to_string());
    let round_one_aggregate_diagonals_by_level =
        round_one_public_aggregate_diagonals_from_package(setup_package, proof_binding_session)?;
    trustee_evaluation_key_verify_progress(|| "shared-inputs-finish".to_string());

    let verify_record = |record_position: usize, proof_record: &Value| -> CanonicalResult<()> {
        let trustee_roster_position = record_position as u64;
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} statement-start")
        });
        let statement =
            trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
                setup_package,
                verified_same_secret_bridge,
                round_one_aggregate_diagonals_by_level: &round_one_aggregate_diagonals_by_level,
                trustee_roster_position,
                accepted_setup_session: proof_binding_session,
            })?;
        trustee_evaluation_key_verify_progress(|| {
            format!("trustee={trustee_roster_position} statement-finish")
        });
        verify_trustee_evaluation_key_proof_record(
            proof_record,
            trustee_roster_position,
            &statement,
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
    trustee_roster_position: u64,
    statement: &TrusteeEvaluationKeyStatement,
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
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    let verification_binding_hash =
        trustee_evaluation_key_proof_verification_binding_hash(proof_record, statement)?;
    if !crate::bgv::setup::consume_accepted_setup_proof_binding(
        proof_binding_session.session_handle,
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        proof_bytes_hash,
        &verification_binding_hash,
    )? {
        let proof_bytes =
            trustee_evaluation_key_proof_bytes_from_hash(proof_bytes_hash, proof_binding_session)?;
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
    derive_canonical_object_hash(&json!({
        "objectType": "AcceptedSetupTrusteeEvaluationKeyProofVerificationBinding",
        "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
        "statementHash": to_hex(&statement.statement_hash()),
    }))
}

pub(in crate::bgv::setup) struct TrusteeEvaluationKeyStatementInputs<'a> {
    pub(in crate::bgv::setup) setup_package: &'a Value,
    pub(in crate::bgv::setup) verified_same_secret_bridge:
        Option<&'a VerifiedSameSecretBridgeMaterial>,
    pub(in crate::bgv::setup) round_one_aggregate_diagonals_by_level:
        &'a BTreeMap<u64, Vec<Vec<u64>>>,
    pub(in crate::bgv::setup) trustee_roster_position: u64,
    pub(in crate::bgv::setup) accepted_setup_session:
        &'a crate::bgv::setup::AcceptedSetupProofBindingSession,
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
    let participant_count = super::accepted_roster_from_package(setup_package)?.participant_count;
    let mut keys = Vec::new();
    for level in &scheduled_levels {
        let record = relinearization_record_for_trustee_and_level(
            rounds,
            "roundOneRecords",
            inputs.trustee_roster_position,
            *level,
            &scheduled_levels,
            participant_count,
        )?;
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&binding, "round-one", *level)?;
        let decoded_material = verify_relinearization_key_switch_sample_binding(
            record,
            &binding,
            "round-one",
            *level,
            inputs.trustee_roster_position,
            inputs.accepted_setup_session,
        )?;
        keys.push(evaluation_key_descriptor_from_verified_sample(
            EvaluationKeyShareKind::RelinearizationRoundOne,
            *level,
            "relinearization".to_string(),
            key_switch_seed_hex,
            decoded_material,
            Vec::new(),
        )?);
    }
    for level in &scheduled_levels {
        let record = relinearization_record_for_trustee_and_level(
            rounds,
            "roundTwoRecords",
            inputs.trustee_roster_position,
            *level,
            &scheduled_levels,
            participant_count,
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
        let key_switch_seed_hex =
            expected_relinearization_key_switch_seed(&binding, "round-two", *level)?;
        let decoded_material = verify_relinearization_key_switch_sample_binding(
            record,
            &binding,
            "round-two",
            *level,
            inputs.trustee_roster_position,
            inputs.accepted_setup_session,
        )?;
        keys.push(evaluation_key_descriptor_from_verified_sample(
            EvaluationKeyShareKind::RelinearizationRoundTwo,
            *level,
            "relinearization".to_string(),
            key_switch_seed_hex,
            decoded_material,
            aggregate_diagonal,
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
        .get(
            usize::try_from(inputs.trustee_roster_position).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "trustee roster position does not fit usize",
                )
            })?,
        )
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "Galois key share batches do not cover the trustee roster position",
            )
        })?;
    let expected_schedule = expected_required_galois_key_schedule()?;
    for (schedule_index, schedule_entry) in expected_schedule
        .as_array()
        .expect("required Galois key schedule is an array")
        .iter()
        .enumerate()
    {
        let rotation = value_u64(schedule_entry, "rotation")?;
        let level = value_u64(schedule_entry, "level")?;
        let material_record = galois_key_share_material_for_schedule(batch, schedule_index)?;
        let galois_element = usize::try_from(rotation).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "Galois rotation does not fit usize",
            )
        })?;
        let key_switch_domain = format!("galois-{rotation}");
        let key_switch_seed_hex = expected_galois_key_switch_seed(&binding, rotation, level)?;
        let decoded_material = verify_galois_key_switch_sample_binding(
            material_record,
            &binding,
            rotation,
            level,
            inputs.trustee_roster_position,
            inputs.accepted_setup_session,
        )?;
        keys.push(evaluation_key_descriptor_from_verified_sample(
            EvaluationKeyShareKind::GaloisRotation { galois_element },
            level,
            key_switch_domain,
            key_switch_seed_hex,
            decoded_material,
            Vec::new(),
        )?);
    }
    let ring_degree = binding.ring_degree;

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
    let same_secret_linkage = SameSecretLinkageStatement {
        public_matrix_seed_hash,
        commitments: vec![source_constant_commitment],
    };
    let context = SuccinctSetupProofContext {
        setup_context_hash: setup_context_hash(setup_context)?,
        trustee_identity: bridge_binding.trustee_identity.clone(),
        trustee_roster_position: inputs.trustee_roster_position,
        binding_roots: vec![
            binding.evaluator_key_schedule_root.clone(),
            source_constant_commitment_root,
        ],
    };
    let statement = TrusteeEvaluationKeyStatement {
        context,
        ring_degree,
        proof: SetupProofStatement::TrusteeEvaluationKey {
            keys,
            same_secret_linkage,
        },
    };
    statement.validate_shape()?;

    Ok(statement)
}

fn evaluation_key_descriptor_from_verified_sample(
    kind: EvaluationKeyShareKind,
    level: u64,
    key_switch_domain: String,
    key_switch_seed_hex: String,
    decoded_material: DecodedEvaluationKeyShareComponentMaterial,
    round_one_aggregate_diagonal: Vec<Vec<u64>>,
) -> CanonicalResult<EvaluationKeyShareDescriptor> {
    let level = usize::try_from(level).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "evaluation-key share level does not fit usize",
        )
    })?;
    Ok(EvaluationKeyShareDescriptor {
        kind,
        level,
        key_switch_domain,
        key_switch_seed_hex,
        component_b_by_digit: decoded_material.component_b_by_digit,
        round_one_aggregate_diagonal,
    })
}

fn relinearization_record_for_trustee_and_level<'a>(
    rounds: &'a Value,
    record_field_name: &str,
    trustee_roster_position: u64,
    level: u64,
    scheduled_levels: &[u64],
    participant_count: u64,
) -> CanonicalResult<&'a Value> {
    let level_index = scheduled_levels
        .iter()
        .position(|scheduled_level| *scheduled_level == level)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "relinearization {record_field_name} do not cover a scheduled trustee and level"
                ),
            )
        })?;
    let participant_count = usize::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "participant count does not fit usize",
        )
    })?;
    let trustee_roster_position = usize::try_from(trustee_roster_position).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "trustee roster position does not fit usize",
        )
    })?;
    let records = array_value(rounds, record_field_name)?;
    if records.len() != scheduled_levels.len() * participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "relinearization {record_field_name} do not cover every scheduled trustee and level"
            ),
        ));
    }
    records
        .get(level_index * participant_count + trustee_roster_position)
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
    accepted_setup_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<BTreeMap<u64, Vec<Vec<u64>>>> {
    let roster = super::accepted_roster_from_package(setup_package)?;
    let rounds = setup_package
        .get("relinearizationKeyShareRounds")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "relinearizationKeyShareRounds was required for round-one aggregate recomputation",
            )
        })?;
    let round_one_records = array_value(rounds, "roundOneRecords")?;
    let binding = evaluation_key_proof_common_binding(setup_package)?;
    let scheduled_levels = scheduled_relinearization_levels()?;
    let participant_count = usize::try_from(roster.participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "participant count does not fit usize",
        )
    })?;
    if round_one_records.len() != scheduled_levels.len() * participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "round-one aggregate requires one component contribution per trustee and scheduled level",
        ));
    }
    let mut aggregates_by_level = BTreeMap::<u64, (Vec<Vec<u64>>, u64)>::new();
    for (record_index, record) in round_one_records.iter().enumerate() {
        let level = scheduled_levels[record_index / participant_count];
        let trustee_roster_position =
            u64::try_from(record_index % participant_count).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "trustee roster position does not fit u64",
                )
            })?;
        let digit_count = usize::try_from(level).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "relinearization level does not fit usize",
            )
        })? + 1;
        let decoded_material = verify_relinearization_key_switch_sample_binding(
            record,
            &binding,
            "round-one",
            level,
            trustee_roster_position,
            accepted_setup_session,
        )?;
        let ring_degree = decoded_material.ring_degree;
        let components = decoded_material.component_b_by_digit;
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

fn trustee_evaluation_key_proof_bytes_from_hash(
    proof_bytes_hash: &str,
    proof_binding_session: &crate::bgv::setup::AcceptedSetupProofBindingSession,
) -> CanonicalResult<SetupProofMaterialBytes> {
    validate_hash_string(proof_bytes_hash, "trusteeEvaluationKeyProof.proofBytesHash")?;
    take_verified_setup_proof_material_bytes(
        TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        proof_bytes_hash,
        "trusteeEvaluationKeyProof.proofBytesHash",
        Some(proof_binding_session),
    )
}
