use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

use serde_json::{Value, json};

use crate::{
    ballot_privacy::BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT,
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, validate_evaluation_keys},
            engine::{
                Ciphertext, ciphertext_canonical_bytes_hex, ciphertext_from_canonical_hex,
                ciphertext_object_root,
            },
            reconstruction::{AggregateContributor, reconstruct_aggregate, score_from_histogram},
            records::{
                EvaluationComparisonProfile, EvaluationParameters, EvaluatorOutputRoots,
                MAXIMUM_OPTION_COUNT, RankPackingMethod, SELECTED_TOP_K_SCORE_DOMAIN_MAXIMUM,
                appendix_d_public_input_statement, describe_evaluator_program,
                evaluation_context_hash, evaluation_noise_certificate, output_encoding_hash,
                public_slot_mask_hash, target_layout_hash, target_proposal_hash,
                top_k_evaluation_record,
            },
            top_k::{
                AGGREGATE_SCORE_COORDINATES_PER_OPTION, evaluate_packed_ranks_from_packed_scores,
                evaluate_packed_ranks_via_difference, evaluate_top_k,
                evaluate_top_k_via_difference, pack_reconstructed_aggregate_scores,
                packed_score_slot, project_packed_sparse_target,
                selected_evaluator_rotation_key_schedule,
            },
        },
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup::{
            generate_passive_setup_public_evaluation_keys_from_request,
            validate_passive_setup_package_for_encrypted_evaluation,
            verify_encrypted_aggregate_bridge_ciphertext_public_bindings,
        },
        setup_helpers::{array_at_path, integer_at_path, string_at_path, value_at_path},
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
    ring::{FIELD_MODULUS, derive_lagrange_coefficients_at_zero_for_roster_positions},
};

const DEFAULT_PLACEHOLDER_HASH_BYTE: &str = "00";
const DEFAULT_WORKING_LEVEL: usize = 10;

struct PreparedEvaluationKeyContext {
    setup_package_hash: String,
    collective_public_key_root: String,
    bgv_public_key_root: String,
    evaluation_key_root: String,
    key_switch_decomposition_hash: String,
    rot_set_hash: String,
    working_level: usize,
    context: EvaluatorContext,
}

static PREPARED_EVALUATION_KEY_CONTEXTS: OnceLock<
    Mutex<BTreeMap<String, PreparedEvaluationKeyContext>>,
> = OnceLock::new();

fn prepared_evaluation_key_contexts()
-> &'static Mutex<BTreeMap<String, PreparedEvaluationKeyContext>> {
    PREPARED_EVALUATION_KEY_CONTEXTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct SetupBoundAggregateCiphertexts {
    aggregate_ciphertexts: Vec<Ciphertext>,
    ciphertext_roots: Vec<String>,
    encrypted_aggregate_share_ciphertext_roots: Vec<String>,
    selected_aggregate_contribution_hashes: Vec<String>,
    selected_contributor_identities: Vec<String>,
    selected_contributor_roster_positions: Vec<u64>,
    bridge_inputs: Vec<Value>,
}

fn encrypted_ciphertext_artifact(role: &str, ciphertext: &Ciphertext) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "EncryptedEvaluatorCiphertext",
        "objectVersion": 1,
        "role": role,
        "ciphertextRoot": ciphertext_object_root(ciphertext)?,
        "canonicalBytesHex": ciphertext_canonical_bytes_hex(ciphertext)?,
    }))
}

fn encrypted_top_k_bundle_artifact(
    parameters: &EvaluationParameters,
    output_roots: &EvaluatorOutputRoots,
    packed_ranks: &Ciphertext,
    top_k_ciphertext_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "EncryptedTopKBundle",
        "objectVersion": 1,
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "topKCiphertextHash": top_k_ciphertext_hash,
        "acceptedOutputCiphertextRoots": {
            "encryptedAggregateReconstructionRoot": output_roots.encrypted_aggregate_reconstruction_root,
            "encryptedScoreBitInputRoot": output_roots.encrypted_score_bit_input_root,
            "greaterThanRoot": output_roots.greater_than_root,
            "equalRoot": output_roots.equal_root,
            "aheadRoot": output_roots.ahead_root,
            "rankRoot": output_roots.rank_root,
        },
        "packedRankCiphertext": encrypted_ciphertext_artifact("packed-rank", packed_ranks)?,
    }))
}

pub(crate) fn prepare_bgv_evaluation_key_material_handle(
    request: &Value,
) -> CanonicalResult<Value> {
    let mut prepared = generate_passive_setup_public_evaluation_keys_from_request(
        request,
        "prepareBgvEvaluationKeyMaterial",
    )?;
    let mut record = prepared.record;
    let handle = derive_protocol_hash("EvaluationKeySetDigest", &record)?;
    for relinearization_key in prepared.keys.relinearization_keys.iter_mut().flatten() {
        relinearization_key.drop_component_b();
    }
    for rotation_key in prepared.keys.rotation_keys.values_mut() {
        rotation_key.drop_component_b();
    }
    let context = EvaluatorContext::from_passive_setup_public_keys(prepared.keys);
    let prepared_context = PreparedEvaluationKeyContext {
        setup_package_hash: string_at_path(&record, &["setupPackageHash"])?.to_string(),
        collective_public_key_root: string_at_path(&record, &["collectivePublicKeyRoot"])?
            .to_string(),
        bgv_public_key_root: string_at_path(&record, &["bgvPublicKeyRoot"])?.to_string(),
        evaluation_key_root: string_at_path(&record, &["evaluationKeyRoot"])?.to_string(),
        key_switch_decomposition_hash: string_at_path(&record, &["keySwitchDecompositionHash"])?
            .to_string(),
        rot_set_hash: string_at_path(&record, &["rotSetHash"])?.to_string(),
        working_level: usize_at_record(&record, "workingLevel")?,
        context,
    };
    let mut contexts = prepared_evaluation_key_contexts().lock().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "prepared evaluation-key material registry is unavailable",
        )
    })?;
    contexts.insert(handle.clone(), prepared_context);
    record["preparedEvaluationKeyMaterialHandle"] = Value::String(handle);
    record["statusLabels"] = json!([
        "PreparedPublicEvaluationKeyMaterialGenerated",
        "PreparedEvaluationKeyMaterialHandleRegistered",
        "SetupPrivateWitnessNotExported",
        "EvaluationKeyRootBound"
    ]);

    Ok(record)
}

fn usize_at_record(record: &Value, field_name: &str) -> CanonicalResult<usize> {
    record
        .get(field_name)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{field_name} must be a non-negative integer"),
            )
        })
}

fn encrypted_sparse_target_artifact(
    parameters: &EvaluationParameters,
    output_roots: &EvaluatorOutputRoots,
    target_id: &Ciphertext,
    target_order: &Ciphertext,
    target_ciphertext_hash: &str,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": "EncryptedSparseTarget",
        "objectVersion": 1,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash(parameters.option_count)?,
        "publicSlotMaskHash": output_roots.public_slot_mask_hash,
        "outputEncodingHash": output_roots.output_encoding_hash,
        "targetIdCiphertext": encrypted_ciphertext_artifact("target-id", target_id)?,
        "targetOrderCiphertext": encrypted_ciphertext_artifact("target-order", target_order)?,
    }))
}

struct AggregateReadyEvaluationRecord {
    aggregate_ready_record_hash: String,
    encrypted_aggregate_bridge_hash: String,
    interpolation_coefficients: Vec<i64>,
    selected_aggregate_contribution_hashes: Vec<String>,
    selected_contributor_identities: Vec<String>,
    selected_contributor_roster_positions: Vec<u64>,
    option_count: usize,
}

struct VerifiedAggregateBridgeInput {
    bridge_verification: Value,
    contributor_identity: String,
    contributor_roster_position: u64,
    aggregate_contribution_hash: Option<String>,
}

fn read_string_or_default(request: &Value, field: &str) -> String {
    request.get(field).and_then(Value::as_str).map_or_else(
        || DEFAULT_PLACEHOLDER_HASH_BYTE.repeat(64),
        ToString::to_string,
    )
}

fn read_required_protocol_hash(request: &Value, field: &str) -> CanonicalResult<String> {
    let value = request.get(field).and_then(Value::as_str).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("accepted encrypted aggregate evaluation requires {field}"),
        )
    })?;
    if value.len() != 128
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field} must be a 128-character lowercase hexadecimal protocol hash"),
        ));
    }

    Ok(value.to_string())
}

fn require_finality_bound_fields_for_aggregate_ready_evaluation(
    request: &Value,
) -> CanonicalResult<()> {
    for field in [
        "canonicalBallotSetHash",
        "preTargetBoardHead",
        "evaluatorSignature",
    ] {
        read_required_protocol_hash(request, field)?;
    }

    Ok(())
}

fn read_u64(request: &Value, field: &str) -> CanonicalResult<u64> {
    request.get(field).and_then(Value::as_u64).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field} must be a non-negative integer"),
        )
    })
}

fn encrypt_broadcast(
    context: &EvaluatorContext,
    value: u64,
    seed: &str,
) -> CanonicalResult<Ciphertext> {
    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    coefficients[0] = value;
    context.key().encrypt_coefficients(&coefficients, seed)
}

fn read_top_count(request: &Value, option_count: usize) -> CanonicalResult<usize> {
    let top_count = usize::try_from(read_u64(request, "topCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount does not fit usize",
        )
    })?;
    if top_count == 0 || top_count > option_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "topCount must be between one and the number of encrypted aggregate inputs",
        ));
    }

    Ok(top_count)
}

fn read_top_count_values(request: &Value) -> CanonicalResult<Vec<usize>> {
    let top_counts = request
        .get("topCounts")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts must be a non-empty array of top-count values",
            )
        })?;
    if top_counts.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "topCounts must be a non-empty array of top-count values",
        ));
    }
    let mut seen = BTreeMap::new();
    let mut parsed = Vec::with_capacity(top_counts.len());
    for (index, value) in top_counts.iter().enumerate() {
        let top_count = value.as_u64().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts entries must be non-negative integers",
            )
        })?;
        let top_count = usize::try_from(top_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "topCounts entry does not fit usize",
            )
        })?;
        if top_count == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts entries must be between one and the number of encrypted aggregate inputs",
            ));
        }
        if seen.insert(top_count, index).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "topCounts must not contain duplicate values",
            ));
        }
        parsed.push(top_count);
    }

    Ok(parsed)
}

fn validate_top_counts_against_option_count(
    top_counts: Vec<usize>,
    option_count: usize,
) -> CanonicalResult<Vec<usize>> {
    if top_counts.iter().any(|top_count| *top_count > option_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "topCounts entries must be between one and the number of encrypted aggregate inputs",
        ));
    }

    Ok(top_counts)
}

fn read_selected_score_domain_max(request: &Value) -> CanonicalResult<u64> {
    let score_domain_max = read_u64(request, "scoreDomainMax")?;
    if score_domain_max != SELECTED_TOP_K_SCORE_DOMAIN_MAXIMUM {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation requires selected scoreDomainMax {SELECTED_TOP_K_SCORE_DOMAIN_MAXIMUM}"
            ),
        ));
    }

    Ok(score_domain_max)
}

fn reject_forbidden_accepted_evaluator_fields(value: &Value) -> CanonicalResult<()> {
    fn visit(value: &Value, path: &mut Vec<String>) -> CanonicalResult<()> {
        match value {
            Value::Object(object) => {
                for (field_name, child) in object {
                    if matches!(
                        field_name.as_str(),
                        "setupPrivateWitness"
                            | "privateSetupWitness"
                            | "privateSetupSeedHash"
                            | "privateSetupSeed"
                            | "developmentKeySet"
                            | "developmentSecretKey"
                            | "developmentEvaluationKeyMaterial"
                            | "trustedDealerSecret"
                            | "trustedDealerSecretHex"
                            | "trustedDealerSecretShares"
                            | "trustedDealerKeyMaterial"
                            | "fullSecretKey"
                            | "collectiveSecretKey"
                            | "secretKeyMaterial"
                            | "rawSecretShares"
                            | "secretShares"
                            | "thresholdSecretShares"
                            | "fullSecretReconstruction"
                            | "aggregateWitness"
                            | "proofWitness"
                            | "rawAggregateWitness"
                            | "receiverPlaintext"
                            | "aggregateInputPlaintext"
                            | "aggregateOpeningRandomness"
                            | "aggregateHistogram"
                            | "aggregateScore"
                            | "aggregateScoreBits"
                            | "plaintextComparisonInputs"
                            | "plaintextScoreBitInputs"
                            | "publicScoreBitFixtures"
                            | "scalarComparatorArtifact"
                            | "comparisonTruthSlots"
                            | "plaintextRanks"
                            | "rankSlots"
                            | "plaintextTarget"
                            | "targetPlaintext"
                            | "targetSlots"
                            | "decodedRanks"
                            | "decodedTargetIdSlots"
                            | "decodedTargetOrderSlots"
                            | "decodedPackedRanks"
                            | "decodedPackedTargetIdSlots"
                            | "decodedPackedTargetOrderSlots"
                            | "evaluationProofVerified"
                            | "targetAccepted"
                            | "acceptedTarget"
                            | "targetDecryptionShare"
                            | "partialDecryptionShare"
                            | "thresholdDecryptionShare"
                    ) {
                        let location = if path.is_empty() {
                            field_name.clone()
                        } else {
                            format!("{}.{}", path.join("."), field_name)
                        };
                        return Err(CanonicalError::new(
                            CanonicalErrorCode::InvalidFixture,
                            format!(
                                "accepted encrypted aggregate evaluation rejects forbidden witness field {location}"
                            ),
                        ));
                    }
                    path.push(field_name.clone());
                    visit(child, path)?;
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (item_index, child) in items.iter().enumerate() {
                    path.push(item_index.to_string());
                    visit(child, path)?;
                    path.pop();
                }
            }
            _ => {}
        }

        Ok(())
    }

    visit(value, &mut Vec::new())
}

fn required_generator_ordered_rotation_keys(
    option_count: usize,
) -> CanonicalResult<Vec<(usize, usize)>> {
    selected_evaluator_rotation_key_schedule(option_count, DATA_PRIMES.len() - 1)
}

fn require_public_rotation_keys_for_aggregate_ready_evaluation(
    context: &EvaluatorContext,
    option_count: usize,
) -> CanonicalResult<()> {
    for (galois_element, level) in required_generator_ordered_rotation_keys(option_count)? {
        if !context.has_public_rotation_key(galois_element, level) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "public evaluation-key material is missing required rotation key {galois_element} at level {level}"
                ),
            ));
        }
    }

    Ok(())
}

fn validate_prepared_context_binding(
    prepared: &PreparedEvaluationKeyContext,
    setup_package: &Value,
    working_level: usize,
) -> CanonicalResult<()> {
    let expected_setup_package_hash = string_at_path(setup_package, &["setupPackageHash"])?;
    let expected_collective_public_key_root = string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?;
    let expected_bgv_public_key_root =
        string_at_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?;
    let expected_evaluation_key_root =
        string_at_path(setup_package, &["evaluationKeys", "evaluationKeyRoot"])?;
    let expected_key_switch_decomposition_hash = string_at_path(
        setup_package,
        &["evaluationKeys", "keySwitchDecompositionHash"],
    )?;
    let expected_rot_set_hash = string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?;
    for (actual, expected, description) in [
        (
            prepared.setup_package_hash.as_str(),
            expected_setup_package_hash,
            "setup package hash",
        ),
        (
            prepared.collective_public_key_root.as_str(),
            expected_collective_public_key_root,
            "collective public key root",
        ),
        (
            prepared.bgv_public_key_root.as_str(),
            expected_bgv_public_key_root,
            "BGV public key root",
        ),
        (
            prepared.evaluation_key_root.as_str(),
            expected_evaluation_key_root,
            "evaluation key root",
        ),
        (
            prepared.key_switch_decomposition_hash.as_str(),
            expected_key_switch_decomposition_hash,
            "key-switch decomposition hash",
        ),
        (
            prepared.rot_set_hash.as_str(),
            expected_rot_set_hash,
            "rotation set hash",
        ),
    ] {
        if actual != expected {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("prepared evaluation-key material {description} does not match setup"),
            ));
        }
    }
    if prepared.working_level != working_level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "prepared evaluation-key material working level does not match the evaluator request",
        ));
    }

    Ok(())
}

fn with_aggregate_ready_evaluator_context<T>(
    request: &Value,
    setup_package: &Value,
    working_level: usize,
    option_count: usize,
    evaluate: impl FnOnce(&EvaluatorContext) -> CanonicalResult<T>,
) -> CanonicalResult<T> {
    let material = request.get("evaluationKeyMaterial");
    let prepared_handle = request
        .get("preparedEvaluationKeyMaterialHandle")
        .and_then(Value::as_str);
    match (material, prepared_handle) {
        (Some(_), Some(_)) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation must provide either public evaluation-key material or a prepared evaluation-key material handle, not both",
        )),
        (Some(evaluation_key_material), None) => {
            let context = EvaluatorContext::from_passive_setup_public_material(
                setup_package,
                evaluation_key_material,
                working_level,
            )?;
            require_public_rotation_keys_for_aggregate_ready_evaluation(&context, option_count)?;
            evaluate(&context)
        }
        (None, Some(handle)) => {
            let contexts = prepared_evaluation_key_contexts().lock().map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "prepared evaluation-key material registry is unavailable",
                )
            })?;
            let prepared = contexts.get(handle).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "prepared evaluation-key material handle is not registered",
                )
            })?;
            validate_prepared_context_binding(prepared, setup_package, working_level)?;
            require_public_rotation_keys_for_aggregate_ready_evaluation(
                &prepared.context,
                option_count,
            )?;
            evaluate(&prepared.context)
        }
        (None, None) => Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation requires public evaluation-key material or a prepared evaluation-key material handle",
        )),
    }
}

fn require_setup_target_layout_for_aggregate_ready_evaluation(
    setup_package: &Value,
    option_count: usize,
) -> CanonicalResult<()> {
    if string_at_path(setup_package, &["profileBindings", "targetLayoutHash"])?
        != target_layout_hash(option_count)?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "setup package target layout hash does not match the accepted evaluator target layout",
        ));
    }

    Ok(())
}

fn setup_bound_parameters(
    request: &Value,
    setup_package: &Value,
    option_count: usize,
    top_count: usize,
    score_domain_max: u64,
    encrypted_aggregate_bridge_hash: String,
    aggregate_ready_record_hash: String,
) -> CanonicalResult<EvaluationParameters> {
    Ok(EvaluationParameters {
        ceremony_id: string_at_path(setup_package, &["setupInputs", "ceremonyId"])?.to_string(),
        manifest_hash: string_at_path(setup_package, &["setupInputs", "manifestHash"])?.to_string(),
        roster_hash: string_at_path(setup_package, &["setupInputs", "rosterHash"])?.to_string(),
        canonical_ballot_set_hash: read_required_protocol_hash(request, "canonicalBallotSetHash")?,
        aggregate_ready_record_hash,
        encrypted_aggregate_bridge_hash,
        encrypted_aggregate_target_basis_root: string_at_path(
            setup_package,
            &["profileBindings", "encryptedAggregateTargetBasisRoot"],
        )?
        .to_string(),
        bgv_public_key_root: string_at_path(
            setup_package,
            &["collectivePublicKey", "bgvPublicKeyRoot"],
        )?
        .to_string(),
        collective_public_key_root: string_at_path(
            setup_package,
            &["collectivePublicKey", "collectivePublicKeyRoot"],
        )?
        .to_string(),
        evaluation_key_root: string_at_path(
            setup_package,
            &["evaluationKeys", "evaluationKeyRoot"],
        )?
        .to_string(),
        rot_set_hash: string_at_path(setup_package, &["evaluationKeys", "rotSetHash"])?.to_string(),
        option_count,
        top_count,
        score_domain_max,
        comparison_profile: EvaluationComparisonProfile::DirectScoreComparison,
        rank_packing_method: RankPackingMethod::PerOptionBroadcast,
    })
}

fn read_setup_bound_aggregate_ciphertexts(
    request: &Value,
    setup_package: &Value,
) -> CanonicalResult<SetupBoundAggregateCiphertexts> {
    let inputs = array_at_path(request, &["encryptedAggregateInputs"])?;
    if inputs.len() < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encryptedAggregateInputs must contain at least two selected bridge ciphertexts",
        ));
    }
    let mut aggregate_ciphertexts = Vec::with_capacity(inputs.len());
    let mut ciphertext_roots = Vec::with_capacity(inputs.len());
    let mut encrypted_aggregate_share_ciphertext_roots = Vec::with_capacity(inputs.len());
    let mut selected_aggregate_contribution_hashes = Vec::with_capacity(inputs.len());
    let mut selected_contributor_identities = Vec::with_capacity(inputs.len());
    let mut selected_contributor_roster_positions = Vec::with_capacity(inputs.len());
    let mut bridge_inputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let verified_input = verify_aggregate_bridge_input_for_evaluation(setup_package, input)?;
        let contributor_identity = verified_input.contributor_identity;
        let contributor_roster_position = verified_input.contributor_roster_position;
        if selected_contributor_identities.contains(&contributor_identity) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encryptedAggregateInputs must not repeat a selected contributor identity",
            ));
        }
        if selected_contributor_roster_positions.contains(&contributor_roster_position) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encryptedAggregateInputs must not repeat a selected contributor roster position",
            ));
        }
        let bridge_encryption = value_at_path(input, &["bridgeEncryption"])?;
        let ciphertext_root = string_at_path(bridge_encryption, &["ciphertextRoot"])?;
        let encrypted_aggregate_share_ciphertext_root = string_at_path(
            &verified_input.bridge_verification,
            &["encryptedAggregateShareCiphertextRoot"],
        )?;
        let canonical_bytes_hex = string_at_path(bridge_encryption, &["canonicalBytesHex"])?;
        aggregate_ciphertexts.push(ciphertext_from_canonical_hex(
            canonical_bytes_hex,
            Some(ciphertext_root),
        )?);
        ciphertext_roots.push(ciphertext_root.to_string());
        encrypted_aggregate_share_ciphertext_roots
            .push(encrypted_aggregate_share_ciphertext_root.to_string());
        if let Some(aggregate_contribution_hash) = verified_input.aggregate_contribution_hash {
            selected_aggregate_contribution_hashes.push(aggregate_contribution_hash);
        }
        selected_contributor_identities.push(contributor_identity);
        selected_contributor_roster_positions.push(contributor_roster_position);
        bridge_inputs.push(input.clone());
    }

    Ok(SetupBoundAggregateCiphertexts {
        aggregate_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        selected_aggregate_contribution_hashes,
        selected_contributor_identities,
        selected_contributor_roster_positions,
        bridge_inputs,
    })
}

fn verify_aggregate_bridge_input_for_evaluation(
    setup_package: &Value,
    input: &Value,
) -> CanonicalResult<VerifiedAggregateBridgeInput> {
    if input.get("bridgeEvidenceVerification").is_none()
        || input.get("aggregateContribution").is_none()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation requires accepted aggregate contributions with bridge evidence verification",
        ));
    }

    verify_compact_aggregate_bridge_input_for_evaluation(setup_package, input)
}

fn require_false(value: &Value, path: &[&str], description: &str) -> CanonicalResult<()> {
    if value_at_path(value, path)?.as_bool() != Some(false) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("encrypted aggregate evaluation rejects {description}"),
        ));
    }

    Ok(())
}

fn require_true(value: &Value, path: &[&str], description: &str) -> CanonicalResult<()> {
    if value_at_path(value, path)?.as_bool() != Some(true) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("encrypted aggregate evaluation requires {description}"),
        ));
    }

    Ok(())
}

fn validate_compact_bridge_status_for_evaluation(
    bridge_encryption: &Value,
    bridge_verification: &Value,
    bridge_proof_record: &Value,
) -> CanonicalResult<()> {
    for (value, object_name) in [
        (bridge_encryption, "bridge encryption"),
        (bridge_verification, "bridge evidence"),
        (bridge_proof_record, "bridge proof record"),
    ] {
        require_false(
            value,
            &["developmentKeyOnly"],
            &format!("development-only {object_name}"),
        )?;
        require_true(
            value,
            &["claimBearingBridgeEncryption"],
            &format!("claim-bearing {object_name}"),
        )?;
        require_true(
            value,
            &["bridgeClaimClosureVerified"],
            &format!("verified bridge proof claim closure for {object_name}"),
        )?;
        if string_at_path(value, &["bridgeClaimVerificationStatus"])?
            != "BridgeProofClaimClosureVerified"
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted aggregate evaluation requires verified bridge proof status for {object_name}"
                ),
            ));
        }
        require_true(
            value,
            &["thresholdDecryptable"],
            &format!("threshold-decryptable {object_name}"),
        )?;
        if string_at_path(value, &["bgvEncryptionKeyMaterialKind"])?
            != "passive-transcript-derived-collective-public-key"
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted aggregate evaluation requires supported BGV key material for {object_name}"
                ),
            ));
        }
    }

    Ok(())
}

fn require_compact_bridge_fresh_randomness_for_evaluation(
    value: &Value,
    object_name: &str,
) -> CanonicalResult<()> {
    let prover_randomness_source = string_at_path(value, &["proverRandomnessSource"])?;
    let encryption_randomness_seed_source =
        string_at_path(value, &["encryptionRandomnessSeedSource"])?;
    if prover_randomness_source != "fresh-csprng"
        || encryption_randomness_seed_source != "fresh-csprng"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation requires fresh bridge prover and encryption randomness for {object_name}"
            ),
        ));
    }

    let randomness_source_evidence = value_at_path(value, &["randomnessSourceEvidence"])?;
    if string_at_path(randomness_source_evidence, &["objectType"])?
        != "AggregateBridgeRandomnessSourceEvidence"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation requires bridge randomness source evidence for {object_name}"
            ),
        ));
    }
    if value_at_path(randomness_source_evidence, &["objectVersion"])?.as_u64() != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            format!(
                "encrypted aggregate evaluation requires supported bridge randomness source evidence for {object_name}"
            ),
        ));
    }
    if string_at_path(randomness_source_evidence, &["proverRandomnessSource"])?
        != prover_randomness_source
        || string_at_path(
            randomness_source_evidence,
            &["encryptionRandomnessSeedSource"],
        )? != encryption_randomness_seed_source
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation requires bridge randomness source evidence to match {object_name}"
            ),
        ));
    }
    if value_at_path(
        randomness_source_evidence,
        &["callerSuppliedDevelopmentRandomness"],
    )?
    .as_bool()
        != Some(false)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation rejects development bridge randomness for {object_name}"
            ),
        ));
    }
    if value_at_path(randomness_source_evidence, &["claimBearingEntropyEvidence"])?.as_bool()
        != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation requires bridge entropy evidence accepted for {object_name}"
            ),
        ));
    }

    Ok(())
}

fn require_same_randomness_source_evidence(
    left: &Value,
    left_name: &str,
    right: &Value,
    right_name: &str,
) -> CanonicalResult<()> {
    if value_at_path(left, &["randomnessSourceEvidence"])?
        != value_at_path(right, &["randomnessSourceEvidence"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!(
                "encrypted aggregate evaluation bridge randomness source evidence does not match between {left_name} and {right_name}"
            ),
        ));
    }

    Ok(())
}

fn validate_compact_bridge_randomness_for_evaluation(
    bridge_encryption: &Value,
    bridge_verification: &Value,
    bridge_proof_record: &Value,
) -> CanonicalResult<()> {
    for (value, object_name) in [
        (bridge_encryption, "bridge encryption"),
        (bridge_verification, "bridge evidence"),
        (bridge_proof_record, "bridge proof record"),
    ] {
        require_compact_bridge_fresh_randomness_for_evaluation(value, object_name)?;
    }

    for field_name in ["proverRandomnessSource", "encryptionRandomnessSeedSource"] {
        require_same_string(
            bridge_encryption,
            &[field_name],
            bridge_verification,
            &[field_name],
            field_name,
        )?;
        require_same_string(
            bridge_proof_record,
            &[field_name],
            bridge_verification,
            &[field_name],
            field_name,
        )?;
    }
    require_same_randomness_source_evidence(
        bridge_encryption,
        "bridge encryption",
        bridge_verification,
        "bridge evidence",
    )?;
    require_same_randomness_source_evidence(
        bridge_proof_record,
        "bridge proof record",
        bridge_verification,
        "bridge evidence",
    )
}

fn require_aggregate_derivation_full_verification_checked(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<()> {
    if string_at_path(value, path)? != "AggregateDerivationFullVerificationChecked" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("encrypted aggregate evaluation requires {description}"),
        ));
    }

    Ok(())
}

fn require_same_string(
    left: &Value,
    left_path: &[&str],
    right: &Value,
    right_path: &[&str],
    description: &str,
) -> CanonicalResult<()> {
    if string_at_path(left, left_path)? != string_at_path(right, right_path)? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("encrypted aggregate evaluation {description} does not match"),
        ));
    }

    Ok(())
}

fn require_same_u64(
    left: &Value,
    left_path: &[&str],
    right: &Value,
    right_path: &[&str],
    description: &str,
) -> CanonicalResult<()> {
    let left_value = value_at_path(left, left_path)?.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be a non-negative integer"),
        )
    })?;
    let right_value = value_at_path(right, right_path)?.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be a non-negative integer"),
        )
    })?;
    if left_value != right_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("encrypted aggregate evaluation {description} does not match"),
        ));
    }

    Ok(())
}

fn validate_compact_bridge_bindings_for_evaluation(
    setup_package: &Value,
    bridge_encryption: &Value,
    bridge_verification: &Value,
    bridge_proof_record: &Value,
) -> CanonicalResult<()> {
    for (proof_record_path, setup_package_path, description) in [
        (
            &["setupPackageHash"][..],
            &["setupPackageHash"][..],
            "setup package hash",
        ),
        (
            &["collectivePublicKeyRoot"][..],
            &["collectivePublicKey", "collectivePublicKeyRoot"][..],
            "collective public key root",
        ),
        (
            &["collectivePublicKeyCoefficientRoot"][..],
            &["collectivePublicKey", "collectivePublicKeyCoefficientRoot"][..],
            "collective public key coefficient root",
        ),
        (
            &["bgvPublicKeyRoot"][..],
            &["collectivePublicKey", "bgvPublicKeyRoot"][..],
            "BGV public key root",
        ),
    ] {
        require_same_string(
            bridge_proof_record,
            proof_record_path,
            setup_package,
            setup_package_path,
            description,
        )?;
    }

    for (proof_record_field, bridge_field, verification_field, description) in [
        (
            "bridgeProofProfileHash",
            "bridgeProofProfileHash",
            "bridgeProofProfileHash",
            "bridge proof profile hash",
        ),
        (
            "proofStatementHash",
            "bridgeProofStatementHash",
            "bridgeProofStatementHash",
            "bridge proof statement hash",
        ),
        (
            "bridgeProofChallengeContextHash",
            "bridgeProofChallengeContextHash",
            "bridgeProofChallengeContextHash",
            "bridge proof challenge context hash",
        ),
        (
            "bridgeProofTargetContractHash",
            "bridgeProofTargetContractHash",
            "bridgeProofTargetContractHash",
            "bridge proof target contract hash",
        ),
        (
            "proofBytesHash",
            "bridgeProofBytesHash",
            "bridgeProofBytesHash",
            "bridge proof bytes hash",
        ),
        (
            "proofRoot",
            "bridgeProofRoot",
            "bridgeProofRoot",
            "bridge proof root",
        ),
        (
            "encryptedAggregateInputRoot",
            "encryptedAggregateInputRoot",
            "encryptedAggregateInputRoot",
            "encrypted aggregate input root",
        ),
        (
            "encryptedAggregateShareCiphertextRoot",
            "encryptedAggregateShareCiphertextRoot",
            "encryptedAggregateShareCiphertextRoot",
            "encrypted aggregate-share ciphertext root",
        ),
        (
            "plaintextCoefficientBindingCommitmentHash",
            "plaintextCoefficientBindingCommitmentHash",
            "plaintextCoefficientBindingCommitmentHash",
            "plaintext coefficient binding commitment hash",
        ),
        (
            "proofFriendlyPlaintextLiftBindingHash",
            "proofFriendlyPlaintextLiftBindingHash",
            "proofFriendlyPlaintextLiftBindingHash",
            "proof-friendly plaintext lift binding hash",
        ),
    ] {
        require_same_string(
            bridge_proof_record,
            &[proof_record_field],
            bridge_encryption,
            &[bridge_field],
            description,
        )?;
        require_same_string(
            bridge_verification,
            &[verification_field],
            bridge_encryption,
            &[bridge_field],
            description,
        )?;
    }

    require_same_string(
        bridge_verification,
        &["collectivePublicKeyCoefficientRoot"],
        bridge_encryption,
        &["collectivePublicKeyCoefficientRoot"],
        "verified collective public key coefficient root",
    )
}

fn verify_compact_aggregate_bridge_input_for_evaluation(
    setup_package: &Value,
    input: &Value,
) -> CanonicalResult<VerifiedAggregateBridgeInput> {
    let bridge_encryption = value_at_path(input, &["bridgeEncryption"])?;
    let bridge_verification = value_at_path(input, &["bridgeEvidenceVerification"])?;
    let aggregate_contribution = value_at_path(input, &["aggregateContribution"])?;
    let bridge_proof_record = value_at_path(aggregate_contribution, &["bridgeProofRecord"])?;
    let aggregate_derivation_component_hash =
        string_at_path(input, &["aggregateDerivationComponentHash"])?;
    let aggregate_derivation_statement_hash =
        string_at_path(input, &["aggregateDerivationStatementHash"])?;
    let post_voting_closed_context_hash = string_at_path(input, &["postVotingClosedContextHash"])?;

    if string_at_path(bridge_verification, &["bridgeProofVerificationStatus"])?
        != "BridgeProofRelationChecked"
        || string_at_path(bridge_verification, &["bridgeEvidenceVerificationStatus"])?
            != "BridgeProofEvidenceChecked"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires checked compact aggregate bridge evidence",
        ));
    }
    validate_compact_bridge_status_for_evaluation(
        bridge_encryption,
        bridge_verification,
        bridge_proof_record,
    )?;
    validate_compact_bridge_randomness_for_evaluation(
        bridge_encryption,
        bridge_verification,
        bridge_proof_record,
    )?;
    validate_compact_bridge_bindings_for_evaluation(
        setup_package,
        bridge_encryption,
        bridge_verification,
        bridge_proof_record,
    )?;
    require_aggregate_derivation_full_verification_checked(
        bridge_verification,
        &["aggregateDerivationVerificationScope"],
        "full aggregate-derivation verification bound to the bridge proof",
    )?;
    if string_at_path(bridge_proof_record, &["bridgeProofVerificationStatus"])?
        != "BridgeProofRelationChecked"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires a proof-checked aggregate contribution",
        ));
    }
    require_aggregate_derivation_full_verification_checked(
        bridge_proof_record,
        &["aggregateDerivationVerificationScope"],
        "a proof record with full aggregate-derivation verification scope",
    )?;
    require_same_string(
        bridge_proof_record,
        &["aggregateDerivationVerificationScope"],
        bridge_verification,
        &["aggregateDerivationVerificationScope"],
        "aggregate-derivation verification scope",
    )?;
    require_same_string(
        bridge_proof_record,
        &["aggregateDerivationComponentHash"],
        input,
        &["aggregateDerivationComponentHash"],
        "aggregate derivation component hash",
    )?;
    require_same_string(
        bridge_proof_record,
        &["aggregateDerivationStatementHash"],
        input,
        &["aggregateDerivationStatementHash"],
        "aggregate derivation statement hash",
    )?;
    require_same_string(
        bridge_proof_record,
        &["postVotingClosedContextHash"],
        input,
        &["postVotingClosedContextHash"],
        "post-voting-closed context hash",
    )?;
    require_same_string(
        bridge_proof_record,
        &["contributorIdentity"],
        aggregate_contribution,
        &["contributorIdentity"],
        "selected contributor identity",
    )?;
    require_same_u64(
        bridge_proof_record,
        &["contributorRosterPosition"],
        aggregate_contribution,
        &["contributorRosterPosition"],
        "selected contributor roster position",
    )?;
    require_canonical_bridge_proof_record_hash_for_evaluation(bridge_proof_record)?;
    require_canonical_aggregate_contribution_hash_for_evaluation(aggregate_contribution)?;
    require_aggregate_contribution_matches_bridge_proof_record_for_evaluation(
        aggregate_contribution,
        bridge_proof_record,
    )?;
    require_same_string(
        bridge_proof_record,
        &["encryptedAggregateShareCiphertextRoot"],
        bridge_verification,
        &["encryptedAggregateShareCiphertextRoot"],
        "verified encrypted aggregate-share ciphertext root",
    )?;
    require_same_string(
        bridge_proof_record,
        &["encryptedAggregateShareCiphertextRoot"],
        bridge_encryption,
        &["encryptedAggregateShareCiphertextRoot"],
        "bridge ciphertext root binding",
    )?;
    for field_name in [
        "bridgeProofProfileHash",
        "bridgeProofTargetContractHash",
        "proofStatementHash",
        "proofBytesHash",
        "proofRoot",
    ] {
        let verification_field_name = match field_name {
            "proofStatementHash" => "bridgeProofStatementHash",
            "proofBytesHash" => "bridgeProofBytesHash",
            "proofRoot" => "bridgeProofRoot",
            other => other,
        };
        require_same_string(
            bridge_proof_record,
            &[field_name],
            bridge_verification,
            &[verification_field_name],
            field_name,
        )?;
    }
    verify_encrypted_aggregate_bridge_ciphertext_public_bindings(
        setup_package,
        aggregate_derivation_component_hash,
        aggregate_derivation_statement_hash,
        post_voting_closed_context_hash,
        bridge_encryption,
    )?;

    Ok(VerifiedAggregateBridgeInput {
        bridge_verification: bridge_verification.clone(),
        contributor_identity: string_at_path(aggregate_contribution, &["contributorIdentity"])?
            .to_string(),
        contributor_roster_position: read_u64(aggregate_contribution, "contributorRosterPosition")?,
        aggregate_contribution_hash: Some(
            string_at_path(aggregate_contribution, &["aggregateContributionHash"])?.to_string(),
        ),
    })
}

fn bridge_proof_record_hash_for_evaluation(bridge_proof_record: &Value) -> CanonicalResult<String> {
    let mut record_without_hash = bridge_proof_record.clone();
    let record_object = record_without_hash.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bridgeProofRecord must be a JSON object",
        )
    })?;
    record_object.remove("bridgeProofRecordHash");

    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "proofRecord": record_without_hash,
            "purpose": "sealed-lattice-aggregate-bridge-proof-record-v1",
        }),
    )
}

fn require_canonical_bridge_proof_record_hash_for_evaluation(
    bridge_proof_record: &Value,
) -> CanonicalResult<()> {
    let supplied_hash = string_at_path(bridge_proof_record, &["bridgeProofRecordHash"])?;
    let expected_hash = bridge_proof_record_hash_for_evaluation(bridge_proof_record)?;
    if supplied_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation bridge proof record hash does not match its canonical payload",
        ));
    }

    Ok(())
}

fn require_aggregate_contribution_matches_bridge_proof_record_for_evaluation(
    aggregate_contribution: &Value,
    bridge_proof_record: &Value,
) -> CanonicalResult<()> {
    require_same_string(
        aggregate_contribution,
        &["bridgeProofRecordHash"],
        bridge_proof_record,
        &["bridgeProofRecordHash"],
        "aggregate contribution bridge proof record hash",
    )?;
    for field_name in [
        "aggregateDerivationComponentHash",
        "aggregateShareCommitmentHash",
        "shareCommitmentMessageBoundCertHash",
        "encryptedAggregateBridgeHash",
        "encryptedAggregateTargetBasisRoot",
        "encryptedAggregateInputRoot",
        "encryptedAggregateShareCiphertextRoot",
        "encryptedAggregateReconstructionHash",
        "bridgeProofProfileHash",
        "bridgeWitnessPrivacyProfileHash",
        "bgvBatchEncoderHash",
        "bridgeLayoutHash",
        "ballotScoreEncodingProfileHash",
        "ballotShareLayoutProfileHash",
        "aggregateInputEncodingProfileHash",
        "encodedShareVectorLayoutHash",
        "encodedAggregateLayoutHash",
        "encryptedAggregateInputLayoutHash",
        "topKEvaluatorInputLayoutHash",
        "heParamHash",
        "bgvProfileHash",
        "rustBgvBackendProfileHash",
        "canonicalCiphertextConventionHash",
        "bgvPublicKeyRoot",
        "collectivePublicKeyRoot",
        "collectivePublicKeyCoefficientRoot",
        "aggregateSelectionPolicyHash",
        "postVotingClosedContextHash",
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "pollSpecHash",
        "thresholdProfileHash",
        "setupPackageHash",
        "ballotSetHash",
        "votingClosedBoardHeadHash",
        "contributorIdentity",
        "contributorRosterExternalAcceptanceHash",
    ] {
        require_same_string(
            aggregate_contribution,
            &[field_name],
            bridge_proof_record,
            &[field_name],
            field_name,
        )?;
    }
    for field_name in [
        "contributorRosterPosition",
        "participantCount",
        "optionCount",
        "shareVectorWidth",
    ] {
        require_same_u64(
            aggregate_contribution,
            &[field_name],
            bridge_proof_record,
            &[field_name],
            field_name,
        )?;
    }

    Ok(())
}

fn aggregate_contribution_hash_for_evaluation(
    aggregate_contribution: &Value,
) -> CanonicalResult<String> {
    let mut contribution_without_hash = aggregate_contribution.clone();
    let contribution_object = contribution_without_hash.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateContribution must be a JSON object",
        )
    })?;
    contribution_object.remove("aggregateContributionHash");
    contribution_object.remove("signature");

    derive_protocol_hash(
        "AggregateContributionHash",
        &json!({
            "contribution": contribution_without_hash,
            "purpose": "sealed-lattice-aggregate-contribution-v1",
        }),
    )
}

fn require_canonical_aggregate_contribution_hash_for_evaluation(
    aggregate_contribution: &Value,
) -> CanonicalResult<()> {
    let supplied_hash = string_at_path(aggregate_contribution, &["aggregateContributionHash"])?;
    let expected_hash = aggregate_contribution_hash_for_evaluation(aggregate_contribution)?;
    if supplied_hash != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation aggregate contribution hash does not match its canonical payload",
        ));
    }

    Ok(())
}

fn aggregate_ready_record_hash(record: &Value) -> CanonicalResult<String> {
    let mut record_without_hash = record.clone();
    let record_object = record_without_hash.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateReadyRecord must be a JSON object",
        )
    })?;
    record_object.remove("aggregateReadyRecordHash");

    derive_protocol_hash(
        "AggregateReadyRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-ready-record-v1",
            "record": record_without_hash,
        }),
    )
}

fn read_string_array(value: &Value, path: &[&str]) -> CanonicalResult<Vec<String>> {
    array_at_path(value, path)?
        .iter()
        .map(|entry| {
            entry.as_str().map(ToString::to_string).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "aggregate-ready record root arrays must contain strings",
                )
            })
        })
        .collect()
}

fn aggregate_ready_binding_from_request(
    request: &Value,
    setup_package: &Value,
    encrypted_aggregate_share_ciphertext_roots: &[String],
    expected_encrypted_aggregate_bridge_hash: &str,
) -> CanonicalResult<(String, String, &'static str)> {
    let Some(record) = request.get("aggregateReadyRecord") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation requires an aggregateReadyRecord",
        ));
    };

    if string_at_path(record, &["objectType"])? != "AggregateReadyRecord" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateReadyRecord must be an AggregateReadyRecord object",
        ));
    }
    if read_u64(record, "objectVersion")? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "aggregateReadyRecord version is not supported",
        ));
    }
    let expected_hash = aggregate_ready_record_hash(record)?;
    if string_at_path(record, &["aggregateReadyRecordHash"])? != expected_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord hash does not match its canonical payload",
        ));
    }
    for (record_path, setup_path, description) in [
        (
            &["setupPackageHash"][..],
            &["setupPackageHash"][..],
            "setup package hash",
        ),
        (
            &["collectivePublicKeyRoot"][..],
            &["collectivePublicKey", "collectivePublicKeyRoot"][..],
            "collective public key root",
        ),
        (
            &["collectivePublicKeyCoefficientRoot"][..],
            &["collectivePublicKey", "collectivePublicKeyCoefficientRoot"][..],
            "collective public key coefficient root",
        ),
        (
            &["manifestHash"][..],
            &["setupInputs", "manifestHash"][..],
            "manifest hash",
        ),
        (
            &["rosterHash"][..],
            &["setupInputs", "rosterHash"][..],
            "roster hash",
        ),
        (
            &["thresholdProfileHash"][..],
            &["setupInputs", "thresholdProfileHash"][..],
            "threshold profile hash",
        ),
        (
            &["bgvProfileHash"][..],
            &["profileBindings", "profileHash"][..],
            "BGV profile hash",
        ),
        (
            &["bgvBatchEncoderHash"][..],
            &["profileBindings", "batchEncoderHash"][..],
            "BGV batch encoder hash",
        ),
        (
            &["encryptedAggregateInputLayoutHash"][..],
            &["profileBindings", "encryptedAggregateInputLayoutHash"][..],
            "encrypted aggregate input layout hash",
        ),
        (
            &["topKEvaluatorInputLayoutHash"][..],
            &["profileBindings", "topKEvaluatorInputLayoutHash"][..],
            "top-k evaluator input layout hash",
        ),
        (
            &["encryptedAggregateTargetBasisRoot"][..],
            &["profileBindings", "encryptedAggregateTargetBasisRoot"][..],
            "encrypted aggregate target-basis root",
        ),
        (
            &["encryptedAggregateReconstructionHash"][..],
            &["profileBindings", "encryptedAggregateReconstructionHash"][..],
            "encrypted aggregate reconstruction hash",
        ),
    ] {
        if string_at_path(record, record_path)? != string_at_path(setup_package, setup_path)? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("aggregateReadyRecord {description} does not match the setup package"),
            ));
        }
    }
    let setup_participant_count = read_usize_field(
        value_at_path(setup_package, &["setupInputs"])?,
        "participantCount",
    )?;
    if setup_participant_count != BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "accepted aggregate evaluation requires the mandatory frozen receiver roster",
        ));
    }
    let record_roster_size = read_usize_field(record, "rosterSize")?;
    if record_roster_size != setup_participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord roster size does not match the setup package participant count",
        ));
    }
    let selected_roots = read_string_array(record, &["encryptedAggregateShareCiphertextRoots"])?;
    if selected_roots != encrypted_aggregate_share_ciphertext_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected ciphertext roots do not match the evaluator bridge inputs",
        ));
    }
    if string_at_path(record, &["encryptedAggregateBridgeHash"])?
        != expected_encrypted_aggregate_bridge_hash
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord bridge hash does not match the verified evaluator bridge inputs",
        ));
    }

    Ok((
        expected_hash,
        string_at_path(record, &["encryptedAggregateBridgeHash"])?.to_string(),
        "aggregate-ready-record-verified",
    ))
}

fn centered_field_element(value: u64) -> CanonicalResult<i64> {
    if value >= FIELD_MODULUS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "interpolation coefficient is outside GF(65537)",
        ));
    }
    let midpoint = (FIELD_MODULUS - 1) / 2;
    let centered = if value > midpoint {
        i128::from(value) - i128::from(FIELD_MODULUS)
    } else {
        i128::from(value)
    };

    i64::try_from(centered).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "centered interpolation coefficient does not fit i64",
        )
    })
}

fn read_u64_array(value: &Value, path: &[&str]) -> CanonicalResult<Vec<u64>> {
    array_at_path(value, path)?
        .iter()
        .map(|entry| {
            entry.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "aggregate-ready record position arrays must contain non-negative integers",
                )
            })
        })
        .collect()
}

fn read_usize_field(value: &Value, field: &str) -> CanonicalResult<usize> {
    let raw_value = read_u64(value, field)?;
    usize::try_from(raw_value).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field} does not fit usize"),
        )
    })
}

fn aggregate_ready_record_from_request(
    request: &Value,
    expected_aggregate_ready_record_hash: &str,
    expected_encrypted_aggregate_bridge_hash: &str,
) -> CanonicalResult<AggregateReadyEvaluationRecord> {
    let record = request.get("aggregateReadyRecord").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encryptedAggregateInputs require an aggregateReadyRecord",
        )
    })?;
    if string_at_path(record, &["aggregateReadyRecordHash"])?
        != expected_aggregate_ready_record_hash
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord hash does not match the verified evaluator binding",
        ));
    }
    if string_at_path(record, &["encryptedAggregateBridgeHash"])?
        != expected_encrypted_aggregate_bridge_hash
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord bridge hash does not match the verified evaluator binding",
        ));
    }

    let option_count = read_usize_field(record, "optionCount")?;
    let share_vector_width = read_usize_field(record, "shareVectorWidth")?;
    if option_count != MAXIMUM_OPTION_COUNT
        || share_vector_width != option_count * AGGREGATE_SCORE_COORDINATES_PER_OPTION
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateReadyRecord option count and share vector width must match the mandatory selected aggregate layout",
        ));
    }
    let quorum = read_usize_field(record, "aggregateContributionQuorum")?;
    let roster_size = read_usize_field(record, "rosterSize")?;
    if roster_size != BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT || quorum == 0 || quorum > roster_size
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateReadyRecord roster size and aggregate contribution quorum must match the mandatory selected aggregate roster",
        ));
    }
    let selected_roster_positions =
        read_u64_array(record, &["selectedContributorRosterPositions"])?;
    let selected_contributor_identities =
        read_string_array(record, &["selectedContributorIdentities"])?;
    let selected_aggregate_contribution_hashes =
        read_string_array(record, &["selectedAggregateContributionHashes"])?;
    let encrypted_aggregate_share_ciphertext_roots =
        read_string_array(record, &["encryptedAggregateShareCiphertextRoots"])?;
    let selected_interpolation_points =
        read_u64_array(record, &["selectedContributorInterpolationPoints"])?;
    if selected_roster_positions != selected_interpolation_points
        || selected_roster_positions.len() != quorum
        || selected_contributor_identities.len() != quorum
        || selected_aggregate_contribution_hashes.len() != quorum
        || encrypted_aggregate_share_ciphertext_roots.len() != quorum
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contributor arrays do not match the aggregate contribution quorum",
        ));
    }
    let first_valid_order_hash = derive_protocol_hash(
        "FirstValidOrderHash",
        &json!({
            "orderedObjectHashes": selected_aggregate_contribution_hashes.clone(),
            "purpose": "sealed-lattice-selected-aggregate-contribution-order-v1",
            "requiredContextHash": string_at_path(record, &["postVotingClosedContextHash"])?,
            "selectionPolicyHash": string_at_path(record, &["aggregateSelectionPolicyHash"])?,
        }),
    )?;
    if string_at_path(record, &["firstValidOrderHash"])? != first_valid_order_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord first-valid order hash does not match the selected contribution order",
        ));
    }
    let recomputed_coefficients =
        derive_lagrange_coefficients_at_zero_for_roster_positions(&selected_roster_positions)?;
    let coefficient_entries = array_at_path(record, &["interpolationCoefficients"])?;
    if coefficient_entries.len() != recomputed_coefficients.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregateReadyRecord interpolation coefficient count does not match the selected contributor set",
        ));
    }
    let mut coefficient_objects = Vec::with_capacity(coefficient_entries.len());
    let mut centered_coefficients = Vec::with_capacity(coefficient_entries.len());
    let mut centered_l1_sum = 0_u64;
    let mut max_centered_abs = 0_u64;
    for (entry, (roster_position, coefficient)) in coefficient_entries
        .iter()
        .zip(recomputed_coefficients.iter())
    {
        let record_roster_position = read_u64(entry, "rosterPosition")?;
        let record_coefficient = read_u64(entry, "coefficient")?;
        let record_centered_coefficient = integer_at_path(entry, &["centeredCoefficient"])?;
        let centered_coefficient = centered_field_element(*coefficient)?;
        if record_roster_position != *roster_position
            || record_coefficient != *coefficient
            || record_centered_coefficient != centered_coefficient
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "aggregateReadyRecord interpolation coefficients do not match recomputation",
            ));
        }
        let centered_abs = centered_coefficient.unsigned_abs();
        centered_l1_sum = centered_l1_sum.checked_add(centered_abs).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregateReadyRecord centered interpolation L1 sum overflowed",
            )
        })?;
        max_centered_abs = max_centered_abs.max(centered_abs);
        centered_coefficients.push(centered_coefficient);
        coefficient_objects.push(json!({
            "rosterPosition": roster_position,
            "coefficient": coefficient,
            "centeredCoefficient": centered_coefficient,
        }));
    }
    if read_u64(record, "centeredL1CoefficientSum")? != centered_l1_sum
        || read_u64(record, "maxCenteredAbsCoefficient")? != max_centered_abs
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord interpolation coefficient bounds do not match recomputation",
        ));
    }
    let interpolation_report_hash = derive_protocol_hash(
        "InterpolationCoefficientReportHash",
        &json!({
            "centeredL1CoefficientSum": centered_l1_sum,
            "coefficients": coefficient_objects,
            "contributorRosterPositions": selected_roster_positions,
            "maxCenteredAbsCoefficient": max_centered_abs,
            "rosterSize": read_u64(record, "rosterSize")?,
            "threshold": read_u64(record, "aggregateContributionQuorum")?,
        }),
    )?;
    if string_at_path(record, &["interpolationCoefficientReportHash"])? != interpolation_report_hash
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord interpolation report hash does not match recomputation",
        ));
    }
    let encrypted_aggregate_reconstruction_root = derive_protocol_hash(
        "EncryptedAggregateReconstructionHash",
        &json!({
            "aggregateSelectionPolicyHash": string_at_path(record, &["aggregateSelectionPolicyHash"])?,
            "encryptedAggregateReconstructionHash": string_at_path(record, &["encryptedAggregateReconstructionHash"])?,
            "encryptedAggregateShareCiphertextRoots": encrypted_aggregate_share_ciphertext_roots,
            "firstValidOrderHash": first_valid_order_hash,
            "interpolationCoefficientReportHash": interpolation_report_hash,
            "purpose": "sealed-lattice-aggregate-ready-reconstruction-root-v1",
            "selectedAggregateContributionHashes": selected_aggregate_contribution_hashes.clone(),
        }),
    )?;
    if string_at_path(record, &["encryptedAggregateReconstructionRoot"])?
        != encrypted_aggregate_reconstruction_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord encrypted aggregate reconstruction root does not match recomputation",
        ));
    }

    Ok(AggregateReadyEvaluationRecord {
        aggregate_ready_record_hash: expected_aggregate_ready_record_hash.to_string(),
        encrypted_aggregate_bridge_hash: expected_encrypted_aggregate_bridge_hash.to_string(),
        interpolation_coefficients: centered_coefficients,
        selected_aggregate_contribution_hashes,
        selected_contributor_identities,
        selected_contributor_roster_positions: selected_roster_positions,
        option_count,
    })
}

// Run a development top-k evaluation: build the evaluation key set, validate the
// relinearization and rotation keys, reconstruct each option's encrypted score
// from its supplied aggregate value, run the encrypted bit-sliced top-k
// evaluator, and emit the evaluator program description, Appendix A
// evaluator/noise certificate, the TopKEvaluationRecord and target proposal, and
// the Appendix D public-input statement. The decoded slots are returned for
// development inspection; this is a development evaluator run, not a
// claim-bearing accepted target.
pub(crate) fn run_development_top_k_evaluation(request: &Value) -> CanonicalResult<Value> {
    let scores = request
        .get("scores")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "scores must be an array of per-option aggregate scores",
            )
        })?
        .iter()
        .map(|score| {
            score.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "score entries must be non-negative integers",
                )
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let option_count = scores.len();
    if option_count < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "development top-k evaluation requires at least two options",
        ));
    }
    let top_count = usize::try_from(read_u64(request, "topCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "topCount does not fit usize",
        )
    })?;
    let score_domain_max = read_u64(request, "scoreDomainMax")?;
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(DEFAULT_WORKING_LEVEL);
    let seed = read_string_or_default(request, "seed");

    let context = EvaluatorContext::new(&seed, working_level)?;
    let evaluation_keys_validated = validate_evaluation_keys(&context, working_level, &seed)?;

    // Reconstruct each option's encrypted score from its aggregate value through
    // the single-contributor reconstruction and single-bucket score paths.
    let mut score_ciphertexts = Vec::with_capacity(option_count);
    for (option, value) in scores.iter().enumerate() {
        let share = encrypt_broadcast(&context, *value, &format!("{seed}-share-{option}"))?;
        let aggregate = reconstruct_aggregate(&[AggregateContributor {
            interpolation_coefficient: 1,
            encrypted_share: share,
        }])?;
        score_ciphertexts.push(score_from_histogram(&[aggregate])?);
    }

    // The development command can run either evaluator profile, and the public
    // record below binds the selected profile so the output cannot be confused
    // with a different evaluator program.
    let comparison_method = request
        .get("comparisonMethod")
        .and_then(Value::as_str)
        .unwrap_or("bitSliced");
    let comparison_profile = match comparison_method {
        "differencePolynomial" => EvaluationComparisonProfile::DirectScoreComparison,
        "bitSliced" => EvaluationComparisonProfile::ScoreBitSliced,
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "comparisonMethod must be bitSliced or differencePolynomial",
            ));
        }
    };
    let outputs = match comparison_profile {
        EvaluationComparisonProfile::DirectScoreComparison => evaluate_top_k_via_difference(
            &context,
            &score_ciphertexts,
            top_count,
            score_domain_max,
        )?,
        EvaluationComparisonProfile::ScoreBitSliced => {
            evaluate_top_k(&context, &score_ciphertexts, top_count, score_domain_max)?
        }
    };
    let decoded_target_id = context.key().decrypt_to_slots(&outputs.target.target_id)?;
    let decoded_target_order = context
        .key()
        .decrypt_to_slots(&outputs.target.target_order)?;
    let decoded_ranks = outputs
        .ranks
        .iter()
        .map(|rank| context.key().decrypt_to_slots(rank).map(|slots| slots[0]))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let rank_packing_method_text = request
        .get("rankPackingMethod")
        .and_then(Value::as_str)
        .unwrap_or("perOptionBroadcast");
    let rank_packing_method = match rank_packing_method_text {
        "perOptionBroadcast" => RankPackingMethod::PerOptionBroadcast,
        "generatorOrdered" => RankPackingMethod::GeneratorOrdered,
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "rankPackingMethod must be perOptionBroadcast or generatorOrdered",
            ));
        }
    };
    let (
        packed_rank_root,
        packed_target_id_root,
        packed_target_order_root,
        decoded_packed_ranks,
        decoded_packed_target_id,
        decoded_packed_target_order,
    ) = match rank_packing_method {
        RankPackingMethod::PerOptionBroadcast => (
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ),
        RankPackingMethod::GeneratorOrdered => {
            if comparison_profile != EvaluationComparisonProfile::DirectScoreComparison {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "generatorOrdered rank packing requires the differencePolynomial comparison method",
                ));
            }
            let packed_ranks = evaluate_packed_ranks_via_difference(
                &context,
                &score_ciphertexts,
                score_domain_max,
                &format!("{seed}-packed-ranks"),
            )?;
            let packed_target =
                project_packed_sparse_target(&context, &packed_ranks, option_count, top_count)?;
            let packed_slots = context.key().decrypt_to_slots(&packed_ranks)?;
            let packed_target_id_slots =
                context.key().decrypt_to_slots(&packed_target.target_id)?;
            let packed_target_order_slots = context
                .key()
                .decrypt_to_slots(&packed_target.target_order)?;
            let decoded = (0..option_count)
                .map(|option| packed_slots[packed_score_slot(option)])
                .collect::<Vec<_>>();
            let decoded_target_id = (0..option_count)
                .map(|option| packed_target_id_slots[packed_score_slot(option)])
                .collect::<Vec<_>>();
            let decoded_target_order = (0..option_count)
                .map(|option| packed_target_order_slots[packed_score_slot(option)])
                .collect::<Vec<_>>();

            (
                Value::String(ciphertext_object_root(&packed_ranks)?),
                Value::String(ciphertext_object_root(&packed_target.target_id)?),
                Value::String(ciphertext_object_root(&packed_target.target_order)?),
                json!(decoded),
                json!(decoded_target_id),
                json!(decoded_target_order),
            )
        }
    };
    let parameters = EvaluationParameters {
        ceremony_id: read_string_or_default(request, "ceremonyId"),
        manifest_hash: read_string_or_default(request, "manifestHash"),
        roster_hash: read_string_or_default(request, "rosterHash"),
        canonical_ballot_set_hash: read_string_or_default(request, "canonicalBallotSetHash"),
        aggregate_ready_record_hash: read_string_or_default(request, "aggregateReadyRecordHash"),
        encrypted_aggregate_bridge_hash: read_string_or_default(
            request,
            "encryptedAggregateBridgeHash",
        ),
        encrypted_aggregate_target_basis_root: read_string_or_default(
            request,
            "encryptedAggregateTargetBasisDataRoot",
        ),
        bgv_public_key_root: read_string_or_default(request, "bgvPublicKeyRoot"),
        collective_public_key_root: read_string_or_default(request, "collectivePublicKeyRoot"),
        evaluation_key_root: read_string_or_default(request, "evaluationKeyRoot"),
        rot_set_hash: read_string_or_default(request, "rotSetHash"),
        option_count,
        top_count,
        score_domain_max,
        comparison_profile,
        rank_packing_method,
    };

    let output_roots = EvaluatorOutputRoots {
        encrypted_aggregate_reconstruction_root: ciphertext_object_root(&score_ciphertexts[0])?,
        encrypted_score_bit_input_root: ciphertext_object_root(&outputs.score_bit_sample)?,
        greater_than_root: ciphertext_object_root(&outputs.greater_than_sample)?,
        equal_root: ciphertext_object_root(&outputs.equal_sample)?,
        ahead_root: ciphertext_object_root(&outputs.ahead_sample)?,
        rank_root: ciphertext_object_root(&outputs.ranks[0])?,
        target_id_root: ciphertext_object_root(&outputs.target.target_id)?,
        target_order_root: ciphertext_object_root(&outputs.target.target_order)?,
        public_slot_mask_hash: public_slot_mask_hash()?,
        output_encoding_hash: output_encoding_hash()?,
        pre_target_board_head: read_string_or_default(request, "preTargetBoardHead"),
        evaluator_signature: read_string_or_default(request, "evaluatorSignature"),
    };

    let certificate = evaluation_noise_certificate(&parameters)?;
    let record = top_k_evaluation_record(&parameters, &output_roots)?;
    let proposal = target_proposal_hash(&parameters, &record)?;
    let appendix_d = appendix_d_public_input_statement(
        &parameters,
        record["topKCiphertextHash"].as_str().unwrap_or_default(),
        record["targetCiphertextHash"].as_str().unwrap_or_default(),
        &output_roots.public_slot_mask_hash,
        &proposal,
    )?;

    Ok(json!({
        "ok": true,
        "operation": "runDevelopmentTopKEvaluation",
        "comparisonProfile": comparison_profile.profile_id(),
        "evaluationContextHash": evaluation_context_hash(&parameters)?,
        "evaluationKeysValidated": evaluation_keys_validated,
        "decodedTargetIdSlots": decoded_target_id[..option_count].to_vec(),
        "decodedTargetOrderSlots": decoded_target_order[..option_count].to_vec(),
        "decodedRanks": decoded_ranks,
        "rankPackingMethod": rank_packing_method_text,
        "packedRankRoot": packed_rank_root,
        "packedTargetIdRoot": packed_target_id_root,
        "packedTargetOrderRoot": packed_target_order_root,
        "decodedPackedRanks": decoded_packed_ranks,
        "decodedPackedTargetIdSlots": decoded_packed_target_id,
        "decodedPackedTargetOrderSlots": decoded_packed_target_order,
        "program": describe_evaluator_program(&parameters)?,
        "evaluationNoiseCertificate": certificate,
        "topKEvaluationRecord": record,
        "targetProposalHash": proposal,
        "appendixDPublicInputStatement": appendix_d,
        "statusLabels": [
            "DevelopmentTopKEvaluationCompleted",
            "TopKEvaluationProposalGenerated",
            "NotAcceptedTarget",
            "EvaluationProofRequiredForAcceptance",
            "NotSupportedPhoneCertified"
        ],
    }))
}

fn run_aggregate_ready_top_k_evaluation(
    request: &Value,
    setup_package: &Value,
    working_level: usize,
) -> CanonicalResult<Value> {
    if working_level != DATA_PRIMES.len() - 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate-ready encrypted evaluation requires the full selected data level",
        ));
    }
    let score_domain_max = read_selected_score_domain_max(request)?;
    require_finality_bound_fields_for_aggregate_ready_evaluation(request)?;
    let SetupBoundAggregateCiphertexts {
        aggregate_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        selected_aggregate_contribution_hashes,
        selected_contributor_identities,
        selected_contributor_roster_positions,
        bridge_inputs,
    } = read_setup_bound_aggregate_ciphertexts(request, setup_package)?;
    let setup_package_hash = string_at_path(setup_package, &["setupPackageHash"])?;
    let encrypted_aggregate_bridge_hash = derive_protocol_hash(
        "EncryptedAggregateBridgeHash",
        &json!({
            "objectType": "EncryptedAggregateBridgeInputSet",
            "objectVersion": 1,
            "setupPackageHash": setup_package_hash,
            "collectivePublicKeyRoot": string_at_path(
                setup_package,
                &["collectivePublicKey", "collectivePublicKeyRoot"],
            )?,
            "evaluationKeyRoot": string_at_path(
                setup_package,
                &["evaluationKeys", "evaluationKeyRoot"],
            )?,
            "ciphertextRoots": ciphertext_roots,
            "bridgeInputs": bridge_inputs,
            "bridgeProofStatus": "aggregate-bridge-proof-relation-verified",
        }),
    )?;
    let (aggregate_ready_record_hash, bound_encrypted_aggregate_bridge_hash, input_binding_status) =
        aggregate_ready_binding_from_request(
            request,
            setup_package,
            &encrypted_aggregate_share_ciphertext_roots,
            &encrypted_aggregate_bridge_hash,
        )?;
    let aggregate_ready_record = aggregate_ready_record_from_request(
        request,
        &aggregate_ready_record_hash,
        &bound_encrypted_aggregate_bridge_hash,
    )?;
    if aggregate_ready_record.interpolation_coefficients.len() != aggregate_ciphertexts.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregateReadyRecord interpolation coefficients do not match the supplied encrypted aggregate inputs",
        ));
    }
    if aggregate_ready_record.selected_contributor_roster_positions
        != selected_contributor_roster_positions
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contributor positions do not match the verified bridge inputs",
        ));
    }
    if aggregate_ready_record.selected_contributor_identities != selected_contributor_identities {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contributor identities do not match the verified bridge inputs",
        ));
    }
    if !selected_aggregate_contribution_hashes.is_empty()
        && aggregate_ready_record.selected_aggregate_contribution_hashes
            != selected_aggregate_contribution_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contribution hashes do not match the verified bridge inputs",
        ));
    }
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;

    let option_count = aggregate_ready_record.option_count;
    require_setup_target_layout_for_aggregate_ready_evaluation(setup_package, option_count)?;
    let top_count = read_top_count(request, option_count)?;
    with_aggregate_ready_evaluator_context(
        request,
        setup_package,
        working_level,
        option_count,
        |context| {
            let contributors = aggregate_ciphertexts
                .into_iter()
                .zip(aggregate_ready_record.interpolation_coefficients.iter())
                .map(
                    |(encrypted_share, interpolation_coefficient)| AggregateContributor {
                        interpolation_coefficient: *interpolation_coefficient,
                        encrypted_share,
                    },
                )
                .collect::<Vec<_>>();
            let reconstructed_aggregate = reconstruct_aggregate(&contributors)?;
            let packed_scores = pack_reconstructed_aggregate_scores(
                context,
                &reconstructed_aggregate,
                option_count,
                &aggregate_ready_record.aggregate_ready_record_hash,
            )?;
            let packed_ranks = evaluate_packed_ranks_from_packed_scores(
                context,
                &packed_scores,
                option_count,
                score_domain_max,
                &aggregate_ready_record.aggregate_ready_record_hash,
            )?;
            let (evaluation, _) = build_aggregate_ready_top_k_evaluation_artifacts(
                request,
                setup_package,
                context,
                option_count,
                top_count,
                score_domain_max,
                &aggregate_ready_record.encrypted_aggregate_bridge_hash,
                &aggregate_ready_record.aggregate_ready_record_hash,
                input_binding_status,
                &reconstructed_aggregate,
                &packed_scores,
                &packed_ranks,
                true,
            )?;

            Ok(evaluation)
        },
    )
}

struct AggregateReadySharedInputs<'a> {
    aggregate_ready_record_hash: String,
    encrypted_aggregate_bridge_hash: String,
    input_binding_status: String,
    reconstructed_aggregate: Ciphertext,
    packed_scores: Ciphertext,
    packed_ranks: Ciphertext,
    request: &'a Value,
    setup_package: &'a Value,
}

fn read_aggregate_ready_shared_inputs<'a>(
    request: &'a Value,
    setup_package: &'a Value,
) -> CanonicalResult<(AggregateReadySharedInputs<'a>, usize, u64)> {
    let score_domain_max = read_selected_score_domain_max(request)?;
    require_finality_bound_fields_for_aggregate_ready_evaluation(request)?;
    let SetupBoundAggregateCiphertexts {
        aggregate_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        selected_aggregate_contribution_hashes,
        selected_contributor_identities,
        selected_contributor_roster_positions,
        bridge_inputs,
    } = read_setup_bound_aggregate_ciphertexts(request, setup_package)?;
    let setup_package_hash = string_at_path(setup_package, &["setupPackageHash"])?;
    let encrypted_aggregate_bridge_hash = derive_protocol_hash(
        "EncryptedAggregateBridgeHash",
        &json!({
            "objectType": "EncryptedAggregateBridgeInputSet",
            "objectVersion": 1,
            "setupPackageHash": setup_package_hash,
            "collectivePublicKeyRoot": string_at_path(
                setup_package,
                &["collectivePublicKey", "collectivePublicKeyRoot"],
            )?,
            "evaluationKeyRoot": string_at_path(
                setup_package,
                &["evaluationKeys", "evaluationKeyRoot"],
            )?,
            "ciphertextRoots": ciphertext_roots,
            "bridgeInputs": bridge_inputs,
            "bridgeProofStatus": "aggregate-bridge-proof-relation-verified",
        }),
    )?;
    let (aggregate_ready_record_hash, bound_encrypted_aggregate_bridge_hash, input_binding_status) =
        aggregate_ready_binding_from_request(
            request,
            setup_package,
            &encrypted_aggregate_share_ciphertext_roots,
            &encrypted_aggregate_bridge_hash,
        )?;
    let aggregate_ready_record = aggregate_ready_record_from_request(
        request,
        &aggregate_ready_record_hash,
        &bound_encrypted_aggregate_bridge_hash,
    )?;
    if aggregate_ready_record.interpolation_coefficients.len() != aggregate_ciphertexts.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregateReadyRecord interpolation coefficients do not match the supplied encrypted aggregate inputs",
        ));
    }
    if aggregate_ready_record.selected_contributor_roster_positions
        != selected_contributor_roster_positions
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contributor positions do not match the verified bridge inputs",
        ));
    }
    if aggregate_ready_record.selected_contributor_identities != selected_contributor_identities {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contributor identities do not match the verified bridge inputs",
        ));
    }
    if !selected_aggregate_contribution_hashes.is_empty()
        && aggregate_ready_record.selected_aggregate_contribution_hashes
            != selected_aggregate_contribution_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contribution hashes do not match the verified bridge inputs",
        ));
    }
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;

    let option_count = aggregate_ready_record.option_count;
    require_setup_target_layout_for_aggregate_ready_evaluation(setup_package, option_count)?;
    let shared_inputs = with_aggregate_ready_evaluator_context(
        request,
        setup_package,
        DATA_PRIMES.len() - 1,
        option_count,
        |context| {
            let contributors = aggregate_ciphertexts
                .into_iter()
                .zip(aggregate_ready_record.interpolation_coefficients.iter())
                .map(
                    |(encrypted_share, interpolation_coefficient)| AggregateContributor {
                        interpolation_coefficient: *interpolation_coefficient,
                        encrypted_share,
                    },
                )
                .collect::<Vec<_>>();
            let reconstructed_aggregate = reconstruct_aggregate(&contributors)?;
            let packed_scores = pack_reconstructed_aggregate_scores(
                context,
                &reconstructed_aggregate,
                option_count,
                &aggregate_ready_record.aggregate_ready_record_hash,
            )?;
            let packed_ranks = evaluate_packed_ranks_from_packed_scores(
                context,
                &packed_scores,
                option_count,
                score_domain_max,
                &aggregate_ready_record.aggregate_ready_record_hash,
            )?;

            Ok(AggregateReadySharedInputs {
                aggregate_ready_record_hash: aggregate_ready_record
                    .aggregate_ready_record_hash
                    .clone(),
                encrypted_aggregate_bridge_hash: aggregate_ready_record
                    .encrypted_aggregate_bridge_hash
                    .clone(),
                input_binding_status: input_binding_status.to_string(),
                reconstructed_aggregate,
                packed_scores,
                packed_ranks,
                request,
                setup_package,
            })
        },
    )?;

    Ok((shared_inputs, option_count, score_domain_max))
}

#[allow(clippy::too_many_arguments)]
fn build_aggregate_ready_top_k_evaluation_artifacts(
    request: &Value,
    setup_package: &Value,
    context: &EvaluatorContext,
    option_count: usize,
    top_count: usize,
    score_domain_max: u64,
    encrypted_aggregate_bridge_hash: &str,
    aggregate_ready_record_hash: &str,
    input_binding_status: &str,
    reconstructed_aggregate: &Ciphertext,
    packed_scores: &Ciphertext,
    packed_ranks: &Ciphertext,
    include_encrypted_top_k_bundle: bool,
) -> CanonicalResult<(Value, Value)> {
    let packed_target =
        project_packed_sparse_target(context, packed_ranks, option_count, top_count)?;
    let parameters = setup_bound_parameters(
        request,
        setup_package,
        option_count,
        top_count,
        score_domain_max,
        encrypted_aggregate_bridge_hash.to_string(),
        aggregate_ready_record_hash.to_string(),
    )?;
    let parameters = EvaluationParameters {
        rank_packing_method: RankPackingMethod::GeneratorOrdered,
        ..parameters
    };
    let output_roots = EvaluatorOutputRoots {
        encrypted_aggregate_reconstruction_root: ciphertext_object_root(reconstructed_aggregate)?,
        encrypted_score_bit_input_root: ciphertext_object_root(packed_scores)?,
        greater_than_root: ciphertext_object_root(packed_ranks)?,
        equal_root: ciphertext_object_root(packed_ranks)?,
        ahead_root: ciphertext_object_root(packed_ranks)?,
        rank_root: ciphertext_object_root(packed_ranks)?,
        target_id_root: ciphertext_object_root(&packed_target.target_id)?,
        target_order_root: ciphertext_object_root(&packed_target.target_order)?,
        public_slot_mask_hash: public_slot_mask_hash()?,
        output_encoding_hash: output_encoding_hash()?,
        pre_target_board_head: read_required_protocol_hash(request, "preTargetBoardHead")?,
        evaluator_signature: read_required_protocol_hash(request, "evaluatorSignature")?,
    };
    let certificate = evaluation_noise_certificate(&parameters)?;
    let record = top_k_evaluation_record(&parameters, &output_roots)?;
    let proposal = target_proposal_hash(&parameters, &record)?;
    let top_k_ciphertext_hash = string_at_path(&record, &["topKCiphertextHash"])?.to_string();
    let target_ciphertext_hash = string_at_path(&record, &["targetCiphertextHash"])?.to_string();
    let encrypted_top_k_bundle = encrypted_top_k_bundle_artifact(
        &parameters,
        &output_roots,
        packed_ranks,
        &top_k_ciphertext_hash,
    )?;
    let encrypted_sparse_target = encrypted_sparse_target_artifact(
        &parameters,
        &output_roots,
        &packed_target.target_id,
        &packed_target.target_order,
        &target_ciphertext_hash,
    )?;
    let appendix_d = appendix_d_public_input_statement(
        &parameters,
        &top_k_ciphertext_hash,
        &target_ciphertext_hash,
        &output_roots.public_slot_mask_hash,
        &proposal,
    )?;
    let status_labels = json!([
        "EncryptedAggregateTopKEvaluationCompleted",
        "PublicEvaluationKeyMaterialConsumed",
        "AggregateReadyRecordVerified",
        "EncryptedAggregateReconstructionEvaluated",
        "EncryptedEvaluatorCiphertextsEmitted",
        "GeneratorOrderedRankPackingUsed",
        "TopKEvaluationProposalGenerated",
        "NotAcceptedTarget",
        "EvaluationProofRequiredForAcceptance",
        "NotSupportedPhoneCertified"
    ]);
    let mut evaluation = json!({
        "ok": true,
        "operation": "runEncryptedAggregateTopKEvaluation",
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "inputBindingStatus": input_binding_status,
        "evaluationContextHash": evaluation_context_hash(&parameters)?,
        "evaluationNoiseCertificate": certificate,
        "topKEvaluationRecord": record,
        "encryptedSparseTarget": encrypted_sparse_target,
        "targetProposalHash": proposal,
        "appendixDPublicInputStatement": appendix_d,
        "statusLabels": status_labels,
    });
    if include_encrypted_top_k_bundle {
        evaluation["encryptedTopKBundle"] = encrypted_top_k_bundle.clone();
    }

    Ok((evaluation, encrypted_top_k_bundle))
}

pub(crate) fn run_encrypted_aggregate_top_k_evaluation(request: &Value) -> CanonicalResult<Value> {
    reject_forbidden_accepted_evaluator_fields(request)?;
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupPackage",
            "evaluationKeyMaterial",
            "preparedEvaluationKeyMaterialHandle",
            "aggregateReadyRecord",
            "encryptedAggregateInputs",
            "topCount",
            "scoreDomainMax",
            "workingLevel",
            "canonicalBallotSetHash",
            "preTargetBoardHead",
            "evaluatorSignature",
        ],
        "runEncryptedAggregateTopKEvaluation",
    )?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    if request.get("encryptedAggregateInputs").is_none() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation requires accepted encrypted aggregate inputs",
        ));
    }
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(DATA_PRIMES.len() - 1);
    run_aggregate_ready_top_k_evaluation(request, setup_package, working_level)
}

pub(crate) fn run_encrypted_aggregate_top_k_evaluation_sweep(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_forbidden_accepted_evaluator_fields(request)?;
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupPackage",
            "evaluationKeyMaterial",
            "preparedEvaluationKeyMaterialHandle",
            "aggregateReadyRecord",
            "encryptedAggregateInputs",
            "topCounts",
            "scoreDomainMax",
            "workingLevel",
            "canonicalBallotSetHash",
            "preTargetBoardHead",
            "evaluatorSignature",
        ],
        "runEncryptedAggregateTopKEvaluationSweep",
    )?;
    let requested_top_counts = read_top_count_values(request)?;
    let setup_package = value_at_path(request, &["setupPackage"])?;
    if request.get("encryptedAggregateInputs").is_none() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate evaluation sweep requires accepted encrypted aggregate inputs",
        ));
    }
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(DATA_PRIMES.len() - 1);
    if working_level != DATA_PRIMES.len() - 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregate-ready encrypted evaluation sweep requires the full selected data level",
        ));
    }
    let (shared_inputs, option_count, score_domain_max) =
        read_aggregate_ready_shared_inputs(request, setup_package)?;
    let top_counts = validate_top_counts_against_option_count(requested_top_counts, option_count)?;
    with_aggregate_ready_evaluator_context(
        request,
        setup_package,
        working_level,
        option_count,
        |context| {
            let mut evaluations = Vec::with_capacity(top_counts.len());
            let mut shared_encrypted_rank_bundle = Value::Null;
            for (index, top_count) in top_counts.iter().enumerate() {
                let (evaluation, encrypted_top_k_bundle) =
                    build_aggregate_ready_top_k_evaluation_artifacts(
                        shared_inputs.request,
                        shared_inputs.setup_package,
                        context,
                        option_count,
                        *top_count,
                        score_domain_max,
                        &shared_inputs.encrypted_aggregate_bridge_hash,
                        &shared_inputs.aggregate_ready_record_hash,
                        &shared_inputs.input_binding_status,
                        &shared_inputs.reconstructed_aggregate,
                        &shared_inputs.packed_scores,
                        &shared_inputs.packed_ranks,
                        false,
                    )?;
                if index == 0 {
                    shared_encrypted_rank_bundle = encrypted_top_k_bundle;
                }
                evaluations.push(evaluation);
            }

            Ok(json!({
                "ok": true,
                "operation": "runEncryptedAggregateTopKEvaluationSweep",
                "comparisonProfile": EvaluationComparisonProfile::DirectScoreComparison.profile_id(),
                "rankPackingMethod": RankPackingMethod::GeneratorOrdered.profile_id(),
                "inputBindingStatus": shared_inputs.input_binding_status,
                "topCounts": top_counts,
                "sharedEncryptedRankBundle": shared_encrypted_rank_bundle,
                "evaluations": evaluations,
                "statusLabels": [
                    "EncryptedAggregateTopKEvaluationSweepCompleted",
                    "PublicEvaluationKeyMaterialConsumed",
                    "AggregateReadyRecordVerified",
                    "EncryptedAggregateReconstructionEvaluated",
                    "EncryptedEvaluatorCiphertextsEmitted",
                    "GeneratorOrderedRankPackingUsed",
                    "TopKEvaluationProposalGenerated",
                    "NotAcceptedTarget",
                    "EvaluationProofRequiredForAcceptance",
                    "NotSupportedPhoneCertified"
                ],
            }))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT, aggregate_contribution_hash_for_evaluation,
        aggregate_ready_binding_from_request, aggregate_ready_record_from_request,
        aggregate_ready_record_hash, bridge_proof_record_hash_for_evaluation,
        encrypted_ciphertext_artifact, read_selected_score_domain_max, read_top_count_values,
        reject_forbidden_accepted_evaluator_fields,
        require_public_rotation_keys_for_aggregate_ready_evaluation,
        require_setup_target_layout_for_aggregate_ready_evaluation,
        required_generator_ordered_rotation_keys, run_encrypted_aggregate_top_k_evaluation,
        run_encrypted_aggregate_top_k_evaluation_sweep, target_layout_hash,
        validate_compact_bridge_bindings_for_evaluation,
        validate_compact_bridge_randomness_for_evaluation,
        validate_compact_bridge_status_for_evaluation, validate_top_counts_against_option_count,
        verify_compact_aggregate_bridge_input_for_evaluation,
    };
    use crate::{
        bgv::{
            evaluator::{
                circuit::{EvaluatorContext, modulus_switch_to, multiply, normalize_scaling},
                engine::{
                    Ciphertext, DevelopmentBgvKey, add_plaintext_coefficients,
                    ciphertext_from_canonical_hex, ciphertext_object_root, ciphertext_sub,
                },
                top_k::{
                    AGGREGATE_SCORE_COORDINATES_PER_OPTION, DIRECT_COMPARISON_OUTPUT_LEVEL,
                    aggregate_score_slot, comparison_polynomials,
                    evaluate_direct_comparison_polynomial, galois_power,
                    pack_reconstructed_aggregate_scores, packed_score_slot,
                    selected_evaluator_rotation_key_schedule,
                },
            },
            profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
            setup::{
                development_evaluator_key_from_passive_setup_package,
                generate_passive_setup_package_from_request,
                generate_passive_setup_public_evaluation_key_material_from_request,
            },
        },
        encoding::{CanonicalErrorCode, CanonicalResult},
        hashing::derive_protocol_hash,
    };
    use serde_json::{Value, json};
    use std::sync::OnceLock;

    static REAL_SETUP_PACKAGE_FIXTURE: OnceLock<Value> = OnceLock::new();

    fn setup_request() -> Value {
        let participants = (0..BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT)
            .map(|participant_index| {
                json!({
                    "trusteeIdentity": format!("trustee-{}", participant_index + 1),
                    "rosterPosition": participant_index,
                    "boardPosition": participant_index + 3,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "ceremonyId": "encrypted-aggregate-evaluator-test",
            "manifestHash": derive_protocol_hash(
                "ElectionManifestHash",
                &json!({ "manifest": "encrypted aggregate evaluator test" }),
            )
            .expect("manifest hash"),
            "rosterHash": derive_protocol_hash(
                "RosterHash",
                &json!({ "roster": "encrypted aggregate evaluator test" }),
            )
            .expect("roster hash"),
            "thresholdProfileHash": derive_protocol_hash(
                "ThresholdProfileHash",
                &json!({ "threshold": "encrypted aggregate evaluator test" }),
            )
            .expect("threshold hash"),
            "participants": participants,
            "setupSeed": "encrypted-aggregate-evaluator-test-seed",
        })
    }

    fn real_setup_package_fixture() -> Value {
        REAL_SETUP_PACKAGE_FIXTURE
            .get_or_init(|| {
                generate_passive_setup_package_from_request(&setup_request())
                    .expect("setup package")
            })
            .clone()
    }

    fn load_checkpoint_json(path: &str) -> Value {
        let checkpoint_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(path);
        let checkpoint_text = std::fs::read_to_string(checkpoint_path)
            .unwrap_or_else(|error| panic!("failed to read {path}: {error}"));

        serde_json::from_str(&checkpoint_text)
            .unwrap_or_else(|error| panic!("failed to parse {path}: {error}"))
    }

    fn ciphertext_from_checkpoint_artifact(artifact: &Value) -> CanonicalResult<Ciphertext> {
        let canonical_bytes_hex = artifact["canonicalBytesHex"]
            .as_str()
            .expect("ciphertext canonical bytes");
        let ciphertext_root = artifact["ciphertextRoot"]
            .as_str()
            .expect("ciphertext root");

        ciphertext_from_canonical_hex(canonical_bytes_hex, Some(ciphertext_root))
    }

    fn expected_variant_fixture_ranks(option_count: usize) -> Vec<usize> {
        let scores = (0..option_count)
            .map(|option_index| u64::try_from((option_index % 10) + 1).expect("score fits u64"))
            .collect::<Vec<_>>();
        (0..option_count)
            .map(|option_index| {
                scores
                    .iter()
                    .enumerate()
                    .filter(|(challenger_index, challenger_score)| {
                        **challenger_score > scores[option_index]
                            || (**challenger_score == scores[option_index]
                                && *challenger_index < option_index)
                    })
                    .count()
            })
            .collect()
    }

    fn expected_variant_fixture_sparse_target(
        option_count: usize,
        top_count: usize,
    ) -> (Vec<u64>, Vec<u64>) {
        let ranks = expected_variant_fixture_ranks(option_count);
        let target_ids = ranks
            .iter()
            .enumerate()
            .map(|(option_index, rank)| {
                if *rank < top_count {
                    u64::try_from(option_index + 1).expect("option identifier fits u64")
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();
        let target_orders = ranks
            .iter()
            .map(|rank| {
                if *rank < top_count {
                    u64::try_from(rank + 1).expect("rank order fits u64")
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();

        (target_ids, target_orders)
    }

    fn expected_variant_fixture_share_slots(option_count: usize) -> Vec<u64> {
        let mut slots = Vec::with_capacity(option_count * AGGREGATE_SCORE_COORDINATES_PER_OPTION);
        for option_index in 0..option_count {
            let score = u64::try_from((option_index % 10) + 1).expect("fixture score fits u64");
            slots.push(score);
            for score_value in 1..=10 {
                slots.push(if score == score_value { 1 } else { 0 });
            }
        }

        slots
    }

    fn packed_target_slots(decrypted_slots: &[u64], option_count: usize) -> Vec<u64> {
        (0..option_count)
            .map(|option_index| decrypted_slots[packed_score_slot(option_index)])
            .collect()
    }

    fn binding_setup_package_with_participant_count(participant_count: usize) -> Value {
        json!({
            "setupPackageHash": valid_hash("0"),
            "setupInputs": {
                "ceremonyId": "encrypted-aggregate-evaluator-test",
                "manifestHash": valid_hash("1"),
                "rosterHash": valid_hash("2"),
                "thresholdProfileHash": valid_hash("3"),
                "participantCount": participant_count,
            },
            "collectivePublicKey": {
                "collectivePublicKeyRoot": valid_hash("4"),
                "collectivePublicKeyCoefficientRoot": valid_hash("5"),
                "bgvPublicKeyRoot": valid_hash("6"),
            },
            "evaluationKeys": {
                "evaluationKeyRoot": valid_hash("7"),
                "rotSetHash": valid_hash("8"),
            },
            "profileBindings": {
                "batchEncoderHash": valid_hash("9"),
                "profileHash": valid_hash("a"),
                "encryptedAggregateInputLayoutHash": valid_hash("b"),
                "encryptedAggregateReconstructionHash": valid_hash("c"),
                "encryptedAggregateTargetBasisRoot": valid_hash("d"),
                "targetLayoutHash": target_layout_hash(20).expect("target layout hash"),
                "topKEvaluatorInputLayoutHash": valid_hash("e"),
            },
        })
    }

    fn binding_setup_package_fixture() -> Value {
        binding_setup_package_with_participant_count(BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT)
    }

    #[test]
    fn encrypted_ciphertext_artifact_round_trips_canonical_bytes_and_root() {
        let evaluator_key =
            DevelopmentBgvKey::generate("encrypted-ciphertext-artifact").expect("test key");
        let ciphertext = evaluator_key
            .encrypt_slots(&[3, 1, 4, 1, 5], "encrypted-ciphertext-artifact")
            .expect("encrypted slots");
        let artifact =
            encrypted_ciphertext_artifact("target-id", &ciphertext).expect("ciphertext artifact");
        let ciphertext_root = artifact["ciphertextRoot"]
            .as_str()
            .expect("ciphertext root");
        let canonical_bytes_hex = artifact["canonicalBytesHex"]
            .as_str()
            .expect("canonical bytes");
        let parsed_ciphertext =
            ciphertext_from_canonical_hex(canonical_bytes_hex, Some(ciphertext_root))
                .expect("parse artifact ciphertext");

        assert_eq!(
            artifact["objectType"].as_str().expect("object type"),
            "EncryptedEvaluatorCiphertext"
        );
        assert_eq!(artifact["role"].as_str().expect("role"), "target-id");
        assert_eq!(
            ciphertext_root,
            ciphertext_object_root(&ciphertext).expect("source root")
        );
        assert_eq!(
            ciphertext_object_root(&parsed_ciphertext).expect("parsed root"),
            ciphertext_root
        );
    }

    fn aggregate_ready_record(setup_package: &Value, selected_roots: &[String]) -> Value {
        let selected_aggregate_contribution_hashes = vec![valid_hash("a"), valid_hash("b")];
        let first_valid_order_hash = derive_protocol_hash(
            "FirstValidOrderHash",
            &json!({
                "orderedObjectHashes": selected_aggregate_contribution_hashes.clone(),
                "purpose": "sealed-lattice-selected-aggregate-contribution-order-v1",
                "requiredContextHash": valid_hash("9"),
                "selectionPolicyHash": valid_hash("8"),
            }),
        )
        .expect("first-valid order hash");
        let interpolation_coefficients = vec![
            json!({
                "rosterPosition": 1,
                "coefficient": 2,
                "centeredCoefficient": 2,
            }),
            json!({
                "rosterPosition": 2,
                "coefficient": 65536,
                "centeredCoefficient": -1,
            }),
        ];
        let interpolation_coefficient_report_hash = derive_protocol_hash(
            "InterpolationCoefficientReportHash",
            &json!({
                "centeredL1CoefficientSum": 3,
                "coefficients": interpolation_coefficients.clone(),
                "contributorRosterPositions": [1, 2],
                "maxCenteredAbsCoefficient": 2,
                "rosterSize": BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT,
                "threshold": 2,
            }),
        )
        .expect("interpolation report hash");
        let encrypted_aggregate_reconstruction_root = derive_protocol_hash(
            "EncryptedAggregateReconstructionHash",
            &json!({
                "aggregateSelectionPolicyHash": valid_hash("8"),
                "encryptedAggregateReconstructionHash": setup_package["profileBindings"]["encryptedAggregateReconstructionHash"],
                "encryptedAggregateShareCiphertextRoots": selected_roots,
                "firstValidOrderHash": first_valid_order_hash.clone(),
                "interpolationCoefficientReportHash": interpolation_coefficient_report_hash.clone(),
                "purpose": "sealed-lattice-aggregate-ready-reconstruction-root-v1",
                "selectedAggregateContributionHashes": selected_aggregate_contribution_hashes.clone(),
            }),
        )
        .expect("reconstruction root");
        let mut record = json!({
            "objectType": "AggregateReadyRecord",
            "objectVersion": 1,
            "aggregateContributionQuorum": 2,
            "aggregateSelectionPolicyHash": valid_hash("8"),
            "ballotSetHash": valid_hash("c"),
            "bgvBatchEncoderHash": setup_package["profileBindings"]["batchEncoderHash"],
            "bgvProfileHash": setup_package["profileBindings"]["profileHash"],
            "bridgeLayoutHash": valid_hash("e"),
            "bridgeWitnessPrivacyProfileHash": valid_hash("f"),
            "centeredL1CoefficientSum": 3,
            "ceremonyId": setup_package["setupInputs"]["ceremonyId"],
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": setup_package["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"],
            "encryptedAggregateInputLayoutHash": setup_package["profileBindings"]["encryptedAggregateInputLayoutHash"],
            "encryptedAggregateReconstructionHash": setup_package["profileBindings"]["encryptedAggregateReconstructionHash"],
            "encryptedAggregateReconstructionRoot": encrypted_aggregate_reconstruction_root,
            "encryptedAggregateShareCiphertextRoots": selected_roots,
            "encryptedAggregateTargetBasisRoot": setup_package["profileBindings"]["encryptedAggregateTargetBasisRoot"],
            "firstValidOrderHash": first_valid_order_hash,
            "interpolationCoefficientReportHash": interpolation_coefficient_report_hash,
            "interpolationCoefficients": interpolation_coefficients,
            "manifestHash": setup_package["setupInputs"]["manifestHash"],
            "maxCenteredAbsCoefficient": 2,
            "optionCount": 20,
            "pollSpecHash": valid_hash("1"),
            "postVotingClosedContextHash": valid_hash("9"),
            "rosterSize": BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT,
            "rosterHash": setup_package["setupInputs"]["rosterHash"],
            "selectedAggregateContributionHashes": selected_aggregate_contribution_hashes,
            "selectedContributorIdentities": ["trustee-1", "trustee-2"],
            "selectedContributorInterpolationPoints": [1, 2],
            "selectedContributorRosterPositions": [1, 2],
            "shareVectorWidth": 220,
            "thresholdProfileHash": setup_package["setupInputs"]["thresholdProfileHash"],
            "topKEvaluatorInputLayoutHash": setup_package["profileBindings"]["topKEvaluatorInputLayoutHash"],
            "encryptedAggregateBridgeHash": valid_hash("7"),
            "votingClosedBoardHeadHash": valid_hash("2"),
        });
        record["aggregateReadyRecordHash"] =
            Value::String(aggregate_ready_record_hash(&record).expect("record hash"));

        record
    }

    fn valid_hash(fill: &str) -> String {
        fill.repeat(128)
    }

    fn compact_bridge_status() -> Value {
        json!({
            "bgvEncryptionKeyMaterialKind": "passive-transcript-derived-collective-public-key",
            "developmentKeyOnly": false,
            "bridgeClaimClosureVerified": true,
            "bridgeClaimVerificationStatus": "BridgeProofClaimClosureVerified",
            "thresholdDecryptable": true,
            "claimBearingBridgeEncryption": true,
        })
    }

    fn compact_bridge_randomness() -> Value {
        json!({
            "proverRandomnessSource": "fresh-csprng",
            "encryptionRandomnessSeedSource": "fresh-csprng",
            "randomnessSourceEvidence": {
                "objectType": "AggregateBridgeRandomnessSourceEvidence",
                "objectVersion": 1,
                "proverRandomnessSource": "fresh-csprng",
                "encryptionRandomnessSeedSource": "fresh-csprng",
                "callerSuppliedDevelopmentRandomness": false,
                "claimBearingEntropyEvidence": true,
            },
        })
    }

    fn compact_bridge_binding_objects(setup_package: &Value) -> (Value, Value, Value) {
        let bridge_encryption = json!({
            "bridgeProofProfileHash": valid_hash("1"),
            "bridgeProofStatementHash": valid_hash("2"),
            "bridgeProofChallengeContextHash": valid_hash("3"),
            "bridgeProofTargetContractHash": valid_hash("4"),
            "bridgeProofBytesHash": valid_hash("5"),
            "bridgeProofRoot": valid_hash("6"),
            "encryptedAggregateInputRoot": valid_hash("7"),
            "encryptedAggregateShareCiphertextRoot": valid_hash("8"),
            "plaintextCoefficientBindingCommitmentHash": valid_hash("9"),
            "proofFriendlyPlaintextLiftBindingHash": valid_hash("a"),
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": setup_package["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"],
            "bgvPublicKeyRoot": setup_package["collectivePublicKey"]["bgvPublicKeyRoot"],
        });
        let bridge_verification = json!({
            "bridgeProofProfileHash": bridge_encryption["bridgeProofProfileHash"],
            "bridgeProofStatementHash": bridge_encryption["bridgeProofStatementHash"],
            "bridgeProofChallengeContextHash": bridge_encryption["bridgeProofChallengeContextHash"],
            "bridgeProofTargetContractHash": bridge_encryption["bridgeProofTargetContractHash"],
            "bridgeProofBytesHash": bridge_encryption["bridgeProofBytesHash"],
            "bridgeProofRoot": bridge_encryption["bridgeProofRoot"],
            "encryptedAggregateInputRoot": bridge_encryption["encryptedAggregateInputRoot"],
            "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
            "plaintextCoefficientBindingCommitmentHash": bridge_encryption["plaintextCoefficientBindingCommitmentHash"],
            "proofFriendlyPlaintextLiftBindingHash": bridge_encryption["proofFriendlyPlaintextLiftBindingHash"],
            "collectivePublicKeyCoefficientRoot": bridge_encryption["collectivePublicKeyCoefficientRoot"],
        });
        let bridge_proof_record = json!({
            "setupPackageHash": setup_package["setupPackageHash"],
            "bridgeProofProfileHash": bridge_encryption["bridgeProofProfileHash"],
            "proofStatementHash": bridge_encryption["bridgeProofStatementHash"],
            "bridgeProofChallengeContextHash": bridge_encryption["bridgeProofChallengeContextHash"],
            "bridgeProofTargetContractHash": bridge_encryption["bridgeProofTargetContractHash"],
            "proofBytesHash": bridge_encryption["bridgeProofBytesHash"],
            "proofRoot": bridge_encryption["bridgeProofRoot"],
            "encryptedAggregateInputRoot": bridge_encryption["encryptedAggregateInputRoot"],
            "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
            "plaintextCoefficientBindingCommitmentHash": bridge_encryption["plaintextCoefficientBindingCommitmentHash"],
            "proofFriendlyPlaintextLiftBindingHash": bridge_encryption["proofFriendlyPlaintextLiftBindingHash"],
            "collectivePublicKeyRoot": bridge_encryption["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": bridge_encryption["collectivePublicKeyCoefficientRoot"],
            "bgvPublicKeyRoot": bridge_encryption["bgvPublicKeyRoot"],
        });

        (bridge_encryption, bridge_verification, bridge_proof_record)
    }

    fn merge_object_fields(target: &mut Value, fields: &Value) {
        let target_object = target.as_object_mut().expect("target object");
        for (field_name, field_value) in fields.as_object().expect("fields object") {
            target_object.insert(field_name.clone(), field_value.clone());
        }
    }

    fn compact_bridge_input_with_contributor_binding(
        setup_package: &Value,
        contributor_identity: &str,
        contributor_roster_position: u64,
    ) -> Value {
        let (mut bridge_encryption, mut bridge_verification, mut bridge_proof_record) =
            compact_bridge_binding_objects(setup_package);
        for target in [
            &mut bridge_encryption,
            &mut bridge_verification,
            &mut bridge_proof_record,
        ] {
            merge_object_fields(target, &compact_bridge_status());
            merge_object_fields(target, &compact_bridge_randomness());
        }
        bridge_verification["bridgeProofVerificationStatus"] =
            Value::String("BridgeProofRelationChecked".to_string());
        bridge_verification["bridgeEvidenceVerificationStatus"] =
            Value::String("BridgeProofEvidenceChecked".to_string());
        bridge_verification["aggregateDerivationVerificationScope"] =
            Value::String("AggregateDerivationFullVerificationChecked".to_string());
        bridge_proof_record["bridgeProofVerificationStatus"] =
            Value::String("BridgeProofRelationChecked".to_string());
        bridge_proof_record["aggregateDerivationVerificationScope"] =
            Value::String("AggregateDerivationFullVerificationChecked".to_string());
        bridge_proof_record["aggregateDerivationComponentHash"] = Value::String(valid_hash("b"));
        bridge_proof_record["aggregateDerivationStatementHash"] = Value::String(valid_hash("c"));
        bridge_proof_record["postVotingClosedContextHash"] = Value::String(valid_hash("d"));
        bridge_proof_record["contributorIdentity"] =
            Value::String(contributor_identity.to_string());
        bridge_proof_record["contributorRosterPosition"] = json!(contributor_roster_position);
        for (field_name, field_value) in [
            ("aggregateShareCommitmentHash", valid_hash("e")),
            ("shareCommitmentMessageBoundCertHash", valid_hash("f")),
            ("encryptedAggregateBridgeHash", valid_hash("1")),
            ("encryptedAggregateTargetBasisRoot", valid_hash("2")),
            ("encryptedAggregateReconstructionHash", valid_hash("3")),
            ("bridgeWitnessPrivacyProfileHash", valid_hash("4")),
            ("bgvBatchEncoderHash", valid_hash("5")),
            ("bridgeLayoutHash", valid_hash("6")),
            ("ballotScoreEncodingProfileHash", valid_hash("7")),
            ("ballotShareLayoutProfileHash", valid_hash("8")),
            ("aggregateInputEncodingProfileHash", valid_hash("9")),
            ("encodedShareVectorLayoutHash", valid_hash("a")),
            ("encodedAggregateLayoutHash", valid_hash("b")),
            ("encryptedAggregateInputLayoutHash", valid_hash("c")),
            ("topKEvaluatorInputLayoutHash", valid_hash("d")),
            ("heParamHash", valid_hash("e")),
            ("bgvProfileHash", valid_hash("f")),
            ("rustBgvBackendProfileHash", valid_hash("1")),
            ("canonicalCiphertextConventionHash", valid_hash("2")),
            ("aggregateSelectionPolicyHash", valid_hash("3")),
            ("manifestHash", valid_hash("4")),
            ("rosterHash", valid_hash("5")),
            ("pollSpecHash", valid_hash("6")),
            ("thresholdProfileHash", valid_hash("7")),
            ("ballotSetHash", valid_hash("8")),
            ("votingClosedBoardHeadHash", valid_hash("9")),
            ("contributorRosterExternalAcceptanceHash", valid_hash("a")),
        ] {
            bridge_proof_record[field_name] = Value::String(field_value);
        }
        bridge_proof_record["ceremonyId"] = Value::String("ceremony-main".to_string());
        bridge_proof_record["participantCount"] = json!(20);
        bridge_proof_record["optionCount"] = json!(20);
        bridge_proof_record["shareVectorWidth"] = json!(220);
        bridge_proof_record["bridgeProofRecordHash"] = Value::String(
            bridge_proof_record_hash_for_evaluation(&bridge_proof_record)
                .expect("bridge proof record hash"),
        );

        let mut aggregate_contribution = json!({
            "aggregateDerivationComponentHash": bridge_proof_record["aggregateDerivationComponentHash"],
            "aggregateShareCommitmentHash": bridge_proof_record["aggregateShareCommitmentHash"],
            "shareCommitmentMessageBoundCertHash": bridge_proof_record["shareCommitmentMessageBoundCertHash"],
            "encryptedAggregateBridgeHash": bridge_proof_record["encryptedAggregateBridgeHash"],
            "encryptedAggregateTargetBasisRoot": bridge_proof_record["encryptedAggregateTargetBasisRoot"],
            "encryptedAggregateInputRoot": bridge_proof_record["encryptedAggregateInputRoot"],
            "encryptedAggregateShareCiphertextRoot": bridge_proof_record["encryptedAggregateShareCiphertextRoot"],
            "encryptedAggregateReconstructionHash": bridge_proof_record["encryptedAggregateReconstructionHash"],
            "bridgeProofProfileHash": bridge_proof_record["bridgeProofProfileHash"],
            "bridgeWitnessPrivacyProfileHash": bridge_proof_record["bridgeWitnessPrivacyProfileHash"],
            "bgvBatchEncoderHash": bridge_proof_record["bgvBatchEncoderHash"],
            "bridgeLayoutHash": bridge_proof_record["bridgeLayoutHash"],
            "ballotScoreEncodingProfileHash": bridge_proof_record["ballotScoreEncodingProfileHash"],
            "ballotShareLayoutProfileHash": bridge_proof_record["ballotShareLayoutProfileHash"],
            "aggregateInputEncodingProfileHash": bridge_proof_record["aggregateInputEncodingProfileHash"],
            "encodedShareVectorLayoutHash": bridge_proof_record["encodedShareVectorLayoutHash"],
            "encodedAggregateLayoutHash": bridge_proof_record["encodedAggregateLayoutHash"],
            "encryptedAggregateInputLayoutHash": bridge_proof_record["encryptedAggregateInputLayoutHash"],
            "topKEvaluatorInputLayoutHash": bridge_proof_record["topKEvaluatorInputLayoutHash"],
            "heParamHash": bridge_proof_record["heParamHash"],
            "bgvProfileHash": bridge_proof_record["bgvProfileHash"],
            "rustBgvBackendProfileHash": bridge_proof_record["rustBgvBackendProfileHash"],
            "canonicalCiphertextConventionHash": bridge_proof_record["canonicalCiphertextConventionHash"],
            "bgvPublicKeyRoot": bridge_proof_record["bgvPublicKeyRoot"],
            "collectivePublicKeyRoot": bridge_proof_record["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": bridge_proof_record["collectivePublicKeyCoefficientRoot"],
            "aggregateSelectionPolicyHash": bridge_proof_record["aggregateSelectionPolicyHash"],
            "postVotingClosedContextHash": bridge_proof_record["postVotingClosedContextHash"],
            "ceremonyId": bridge_proof_record["ceremonyId"],
            "manifestHash": bridge_proof_record["manifestHash"],
            "rosterHash": bridge_proof_record["rosterHash"],
            "pollSpecHash": bridge_proof_record["pollSpecHash"],
            "thresholdProfileHash": bridge_proof_record["thresholdProfileHash"],
            "setupPackageHash": bridge_proof_record["setupPackageHash"],
            "ballotSetHash": bridge_proof_record["ballotSetHash"],
            "votingClosedBoardHeadHash": bridge_proof_record["votingClosedBoardHeadHash"],
            "contributorIdentity": contributor_identity,
            "contributorRosterPosition": contributor_roster_position,
            "contributorRosterExternalAcceptanceHash": bridge_proof_record["contributorRosterExternalAcceptanceHash"],
            "participantCount": bridge_proof_record["participantCount"],
            "optionCount": bridge_proof_record["optionCount"],
            "shareVectorWidth": bridge_proof_record["shareVectorWidth"],
            "bridgeProofRecordHash": bridge_proof_record["bridgeProofRecordHash"],
            "aggregateContributionHash": valid_hash("e"),
            "bridgeProofRecord": bridge_proof_record,
        });
        aggregate_contribution["aggregateContributionHash"] = Value::String(
            aggregate_contribution_hash_for_evaluation(&aggregate_contribution)
                .expect("aggregate contribution hash"),
        );

        json!({
            "aggregateDerivationComponentHash": valid_hash("b"),
            "aggregateDerivationStatementHash": valid_hash("c"),
            "postVotingClosedContextHash": valid_hash("d"),
            "bridgeEncryption": bridge_encryption,
            "bridgeEvidenceVerification": bridge_verification,
            "aggregateContribution": aggregate_contribution,
        })
    }

    #[test]
    fn compact_bridge_status_rejects_inflated_or_wrong_key_status() {
        validate_compact_bridge_status_for_evaluation(
            &compact_bridge_status(),
            &compact_bridge_status(),
            &compact_bridge_status(),
        )
        .expect("consistent claim-bearing compact bridge status should validate");

        for (object_index, field_name, mutated_value, expected_message) in [
            (
                0,
                "developmentKeyOnly",
                Value::Bool(true),
                "development-only",
            ),
            (
                1,
                "thresholdDecryptable",
                Value::Bool(false),
                "threshold-decryptable",
            ),
            (
                2,
                "claimBearingBridgeEncryption",
                Value::Bool(false),
                "claim-bearing",
            ),
            (
                0,
                "bridgeClaimClosureVerified",
                Value::Bool(false),
                "verified bridge proof claim closure",
            ),
            (
                2,
                "bridgeClaimVerificationStatus",
                Value::String("UnsupportedBridgeClaimClosureStatus".to_string()),
                "verified bridge proof status",
            ),
            (
                1,
                "bgvEncryptionKeyMaterialKind",
                Value::String("development-fixture-key".to_string()),
                "supported BGV key material",
            ),
        ] {
            let mut bridge_encryption = compact_bridge_status();
            let mut bridge_verification = compact_bridge_status();
            let mut bridge_proof_record = compact_bridge_status();
            match object_index {
                0 => bridge_encryption[field_name] = mutated_value,
                1 => bridge_verification[field_name] = mutated_value,
                2 => bridge_proof_record[field_name] = mutated_value,
                _ => unreachable!("test object index is fixed"),
            }

            let error = validate_compact_bridge_status_for_evaluation(
                &bridge_encryption,
                &bridge_verification,
                &bridge_proof_record,
            )
            .expect_err("mutated compact bridge status should reject");

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }
    }

    #[test]
    fn compact_bridge_randomness_rejects_development_or_inconsistent_entropy() {
        validate_compact_bridge_randomness_for_evaluation(
            &compact_bridge_randomness(),
            &compact_bridge_randomness(),
            &compact_bridge_randomness(),
        )
        .expect("consistent claim-bearing compact bridge randomness should validate");

        for (object_index, field_name, expected_message) in [
            (
                0,
                "proverRandomnessSource",
                "fresh bridge prover and encryption randomness",
            ),
            (
                1,
                "encryptionRandomnessSeedSource",
                "fresh bridge prover and encryption randomness",
            ),
            (
                2,
                "claimBearingEntropyEvidence",
                "bridge entropy evidence accepted",
            ),
            (
                0,
                "callerSuppliedDevelopmentRandomness",
                "development bridge randomness",
            ),
        ] {
            let mut bridge_encryption = compact_bridge_randomness();
            let mut bridge_verification = compact_bridge_randomness();
            let mut bridge_proof_record = compact_bridge_randomness();
            let target = match object_index {
                0 => &mut bridge_encryption,
                1 => &mut bridge_verification,
                2 => &mut bridge_proof_record,
                _ => unreachable!("test object index is fixed"),
            };
            match field_name {
                "proverRandomnessSource" => {
                    target[field_name] = Value::String("development-deterministic-fixture".into());
                    target["randomnessSourceEvidence"][field_name] =
                        Value::String("development-deterministic-fixture".into());
                    target["randomnessSourceEvidence"]["callerSuppliedDevelopmentRandomness"] =
                        Value::Bool(true);
                    target["randomnessSourceEvidence"]["claimBearingEntropyEvidence"] =
                        Value::Bool(false);
                }
                "encryptionRandomnessSeedSource" => {
                    target[field_name] = Value::String("development-deterministic-fixture".into());
                    target["randomnessSourceEvidence"][field_name] =
                        Value::String("development-deterministic-fixture".into());
                    target["randomnessSourceEvidence"]["callerSuppliedDevelopmentRandomness"] =
                        Value::Bool(true);
                    target["randomnessSourceEvidence"]["claimBearingEntropyEvidence"] =
                        Value::Bool(false);
                }
                "claimBearingEntropyEvidence" => {
                    target["randomnessSourceEvidence"][field_name] = Value::Bool(false);
                }
                "callerSuppliedDevelopmentRandomness" => {
                    target["randomnessSourceEvidence"][field_name] = Value::Bool(true);
                }
                _ => unreachable!("test field is fixed"),
            }

            let error = validate_compact_bridge_randomness_for_evaluation(
                &bridge_encryption,
                &bridge_verification,
                &bridge_proof_record,
            )
            .expect_err("mutated compact bridge randomness should reject");

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }

        let mut bridge_proof_record = compact_bridge_randomness();
        bridge_proof_record["randomnessSourceEvidence"]["objectVersion"] = Value::from(2_u64);
        let error = validate_compact_bridge_randomness_for_evaluation(
            &compact_bridge_randomness(),
            &compact_bridge_randomness(),
            &bridge_proof_record,
        )
        .expect_err("unsupported randomness-source evidence should reject");
        assert!(
            error.message.contains("supported bridge randomness"),
            "{}",
            error.message
        );

        let mut bridge_encryption = compact_bridge_randomness();
        bridge_encryption["randomnessSourceEvidence"]["encryptionRandomnessSeedSource"] =
            Value::String("development-deterministic-fixture".into());
        let error = validate_compact_bridge_randomness_for_evaluation(
            &bridge_encryption,
            &compact_bridge_randomness(),
            &compact_bridge_randomness(),
        )
        .expect_err("nested randomness-source evidence drift should reject");
        assert!(
            error
                .message
                .contains("randomness source evidence to match"),
            "{}",
            error.message
        );
    }

    #[test]
    fn compact_bridge_bindings_reject_wrong_context_or_key_roots() {
        let setup_package = binding_setup_package_fixture();
        let (bridge_encryption, bridge_verification, bridge_proof_record) =
            compact_bridge_binding_objects(&setup_package);
        validate_compact_bridge_bindings_for_evaluation(
            &setup_package,
            &bridge_encryption,
            &bridge_verification,
            &bridge_proof_record,
        )
        .expect("consistent compact bridge bindings should validate");

        for (object_index, field_name, expected_message) in [
            (0, "bridgeProofChallengeContextHash", "challenge context"),
            (1, "collectivePublicKeyCoefficientRoot", "coefficient root"),
            (2, "setupPackageHash", "setup package hash"),
            (2, "bgvPublicKeyRoot", "BGV public key root"),
        ] {
            let (mut bridge_encryption, mut bridge_verification, mut bridge_proof_record) =
                compact_bridge_binding_objects(&setup_package);
            match object_index {
                0 => bridge_encryption[field_name] = Value::String(valid_hash("b")),
                1 => bridge_verification[field_name] = Value::String(valid_hash("c")),
                2 => bridge_proof_record[field_name] = Value::String(valid_hash("d")),
                _ => unreachable!("test object index is fixed"),
            }

            let error = validate_compact_bridge_bindings_for_evaluation(
                &setup_package,
                &bridge_encryption,
                &bridge_verification,
                &bridge_proof_record,
            )
            .expect_err("mutated compact bridge binding should reject");

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }
    }

    #[test]
    fn compact_bridge_input_rejects_contributor_identity_or_position_drift() {
        let setup_package = binding_setup_package_fixture();

        for (field_name, replacement, expected_message) in [
            (
                "contributorIdentity",
                Value::String("receiver-9".to_string()),
                "selected contributor identity",
            ),
            (
                "contributorRosterPosition",
                json!(9),
                "selected contributor roster position",
            ),
        ] {
            let mut input =
                compact_bridge_input_with_contributor_binding(&setup_package, "receiver-1", 1);
            input["aggregateContribution"]["bridgeProofRecord"][field_name] = replacement;

            let error = match verify_compact_aggregate_bridge_input_for_evaluation(
                &setup_package,
                &input,
            ) {
                Ok(_) => panic!("compact bridge contributor identity drift should reject"),
                Err(error) => error,
            };

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }
    }

    #[test]
    fn compact_bridge_input_rejects_rehashed_contribution_or_proof_record_drift() {
        let setup_package = binding_setup_package_fixture();

        for (path, replacement, expected_message) in [
            (
                vec!["aggregateContributionHash"],
                Value::String(valid_hash("f")),
                "aggregate contribution hash",
            ),
            (
                vec!["bridgeProofRecord", "bridgeProofRecordHash"],
                Value::String(valid_hash("f")),
                "bridge proof record hash",
            ),
        ] {
            let mut input =
                compact_bridge_input_with_contributor_binding(&setup_package, "receiver-1", 1);
            let mut target = &mut input["aggregateContribution"];
            for path_segment in path.iter().take(path.len() - 1) {
                target = &mut target[*path_segment];
            }
            target[path.last().expect("path is not empty")] = replacement;

            let error = match verify_compact_aggregate_bridge_input_for_evaluation(
                &setup_package,
                &input,
            ) {
                Ok(_) => panic!("compact bridge contribution hash drift should reject"),
                Err(error) => error,
            };

            assert!(
                error.message.contains(expected_message),
                "{path:?}: {error:?}"
            );
        }
    }

    #[test]
    fn compact_bridge_input_rejects_aggregate_contribution_public_field_drift() {
        let setup_package = binding_setup_package_fixture();
        let mut input =
            compact_bridge_input_with_contributor_binding(&setup_package, "receiver-1", 1);
        input["aggregateContribution"]["bridgeProofRecord"]["ballotSetHash"] =
            Value::String(valid_hash("f"));
        let bridge_proof_record_hash = bridge_proof_record_hash_for_evaluation(
            &input["aggregateContribution"]["bridgeProofRecord"],
        )
        .expect("bridge proof record hash");
        input["aggregateContribution"]["bridgeProofRecord"]["bridgeProofRecordHash"] =
            Value::String(bridge_proof_record_hash.clone());
        input["aggregateContribution"]["bridgeProofRecordHash"] =
            Value::String(bridge_proof_record_hash);
        input["aggregateContribution"]["aggregateContributionHash"] = Value::String(
            aggregate_contribution_hash_for_evaluation(&input["aggregateContribution"])
                .expect("aggregate contribution hash"),
        );

        let error =
            match verify_compact_aggregate_bridge_input_for_evaluation(&setup_package, &input) {
                Ok(_) => panic!("compact bridge contribution public-field drift should reject"),
                Err(error) => error,
            };

        assert!(error.message.contains("ballotSetHash"), "{}", error.message);
    }

    #[test]
    fn generator_ordered_required_rotation_keys_match_full_evaluator_schedule() {
        let required = required_generator_ordered_rotation_keys(20).expect("rotation schedule");
        let unique = required
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        let full_level = DATA_PRIMES.len() - 1;
        let full_level_count = required
            .iter()
            .filter(|(_, level)| *level == full_level)
            .count();
        let direct_comparison_return_count = required
            .iter()
            .filter(|(_, level)| *level == DIRECT_COMPARISON_OUTPUT_LEVEL)
            .count();

        assert_eq!(required.len(), unique.len());
        assert_eq!(required.len(), 20);
        assert_eq!(full_level_count, 15);
        assert_eq!(direct_comparison_return_count, 5);
        assert!(required.contains(&(3, full_level)));
        assert!(required.contains(&(2 * POLYNOMIAL_DEGREE - 1, full_level)));
    }

    #[test]
    fn aggregate_ready_evaluator_rejects_public_material_missing_selected_rotations() {
        let context = EvaluatorContext::new("missing-selected-rotations", 1)
            .expect("evaluator context without public rotation keys");

        let error = require_public_rotation_keys_for_aggregate_ready_evaluation(&context, 20)
            .expect_err("mandatory evaluator schedule must reject missing setup rotations");

        assert!(
            error.message.contains("missing required rotation key"),
            "{}",
            error.message
        );
    }

    #[test]
    #[ignore = "heavy setup-bound packed evaluator primitive; run selectively"]
    fn setup_public_evaluation_keys_run_packed_full_domain_target_primitives() {
        let setup_package = real_setup_package_fixture();
        let option_count = 20;
        let score_domain_max = 200;
        let rotation_keys =
            selected_evaluator_rotation_key_schedule(option_count, DATA_PRIMES.len() - 1)
                .expect("compact evaluator rotation schedule")
                .into_iter()
                .map(|(rotation, level)| {
                    json!({
                        "rotation": rotation,
                        "level": level,
                    })
                })
                .collect::<Vec<_>>();
        let public_material =
            generate_passive_setup_public_evaluation_key_material_from_request(&json!({
                "setupPackage": setup_package.clone(),
                "setupPrivateWitness": {
                    "setupSeed": "encrypted-aggregate-evaluator-test-seed",
                },
                "workingLevel": DATA_PRIMES.len() - 1,
                "rotationKeys": rotation_keys,
            }))
            .expect("setup-bound public evaluation-key material");
        let context = EvaluatorContext::from_passive_setup_public_material(
            &setup_package,
            &public_material,
            DATA_PRIMES.len() - 1,
        )
        .expect("public evaluator context");
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            "encrypted-aggregate-evaluator-test-seed",
        )
        .expect("test-only setup secret");
        let multiplication_left = modulus_switch_to(
            &evaluator_key
                .encrypt_slots(&[2, 3, 4, 5], "setup-public-primitives-left")
                .expect("left multiplicand"),
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        )
        .expect("left level");
        let multiplication_right = modulus_switch_to(
            &evaluator_key
                .encrypt_slots(&[7, 8, 9, 10], "setup-public-primitives-right")
                .expect("right multiplicand"),
            DIRECT_COMPARISON_OUTPUT_LEVEL,
        )
        .expect("right level");
        let product =
            multiply(&context, &multiplication_left, &multiplication_right).expect("product");
        let product_slots = evaluator_key
            .decrypt_to_slots(&product)
            .expect("product slots");
        assert_eq!(&product_slots[..4], &[14, 24, 36, 50]);

        let option_scores = [170_u64, 88];
        let mut aggregate_slots = vec![0_u64; POLYNOMIAL_DEGREE];
        for (option_index, score) in option_scores.iter().enumerate() {
            aggregate_slots[aggregate_score_slot(option_index)] = *score;
        }
        let encrypted_aggregate = evaluator_key
            .encrypt_slots(&aggregate_slots, "setup-public-packed-primitives")
            .expect("encrypted aggregate");
        let packed_scores = pack_reconstructed_aggregate_scores(
            &context,
            &encrypted_aggregate,
            option_count,
            "setup-public-packed-primitives",
        )
        .expect("packed scores");
        let decrypted_packed_scores = evaluator_key
            .decrypt_to_slots(&packed_scores)
            .expect("packed score slots");
        assert_eq!(
            [0, 1, option_count, option_count + 1]
                .map(|option_index| decrypted_packed_scores[packed_score_slot(option_index)])
                .to_vec(),
            vec![170, 88, 170, 88]
        );

        let shifted_scores = context
            .rotate_ciphertext(
                &packed_scores,
                galois_power(1),
                packed_scores.level,
                "setup-public-packed-primitives-shift",
            )
            .expect("shifted packed scores");
        let mut shift_constant = vec![0_u64; POLYNOMIAL_DEGREE];
        shift_constant[0] = score_domain_max;
        let shifted_difference = add_plaintext_coefficients(
            &normalize_scaling(
                &ciphertext_sub(&packed_scores, &shifted_scores).expect("score difference"),
            )
            .expect("normalized difference"),
            &shift_constant,
        )
        .expect("shifted difference");
        let shifted_difference =
            modulus_switch_to(&shifted_difference, shifted_difference.level - 1)
                .expect("refreshed shifted difference");
        let (_, greater_or_equal_polynomial) =
            comparison_polynomials(score_domain_max).expect("comparison polynomial");
        let lower_beats_higher = evaluate_direct_comparison_polynomial(
            &context,
            &shifted_difference,
            &greater_or_equal_polynomial,
        )
        .expect("representative comparison");
        let comparison_slots = evaluator_key
            .decrypt_to_slots(&lower_beats_higher)
            .expect("comparison slots");

        assert_eq!(
            comparison_slots[packed_score_slot(0)],
            1,
            "lower-index option with higher score should beat the next option"
        );
    }

    #[test]
    #[ignore = "checkpoint-bound accepted-input evaluator evidence; run after representative evaluator generation"]
    fn accepted_input_representative_targets_decrypt_to_fixture_oracle() {
        let sweep = load_checkpoint_json(
            "temp/test-checkpoints/encrypted-aggregate-evaluator-representative-top-counts-10-20.json",
        );
        assert_eq!(
            sweep["comparisonProfile"].as_str(),
            Some("direct-encrypted-score-comparison-v1")
        );
        assert_eq!(
            sweep["rankPackingMethod"].as_str(),
            Some("generator-ordered")
        );

        let option_count = 20;
        let evaluations = sweep["evaluations"].as_array().expect("sweep evaluations");
        assert_eq!(evaluations.len(), 2);
        let setup_package = load_checkpoint_json(
            "temp/test-checkpoints/aggregate-derivation-kernel-last-setup-package.json",
        );
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            "accepted-encrypted-aggregate-evaluator-test-seed",
        )
        .expect("test-only setup secret");
        let request_base = load_checkpoint_json(
            "temp/test-checkpoints/aggregate-derivation-kernel-last-evaluator-request-base.json",
        );
        let first_bridge_ciphertext = ciphertext_from_checkpoint_artifact(
            &request_base["encryptedAggregateInputs"][0]["bridgeEncryption"],
        )
        .expect("first accepted bridge ciphertext");
        let first_bridge_slots = evaluator_key
            .decrypt_to_slots(&first_bridge_ciphertext)
            .expect("first accepted bridge slots");
        let expected_bridge_slots = expected_variant_fixture_share_slots(option_count);
        assert_eq!(
            &first_bridge_slots[..expected_bridge_slots.len()],
            expected_bridge_slots.as_slice(),
            "accepted bridge input must decrypt to the deterministic aggregate-share fixture before evaluation"
        );
        let packed_rank_ciphertext = ciphertext_from_checkpoint_artifact(
            &sweep["sharedEncryptedRankBundle"]["packedRankCiphertext"],
        )
        .expect("shared packed-rank ciphertext");
        let packed_rank_slots = evaluator_key
            .decrypt_to_slots(&packed_rank_ciphertext)
            .expect("shared packed-rank slots");
        let actual_ranks = packed_target_slots(&packed_rank_slots, option_count);
        let expected_ranks = expected_variant_fixture_ranks(option_count)
            .into_iter()
            .map(|rank| u64::try_from(rank).expect("rank fits u64"))
            .collect::<Vec<_>>();
        assert_eq!(
            actual_ranks, expected_ranks,
            "shared packed ranks must match the deterministic fixture oracle before target projection"
        );

        let mut observed_top_counts = Vec::with_capacity(evaluations.len());
        for evaluation in evaluations {
            let top_count = evaluation["appendixDPublicInputStatement"]["topCount"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .expect("top-count value");
            observed_top_counts.push(top_count);
            let labels = evaluation["statusLabels"]
                .as_array()
                .expect("evaluation status labels");
            assert!(
                labels
                    .iter()
                    .any(|label| label.as_str() == Some("NotAcceptedTarget")),
                "representative evaluator output must remain a target proposal"
            );

            let encrypted_target = &evaluation["encryptedSparseTarget"];
            let target_id_ciphertext =
                ciphertext_from_checkpoint_artifact(&encrypted_target["targetIdCiphertext"])
                    .expect("target-id ciphertext");
            let target_order_ciphertext =
                ciphertext_from_checkpoint_artifact(&encrypted_target["targetOrderCiphertext"])
                    .expect("target-order ciphertext");
            let decrypted_target_id_slots = evaluator_key
                .decrypt_to_slots(&target_id_ciphertext)
                .expect("target-id slots");
            let decrypted_target_order_slots = evaluator_key
                .decrypt_to_slots(&target_order_ciphertext)
                .expect("target-order slots");
            let actual_target_ids = packed_target_slots(&decrypted_target_id_slots, option_count);
            let actual_target_orders =
                packed_target_slots(&decrypted_target_order_slots, option_count);
            let (expected_target_ids, expected_target_orders) =
                expected_variant_fixture_sparse_target(option_count, top_count);

            assert_eq!(
                actual_target_ids, expected_target_ids,
                "target identifiers must match the deterministic fixture oracle for topCount={top_count}"
            );
            assert_eq!(
                actual_target_orders, expected_target_orders,
                "target order values must match the deterministic fixture oracle for topCount={top_count}"
            );
        }

        assert_eq!(observed_top_counts, vec![10, 20]);
    }

    #[test]
    fn aggregate_ready_evaluator_rejects_non_selected_score_domain() {
        let error = read_selected_score_domain_max(&json!({
            "scoreDomainMax": 10,
        }))
        .expect_err("aggregate-ready evaluator must reject non-selected score domain");

        assert!(
            error
                .message
                .contains("requires selected scoreDomainMax 200"),
            "{}",
            error.message
        );
    }

    #[test]
    fn aggregate_ready_evaluator_rejects_wrong_setup_target_layout() {
        let setup_package = binding_setup_package_fixture();
        require_setup_target_layout_for_aggregate_ready_evaluation(&setup_package, 20)
            .expect("generated setup target layout should match the selected evaluator layout");

        let mut wrong_layout_setup = setup_package;
        wrong_layout_setup["profileBindings"]["targetLayoutHash"] = Value::String(valid_hash("e"));
        let error =
            require_setup_target_layout_for_aggregate_ready_evaluation(&wrong_layout_setup, 20)
                .expect_err("wrong target layout hash must reject before accepted evaluation");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(
            error.message.contains("target layout hash"),
            "{}",
            error.message
        );
    }

    #[test]
    fn aggregate_ready_binding_rejects_selected_ciphertext_root_drift() {
        let setup_package = binding_setup_package_fixture();
        let selected_roots = vec![valid_hash("1"), valid_hash("2")];
        let record = aggregate_ready_record(&setup_package, &selected_roots);
        let request = json!({
            "aggregateReadyRecord": record,
        });
        let accepted = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &selected_roots,
            &valid_hash("7"),
        )
        .expect("aggregate-ready record should bind");
        assert_eq!(accepted.2, "aggregate-ready-record-verified");

        let wrong_roots = vec![valid_hash("1"), valid_hash("4")];
        let error = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &wrong_roots,
            &valid_hash("7"),
        )
        .expect_err("root drift should reject");
        assert!(
            error
                .message
                .contains("selected ciphertext roots do not match"),
            "{}",
            error.message
        );

        let bridge_hash_error = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &selected_roots,
            &valid_hash("8"),
        )
        .expect_err("bridge hash drift should reject");
        assert!(
            bridge_hash_error
                .message
                .contains("bridge hash does not match"),
            "{}",
            bridge_hash_error.message
        );

        let mut wrong_profile_record = aggregate_ready_record(&setup_package, &selected_roots);
        wrong_profile_record["encryptedAggregateTargetBasisRoot"] = Value::String(valid_hash("5"));
        wrong_profile_record["aggregateReadyRecordHash"] =
            Value::String(aggregate_ready_record_hash(&wrong_profile_record).expect("record hash"));
        let profile_error = aggregate_ready_binding_from_request(
            &json!({ "aggregateReadyRecord": wrong_profile_record }),
            &setup_package,
            &selected_roots,
            &valid_hash("7"),
        )
        .expect_err("setup profile drift should reject");
        assert!(
            profile_error.message.contains("target-basis root"),
            "{}",
            profile_error.message
        );
    }

    #[test]
    fn aggregate_ready_record_rejects_rehashed_order_or_reconstruction_drift() {
        let setup_package = binding_setup_package_fixture();
        let selected_roots = vec![valid_hash("1"), valid_hash("2")];
        let record = aggregate_ready_record(&setup_package, &selected_roots);
        let record_hash = record["aggregateReadyRecordHash"]
            .as_str()
            .expect("record hash")
            .to_string();
        aggregate_ready_record_from_request(
            &json!({ "aggregateReadyRecord": record }),
            &record_hash,
            &valid_hash("7"),
        )
        .expect("aggregate-ready record should recompute selected-order and reconstruction roots");

        for (field_name, replacement, expected_message) in [
            (
                "firstValidOrderHash",
                Value::String(valid_hash("3")),
                "first-valid order hash",
            ),
            (
                "encryptedAggregateReconstructionRoot",
                Value::String(valid_hash("4")),
                "encrypted aggregate reconstruction root",
            ),
        ] {
            let mut forged_record = aggregate_ready_record(&setup_package, &selected_roots);
            forged_record[field_name] = replacement;
            forged_record["aggregateReadyRecordHash"] =
                Value::String(aggregate_ready_record_hash(&forged_record).expect("record hash"));
            let forged_record_hash = forged_record["aggregateReadyRecordHash"]
                .as_str()
                .expect("forged record hash")
                .to_string();

            let result = aggregate_ready_record_from_request(
                &json!({ "aggregateReadyRecord": forged_record }),
                &forged_record_hash,
                &valid_hash("7"),
            );
            let error = match result {
                Ok(_) => panic!("semantically drifted aggregate-ready record should reject"),
                Err(error) => error,
            };

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }

        for (field_name, replacement, expected_message) in [
            (
                "selectedContributorIdentities",
                json!(["trustee-1"]),
                "selected contributor arrays",
            ),
            (
                "rosterSize",
                json!(2),
                "roster size and aggregate contribution quorum",
            ),
            (
                "aggregateContributionQuorum",
                json!(0),
                "roster size and aggregate contribution quorum",
            ),
        ] {
            let mut forged_record = aggregate_ready_record(&setup_package, &selected_roots);
            forged_record[field_name] = replacement;
            forged_record["aggregateReadyRecordHash"] =
                Value::String(aggregate_ready_record_hash(&forged_record).expect("record hash"));
            let forged_record_hash = forged_record["aggregateReadyRecordHash"]
                .as_str()
                .expect("forged record hash")
                .to_string();

            let result = aggregate_ready_record_from_request(
                &json!({ "aggregateReadyRecord": forged_record }),
                &forged_record_hash,
                &valid_hash("7"),
            );
            let error = match result {
                Ok(_) => panic!("structurally drifted aggregate-ready record should reject"),
                Err(error) => error,
            };

            assert!(
                error.message.contains(expected_message),
                "{field_name}: {error:?}"
            );
        }
    }

    #[test]
    fn aggregate_ready_binding_requires_supplied_record() {
        let setup_package = binding_setup_package_fixture();
        let request = json!({});

        let error = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &[valid_hash("1"), valid_hash("2")],
            &valid_hash("3"),
        )
        .expect_err("aggregate-ready binding must require a real record");

        assert!(
            error.message.contains("requires an aggregateReadyRecord"),
            "{}",
            error.message
        );
    }

    #[test]
    fn aggregate_ready_record_rejects_reduced_option_count_on_accepted_path() {
        let setup_package = binding_setup_package_fixture();
        let mut record =
            aggregate_ready_record(&setup_package, &[valid_hash("a"), valid_hash("b")]);
        record["optionCount"] = json!(2);
        record["shareVectorWidth"] = json!(22);
        record["aggregateReadyRecordHash"] =
            Value::String(aggregate_ready_record_hash(&record).expect("record hash"));

        let record_hash = record["aggregateReadyRecordHash"]
            .as_str()
            .expect("record hash")
            .to_string();
        let bridge_hash = record["encryptedAggregateBridgeHash"]
            .as_str()
            .expect("bridge hash")
            .to_string();
        let error = match aggregate_ready_record_from_request(
            &json!({ "aggregateReadyRecord": record }),
            &record_hash,
            &bridge_hash,
        ) {
            Ok(_) => panic!("accepted evaluator must reject reduced aggregate-ready option counts"),
            Err(error) => error,
        };

        assert!(
            error
                .message
                .contains("mandatory selected aggregate layout"),
            "{}",
            error.message
        );
    }

    #[test]
    fn aggregate_ready_record_rejects_reduced_roster_size_on_accepted_path() {
        let setup_package = binding_setup_package_fixture();
        let selected_roots = vec![valid_hash("a"), valid_hash("b")];
        let mut record = aggregate_ready_record(&setup_package, &selected_roots);
        let selected_aggregate_contribution_hashes = record["selectedAggregateContributionHashes"]
            .as_array()
            .expect("selected contribution hashes")
            .clone();
        let interpolation_coefficients = record["interpolationCoefficients"]
            .as_array()
            .expect("interpolation coefficients")
            .clone();
        let reduced_interpolation_report_hash = derive_protocol_hash(
            "InterpolationCoefficientReportHash",
            &json!({
                "centeredL1CoefficientSum": 3,
                "coefficients": interpolation_coefficients,
                "contributorRosterPositions": [1, 2],
                "maxCenteredAbsCoefficient": 2,
                "rosterSize": 3,
                "threshold": 2,
            }),
        )
        .expect("reduced interpolation report hash");
        let reduced_reconstruction_root = derive_protocol_hash(
            "EncryptedAggregateReconstructionHash",
            &json!({
                "aggregateSelectionPolicyHash": valid_hash("8"),
                "encryptedAggregateReconstructionHash": setup_package["profileBindings"]["encryptedAggregateReconstructionHash"],
                "encryptedAggregateShareCiphertextRoots": selected_roots,
                "firstValidOrderHash": record["firstValidOrderHash"],
                "interpolationCoefficientReportHash": reduced_interpolation_report_hash,
                "purpose": "sealed-lattice-aggregate-ready-reconstruction-root-v1",
                "selectedAggregateContributionHashes": selected_aggregate_contribution_hashes,
            }),
        )
        .expect("reduced reconstruction root");
        record["rosterSize"] = json!(3);
        record["interpolationCoefficientReportHash"] =
            Value::String(reduced_interpolation_report_hash);
        record["encryptedAggregateReconstructionRoot"] = Value::String(reduced_reconstruction_root);
        record["aggregateReadyRecordHash"] =
            Value::String(aggregate_ready_record_hash(&record).expect("record hash"));

        let record_hash = record["aggregateReadyRecordHash"]
            .as_str()
            .expect("record hash")
            .to_string();
        let bridge_hash = record["encryptedAggregateBridgeHash"]
            .as_str()
            .expect("bridge hash")
            .to_string();
        let error = match aggregate_ready_record_from_request(
            &json!({ "aggregateReadyRecord": record }),
            &record_hash,
            &bridge_hash,
        ) {
            Ok(_) => panic!("accepted evaluator must reject reduced aggregate-ready roster sizes"),
            Err(error) => error,
        };

        assert!(
            error
                .message
                .contains("mandatory selected aggregate roster"),
            "{}",
            error.message
        );
    }

    #[test]
    fn aggregate_ready_binding_rejects_reduced_setup_roster_on_accepted_path() {
        let setup_package = binding_setup_package_with_participant_count(3);
        let selected_roots = vec![valid_hash("a"), valid_hash("b")];
        let record = aggregate_ready_record(&setup_package, &selected_roots);

        let error = aggregate_ready_binding_from_request(
            &json!({ "aggregateReadyRecord": record }),
            &setup_package,
            &selected_roots,
            &valid_hash("7"),
        )
        .expect_err("accepted evaluator must reject reduced setup rosters");

        assert!(
            error.message.contains("mandatory frozen receiver roster"),
            "{}",
            error.message
        );
    }

    #[test]
    fn accepted_evaluator_rejects_plaintext_or_private_witness_fields() {
        reject_forbidden_accepted_evaluator_fields(&json!({
            "setupPackage": {
                "trustedDealerBoundary": {
                    "rawSecretSharesExported": false,
                },
            },
            "aggregateReadyRecord": {
                "bridgeWitnessPrivacyProfileHash": valid_hash("1"),
            },
        }))
        .expect("public boundary and profile hashes should not count as witness leakage");

        for (field_name, field_value) in [
            ("decodedTargetIdSlots", json!([1, 0])),
            ("plaintextRanks", json!([0, 1])),
            ("developmentKeySet", json!({ "keySeed": "do-not-accept" })),
            ("rawSecretShares", json!(["share-1", "share-2"])),
            (
                "trustedDealerSecret",
                json!({ "secret": "not-on-accepted-evaluation-path" }),
            ),
            (
                "fullSecretReconstruction",
                json!({ "shares": ["not", "accepted"] }),
            ),
            (
                "setupPrivateWitness",
                json!({ "setupSeed": "do-not-accept-on-evaluation-path" }),
            ),
            ("targetDecryptionShare", json!({ "share": "not-yet-owned" })),
            ("evaluationProofVerified", json!(true)),
        ] {
            let mut request = json!({
                "setupPackage": {},
                "encryptedAggregateInputs": [],
                "topCount": 1,
                "scoreDomainMax": 200,
            });
            request[field_name] = field_value.clone();
            let error = run_encrypted_aggregate_top_k_evaluation(&request).expect_err(
                "accepted evaluator request should reject forbidden witness fields first",
            );

            assert_eq!(
                error.code,
                CanonicalErrorCode::InvalidFixture,
                "{field_name}: {}",
                error.message
            );
            assert!(
                error.message.contains(field_name),
                "{field_name}: {}",
                error.message
            );

            let mut sweep_request = json!({
                "topCounts": [1],
            });
            sweep_request[field_name] = field_value;
            let sweep_error = run_encrypted_aggregate_top_k_evaluation_sweep(&sweep_request)
                .expect_err(
                    "accepted evaluator sweep should reject forbidden witness fields first",
                );

            assert_eq!(
                sweep_error.code,
                CanonicalErrorCode::InvalidFixture,
                "{field_name}: {}",
                sweep_error.message
            );
            assert!(
                sweep_error.message.contains(field_name),
                "{field_name}: {}",
                sweep_error.message
            );
        }

        let nested_error = run_encrypted_aggregate_top_k_evaluation(&json!({
            "setupPackage": {},
            "encryptedAggregateInputs": [{
                "aggregateContribution": {
                    "proofWitness": {
                        "aggregateScore": [3, 2, 1],
                    },
                },
            }],
            "topCount": 1,
            "scoreDomainMax": 200,
        }))
        .expect_err("nested witness leakage should reject");

        assert_eq!(nested_error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            nested_error
                .message
                .contains("encryptedAggregateInputs.0.aggregateContribution.proofWitness"),
            "{}",
            nested_error.message
        );
    }

    #[test]
    fn encrypted_aggregate_top_count_sweep_parser_accepts_only_unique_supported_counts() {
        assert_eq!(
            validate_top_counts_against_option_count(
                read_top_count_values(&json!({ "topCounts": [1, 10, 20] }))
                    .expect("valid top-count sweep"),
                20,
            )
            .expect("valid top-count range"),
            vec![1, 10, 20]
        );

        for (case_name, request) in [
            ("missing", json!({})),
            ("empty", json!({ "topCounts": [] })),
            ("zero", json!({ "topCounts": [0] })),
            ("duplicate", json!({ "topCounts": [1, 1] })),
            ("fractional", json!({ "topCounts": [1.5] })),
            ("string", json!({ "topCounts": ["1"] })),
        ] {
            let error =
                read_top_count_values(&request).expect_err("invalid top-count sweep should reject");

            assert_eq!(
                error.code,
                CanonicalErrorCode::InvalidFixture,
                "{case_name}: {}",
                error.message
            );
            assert!(
                error.message.contains("topCounts"),
                "{case_name}: {}",
                error.message
            );
        }

        let range_error = validate_top_counts_against_option_count(
            read_top_count_values(&json!({ "topCounts": [21] }))
                .expect("syntactically valid top-count sweep"),
            20,
        )
        .expect_err("out-of-range top-count sweep should reject");
        assert_eq!(range_error.code, CanonicalErrorCode::InvalidFixture);
        assert!(range_error.message.contains("topCounts"));
    }

    #[test]
    fn accepted_evaluator_rejects_unknown_top_level_fields() {
        let error = run_encrypted_aggregate_top_k_evaluation(&json!({
            "setupPackage": {},
            "evaluationKeyMaterial": {},
            "aggregateReadyRecord": {},
            "encryptedAggregateInputs": [],
            "topCount": 1,
            "scoreDomainMax": 200,
            "unboundDebugArtifact": "not-on-accepted-path",
        }))
        .expect_err("unknown accepted evaluator fields must reject before evaluation");

        assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
        assert!(
            error.message.contains("unboundDebugArtifact"),
            "{}",
            error.message
        );
    }

    #[test]
    fn accepted_evaluator_requires_finality_bound_hashes() {
        let base_request = json!({
            "setupPackage": {},
            "evaluationKeyMaterial": {},
            "aggregateReadyRecord": {},
            "encryptedAggregateInputs": [],
            "topCount": 1,
            "scoreDomainMax": 200,
            "canonicalBallotSetHash": valid_hash("1"),
            "preTargetBoardHead": valid_hash("2"),
            "evaluatorSignature": valid_hash("3"),
        });

        for field_name in [
            "canonicalBallotSetHash",
            "preTargetBoardHead",
            "evaluatorSignature",
        ] {
            let mut missing = base_request.clone();
            missing
                .as_object_mut()
                .expect("request object")
                .remove(field_name);
            let missing_error = run_encrypted_aggregate_top_k_evaluation(&missing)
                .expect_err("accepted evaluator must require finality-bound fields");
            assert!(
                missing_error.message.contains(field_name),
                "{field_name}: {}",
                missing_error.message
            );

            let mut malformed = base_request.clone();
            malformed[field_name] = json!("ABC");
            let malformed_error = run_encrypted_aggregate_top_k_evaluation(&malformed)
                .expect_err("accepted evaluator must require canonical protocol hashes");
            assert!(
                malformed_error.message.contains(field_name),
                "{field_name}: {}",
                malformed_error.message
            );
        }
    }

    #[test]
    fn encrypted_aggregate_evaluator_rejects_proofless_aggregate_ready_inputs() {
        let request = json!({
            "setupPackage": {},
            "encryptedAggregateInputs": [
                { "bridgeEncryption": {} },
                { "bridgeEncryption": {} }
            ],
            "topCount": 1,
            "scoreDomainMax": 200,
            "canonicalBallotSetHash": valid_hash("1"),
            "preTargetBoardHead": valid_hash("2"),
            "evaluatorSignature": valid_hash("3"),
        });

        let error = run_encrypted_aggregate_top_k_evaluation(&request)
            .expect_err("aggregate-ready inputs without bridge proof should reject");

        assert!(
            error
                .message
                .contains("requires accepted aggregate contributions"),
            "{}",
            error.message
        );
    }

    #[test]
    fn encrypted_aggregate_evaluator_requires_accepted_inputs() {
        let request = json!({
            "setupPackage": {},
            "topCount": 1,
            "scoreDomainMax": 200,
        });

        let error = run_encrypted_aggregate_top_k_evaluation(&request)
            .expect_err("missing accepted encrypted aggregate inputs should reject");

        assert!(
            error
                .message
                .contains("requires accepted encrypted aggregate inputs"),
            "{}",
            error.message
        );
    }
}
