use serde_json::{Value, json};

use crate::{
    ballot_privacy::verify_aggregate_bridge_encryption_for_evaluator,
    bgv::{
        evaluator::{
            circuit::{EvaluatorContext, validate_evaluation_keys},
            engine::{Ciphertext, ciphertext_from_canonical_hex, ciphertext_object_root},
            reconstruction::{AggregateContributor, reconstruct_aggregate, score_from_histogram},
            records::{
                EvaluationComparisonProfile, EvaluationParameters, EvaluatorOutputRoots,
                RankPackingMethod, appendix_d_public_input_statement, describe_evaluator_program,
                evaluation_context_hash, evaluation_noise_certificate, output_encoding_hash,
                public_slot_mask_hash, target_proposal_hash, top_k_evaluation_record,
            },
            top_k::{
                evaluate_packed_ranks_from_packed_scores, evaluate_packed_ranks_via_difference,
                evaluate_top_k, evaluate_top_k_via_difference, pack_reconstructed_aggregate_scores,
                packed_score_slot, project_packed_sparse_target,
            },
        },
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        setup::verify_encrypted_aggregate_bridge_ciphertext_public_bindings,
        setup_helpers::{array_at_path, integer_at_path, string_at_path, value_at_path},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_protocol_hash,
    ring::{FIELD_MODULUS, derive_lagrange_coefficients_at_zero_for_roster_positions},
};

const DEFAULT_PLACEHOLDER_HASH_BYTE: &str = "00";
const DEFAULT_WORKING_LEVEL: usize = 10;

struct SetupBoundScoreCiphertexts {
    score_ciphertexts: Vec<Ciphertext>,
    ciphertext_roots: Vec<String>,
    encrypted_aggregate_share_ciphertext_roots: Vec<String>,
    bridge_inputs: Vec<Value>,
}

struct SetupBoundAggregateCiphertexts {
    aggregate_ciphertexts: Vec<Ciphertext>,
    ciphertext_roots: Vec<String>,
    encrypted_aggregate_share_ciphertext_roots: Vec<String>,
    selected_aggregate_contribution_hashes: Vec<String>,
    selected_contributor_roster_positions: Vec<u64>,
    bridge_inputs: Vec<Value>,
}

struct AggregateReadyEvaluationRecord {
    aggregate_ready_record_hash: String,
    encrypted_aggregate_bridge_hash: String,
    interpolation_coefficients: Vec<i64>,
    selected_aggregate_contribution_hashes: Vec<String>,
    selected_contributor_roster_positions: Vec<u64>,
    option_count: usize,
}

struct VerifiedAggregateBridgeInput {
    bridge_verification: Value,
    contributor_roster_position: u64,
    aggregate_contribution_hash: Option<String>,
}

fn read_string_or_default(request: &Value, field: &str) -> String {
    request.get(field).and_then(Value::as_str).map_or_else(
        || DEFAULT_PLACEHOLDER_HASH_BYTE.repeat(64),
        ToString::to_string,
    )
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
        canonical_ballot_set_hash: read_string_or_default(request, "canonicalBallotSetHash"),
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

fn read_setup_bound_score_ciphertexts(
    request: &Value,
    setup_package: &Value,
) -> CanonicalResult<SetupBoundScoreCiphertexts> {
    let inputs = array_at_path(request, &["encryptedAggregateScoreInputs"])?;
    if inputs.len() < 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encryptedAggregateScoreInputs must contain at least two bridge ciphertexts",
        ));
    }
    let mut score_ciphertexts = Vec::with_capacity(inputs.len());
    let mut ciphertext_roots = Vec::with_capacity(inputs.len());
    let mut encrypted_aggregate_share_ciphertext_roots = Vec::with_capacity(inputs.len());
    let mut bridge_inputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let bridge_encryption = value_at_path(input, &["bridgeEncryption"])?;
        let aggregate_derivation_component_hash =
            string_at_path(input, &["aggregateDerivationComponentHash"])?;
        let aggregate_derivation_statement_hash =
            string_at_path(input, &["aggregateDerivationStatementHash"])?;
        let post_voting_closed_context_hash =
            string_at_path(input, &["postVotingClosedContextHash"])?;
        verify_encrypted_aggregate_bridge_ciphertext_public_bindings(
            setup_package,
            aggregate_derivation_component_hash,
            aggregate_derivation_statement_hash,
            post_voting_closed_context_hash,
            bridge_encryption,
        )?;
        let ciphertext_root = string_at_path(bridge_encryption, &["ciphertextRoot"])?;
        let encrypted_aggregate_share_ciphertext_root = string_at_path(
            bridge_encryption,
            &["encryptedAggregateShareCiphertextRoot"],
        )?;
        let canonical_bytes_hex = string_at_path(bridge_encryption, &["canonicalBytesHex"])?;
        score_ciphertexts.push(ciphertext_from_canonical_hex(
            canonical_bytes_hex,
            Some(ciphertext_root),
        )?);
        ciphertext_roots.push(ciphertext_root.to_string());
        encrypted_aggregate_share_ciphertext_roots
            .push(encrypted_aggregate_share_ciphertext_root.to_string());
        bridge_inputs.push(input.clone());
    }

    Ok(SetupBoundScoreCiphertexts {
        score_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        bridge_inputs,
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
    let mut selected_contributor_roster_positions = Vec::with_capacity(inputs.len());
    let mut bridge_inputs = Vec::with_capacity(inputs.len());
    for input in inputs {
        let verified_input =
            verify_aggregate_bridge_input_for_evaluation(request, setup_package, input)?;
        let contributor_roster_position = verified_input.contributor_roster_position;
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
        selected_contributor_roster_positions.push(contributor_roster_position);
        bridge_inputs.push(input.clone());
    }

    Ok(SetupBoundAggregateCiphertexts {
        aggregate_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        selected_aggregate_contribution_hashes,
        selected_contributor_roster_positions,
        bridge_inputs,
    })
}

fn verify_aggregate_bridge_input_for_evaluation(
    request: &Value,
    setup_package: &Value,
    input: &Value,
) -> CanonicalResult<VerifiedAggregateBridgeInput> {
    if input.get("bridgeEvidenceVerification").is_some() {
        return verify_compact_aggregate_bridge_input_for_evaluation(setup_package, input);
    }
    let aggregate_derivation_component = value_at_path(input, &["aggregateDerivationComponent"])?;
    let bridge_encryption = value_at_path(input, &["bridgeEncryption"])?;
    let bridge_verification = verify_aggregate_bridge_encryption_for_evaluator(&json!({
        "aggregateDerivationComponent": aggregate_derivation_component,
        "setupPackage": setup_package,
        "bridgeEncryption": bridge_encryption,
        "aggregateSelectionPolicyHash": string_at_path(
            request,
            &["aggregateSelectionPolicyHash"],
        )?,
        "bridgeWitnessPrivacyProfileHash": string_at_path(
            request,
            &["bridgeWitnessPrivacyProfileHash"],
        )?,
        "heParamHash": string_at_path(request, &["heParamHash"])?,
    }))?;
    if string_at_path(&bridge_verification, &["bridgeProofVerificationStatus"])?
        != "BridgeProofRelationChecked"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires a checked aggregate bridge proof relation",
        ));
    }
    if bridge_verification
        .get("developmentKeyOnly")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation rejects development-only bridge key material",
        ));
    }
    if string_at_path(&bridge_verification, &["proverRandomnessSource"])? != "fresh-csprng"
        || string_at_path(&bridge_verification, &["encryptionRandomnessSeedSource"])?
            != "fresh-csprng"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires fresh bridge prover and encryption randomness",
        ));
    }
    if value_at_path(&bridge_verification, &["randomnessSourceEvidence"])?
        .get("claimBearingEntropyEvidence")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires bridge entropy evidence accepted for evaluation",
        ));
    }
    require_aggregate_derivation_full_verification_checked(
        &bridge_verification,
        &["aggregateDerivationVerificationScope"],
        "full aggregate-derivation verification bound to the bridge proof",
    )?;

    Ok(VerifiedAggregateBridgeInput {
        bridge_verification,
        contributor_roster_position: read_u64(
            value_at_path(input, &["aggregateDerivationComponent", "statement"])?,
            "contributorRosterPosition",
        )?,
        aggregate_contribution_hash: None,
    })
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
    require_false(
        bridge_verification,
        &["developmentKeyOnly"],
        "development-only bridge evidence",
    )?;
    if string_at_path(bridge_verification, &["proverRandomnessSource"])? != "fresh-csprng"
        || string_at_path(bridge_verification, &["encryptionRandomnessSeedSource"])?
            != "fresh-csprng"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires fresh bridge prover and encryption randomness",
        ));
    }
    if value_at_path(bridge_verification, &["randomnessSourceEvidence"])?
        .get("claimBearingEntropyEvidence")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate evaluation requires bridge entropy evidence accepted for evaluation",
        ));
    }
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
    require_false(
        bridge_proof_record,
        &["developmentKeyOnly"],
        "development-only bridge proof record",
    )?;
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
        &["postVotingClosedContextHash"],
        input,
        &["postVotingClosedContextHash"],
        "post-voting-closed context hash",
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
        contributor_roster_position: read_u64(aggregate_contribution, "contributorRosterPosition")?,
        aggregate_contribution_hash: Some(
            string_at_path(aggregate_contribution, &["aggregateContributionHash"])?.to_string(),
        ),
    })
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
    fallback_encrypted_aggregate_bridge_hash: &str,
) -> CanonicalResult<(String, String, &'static str)> {
    let Some(record) = request.get("aggregateReadyRecord") else {
        let aggregate_ready_record_hash = derive_protocol_hash(
            "AggregateReadyRecordHash",
            &json!({
                "objectType": "AggregateReadyRecord",
                "objectVersion": 1,
                "setupPackageHash": string_at_path(setup_package, &["setupPackageHash"])?,
                "encryptedAggregateBridgeHash": fallback_encrypted_aggregate_bridge_hash,
                "inputKind": "encrypted-aggregate-score-ciphertexts",
                "encryptedAggregateShareCiphertextRoots": encrypted_aggregate_share_ciphertext_roots,
                "fullBridgeProofClosurePending": true,
            }),
        )?;

        return Ok((
            aggregate_ready_record_hash,
            fallback_encrypted_aggregate_bridge_hash.to_string(),
            "public-bridge-bindings-only",
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
            &["topKEvaluatorInputLayoutHash"][..],
            &["profileBindings", "topKEvaluatorInputLayoutHash"][..],
            "top-k evaluator input layout hash",
        ),
    ] {
        if string_at_path(record, record_path)? != string_at_path(setup_package, setup_path)? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("aggregateReadyRecord {description} does not match the setup package"),
            ));
        }
    }
    let selected_roots = read_string_array(record, &["encryptedAggregateShareCiphertextRoots"])?;
    if selected_roots != encrypted_aggregate_share_ciphertext_roots {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected ciphertext roots do not match the evaluator bridge inputs",
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
    if !(2..=20).contains(&option_count) || share_vector_width != option_count * 11 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "aggregateReadyRecord option count and share vector width do not match the selected aggregate layout",
        ));
    }
    let quorum = read_usize_field(record, "aggregateContributionQuorum")?;
    let selected_roster_positions =
        read_u64_array(record, &["selectedContributorRosterPositions"])?;
    let selected_aggregate_contribution_hashes =
        read_string_array(record, &["selectedAggregateContributionHashes"])?;
    let selected_interpolation_points =
        read_u64_array(record, &["selectedContributorInterpolationPoints"])?;
    if selected_roster_positions != selected_interpolation_points
        || selected_roster_positions.len() != quorum
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected interpolation points do not match the selected roster positions",
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

    Ok(AggregateReadyEvaluationRecord {
        aggregate_ready_record_hash: expected_aggregate_ready_record_hash.to_string(),
        encrypted_aggregate_bridge_hash: expected_encrypted_aggregate_bridge_hash.to_string(),
        interpolation_coefficients: centered_coefficients,
        selected_aggregate_contribution_hashes,
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
    let SetupBoundAggregateCiphertexts {
        aggregate_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        selected_aggregate_contribution_hashes,
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
    if !selected_aggregate_contribution_hashes.is_empty()
        && aggregate_ready_record.selected_aggregate_contribution_hashes
            != selected_aggregate_contribution_hashes
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "aggregateReadyRecord selected contribution hashes do not match the verified bridge inputs",
        ));
    }

    let context = EvaluatorContext::from_passive_setup_package(setup_package, working_level)?;
    let option_count = aggregate_ready_record.option_count;
    let top_count = read_top_count(request, option_count)?;
    let score_domain_max = read_u64(request, "scoreDomainMax")?;
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
        &context,
        &reconstructed_aggregate,
        option_count,
        &aggregate_ready_record.aggregate_ready_record_hash,
    )?;
    let packed_ranks = evaluate_packed_ranks_from_packed_scores(
        &context,
        &packed_scores,
        option_count,
        score_domain_max,
        &aggregate_ready_record.aggregate_ready_record_hash,
    )?;
    let packed_target =
        project_packed_sparse_target(&context, &packed_ranks, option_count, top_count)?;
    let parameters = setup_bound_parameters(
        request,
        setup_package,
        option_count,
        top_count,
        score_domain_max,
        aggregate_ready_record.encrypted_aggregate_bridge_hash,
        aggregate_ready_record.aggregate_ready_record_hash,
    )?;
    let parameters = EvaluationParameters {
        rank_packing_method: RankPackingMethod::GeneratorOrdered,
        ..parameters
    };
    let output_roots = EvaluatorOutputRoots {
        encrypted_aggregate_reconstruction_root: ciphertext_object_root(&reconstructed_aggregate)?,
        encrypted_score_bit_input_root: ciphertext_object_root(&packed_scores)?,
        greater_than_root: ciphertext_object_root(&packed_ranks)?,
        equal_root: ciphertext_object_root(&packed_ranks)?,
        ahead_root: ciphertext_object_root(&packed_ranks)?,
        rank_root: ciphertext_object_root(&packed_ranks)?,
        target_id_root: ciphertext_object_root(&packed_target.target_id)?,
        target_order_root: ciphertext_object_root(&packed_target.target_order)?,
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
        "operation": "runEncryptedAggregateTopKEvaluation",
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "inputBindingStatus": input_binding_status,
        "evaluationContextHash": evaluation_context_hash(&parameters)?,
        "evaluationNoiseCertificate": certificate,
        "topKEvaluationRecord": record,
        "targetProposalHash": proposal,
        "appendixDPublicInputStatement": appendix_d,
        "statusLabels": [
            "EncryptedAggregateTopKEvaluationCompleted",
            "SetupBoundEvaluationKeysUsed",
            "AggregateReadyRecordVerified",
            "EncryptedAggregateReconstructionEvaluated",
            "GeneratorOrderedRankPackingUsed",
            "TopKEvaluationProposalGenerated",
            "NotAcceptedTarget",
            "EvaluationProofRequiredForAcceptance",
            "NotSupportedPhoneCertified"
        ],
    }))
}

pub(crate) fn run_encrypted_aggregate_top_k_evaluation(request: &Value) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let aggregate_ready_inputs_requested = request.get("encryptedAggregateInputs").is_some();
    let working_level = request
        .get("workingLevel")
        .and_then(Value::as_u64)
        .and_then(|level| usize::try_from(level).ok())
        .unwrap_or(if aggregate_ready_inputs_requested {
            DATA_PRIMES.len() - 1
        } else {
            DEFAULT_WORKING_LEVEL
        });
    if aggregate_ready_inputs_requested {
        return run_aggregate_ready_top_k_evaluation(request, setup_package, working_level);
    }
    let SetupBoundScoreCiphertexts {
        score_ciphertexts,
        ciphertext_roots,
        encrypted_aggregate_share_ciphertext_roots,
        bridge_inputs,
    } = read_setup_bound_score_ciphertexts(request, setup_package)?;
    let context = EvaluatorContext::from_passive_setup_package(setup_package, working_level)?;
    let option_count = score_ciphertexts.len();
    let top_count = read_top_count(request, option_count)?;
    let score_domain_max = read_u64(request, "scoreDomainMax")?;

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
            "bridgeProofStatus": "bridge-ciphertext-public-bindings-verified-proof-closure-pending",
        }),
    )?;
    let (aggregate_ready_record_hash, bound_encrypted_aggregate_bridge_hash, input_binding_status) =
        aggregate_ready_binding_from_request(
            request,
            setup_package,
            &encrypted_aggregate_share_ciphertext_roots,
            &encrypted_aggregate_bridge_hash,
        )?;
    let parameters = setup_bound_parameters(
        request,
        setup_package,
        option_count,
        top_count,
        score_domain_max,
        bound_encrypted_aggregate_bridge_hash,
        aggregate_ready_record_hash,
    )?;

    let outputs =
        evaluate_top_k_via_difference(&context, &score_ciphertexts, top_count, score_domain_max)?;
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
        "operation": "runEncryptedAggregateTopKEvaluation",
        "comparisonProfile": parameters.comparison_profile.profile_id(),
        "rankPackingMethod": parameters.rank_packing_method.profile_id(),
        "inputBindingStatus": input_binding_status,
        "evaluationContextHash": evaluation_context_hash(&parameters)?,
        "evaluationNoiseCertificate": certificate,
        "topKEvaluationRecord": record,
        "targetProposalHash": proposal,
        "appendixDPublicInputStatement": appendix_d,
        "statusLabels": [
            "EncryptedAggregateTopKEvaluationCompleted",
            "SetupBoundEvaluationKeysUsed",
            "AggregateBridgeCiphertextRootsBound",
            "TopKEvaluationProposalGenerated",
            "NotAcceptedTarget",
            "EvaluationProofRequiredForAcceptance",
            "NotSupportedPhoneCertified"
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_ready_binding_from_request, aggregate_ready_record_hash,
        run_encrypted_aggregate_top_k_evaluation,
    };
    use crate::{
        bgv::setup::{
            generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots,
            generate_passive_setup_package_from_request,
        },
        hashing::derive_protocol_hash,
    };
    use serde_json::{Value, json};

    fn setup_request() -> Value {
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
            "participants": [
                { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
                { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 4 },
                { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 5 }
            ],
            "setupSeed": "encrypted-aggregate-evaluator-test-seed",
        })
    }

    fn bridge_score_input(
        setup_package: &Value,
        contributor_identity: &str,
        score: u64,
        active_slot_count: usize,
    ) -> Value {
        let aggregate_derivation_component_hash = derive_protocol_hash(
            "AggregateDerivationComponentHash",
            &json!({
                "component": contributor_identity,
                "score": score,
            }),
        )
        .expect("component hash");
        let aggregate_derivation_statement_hash = derive_protocol_hash(
            "AggregateContributionHash",
            &json!({
                "statement": contributor_identity,
                "score": score,
            }),
        )
        .expect("statement hash");
        let post_voting_closed_context_hash = derive_protocol_hash(
            "PostVotingClosedContextHash",
            &json!({
                "context": "encrypted aggregate evaluator test",
                "contributor": contributor_identity,
            }),
        )
        .expect("context hash");
        let slots = vec![score; active_slot_count];
        let trace = generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots(
            setup_package,
            contributor_identity,
            &aggregate_derivation_component_hash,
            &aggregate_derivation_statement_hash,
            &post_voting_closed_context_hash,
            &slots,
            &format!("{score:032x}"),
            true,
        )
        .expect("bridge score ciphertext");

        json!({
            "aggregateDerivationComponentHash": aggregate_derivation_component_hash,
            "aggregateDerivationStatementHash": aggregate_derivation_statement_hash,
            "postVotingClosedContextHash": post_voting_closed_context_hash,
            "bridgeEncryption": trace.public_artifact,
        })
    }

    fn minimal_wrong_key_bridge_input(setup_package: &Value) -> Value {
        json!({
            "aggregateDerivationComponentHash": "11".repeat(64),
            "aggregateDerivationStatementHash": "22".repeat(64),
            "postVotingClosedContextHash": "33".repeat(64),
            "bridgeEncryption": {
                "profileHash": setup_package["profileBindings"]["profileHash"],
                "rustBgvBackendProfileHash": setup_package["profileBindings"]["backendProfileHash"],
                "canonicalCiphertextConventionHash": setup_package["profileBindings"]["canonicalCiphertextConventionHash"],
                "plaintextRoot": "44".repeat(64),
                "ciphertextRoot": "55".repeat(64),
                "collectivePublicKeyRoot": "66".repeat(64)
            },
        })
    }

    fn aggregate_ready_record(setup_package: &Value, selected_roots: &[String]) -> Value {
        let mut record = json!({
            "objectType": "AggregateReadyRecord",
            "objectVersion": 1,
            "setupPackageHash": setup_package["setupPackageHash"],
            "collectivePublicKeyRoot": setup_package["collectivePublicKey"]["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": setup_package["collectivePublicKey"]["collectivePublicKeyCoefficientRoot"],
            "manifestHash": setup_package["setupInputs"]["manifestHash"],
            "rosterHash": setup_package["setupInputs"]["rosterHash"],
            "topKEvaluatorInputLayoutHash": setup_package["profileBindings"]["topKEvaluatorInputLayoutHash"],
            "encryptedAggregateBridgeHash": valid_hash("7"),
            "encryptedAggregateShareCiphertextRoots": selected_roots,
        });
        record["aggregateReadyRecordHash"] =
            Value::String(aggregate_ready_record_hash(&record).expect("record hash"));

        record
    }

    fn valid_hash(fill: &str) -> String {
        fill.repeat(128)
    }

    #[test]
    fn aggregate_ready_binding_rejects_selected_ciphertext_root_drift() {
        let setup_package =
            generate_passive_setup_package_from_request(&setup_request()).expect("setup package");
        let selected_roots = vec![valid_hash("1"), valid_hash("2")];
        let record = aggregate_ready_record(&setup_package, &selected_roots);
        let request = json!({
            "aggregateReadyRecord": record,
        });
        let accepted = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &selected_roots,
            &valid_hash("3"),
        )
        .expect("aggregate-ready record should bind");
        assert_eq!(accepted.2, "aggregate-ready-record-verified");

        let wrong_roots = vec![valid_hash("1"), valid_hash("4")];
        let error = aggregate_ready_binding_from_request(
            &request,
            &setup_package,
            &wrong_roots,
            &valid_hash("3"),
        )
        .expect_err("root drift should reject");
        assert!(
            error
                .message
                .contains("selected ciphertext roots do not match"),
            "{}",
            error.message
        );
    }

    #[test]
    #[ignore = "setup-bound encrypted aggregate evaluator command generates full bridge ciphertexts and is a manual integration check"]
    fn encrypted_aggregate_evaluator_consumes_setup_bound_bridge_ciphertexts() {
        let setup_package =
            generate_passive_setup_package_from_request(&setup_request()).expect("setup package");
        let request = json!({
            "setupPackage": setup_package,
            "encryptedAggregateScoreInputs": [
                bridge_score_input(&setup_package, "trustee-1", 3, 4),
                bridge_score_input(&setup_package, "trustee-2", 7, 4)
            ],
            "topCount": 1,
            "scoreDomainMax": 10,
            "workingLevel": 6,
        });

        let output =
            run_encrypted_aggregate_top_k_evaluation(&request).expect("evaluation should run");

        assert_eq!(output["ok"], true);
        assert_eq!(output["operation"], "runEncryptedAggregateTopKEvaluation");
        assert_eq!(
            output["topKEvaluationRecord"]["comparisonProfile"],
            "direct-encrypted-score-comparison-v1"
        );
        assert_eq!(
            output["topKEvaluationRecord"]["bgvPublicKeyRoot"],
            setup_package["collectivePublicKey"]["bgvPublicKeyRoot"]
        );
        assert_eq!(
            output["topKEvaluationRecord"]["evaluationKeyRoot"],
            setup_package["evaluationKeys"]["evaluationKeyRoot"]
        );
        assert!(output.get("decodedTargetIdSlots").is_none());
        assert!(output.get("decodedRanks").is_none());
    }

    #[test]
    fn encrypted_aggregate_evaluator_rejects_proofless_aggregate_ready_inputs() {
        let setup_package =
            generate_passive_setup_package_from_request(&setup_request()).expect("setup package");
        let request = json!({
            "setupPackage": setup_package,
            "encryptedAggregateInputs": [
                minimal_wrong_key_bridge_input(&setup_package),
                minimal_wrong_key_bridge_input(&setup_package)
            ],
            "topCount": 1,
            "scoreDomainMax": 10,
        });

        let error = run_encrypted_aggregate_top_k_evaluation(&request)
            .expect_err("aggregate-ready inputs without bridge proof should reject");

        assert!(
            error.message.contains("aggregateDerivationComponent"),
            "{}",
            error.message
        );
    }

    #[test]
    fn encrypted_aggregate_evaluator_rejects_bridge_ciphertext_under_wrong_key_root() {
        let setup_package =
            generate_passive_setup_package_from_request(&setup_request()).expect("setup package");
        let bridge_input = minimal_wrong_key_bridge_input(&setup_package);
        let request = json!({
            "setupPackage": setup_package,
            "encryptedAggregateScoreInputs": [
                bridge_input,
                minimal_wrong_key_bridge_input(&setup_package)
            ],
            "topCount": 1,
            "scoreDomainMax": 10,
            "workingLevel": 6,
        });

        let error = run_encrypted_aggregate_top_k_evaluation(&request)
            .expect_err("wrong bridge key root should reject");

        assert!(
            error
                .message
                .contains("collective public key root does not match"),
            "{}",
            error.message
        );
    }
}
