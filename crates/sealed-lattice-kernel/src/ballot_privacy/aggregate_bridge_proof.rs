use serde_json::{Map, Value, json};

use crate::{
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, derive_protocol_digest, hash512, to_hex},
    transcript_core::decode_hex,
};

use super::protocol_constants::{
    BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION, BALLOT_PRIVACY_FIELD_MODULUS,
    BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT, BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT,
    BALLOT_PRIVACY_MINIMUM_OPTION_COUNT, BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT,
    BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT,
};
use super::{
    PolynomialVector, SHARE_COMMITMENT_MODULE_RANK, SHARE_COMMITMENT_OPENING_DIMENSION,
    check_aggregate_derivation_witness_relation, is_protocol_digest, required_json_field,
    required_string_field, sparse_matrix_from_sparse_component_statement, string_field,
    structural_refusal, structural_rejection,
    verify_aggregate_derivation_relation_subproof_for_component,
};

const BRIDGE_PROOF_PROFILE_ID: &str = "EncryptedAggregateBridge-v1";
const BRIDGE_PROOF_BACKEND: &str = "SealedLatticeBridgeRelation";
const BGV_ENCRYPTION_PROOF_SUBRELATION: &str = "SealedLatticeBoundedEncryptionRelation";
const BRIDGE_PROOF_PENDING_STATUS: &str = "BridgeProofBackendPending";
const SHARED_WITNESS_BINDING_PENDING_STATUS: &str = "SharedWitnessBindingProofPending";
const AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS: &str =
    "AggregateToPlaintextBindingProofPending";
const BGV_ENCRYPTION_PROOF_PENDING_STATUS: &str = "BoundedEncryptionProofPending";
const RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS: &str = "RnsCrtConsistencyProofPending";
const BRIDGE_PROOF_CHECKED_STATUS: &str = "BridgeProofRelationChecked";
const SHARED_WITNESS_BINDING_CHECKED_STATUS: &str = "SharedWitnessBindingProofChecked";
const AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS: &str =
    "AggregateToPlaintextBindingProofChecked";
const BGV_ENCRYPTION_PROOF_CHECKED_STATUS: &str = "BoundedEncryptionProofChecked";
const RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS: &str = "RnsCrtConsistencyProofChecked";
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537InverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForClaimBearingM9";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForM9Closure";
const PLAINTEXT_ROOT_PROOF_BINDING_CHECKED_STATUS: &str = "PlaintextRootProofBindingChecked";
const BRIDGE_SHARED_WITNESS_CHECK_COUNT: usize = 1;

pub(crate) fn generate_aggregate_bridge_encryption_from_command_request(request: &Value) -> Value {
    match generate_aggregate_bridge_encryption(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "generateAggregateBridgeEncryption",
            vec![structural_refusal(error.message, None)],
        ),
    }
}

pub(crate) fn verify_aggregate_bridge_encryption_from_command_request(request: &Value) -> Value {
    match verify_aggregate_bridge_encryption(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "verifyAggregateBridgeEncryption",
            vec![structural_refusal(error.message, None)],
        ),
    }
}

pub(crate) fn evaluate_aggregate_bridge_relation_from_command_request(request: &Value) -> Value {
    match evaluate_aggregate_bridge_relation(request) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "evaluateAggregateBridgeRelation",
            vec![structural_refusal(error.message, None)],
        ),
    }
}

fn generate_aggregate_bridge_encryption(request: &Value) -> CanonicalResult<Value> {
    let component = required_json_field(
        request,
        "aggregateDerivationComponent",
        "generateAggregateBridgeEncryption",
    )?;
    let setup_package =
        required_json_field(request, "setupPackage", "generateAggregateBridgeEncryption")?;
    let witness = required_json_field(
        request,
        "aggregateWitness",
        "generateAggregateBridgeEncryption",
    )?;
    let prover_randomness_hex = required_string_field(
        request,
        "proverRandomnessHex",
        "generateAggregateBridgeEncryption",
    )?;
    validate_hex_field(prover_randomness_hex, "proverRandomnessHex")?;
    let aggregate_selection_policy_digest = required_protocol_digest_field(
        request,
        "aggregateSelectionPolicyDigest",
        "generateAggregateBridgeEncryption",
    )?;
    let bridge_witness_privacy_profile_digest = required_protocol_digest_field(
        request,
        "bridgeWitnessPrivacyProfileDigest",
        "generateAggregateBridgeEncryption",
    )?;
    let he_param_digest = required_protocol_digest_field(
        request,
        "heParamDigest",
        "generateAggregateBridgeEncryption",
    )?;
    let include_canonical_bytes_hex = request
        .get("includeCanonicalBytesHex")
        .and_then(Value::as_bool)
        == Some(true);

    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let proof_input = required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let component_digest = required_string_field(
        component,
        "aggregateDerivationComponentDigest",
        "aggregateDerivationComponent",
    )?;
    let statement_digest = required_string_field(
        statement,
        "aggregateDerivationStatementDigest",
        "aggregateDerivationComponent.statement",
    )?;
    let contributor_identity = required_string_field(
        statement,
        "contributorIdentity",
        "aggregateDerivationComponent.statement",
    )?;
    let post_voting_closed_context_digest = required_string_field(
        statement,
        "postVotingClosedContextDigest",
        "aggregateDerivationComponent.statement",
    )?;
    let canonical_turnout = read_u64_object_field(
        statement,
        "canonicalTurnout",
        "aggregateDerivationComponent.statement",
    )?;
    let dimensions = bridge_variant_dimensions(statement)?;
    let aggregate_integer_share_vector =
        read_u64_array(witness, "aggregateIntegerShareVector", "aggregateWitness")?;
    let aggregate_opening_randomness =
        read_i64_array(witness, "aggregateOpeningRandomness", "aggregateWitness")?;
    if aggregate_integer_share_vector.len() != dimensions.share_vector_width {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge aggregate witness width does not match the accepted variant shareVectorWidth",
        ));
    }
    if string_field(proof_input, "statementDigest") != Some(statement_digest) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof input does not bind the accepted aggregate derivation statement",
        ));
    }

    let witness_relation_check = check_aggregate_derivation_witness_relation(
        proof_input,
        &aggregate_integer_share_vector,
        &aggregate_opening_randomness,
        canonical_turnout,
        prover_randomness_hex,
    )?;
    let trace = crate::bgv::commands::generate_m9_bridge_ciphertext_relation_trace_from_slots(
        setup_package,
        contributor_identity,
        component_digest,
        statement_digest,
        post_voting_closed_context_digest,
        &witness_relation_check.reduced_field_vector,
        prover_randomness_hex,
        include_canonical_bytes_hex,
    )?;
    let mut encryption = trace.public_artifact.clone();
    let bridge_proof_profile_digest = bridge_proof_profile_digest()?;
    let bridge_proof_statement = build_bridge_proof_statement(
        component,
        setup_package,
        &encryption,
        &bridge_proof_profile_digest,
        aggregate_selection_policy_digest,
        bridge_witness_privacy_profile_digest,
        he_param_digest,
    )?;
    let bridge_proof_statement_digest = bridge_proof_statement_digest(&bridge_proof_statement)?;
    let bridge_proof_target_contract_digest = required_string_field(
        &bridge_proof_statement,
        "bridgeProofTargetContractDigest",
        "bridgeProofStatement",
    )?;
    let shared_witness_proof =
        generate_bridge_shared_witness_proof(BridgeSharedWitnessProverInput {
            setup_package,
            bridge_encryption: &encryption,
            proof_input,
            bridge_proof_statement_digest: &bridge_proof_statement_digest,
            contributor_identity,
            aggregate_derivation_statement_digest: statement_digest,
            aggregate_integer_share_vector: &aggregate_integer_share_vector,
            aggregate_opening_randomness: &aggregate_opening_randomness,
            aggregate_reduced_coordinates: &witness_relation_check.reduced_field_vector,
            aggregate_quotient_vector: &witness_relation_check.quotient_vector,
            trace: &trace,
            prover_randomness_hex,
        })?;
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeRelationProof",
        "objectVersion": 1,
        "profileId": BRIDGE_PROOF_PROFILE_ID,
        "bridgeProofProfileDigest": bridge_proof_profile_digest,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "bridgeSharedWitnessProof": shared_witness_proof,
        "bridgeProofStatement": bridge_proof_statement,
        "bridgeProofStatementDigest": bridge_proof_statement_digest,
        "bridgeProofTargetContractDigest": bridge_proof_target_contract_digest,
        "aggregateDerivationComponentDigest": component_digest,
        "aggregateDerivationStatementDigest": statement_digest,
        "aggregateRelationSubproofHex": witness_relation_check.proof_hex,
        "aggregateRelationSubproofSizeBytes": witness_relation_check.proof_size_bytes,
        "aggregateRelationChallengeHex": witness_relation_check.challenge_hex,
        "aggregateRelationCommitmentDigest": witness_relation_check.relation_commitment_digest,
        "aggregateReducedCoordinateCount": witness_relation_check.reduced_field_vector.len(),
        "aggregateQuotientCoordinateCount": witness_relation_check.quotient_vector.len(),
        "plaintextRoot": encryption["plaintextRoot"],
        "ciphertextRoot": encryption["ciphertextRoot"],
        "encryptedAggregateShareCiphertextRoot": encryption["encryptedAggregateShareCiphertextRoot"],
        "collectivePublicKeyRoot": encryption["collectivePublicKeyRoot"],
        "bgvPublicKeyRoot": encryption["bgvPublicKeyRoot"],
        "postVotingClosedContextDigest": post_voting_closed_context_digest,
        "proverRandomnessPublicDigest": derive_protocol_digest(
            "ProofBytesDigest",
            &json!({
                "purpose": "m9-bridge-prover-randomness-public-digest-v1",
                "proverRandomnessHex": prover_randomness_hex,
            }),
        )?,
        "privateMaterialDisclosure": {
            "aggregateOpeningMaterialExported": false,
            "aggregateShareMaterialExported": false,
            "layoutMessageMaterialExported": false,
            "encodedMessageMaterialExported": false,
            "encryptionRandomizerMaterialExported": false,
            "noiseMaterialExported": false
        },
        "relationScope": "m9-scoped-bridge-relation",
        "singleContributionBridgeRelationChecked": true,
        "scopedBridgeRelationClosure": false,
        "finalBridgeTheoremClosure": false
    });
    let proof_json = canonical_json(&proof_value)?;
    let proof_bytes_hex = to_hex(proof_json.as_bytes());
    let proof_bytes_digest = derive_protocol_digest(
        "ProofBytesDigest",
        &json!({
            "purpose": "m9-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": proof_bytes_hex,
        }),
    )?;
    let proof_root = derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentDigest": component_digest,
            "aggregateDerivationStatementDigest": statement_digest,
            "bridgeProofProfileDigest": proof_value["bridgeProofProfileDigest"],
            "bridgeProofStatementDigest": proof_value["bridgeProofStatementDigest"],
            "proofBytesDigest": proof_bytes_digest,
            "encryptedAggregateShareCiphertextRoot": encryption["encryptedAggregateShareCiphertextRoot"],
            "collectivePublicKeyRoot": encryption["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": encryption["bgvPublicKeyRoot"],
        }),
    )?;

    let object = encryption.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge encryption result must be an object",
        )
    })?;
    object.insert(
        "aggregateDerivationComponentDigest".to_string(),
        Value::String(component_digest.to_string()),
    );
    object.insert(
        "aggregateDerivationStatementDigest".to_string(),
        Value::String(statement_digest.to_string()),
    );
    object.insert(
        "bridgeProofProfileDigest".to_string(),
        proof_value["bridgeProofProfileDigest"].clone(),
    );
    object.insert(
        "bridgeProofStatementDigest".to_string(),
        proof_value["bridgeProofStatementDigest"].clone(),
    );
    object.insert(
        "bridgeProofTargetContractDigest".to_string(),
        proof_value["bridgeProofTargetContractDigest"].clone(),
    );
    object.insert(
        "bridgeProofBytesHex".to_string(),
        Value::String(proof_bytes_hex),
    );
    object.insert(
        "bridgeProofBytesDigest".to_string(),
        Value::String(proof_bytes_digest),
    );
    object.insert("bridgeProofRoot".to_string(), Value::String(proof_root));
    object.insert(
        "aggregateRelationSubproofSizeBytes".to_string(),
        proof_value["aggregateRelationSubproofSizeBytes"].clone(),
    );
    object.insert(
        "aggregateRelationChallengeHex".to_string(),
        proof_value["aggregateRelationChallengeHex"].clone(),
    );
    object.insert(
        "aggregateRelationCommitmentDigest".to_string(),
        proof_value["aggregateRelationCommitmentDigest"].clone(),
    );
    object.insert(
        "aggregateReducedCoordinateCount".to_string(),
        proof_value["aggregateReducedCoordinateCount"].clone(),
    );
    object.insert(
        "aggregateQuotientCoordinateCount".to_string(),
        proof_value["aggregateQuotientCoordinateCount"].clone(),
    );
    object.insert(
        "bridgeProofVerificationStatus".to_string(),
        Value::String(BRIDGE_PROOF_CHECKED_STATUS.to_string()),
    );
    object.insert(
        "statusLabels".to_string(),
        json!([
            "M9BridgePlaintextAssembled",
            "M9BridgeCiphertextGenerated",
            "CollectivePublicKeyRootBound",
            "CoefficientDomainCanonical",
            "BridgeProofRelationChecked"
        ]),
    );

    Ok(encryption)
}

fn evaluate_aggregate_bridge_relation(request: &Value) -> CanonicalResult<Value> {
    let component = required_json_field(
        request,
        "aggregateDerivationComponent",
        "evaluateAggregateBridgeRelation",
    )?;
    let setup_package =
        required_json_field(request, "setupPackage", "evaluateAggregateBridgeRelation")?;
    let witness = required_json_field(
        request,
        "aggregateWitness",
        "evaluateAggregateBridgeRelation",
    )?;
    let bridge_encryption = required_json_field(
        request,
        "bridgeEncryption",
        "evaluateAggregateBridgeRelation",
    )?;
    validate_bridge_encryption_public_shell(bridge_encryption)?;
    required_string_field(bridge_encryption, "canonicalBytesHex", "bridgeEncryption")?;

    let prover_randomness_hex = required_string_field(
        request,
        "proverRandomnessHex",
        "evaluateAggregateBridgeRelation",
    )?;
    validate_hex_field(prover_randomness_hex, "proverRandomnessHex")?;
    let aggregate_selection_policy_digest = required_protocol_digest_field(
        request,
        "aggregateSelectionPolicyDigest",
        "evaluateAggregateBridgeRelation",
    )?;
    let bridge_witness_privacy_profile_digest = required_protocol_digest_field(
        request,
        "bridgeWitnessPrivacyProfileDigest",
        "evaluateAggregateBridgeRelation",
    )?;
    let he_param_digest = required_protocol_digest_field(
        request,
        "heParamDigest",
        "evaluateAggregateBridgeRelation",
    )?;

    reject_forbidden_public_bridge_fields(component, "aggregateDerivationComponent")?;
    reject_forbidden_public_bridge_fields(setup_package, "setupPackage")?;

    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let dimensions = bridge_variant_dimensions(statement)?;
    let aggregate_integer_share_vector =
        read_u64_array(witness, "aggregateIntegerShareVector", "aggregateWitness")?;
    let aggregate_opening_randomness =
        read_i64_array(witness, "aggregateOpeningRandomness", "aggregateWitness")?;
    if aggregate_integer_share_vector.len() != dimensions.share_vector_width {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge private evaluator aggregate witness width does not match the variant shareVectorWidth",
        ));
    }
    if aggregate_opening_randomness.len() != SHARE_COMMITMENT_OPENING_DIMENSION {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge private evaluator aggregate opening randomness width is invalid",
        ));
    }

    let expected_bridge_encryption = generate_aggregate_bridge_encryption(&json!({
        "aggregateDerivationComponent": component,
        "setupPackage": setup_package,
        "aggregateWitness": witness,
        "proverRandomnessHex": prover_randomness_hex,
        "aggregateSelectionPolicyDigest": aggregate_selection_policy_digest,
        "bridgeWitnessPrivacyProfileDigest": bridge_witness_privacy_profile_digest,
        "heParamDigest": he_param_digest,
        "includeCanonicalBytesHex": true,
    }))?;
    compare_bridge_relation_public_artifacts(
        bridge_encryption,
        &expected_bridge_encryption,
        "bridgeEncryption",
    )?;

    let public_verification = verify_aggregate_bridge_encryption(&json!({
        "aggregateDerivationComponent": component,
        "setupPackage": setup_package,
        "bridgeEncryption": bridge_encryption,
        "aggregateSelectionPolicyDigest": aggregate_selection_policy_digest,
        "bridgeWitnessPrivacyProfileDigest": bridge_witness_privacy_profile_digest,
        "heParamDigest": he_param_digest,
    }))?;
    let proof_bytes_hex =
        required_string_field(bridge_encryption, "bridgeProofBytesHex", "bridgeEncryption")?;
    let proof_byte_length = u64::try_from(proof_bytes_hex.len() / 2).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge proof byte length does not fit u64",
        )
    })?;
    let bridge_proof_statement_digest = required_string_field(
        bridge_encryption,
        "bridgeProofStatementDigest",
        "bridgeEncryption",
    )?;
    let bridge_proof_target_contract_digest = required_string_field(
        bridge_encryption,
        "bridgeProofTargetContractDigest",
        "bridgeEncryption",
    )?;
    let bridge_proof_root =
        required_string_field(bridge_encryption, "bridgeProofRoot", "bridgeEncryption")?;
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        bridge_encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?;
    let aggregate_reduced_coordinate_count = read_u64_object_field(
        bridge_encryption,
        "aggregateReducedCoordinateCount",
        "bridgeEncryption",
    )?;
    let aggregate_quotient_coordinate_count = read_u64_object_field(
        bridge_encryption,
        "aggregateQuotientCoordinateCount",
        "bridgeEncryption",
    )?;
    let bridge_relation_evaluation_digest = derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-private-bridge-relation-evaluation-v1",
            "participantCount": dimensions.participant_count,
            "optionCount": dimensions.option_count,
            "shareVectorWidth": dimensions.share_vector_width,
            "aggregateDerivationComponentDigest": required_string_field(
                component,
                "aggregateDerivationComponentDigest",
                "aggregateDerivationComponent",
            )?,
            "bridgeProofStatementDigest": bridge_proof_statement_digest,
            "bridgeProofTargetContractDigest": bridge_proof_target_contract_digest,
            "bridgeProofRoot": bridge_proof_root,
            "encryptedAggregateShareCiphertextRoot": encrypted_aggregate_share_ciphertext_root,
        }),
    )?;
    let public_verifier_checked_relation =
        public_verification["bridgeProofVerificationStatus"] == BRIDGE_PROOF_CHECKED_STATUS;
    let private_relation_status_labels = if public_verifier_checked_relation {
        vec![
            "AggregateBridgePrivateRelationSatisfied",
            "M9PrivateRelationEvaluator",
            "BridgeProofRelationChecked",
            "FinalBridgeTheoremPending",
        ]
    } else {
        vec![
            "AggregateBridgePrivateRelationSatisfied",
            "M9PrivateRelationEvaluator",
            "BridgeProofBackendStillRequired",
            "FinalBridgeTheoremPending",
        ]
    };

    Ok(json!({
        "ok": true,
        "operation": "evaluateAggregateBridgeRelation",
        "relationEvaluationStatus": "AggregateBridgePrivateRelationSatisfied",
        "bridgeProofVerificationStatus": public_verification["bridgeProofVerificationStatus"],
        "bridgeEvidenceVerificationStatus": public_verification["bridgeEvidenceVerificationStatus"],
        "publicArtifactWitnessCleanResult": true,
        "bridgeProofBackendStillRequired": !public_verifier_checked_relation,
        "scopedBridgeRelationClosure": false,
        "participantCount": dimensions.participant_count,
        "optionCount": dimensions.option_count,
        "claimTier": dimensions.claim_tier,
        "shareVectorWidth": dimensions.share_vector_width,
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "proofByteLength": proof_byte_length,
        "ciphertextShape": {
            "basisId": required_string_field(bridge_encryption, "basisId", "bridgeEncryption")?,
            "level": read_u64_object_field(bridge_encryption, "level", "bridgeEncryption")?,
            "coefficientCount": read_u64_object_field(
                bridge_encryption,
                "coefficientCount",
                "bridgeEncryption",
            )?,
            "slotCount": read_u64_object_field(bridge_encryption, "slotCount", "bridgeEncryption")?,
            "dataPrimeCount": DATA_PRIMES.len(),
            "ciphertextComponentCount": 2,
            "canonicalByteLength": read_u64_object_field(
                bridge_encryption,
                "canonicalByteLength",
                "bridgeEncryption",
            )?,
        },
        "acceptedDigests": [
            bridge_relation_evaluation_digest,
            bridge_proof_statement_digest,
            bridge_proof_target_contract_digest,
            bridge_proof_root,
            encrypted_aggregate_share_ciphertext_root,
        ],
        "statusLabels": private_relation_status_labels,
    }))
}

#[derive(Debug)]
struct BridgeVariantDimensions {
    participant_count: u64,
    option_count: u64,
    share_vector_width: usize,
    claim_tier: &'static str,
}

fn bridge_variant_dimensions(statement: &Value) -> CanonicalResult<BridgeVariantDimensions> {
    let participant_count = read_u64_object_field(
        statement,
        "participantCount",
        "aggregateDerivationStatement",
    )?;
    let option_count =
        read_u64_object_field(statement, "optionCount", "aggregateDerivationStatement")?;
    let share_vector_width = read_usize_object_field(
        statement,
        "shareVectorWidth",
        "aggregateDerivationStatement",
    )?;
    let maximum_m9_participant_count = u64::try_from(BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 maximum participant count does not fit u64",
            )
        })?;
    if participant_count < BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT as u64
        || participant_count > maximum_m9_participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge participantCount must be within the n=3..20 variant matrix",
        ));
    }
    if option_count < BALLOT_PRIVACY_MINIMUM_OPTION_COUNT as u64
        || option_count > BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge optionCount must be within the m=2..20 variant matrix",
        ));
    }
    let expected_share_vector_width = option_count
        .checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge shareVectorWidth calculation overflowed",
            )
        })?;
    if u64::try_from(share_vector_width).ok() != Some(expected_share_vector_width) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge shareVectorWidth must equal 11 * optionCount",
        ));
    }
    let claim_tier = if participant_count < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT as u64 {
        "micro-roster-outside-claim"
    } else {
        "claim-candidate"
    };

    Ok(BridgeVariantDimensions {
        participant_count,
        option_count,
        share_vector_width,
        claim_tier,
    })
}

fn compare_bridge_relation_public_artifacts(
    actual: &Value,
    expected: &Value,
    object_name: &str,
) -> CanonicalResult<()> {
    let actual_object = actual.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge {object_name} must be an object"),
        )
    })?;
    let expected_object = expected.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge expected relation artifact must be an object",
        )
    })?;
    for actual_field_name in actual_object.keys() {
        if !expected_object.contains_key(actual_field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge private evaluator public artifact has unexpected field {object_name}.{actual_field_name}"
                ),
            ));
        }
    }
    for (field_name, expected_value) in expected_object {
        let actual_value = actual_object.get(field_name).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("M9 bridge {object_name}.{field_name} is required"),
            )
        })?;
        if actual_value != expected_value {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge private evaluator public artifact field {object_name}.{field_name} does not match the recomputed shared-witness relation"
                ),
            ));
        }
    }

    Ok(())
}

struct BridgeSharedWitnessProverInput<'value> {
    setup_package: &'value Value,
    bridge_encryption: &'value Value,
    proof_input: &'value Value,
    bridge_proof_statement_digest: &'value str,
    contributor_identity: &'value str,
    aggregate_derivation_statement_digest: &'value str,
    aggregate_integer_share_vector: &'value [u64],
    aggregate_opening_randomness: &'value [i64],
    aggregate_reduced_coordinates: &'value [u64],
    aggregate_quotient_vector: &'value [u64],
    trace: &'value crate::bgv::commands::M9BridgeCiphertextRelationTrace,
    prover_randomness_hex: &'value str,
}

struct BridgeSharedWitnessProofVerification {
    challenge_hex: String,
    shared_response_scalar_count: u64,
}

fn generate_bridge_shared_witness_proof(
    input: BridgeSharedWitnessProverInput<'_>,
) -> CanonicalResult<Value> {
    let aggregate_integer_witness = u64_slice_to_i128_vec(input.aggregate_integer_share_vector);
    let aggregate_opening_witness = i64_slice_to_i128_vec(input.aggregate_opening_randomness);
    let aggregate_reduced_witness = u64_slice_to_i128_vec(input.aggregate_reduced_coordinates);
    let aggregate_quotient_witness = u64_slice_to_i128_vec(input.aggregate_quotient_vector);
    let plaintext_coefficient_witness =
        u64_slice_to_i128_vec(&input.trace.plaintext_coefficients_mod_plaintext);
    let randomizer_witness = i64_slice_to_i128_vec(&input.trace.encryption_randomness_coefficients);
    let perturbation_zero_witness =
        i64_slice_to_i128_vec(&input.trace.encryption_error_zero_coefficients);
    let perturbation_one_witness =
        i64_slice_to_i128_vec(&input.trace.encryption_error_one_coefficients);
    let mut checks = Vec::with_capacity(BRIDGE_SHARED_WITNESS_CHECK_COUNT);
    let mut challenge_hex = String::new();

    for check_index in 0..BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        let aggregate_integer_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-share",
            aggregate_integer_witness.len(),
        );
        let aggregate_opening_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-opening",
            aggregate_opening_witness.len(),
        );
        let aggregate_reduced_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-reduced",
            aggregate_reduced_witness.len(),
        );
        let aggregate_quotient_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "aggregate-quotient",
            aggregate_quotient_witness.len(),
        );
        let plaintext_coefficient_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "batch-coefficient",
            plaintext_coefficient_witness.len(),
        );
        let randomizer_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "cipher-randomizer",
            randomizer_witness.len(),
        );
        let perturbation_zero_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "bounded-perturbation-zero",
            perturbation_zero_witness.len(),
        );
        let perturbation_one_mask = sample_bridge_mask_vector(
            input.bridge_proof_statement_digest,
            input.prover_randomness_hex,
            check_index,
            "bounded-perturbation-one",
            perturbation_one_witness.len(),
        );
        let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
            input.proof_input,
            &aggregate_integer_mask,
            &aggregate_opening_mask,
            &aggregate_reduced_mask,
            &aggregate_quotient_mask,
            0,
        )?;
        let batch_commitment_digest =
            crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                &aggregate_reduced_mask,
                &plaintext_coefficient_mask,
            )?;
        let bgv_commitment_digest =
            crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                input.setup_package,
                input.contributor_identity,
                input.aggregate_derivation_statement_digest,
                input.bridge_encryption,
                0,
                &plaintext_coefficient_mask,
                &randomizer_mask,
                &perturbation_zero_mask,
                &perturbation_one_mask,
            )?;
        let challenge_scalar = bridge_shared_witness_challenge_scalar(
            input.bridge_proof_statement_digest,
            check_index,
            &aggregate_commitment_digest,
            &batch_commitment_digest,
            &bgv_commitment_digest,
        );
        let check_challenge_hex = bridge_challenge_hex(challenge_scalar);
        challenge_hex.push_str(&check_challenge_hex);

        checks.push(json!({
            "checkIndex": check_index,
            "challengeScalarHex": check_challenge_hex,
            "aggregateRelationCommitmentDigest": aggregate_commitment_digest,
            "batchEncodingCommitmentDigest": batch_commitment_digest,
            "bgvCiphertextCommitmentDigest": bgv_commitment_digest,
            "aggregateShareResponseHex": i128_vector_hex(&response_vector(
                &aggregate_integer_mask,
                challenge_scalar,
                &aggregate_integer_witness,
            )?),
            "aggregateOpeningResponseHex": i128_vector_hex(&response_vector(
                &aggregate_opening_mask,
                challenge_scalar,
                &aggregate_opening_witness,
            )?),
            "aggregateReducedResponseHex": i128_vector_hex(&response_vector(
                &aggregate_reduced_mask,
                challenge_scalar,
                &aggregate_reduced_witness,
            )?),
            "aggregateQuotientResponseHex": i128_vector_hex(&response_vector(
                &aggregate_quotient_mask,
                challenge_scalar,
                &aggregate_quotient_witness,
            )?),
            "batchCoefficientResponseHex": i128_vector_hex(&response_vector(
                &plaintext_coefficient_mask,
                challenge_scalar,
                &plaintext_coefficient_witness,
            )?),
            "cipherRandomizerResponseHex": i128_vector_hex(&response_vector(
                &randomizer_mask,
                challenge_scalar,
                &randomizer_witness,
            )?),
            "boundedPerturbationZeroResponseHex": i128_vector_hex(&response_vector(
                &perturbation_zero_mask,
                challenge_scalar,
                &perturbation_zero_witness,
            )?),
            "boundedPerturbationOneResponseHex": i128_vector_hex(&response_vector(
                &perturbation_one_mask,
                challenge_scalar,
                &perturbation_one_witness,
            )?),
        }));
    }

    let shared_response_scalar_count = shared_response_scalar_count(
        aggregate_integer_witness.len(),
        aggregate_opening_witness.len(),
        aggregate_reduced_witness.len(),
        aggregate_quotient_witness.len(),
    )?;

    Ok(json!({
        "objectType": "AggregateBridgeSharedWitnessProof",
        "objectVersion": 1,
        "proofModel": "fiat-shamir-linear-shared-response-v1",
        "bridgeProofStatementDigest": input.bridge_proof_statement_digest,
        "relationCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT,
        "challengeHex": challenge_hex,
        "sharedResponseScalarCount": shared_response_scalar_count,
        "sameHiddenAggregateCoordinatesLinked": true,
        "checks": checks,
        "responseEncoding": "signed-i128-little-endian-hex-v1",
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_bridge_shared_witness_proof(
    proof_value: &Value,
    component: &Value,
    setup_package: &Value,
    bridge_encryption: &Value,
    bridge_proof_statement_digest: &str,
    contributor_identity: &str,
    aggregate_derivation_statement_digest: &str,
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<BridgeSharedWitnessProofVerification> {
    let proof_input = required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let shared_proof = required_json_field(proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
    reject_forbidden_public_bridge_fields(shared_proof, "bridgeProof.bridgeSharedWitnessProof")?;
    if string_field(shared_proof, "objectType") != Some("AggregateBridgeSharedWitnessProof")
        || read_u64_object_field(shared_proof, "objectVersion", "bridgeSharedWitnessProof")? != 1
        || string_field(shared_proof, "proofModel") != Some("fiat-shamir-linear-shared-response-v1")
        || string_field(shared_proof, "responseEncoding")
            != Some("signed-i128-little-endian-hex-v1")
        || shared_proof
            .get("sameHiddenAggregateCoordinatesLinked")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge shared-witness proof shell is not the supported verifier relation",
        ));
    }
    require_equal_string(
        shared_proof,
        "bridgeProofStatementDigest",
        bridge_proof_statement_digest,
        "shared-witness proof statement digest",
    )?;
    let relation_check_count = read_usize_object_field(
        shared_proof,
        "relationCheckCount",
        "bridgeSharedWitnessProof",
    )?;
    if relation_check_count != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof has an unsupported check count",
        ));
    }
    let expected_aggregate_count =
        usize::try_from(aggregate_reduced_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate reduced coordinate count does not fit usize",
            )
        })?;
    let expected_quotient_count =
        usize::try_from(aggregate_quotient_coordinate_count).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate quotient coordinate count does not fit usize",
            )
        })?;
    let expected_shared_response_scalar_count = shared_response_scalar_count(
        expected_aggregate_count,
        SHARE_COMMITMENT_OPENING_DIMENSION,
        expected_aggregate_count,
        expected_quotient_count,
    )?;
    require_equal_u64(
        shared_proof,
        "sharedResponseScalarCount",
        expected_shared_response_scalar_count,
        "shared-witness proof scalar count",
    )?;
    let checks = shared_proof
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bridgeSharedWitnessProof.checks must be an array",
            )
        })?;
    if checks.len() != BRIDGE_SHARED_WITNESS_CHECK_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof check array has the wrong length",
        ));
    }
    let mut challenge_hex = String::new();
    for (check_index, check) in checks.iter().enumerate() {
        require_equal_u64(
            check,
            "checkIndex",
            check_index as u64,
            "shared-witness proof check index",
        )?;
        let challenge_scalar_hex = required_string_field(
            check,
            "challengeScalarHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let challenge_scalar = parse_bridge_challenge_scalar(challenge_scalar_hex)?;
        let aggregate_share_response = read_i128_hex_vector(
            check,
            "aggregateShareResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_opening_response = read_i128_hex_vector(
            check,
            "aggregateOpeningResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_reduced_response = read_i128_hex_vector(
            check,
            "aggregateReducedResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let aggregate_quotient_response = read_i128_hex_vector(
            check,
            "aggregateQuotientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let batch_coefficient_response = read_i128_hex_vector(
            check,
            "batchCoefficientResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let cipher_randomizer_response = read_i128_hex_vector(
            check,
            "cipherRandomizerResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_zero_response = read_i128_hex_vector(
            check,
            "boundedPerturbationZeroResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        let bounded_perturbation_one_response = read_i128_hex_vector(
            check,
            "boundedPerturbationOneResponseHex",
            "bridgeSharedWitnessProof.check",
        )?;
        validate_response_lengths(
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            &batch_coefficient_response,
            &cipher_randomizer_response,
            &bounded_perturbation_zero_response,
            &bounded_perturbation_one_response,
            expected_aggregate_count,
            expected_quotient_count,
        )?;
        let aggregate_commitment_digest = aggregate_relation_commitment_digest_from_responses(
            proof_input,
            &aggregate_share_response,
            &aggregate_opening_response,
            &aggregate_reduced_response,
            &aggregate_quotient_response,
            challenge_scalar,
        )?;
        let batch_commitment_digest =
            crate::bgv::commands::m9_bridge_batch_encoding_commitment_digest_from_responses(
                &aggregate_reduced_response,
                &batch_coefficient_response,
            )?;
        let bgv_commitment_digest =
            crate::bgv::commands::m9_bridge_ciphertext_commitment_digest_from_responses(
                setup_package,
                contributor_identity,
                aggregate_derivation_statement_digest,
                bridge_encryption,
                challenge_scalar,
                &batch_coefficient_response,
                &cipher_randomizer_response,
                &bounded_perturbation_zero_response,
                &bounded_perturbation_one_response,
            )?;
        require_equal_string(
            check,
            "aggregateRelationCommitmentDigest",
            &aggregate_commitment_digest,
            "shared-witness aggregate relation commitment digest",
        )?;
        require_equal_string(
            check,
            "batchEncodingCommitmentDigest",
            &batch_commitment_digest,
            "shared-witness batch encoding commitment digest",
        )?;
        require_equal_string(
            check,
            "bgvCiphertextCommitmentDigest",
            &bgv_commitment_digest,
            "shared-witness BGV ciphertext commitment digest",
        )?;
        let recomputed_challenge_scalar = bridge_shared_witness_challenge_scalar(
            bridge_proof_statement_digest,
            check_index,
            &aggregate_commitment_digest,
            &batch_commitment_digest,
            &bgv_commitment_digest,
        );
        if challenge_scalar != recomputed_challenge_scalar {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge shared-witness proof challenge does not match the Fiat-Shamir transcript",
            ));
        }
        challenge_hex.push_str(challenge_scalar_hex);
    }
    require_equal_string(
        shared_proof,
        "challengeHex",
        &challenge_hex,
        "shared-witness proof challenge transcript",
    )?;

    Ok(BridgeSharedWitnessProofVerification {
        challenge_hex,
        shared_response_scalar_count: expected_shared_response_scalar_count,
    })
}

fn aggregate_relation_commitment_digest_from_responses(
    proof_input: &Value,
    aggregate_share_response: &[i128],
    aggregate_opening_response: &[i128],
    aggregate_reduced_response: &[i128],
    aggregate_quotient_response: &[i128],
    challenge_scalar: u64,
) -> CanonicalResult<String> {
    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parsed_statement = sparse_matrix_from_sparse_component_statement(proof_statement)
        .map_err(|error| CanonicalError::new(CanonicalErrorCode::InvalidFixture, error.message))?;
    let ring = parsed_statement.source_statement_matrix.ring();
    let response_entries = aggregate_share_response
        .iter()
        .chain(aggregate_opening_response.iter())
        .chain(aggregate_reduced_response.iter())
        .chain(aggregate_quotient_response.iter())
        .map(|response| constant_response_polynomial(*response, ring.degree(), ring.modulus()))
        .collect::<Vec<_>>();
    let response_vector = PolynomialVector::new(ring, response_entries)?;
    let response_image = parsed_statement
        .source_statement_matrix
        .multiply_vector(&response_vector)?;
    let target_vector = PolynomialVector::new(ring, parsed_statement.target_vector_coefficients)?;
    let challenge_residue =
        u64::try_from(u128::from(challenge_scalar) % u128::from(ring.modulus())).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge challenge residue does not fit u64",
            )
        })?;
    let scaled_target_entries = target_vector
        .entries()
        .iter()
        .map(|entry| ring.scale(challenge_residue, entry))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let scaled_target = PolynomialVector::new(ring, scaled_target_entries)?;
    let commitment_vector = response_image.add(&scaled_target)?;

    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-aggregate-relation-commitment-v1",
            "commitmentVector": canonical_polynomial_vector_response(commitment_vector.entries()),
        }),
    )
}

fn sample_bridge_mask_vector(
    statement_digest: &str,
    prover_randomness_hex: &str,
    check_index: usize,
    role: &str,
    length: usize,
) -> Vec<i128> {
    let check_index_bytes = (check_index as u64).to_le_bytes();
    (0..length)
        .map(|coordinate_index| {
            let coordinate_index_bytes = (coordinate_index as u64).to_le_bytes();
            let digest = hash512(
                "sealed-lattice-root/m9-bridge-shared-witness-mask-v1",
                &[
                    statement_digest.as_bytes(),
                    prover_randomness_hex.as_bytes(),
                    role.as_bytes(),
                    &check_index_bytes,
                    &coordinate_index_bytes,
                ],
            );
            let mut magnitude_bytes = [0_u8; 16];
            magnitude_bytes[..14].copy_from_slice(&digest[..14]);
            let magnitude = i128::from_le_bytes(magnitude_bytes);
            if digest[14] & 1 == 0 {
                magnitude
            } else {
                -magnitude
            }
        })
        .collect()
}

fn bridge_shared_witness_challenge_scalar(
    statement_digest: &str,
    check_index: usize,
    aggregate_commitment_digest: &str,
    batch_commitment_digest: &str,
    bgv_commitment_digest: &str,
) -> u64 {
    let check_index_bytes = (check_index as u64).to_le_bytes();
    let digest = hash512(
        "sealed-lattice-root/m9-bridge-shared-witness-challenge-v1",
        &[
            statement_digest.as_bytes(),
            &check_index_bytes,
            aggregate_commitment_digest.as_bytes(),
            batch_commitment_digest.as_bytes(),
            bgv_commitment_digest.as_bytes(),
        ],
    );
    for chunk in digest.chunks_exact(8) {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(chunk);
        let challenge = u64::from_le_bytes(bytes);
        if challenge != 0 {
            return challenge;
        }
    }

    1
}

fn bridge_challenge_hex(challenge_scalar: u64) -> String {
    format!("{challenge_scalar:016x}")
}

fn parse_bridge_challenge_scalar(challenge_scalar_hex: &str) -> CanonicalResult<u64> {
    if challenge_scalar_hex.len() != 16
        || !challenge_scalar_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar must be 16 lowercase hex characters",
        ));
    }
    let challenge = u64::from_str_radix(challenge_scalar_hex, 16).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            "M9 bridge shared-witness challenge scalar is malformed",
        )
    })?;
    if challenge == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge shared-witness challenge scalar must be non-zero",
        ));
    }

    Ok(challenge)
}

fn response_vector(
    masks: &[i128],
    challenge_scalar: u64,
    witness: &[i128],
) -> CanonicalResult<Vec<i128>> {
    if masks.len() != witness.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge proof mask and witness dimensions do not match",
        ));
    }
    let challenge = i128::from(challenge_scalar);
    masks
        .iter()
        .zip(witness.iter())
        .map(|(mask, witness_value)| {
            let scaled_witness = challenge.checked_mul(*witness_value).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof response multiplication overflowed i128",
                )
            })?;
            mask.checked_add(scaled_witness).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "M9 bridge proof response addition overflowed i128",
                )
            })
        })
        .collect()
}

fn constant_response_polynomial(value: i128, degree: usize, modulus: u64) -> Vec<u64> {
    let mut polynomial = vec![0_u64; degree];
    polynomial[0] = signed_i128_to_modulus_residue(value, modulus);

    polynomial
}

fn signed_i128_to_modulus_residue(value: i128, modulus: u64) -> u64 {
    let residue = value.rem_euclid(i128::from(modulus));

    u64::try_from(residue).expect("non-negative i128 residue below a u64 modulus fits u64")
}

fn i128_vector_hex(values: &[i128]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 16);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    to_hex(&bytes)
}

fn read_i128_hex_vector(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<Vec<i128>> {
    let encoded = required_string_field(value, field_name, object_name)?;
    let bytes = decode_hex(encoded)?;
    if bytes.len() % 16 != 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_name}.{field_name} must encode whole i128 values"),
        ));
    }

    Ok(bytes
        .chunks_exact(16)
        .map(|chunk| {
            let mut value_bytes = [0_u8; 16];
            value_bytes.copy_from_slice(chunk);
            i128::from_le_bytes(value_bytes)
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn validate_response_lengths(
    aggregate_share_response: &[i128],
    aggregate_opening_response: &[i128],
    aggregate_reduced_response: &[i128],
    aggregate_quotient_response: &[i128],
    batch_coefficient_response: &[i128],
    cipher_randomizer_response: &[i128],
    bounded_perturbation_zero_response: &[i128],
    bounded_perturbation_one_response: &[i128],
    expected_aggregate_count: usize,
    expected_quotient_count: usize,
) -> CanonicalResult<()> {
    if aggregate_share_response.len() != expected_aggregate_count
        || aggregate_opening_response.len() != SHARE_COMMITMENT_OPENING_DIMENSION
        || aggregate_reduced_response.len() != expected_aggregate_count
        || aggregate_quotient_response.len() != expected_quotient_count
        || batch_coefficient_response.len() != POLYNOMIAL_DEGREE
        || cipher_randomizer_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_zero_response.len() != POLYNOMIAL_DEGREE
        || bounded_perturbation_one_response.len() != POLYNOMIAL_DEGREE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared-witness proof response dimensions do not match the public statement",
        ));
    }

    Ok(())
}

fn shared_response_scalar_count(
    aggregate_share_count: usize,
    aggregate_opening_count: usize,
    aggregate_reduced_count: usize,
    aggregate_quotient_count: usize,
) -> CanonicalResult<u64> {
    let total = aggregate_share_count
        .checked_add(aggregate_opening_count)
        .and_then(|value| value.checked_add(aggregate_reduced_count))
        .and_then(|value| value.checked_add(aggregate_quotient_count))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .and_then(|value| value.checked_add(POLYNOMIAL_DEGREE))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge shared response scalar count overflowed",
            )
        })?;

    u64::try_from(total).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge shared response scalar count does not fit u64",
        )
    })
}

fn u64_slice_to_i128_vec(values: &[u64]) -> Vec<i128> {
    values.iter().map(|value| i128::from(*value)).collect()
}

fn i64_slice_to_i128_vec(values: &[i64]) -> Vec<i128> {
    values.iter().map(|value| i128::from(*value)).collect()
}

fn canonical_polynomial_vector_response(entries: &[Vec<u64>]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|entry| {
                Value::Array(
                    entry
                        .iter()
                        .map(|coefficient| Value::String(coefficient.to_string()))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn verify_aggregate_bridge_encryption(request: &Value) -> CanonicalResult<Value> {
    let component = required_json_field(
        request,
        "aggregateDerivationComponent",
        "verifyAggregateBridgeEncryption",
    )?;
    let setup_package =
        required_json_field(request, "setupPackage", "verifyAggregateBridgeEncryption")?;
    let bridge_encryption = required_json_field(
        request,
        "bridgeEncryption",
        "verifyAggregateBridgeEncryption",
    )?;
    validate_bridge_encryption_public_shell(bridge_encryption)?;
    let aggregate_selection_policy_digest = required_protocol_digest_field(
        request,
        "aggregateSelectionPolicyDigest",
        "verifyAggregateBridgeEncryption",
    )?;
    let bridge_witness_privacy_profile_digest = required_protocol_digest_field(
        request,
        "bridgeWitnessPrivacyProfileDigest",
        "verifyAggregateBridgeEncryption",
    )?;
    let he_param_digest = required_protocol_digest_field(
        request,
        "heParamDigest",
        "verifyAggregateBridgeEncryption",
    )?;
    let bridge_proof_bytes_hex =
        required_string_field(bridge_encryption, "bridgeProofBytesHex", "bridgeEncryption")?;
    let canonical_bytes_hex =
        required_string_field(bridge_encryption, "canonicalBytesHex", "bridgeEncryption")?;
    let proof_value = parse_bridge_proof_value(bridge_proof_bytes_hex)?;
    validate_bridge_proof_public_shell(&proof_value)?;
    let component_digest = required_string_field(
        component,
        "aggregateDerivationComponentDigest",
        "aggregateDerivationComponent",
    )?;
    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let statement_digest = required_string_field(
        statement,
        "aggregateDerivationStatementDigest",
        "aggregateDerivationComponent.statement",
    )?;
    let contributor_identity = required_string_field(
        statement,
        "contributorIdentity",
        "aggregateDerivationComponent.statement",
    )?;
    let post_voting_closed_context_digest = required_string_field(
        statement,
        "postVotingClosedContextDigest",
        "aggregateDerivationComponent.statement",
    )?;
    crate::bgv::commands::verify_bgv_passive_setup_from_request(&json!({
        "setupPackage": setup_package,
    }))?;
    let setup_collective_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        "setupPackage",
    )?;
    let setup_bgv_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        "setupPackage",
    )?;
    let ciphertext_validation =
        crate::bgv::commands::validate_bgv_ciphertext_from_request(&json!({
            "canonicalBytesHex": canonical_bytes_hex,
            "expectedCiphertextRoot": string_field(bridge_encryption, "ciphertextRoot"),
        }))?;
    if ciphertext_validation["ok"] != true {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge ciphertext canonical validation failed",
        ));
    }
    let canonical_bytes_hash = required_string_field(
        &ciphertext_validation,
        "canonicalBytesHash512",
        "ciphertextValidation",
    )?;
    if !is_protocol_digest(canonical_bytes_hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge canonical ciphertext bytes hash must be a nonzero lowercase 512-bit hash",
        ));
    }
    require_equal_string(
        bridge_encryption,
        "canonicalBytesHash512",
        canonical_bytes_hash,
        "canonical ciphertext bytes hash",
    )?;
    let canonical_byte_length = u64::try_from(canonical_bytes_hex.len() / 2).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge canonical ciphertext byte length does not fit u64",
        )
    })?;
    require_equal_u64(
        bridge_encryption,
        "canonicalByteLength",
        canonical_byte_length,
        "canonical ciphertext byte length",
    )?;
    crate::bgv::commands::verify_m9_bridge_ciphertext_public_bindings(
        setup_package,
        component_digest,
        statement_digest,
        post_voting_closed_context_digest,
        bridge_encryption,
    )?;
    let aggregate_relation_subproof_hex =
        required_string_field(&proof_value, "aggregateRelationSubproofHex", "bridgeProof")?;
    let aggregate_relation_verification =
        verify_aggregate_derivation_relation_subproof_for_component(
            component,
            aggregate_relation_subproof_hex,
        )?;
    let bridge_proof_profile_digest = bridge_proof_profile_digest()?;
    let bridge_proof_statement = build_bridge_proof_statement(
        component,
        setup_package,
        bridge_encryption,
        &bridge_proof_profile_digest,
        aggregate_selection_policy_digest,
        bridge_witness_privacy_profile_digest,
        he_param_digest,
    )?;
    let bridge_proof_statement_digest = bridge_proof_statement_digest(&bridge_proof_statement)?;
    let bridge_proof_target_contract_digest = required_string_field(
        &bridge_proof_statement,
        "bridgeProofTargetContractDigest",
        "bridgeProofStatement",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofProfileDigest",
        &bridge_proof_profile_digest,
        "bridge proof profile digest",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofStatementDigest",
        &bridge_proof_statement_digest,
        "bridge proof statement digest",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofTargetContractDigest",
        bridge_proof_target_contract_digest,
        "bridge proof target contract digest",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofProfileDigest",
        &bridge_proof_profile_digest,
        "bridge proof profile digest",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofStatementDigest",
        &bridge_proof_statement_digest,
        "bridge proof statement digest",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofTargetContractDigest",
        bridge_proof_target_contract_digest,
        "bridge proof target contract digest",
    )?;
    let proof_statement_value =
        required_json_field(&proof_value, "bridgeProofStatement", "bridgeProof")?;
    if proof_statement_value != &bridge_proof_statement {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof statement does not match its canonical public inputs",
        ));
    }
    let relation_requirements = required_json_field(
        &bridge_proof_statement,
        "relationRequirements",
        "bridgeProofStatement",
    )?;
    let aggregate_reduced_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateReducedCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    let aggregate_quotient_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateQuotientCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    require_equal_u64(
        &proof_value,
        "aggregateRelationSubproofSizeBytes",
        u64::try_from(aggregate_relation_verification.proof_size_bytes).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge aggregate relation subproof size does not fit u64",
            )
        })?,
        "aggregate relation subproof size",
    )?;
    require_equal_string(
        &proof_value,
        "aggregateRelationChallengeHex",
        &aggregate_relation_verification.challenge_hex,
        "aggregate relation challenge summary",
    )?;
    require_equal_string(
        &proof_value,
        "aggregateRelationCommitmentDigest",
        &aggregate_relation_verification.relation_commitment_digest,
        "aggregate relation commitment digest",
    )?;
    require_equal_u64(
        &proof_value,
        "aggregateReducedCoordinateCount",
        aggregate_reduced_coordinate_count,
        "aggregate reduced coordinate count",
    )?;
    require_equal_u64(
        &proof_value,
        "aggregateQuotientCoordinateCount",
        aggregate_quotient_coordinate_count,
        "aggregate quotient coordinate count",
    )?;

    require_equal_string(
        &proof_value,
        "aggregateDerivationComponentDigest",
        component_digest,
        "bridge proof component digest",
    )?;
    require_equal_string(
        &proof_value,
        "aggregateDerivationStatementDigest",
        statement_digest,
        "bridge proof statement digest",
    )?;
    require_equal_string(
        &proof_value,
        "postVotingClosedContextDigest",
        post_voting_closed_context_digest,
        "bridge proof post-close context digest",
    )?;
    for field_name in [
        "plaintextRoot",
        "ciphertextRoot",
        "encryptedAggregateShareCiphertextRoot",
        "collectivePublicKeyRoot",
        "bgvPublicKeyRoot",
    ] {
        require_equal_string(
            &proof_value,
            field_name,
            required_string_field(bridge_encryption, field_name, "bridgeEncryption")?,
            field_name,
        )?;
    }
    require_equal_string(
        bridge_encryption,
        "collectivePublicKeyRoot",
        setup_collective_public_key_root,
        "collective public key root",
    )?;
    require_equal_string(
        bridge_encryption,
        "bgvPublicKeyRoot",
        setup_bgv_public_key_root,
        "BGV public key root",
    )?;
    let proof_object_type = string_field(&proof_value, "objectType").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge proof objectType is required",
        )
    })?;
    let proof_is_checked_relation =
        proof_object_type == "SealedLatticeAggregateBridgeRelationProof";
    if !proof_is_checked_relation
        && proof_object_type != "SealedLatticeAggregateBridgeEncryptionEvidence"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof object type is not supported",
        ));
    }
    if read_u64_object_field(&proof_value, "objectVersion", "bridgeProof")? != 1
        || string_field(&proof_value, "profileId") != Some(BRIDGE_PROOF_PROFILE_ID)
        || string_field(&proof_value, "proofBackend") != Some(BRIDGE_PROOF_BACKEND)
        || string_field(&proof_value, "bgvEncryptionProofSubrelation")
            != Some(BGV_ENCRYPTION_PROOF_SUBRELATION)
        || string_field(&proof_value, "relationScope") != Some("m9-scoped-bridge-relation")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof shell is not the supported scoped relation",
        ));
    }
    if proof_is_checked_relation {
        if string_field(bridge_encryption, "bridgeProofVerificationStatus")
            != Some(BRIDGE_PROOF_CHECKED_STATUS)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge relation proof requires verifier-checked bridge encryption status",
            ));
        }
    } else if string_field(bridge_encryption, "bridgeProofVerificationStatus")
        == Some(BRIDGE_PROOF_CHECKED_STATUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge checked status requires a real shared-witness relation proof",
        ));
    }
    let shared_witness_verification = if proof_is_checked_relation {
        Some(verify_bridge_shared_witness_proof(
            &proof_value,
            component,
            setup_package,
            bridge_encryption,
            &bridge_proof_statement_digest,
            contributor_identity,
            statement_digest,
            aggregate_reduced_coordinate_count,
            aggregate_quotient_coordinate_count,
        )?)
    } else {
        None
    };
    let bridge_proof_bytes_digest = derive_protocol_digest(
        "ProofBytesDigest",
        &json!({
            "purpose": "m9-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": bridge_proof_bytes_hex,
        }),
    )?;
    let bridge_proof_root = derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentDigest": component_digest,
            "aggregateDerivationStatementDigest": statement_digest,
            "bridgeProofProfileDigest": bridge_proof_profile_digest,
            "bridgeProofStatementDigest": bridge_proof_statement_digest,
            "proofBytesDigest": bridge_proof_bytes_digest,
            "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
            "collectivePublicKeyRoot": bridge_encryption["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": bridge_encryption["bgvPublicKeyRoot"],
        }),
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofBytesDigest",
        &bridge_proof_bytes_digest,
        "bridge proof bytes digest",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofRoot",
        &bridge_proof_root,
        "bridge proof root",
    )?;
    let bridge_proof_verification_status = if shared_witness_verification.is_some() {
        BRIDGE_PROOF_CHECKED_STATUS
    } else {
        BRIDGE_PROOF_PENDING_STATUS
    };
    let status_labels = if shared_witness_verification.is_some() {
        vec![
            "BridgeProofEvidenceChecked",
            "BridgeProofRelationChecked",
            "M9SingleContributionBridgeRelationChecked",
            "FinalBridgeTheoremPending",
        ]
    } else {
        vec![
            "BridgeProofEvidenceChecked",
            "BridgeProofBackendStillRequired",
            "FinalBridgeTheoremPending",
        ]
    };

    Ok(json!({
        "ok": true,
        "backendAvailable": true,
        "operation": "verifyAggregateBridgeEncryption",
        "statusLabels": status_labels,
        "acceptedDigests": [
            component_digest,
            statement_digest,
            bridge_proof_profile_digest,
            bridge_proof_statement_digest,
            bridge_proof_target_contract_digest,
            bridge_proof_bytes_digest,
            bridge_proof_root,
            required_string_field(
                bridge_encryption,
                "encryptedAggregateShareCiphertextRoot",
                "bridgeEncryption",
            )?
        ],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "bridgeProofVerificationStatus": bridge_proof_verification_status,
        "bridgeEvidenceVerificationStatus": "BridgeProofEvidenceChecked",
        "bridgeProofProfileDigest": bridge_proof_profile_digest,
        "bridgeProofStatementDigest": bridge_proof_statement_digest,
        "bridgeProofTargetContractDigest": bridge_proof_target_contract_digest,
        "bridgeProofBytesDigest": bridge_proof_bytes_digest,
        "bridgeProofRoot": bridge_proof_root,
        "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
        "aggregateRelationSubproofSizeBytes": aggregate_relation_verification.proof_size_bytes,
        "aggregateRelationChallengeHex": aggregate_relation_verification.challenge_hex,
        "aggregateRelationCommitmentDigest": aggregate_relation_verification.relation_commitment_digest,
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "sharedWitnessChallengeHex": shared_witness_verification
            .as_ref()
            .map(|verification| verification.challenge_hex.clone()),
        "sharedResponseScalarCount": shared_witness_verification
            .as_ref()
            .map(|verification| verification.shared_response_scalar_count),
    }))
}

#[cfg(test)]
fn bridge_relation_gap_status_value() -> Value {
    json!({
        "objectType": "AggregateBridgeRelationGapStatus",
        "objectVersion": 1,
        "scopedBridgeRelationClosure": false,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_CHECKED_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_PENDING_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS,
        "sampledOnlyBridgeVerificationAccepted": false,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
    })
}

fn bridge_proof_profile_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofProfileDigest",
        &json!({
            "purpose": "m9-bridge-proof-profile-v1",
            "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
            "proofBackend": BRIDGE_PROOF_BACKEND,
            "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        }),
    )
}

fn bridge_proof_target_contract_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> CanonicalResult<Value> {
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = 2_u64;
    let shared_witness_layout = shared_witness_layout_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
    );
    let shared_witness_layout_digest = shared_witness_layout_digest(&shared_witness_layout)?;

    Ok(json!({
        "objectType": "AggregateBridgeProofTargetContract",
        "objectVersion": 1,
        "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "relationScope": "m9-scoped-bridge-relation",
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "commitmentOpeningCoordinateCount": SHARE_COMMITMENT_OPENING_DIMENSION,
        "aggregateReductionRowCount": aggregate_reduced_coordinate_count,
        "fieldReductionModulus": BALLOT_PRIVACY_FIELD_MODULUS,
        "plaintextEncodingRelation": PLAINTEXT_ENCODING_RELATION,
        "plaintextCoefficientCount": polynomial_degree,
        "polynomialDegree": polynomial_degree,
        "dataPrimeCount": data_prime_count,
        "ciphertextComponentCount": ciphertext_component_count,
        "ciphertextCoefficientEquationCount": data_prime_count
            * polynomial_degree
            * ciphertext_component_count,
        "fullRnsCoverageRequired": true,
        "coefficientDomainCanonical": true,
        "sampledDiagnosticsAcceptedForVerification": false,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_CHECKED_STATUS,
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsClosureStatus": SEPARATE_SUBPROOFS_CLOSURE_STATUS,
        "separateSubproofsAcceptedForClosure": false,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "proofFriendlyPlaintextBindingRequired": true,
        "plaintextRootProofBindingStatus": PLAINTEXT_ROOT_PROOF_BINDING_CHECKED_STATUS,
        "publicPlaintextRootAcceptedAsClosureEvidence": false,
        "sharedWitnessLayout": shared_witness_layout,
        "sharedWitnessLayoutDigest": shared_witness_layout_digest,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
        "naiveLinearExpansionBackendStatus": NAIVE_LINEAR_EXPANSION_BACKEND_STATUS,
    }))
}

fn shared_witness_layout_value(
    aggregate_reduced_coordinate_count: u64,
    aggregate_quotient_coordinate_count: u64,
) -> Value {
    let polynomial_degree = POLYNOMIAL_DEGREE as u64;
    let data_prime_count = DATA_PRIMES.len() as u64;
    let ciphertext_component_count = 2_u64;
    let aggregate_integer_share_coordinate_count = aggregate_reduced_coordinate_count;
    let commitment_opening_coordinate_count = SHARE_COMMITMENT_OPENING_DIMENSION as u64;
    let plaintext_coefficient_count = polynomial_degree;
    let plaintext_encoding_quotient_count = 0_u64;
    let encryption_randomizer_coefficient_count = polynomial_degree;
    let encryption_error_coefficient_count = ciphertext_component_count * polynomial_degree;
    let shared_response_scalar_count = aggregate_integer_share_coordinate_count
        + commitment_opening_coordinate_count
        + aggregate_reduced_coordinate_count
        + aggregate_quotient_coordinate_count
        + plaintext_coefficient_count
        + plaintext_encoding_quotient_count
        + encryption_randomizer_coefficient_count
        + encryption_error_coefficient_count;

    json!({
        "objectType": "AggregateBridgeSharedWitnessLayout",
        "objectVersion": 1,
        "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
        "layoutModel": "single-shared-response-vector-v1",
        "aggregateIntegerShareCoordinateCount": aggregate_integer_share_coordinate_count,
        "commitmentOpeningCoordinateCount": commitment_opening_coordinate_count,
        "aggregateReducedCoordinateCount": aggregate_reduced_coordinate_count,
        "aggregateQuotientCoordinateCount": aggregate_quotient_coordinate_count,
        "plaintextCoefficientCount": plaintext_coefficient_count,
        "plaintextEncodingQuotientCount": plaintext_encoding_quotient_count,
        "encryptionRandomizerCoefficientCount": encryption_randomizer_coefficient_count,
        "encryptionErrorCoefficientCount": encryption_error_coefficient_count,
        "aggregateRelationRowCount": SHARE_COMMITMENT_MODULE_RANK as u64
            + aggregate_reduced_coordinate_count,
        "plaintextEncodingRelationRowCount": polynomial_degree,
        "bgvCiphertextEquationRowCount": data_prime_count
            * polynomial_degree
            * ciphertext_component_count,
        "sharedResponseScalarCount": shared_response_scalar_count,
        "sharedReducedCoordinateColumnRole": "aggregate-reduction-and-bgv-plaintext-slot",
        "plaintextCoefficientColumnRole": "bgv-batch-encoding-and-bgv-encryption-message",
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsAcceptedForClosure": false,
    })
}

fn shared_witness_layout_digest(layout: &Value) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-shared-witness-layout-v1",
            "layout": layout,
        }),
    )
}

fn bridge_proof_target_contract_digest(target_contract: &Value) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-bridge-proof-target-contract-v1",
            "contract": target_contract,
        }),
    )
}

fn build_bridge_proof_statement(
    component: &Value,
    setup_package: &Value,
    bridge_encryption: &Value,
    bridge_proof_profile_digest: &str,
    aggregate_selection_policy_digest: &str,
    bridge_witness_privacy_profile_digest: &str,
    he_param_digest: &str,
) -> CanonicalResult<Value> {
    let component_statement =
        required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let component_proof_input =
        required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let aggregate_commitment = required_json_field(
        component,
        "aggregateCommitment",
        "aggregateDerivationComponent",
    )?;
    let aggregate_proof_record =
        required_json_field(component, "proofRecord", "aggregateDerivationComponent")?;
    let share_commitment_message_bound_cert = required_json_field(
        component,
        "shareCommitmentMessageBoundCert",
        "aggregateDerivationComponent",
    )?;
    let aggregate_derivation_component_digest = required_string_field(
        component,
        "aggregateDerivationComponentDigest",
        "aggregateDerivationComponent",
    )?;
    let aggregate_derivation_statement_digest = required_string_field(
        component_statement,
        "aggregateDerivationStatementDigest",
        "aggregateDerivationComponent.statement",
    )?;
    let aggregate_share_commitment_digest = required_string_field(
        aggregate_commitment,
        "aggregateShareCommitmentDigest",
        "aggregateDerivationComponent.aggregateCommitment",
    )?;
    require_matching_string_field(
        component_statement,
        "aggregateShareCommitmentDigest",
        aggregate_share_commitment_digest,
        "aggregate share commitment digest",
    )?;
    let share_commitment_message_bound_cert_digest = required_string_field(
        share_commitment_message_bound_cert,
        "shareCommitmentMessageBoundCertDigest",
        "aggregateDerivationComponent.shareCommitmentMessageBoundCert",
    )?;
    require_matching_string_field(
        component_statement,
        "shareCommitmentMessageBoundCertDigest",
        share_commitment_message_bound_cert_digest,
        "share commitment message-bound certificate digest",
    )?;
    validate_bridge_share_commitment_bound_cert(
        share_commitment_message_bound_cert,
        component_statement,
    )?;
    let setup_manifest_digest = required_string_at_path(
        setup_package,
        &["setupInputs", "manifestDigest"],
        "setupPackage",
    )?;
    let setup_roster_digest = required_string_at_path(
        setup_package,
        &["setupInputs", "rosterDigest"],
        "setupPackage",
    )?;
    let setup_threshold_profile_digest = required_string_at_path(
        setup_package,
        &["setupInputs", "thresholdProfileDigest"],
        "setupPackage",
    )?;
    let setup_package_digest =
        required_string_field(setup_package, "setupPackageDigest", "setupPackage")?;
    let setup_participant_count = read_u64_at_path(
        setup_package,
        &["setupInputs", "participantCount"],
        "setupPackage",
    )?;
    let dimensions = bridge_variant_dimensions(component_statement)?;
    if setup_participant_count != dimensions.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge setup participant count does not match the aggregate statement participantCount",
        ));
    }
    require_matching_string_field(
        component_statement,
        "manifestDigest",
        setup_manifest_digest,
        "manifest digest",
    )?;
    require_matching_string_field(
        component_statement,
        "rosterDigest",
        setup_roster_digest,
        "roster digest",
    )?;
    require_matching_string_field(
        component_statement,
        "thresholdProfileDigest",
        setup_threshold_profile_digest,
        "threshold profile digest",
    )?;
    let share_vector_width = read_u64_object_field(
        component_statement,
        "shareVectorWidth",
        "aggregateDerivationComponent.statement",
    )?;
    let encrypted_aggregate_input_layout_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutDigest"],
        "setupPackage",
    )?;
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        bridge_encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?;
    let encrypted_aggregate_bridge_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateBridgeDigest"],
        "setupPackage",
    )?;
    let encrypted_aggregate_target_basis_data_root = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateTargetBasisDataRoot"],
        "setupPackage",
    )?;
    let encrypted_aggregate_reconstruction_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateReconstructionDigest"],
        "setupPackage",
    )?;
    let bgv_batch_encoder_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "batchEncoderDigest"],
        "setupPackage",
    )?;
    let ballot_score_encoding_profile_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "ballotScoreEncodingProfileDigest"],
        "setupPackage",
    )?;
    let ballot_share_layout_profile_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "ballotShareLayoutProfileDigest"],
        "setupPackage",
    )?;
    let aggregate_input_encoding_profile_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "aggregateInputEncodingProfileDigest"],
        "setupPackage",
    )?;
    let encoded_share_vector_layout_digest = required_string_field(
        component_statement,
        "encodedShareVectorLayoutDigest",
        "aggregateDerivationComponent.statement",
    )?;
    let encoded_aggregate_layout_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "encodedAggregateLayoutDigest"],
        "setupPackage",
    )?;
    let top_k_evaluator_input_layout_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "topKEvaluatorInputLayoutDigest"],
        "setupPackage",
    )?;
    let bgv_profile_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "profileDigest"],
        "setupPackage",
    )?;
    let rust_bgv_backend_profile_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "backendProfileDigest"],
        "setupPackage",
    )?;
    let canonical_ciphertext_convention_digest = required_string_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionDigest"],
        "setupPackage",
    )?;
    let collective_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        "setupPackage",
    )?;
    let bgv_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        "setupPackage",
    )?;
    let component_binding = json!({
        "aggregateDerivationStatementDigest": aggregate_derivation_statement_digest,
        "shareCommitmentMessageBoundCertDigest": share_commitment_message_bound_cert_digest,
        "componentProofStatementDigest": required_string_field(
            component_proof_input,
            "componentProofStatementDigest",
            "aggregateDerivationComponent.proofInput",
        )?,
        "componentProofBytesDigest": required_string_field(
            aggregate_proof_record,
            "proofBytesDigest",
            "aggregateDerivationComponent.proofRecord",
        )?,
        "participantCount": dimensions.participant_count,
        "optionCount": dimensions.option_count,
        "shareVectorWidth": share_vector_width,
    });
    let setup_binding = json!({
        "setupPackageDigest": setup_package_digest,
        "encryptedAggregateBridgeDigest": encrypted_aggregate_bridge_digest,
        "encryptedAggregateTargetBasisDataRoot": encrypted_aggregate_target_basis_data_root,
        "encryptedAggregateReconstructionDigest": encrypted_aggregate_reconstruction_digest,
        "bgvBatchEncoderDigest": bgv_batch_encoder_digest,
        "bridgeLayoutDigest": encrypted_aggregate_input_layout_digest,
        "ballotScoreEncodingProfileDigest": ballot_score_encoding_profile_digest,
        "ballotShareLayoutProfileDigest": ballot_share_layout_profile_digest,
        "aggregateInputEncodingProfileDigest": aggregate_input_encoding_profile_digest,
        "encodedShareVectorLayoutDigest": encoded_share_vector_layout_digest,
        "encodedAggregateLayoutDigest": encoded_aggregate_layout_digest,
        "topKEvaluatorInputLayoutDigest": top_k_evaluator_input_layout_digest,
        "bgvProfileDigest": bgv_profile_digest,
        "rustBgvBackendProfileDigest": rust_bgv_backend_profile_digest,
        "canonicalCiphertextConventionDigest": canonical_ciphertext_convention_digest,
        "setupParticipantCount": setup_participant_count,
    });
    let context_binding = json!({
        "ceremonyId": required_string_field(
            component_statement,
            "ceremonyId",
            "aggregateDerivationComponent.statement",
        )?,
        "pollSpecDigest": required_string_field(
            component_statement,
            "pollSpecDigest",
            "aggregateDerivationComponent.statement",
        )?,
        "thresholdProfileDigest": setup_threshold_profile_digest,
        "ballotSetDigest": required_string_field(
            component_statement,
            "ballotSetDigest",
            "aggregateDerivationComponent.statement",
        )?,
        "votingClosedBoardHeadDigest": required_string_field(
            component_statement,
            "votingClosedBoardHeadDigest",
            "aggregateDerivationComponent.statement",
        )?,
        "contributorIdentity": required_string_field(
            component_statement,
            "contributorIdentity",
            "aggregateDerivationComponent.statement",
        )?,
        "contributorRosterPosition": read_u64_object_field(
            component_statement,
            "contributorRosterPosition",
            "aggregateDerivationComponent.statement",
        )?,
        "contributorRosterExternalAcceptanceDigest": required_string_field(
            component_statement,
            "contributorRosterExternalAcceptanceDigest",
            "aggregateDerivationComponent.statement",
        )?,
        "contributorActionContextDigest": required_string_field(
            component_statement,
            "contributorActionContextDigest",
            "aggregateDerivationComponent.statement",
        )?,
    });
    let ciphertext_binding = json!({
        "plaintextRoot": required_string_field(bridge_encryption, "plaintextRoot", "bridgeEncryption")?,
        "ciphertextRoot": required_string_field(bridge_encryption, "ciphertextRoot", "bridgeEncryption")?,
        "canonicalBytesHash512": required_string_field(
            bridge_encryption,
            "canonicalBytesHash512",
            "bridgeEncryption",
        )?,
        "canonicalByteLength": read_u64_object_field(
            bridge_encryption,
            "canonicalByteLength",
            "bridgeEncryption",
        )?,
        "basisId": required_string_field(bridge_encryption, "basisId", "bridgeEncryption")?,
        "level": read_u64_object_field(bridge_encryption, "level", "bridgeEncryption")?,
        "coefficientCount": read_u64_object_field(
            bridge_encryption,
            "coefficientCount",
            "bridgeEncryption",
        )?,
        "slotCount": read_u64_object_field(bridge_encryption, "slotCount", "bridgeEncryption")?,
    });
    let sampled_public_relation_check_policy = required_json_field(
        bridge_encryption,
        "sampledPublicRelationCheckPolicy",
        "bridgeEncryption",
    )?;
    let sampled_public_relation_check_policy_digest =
        sampled_public_relation_check_policy_digest(sampled_public_relation_check_policy)?;
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": share_vector_width,
        "aggregateQuotientCoordinateCount": share_vector_width,
        "sharedWitnessBindingRequired": true,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_CHECKED_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "sampledOnlyBridgeVerificationAccepted": false,
        "coefficientDomainCanonical": true,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
    });
    let bridge_proof_target_contract =
        bridge_proof_target_contract_value(share_vector_width, share_vector_width)?;
    let bridge_proof_target_contract_digest =
        bridge_proof_target_contract_digest(&bridge_proof_target_contract)?;

    let mut bridge_statement = Map::new();
    bridge_statement.insert(
        "objectType".to_string(),
        Value::String("AggregateBridgeProofStatement".to_string()),
    );
    bridge_statement.insert("objectVersion".to_string(), json!(1));
    bridge_statement.insert(
        "bridgeProofProfileId".to_string(),
        Value::String(BRIDGE_PROOF_PROFILE_ID.to_string()),
    );
    bridge_statement.insert(
        "bridgeProofProfileDigest".to_string(),
        Value::String(bridge_proof_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "proofBackend".to_string(),
        Value::String(BRIDGE_PROOF_BACKEND.to_string()),
    );
    bridge_statement.insert(
        "bgvEncryptionProofSubrelation".to_string(),
        Value::String(BGV_ENCRYPTION_PROOF_SUBRELATION.to_string()),
    );
    bridge_statement.insert(
        "aggregateDerivationComponentDigest".to_string(),
        Value::String(aggregate_derivation_component_digest.to_string()),
    );
    bridge_statement.insert(
        "aggregateShareCommitmentDigest".to_string(),
        Value::String(aggregate_share_commitment_digest.to_string()),
    );
    bridge_statement.insert(
        "shareCommitmentMessageBoundCertDigest".to_string(),
        Value::String(share_commitment_message_bound_cert_digest.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateBridgeDigest".to_string(),
        Value::String(encrypted_aggregate_bridge_digest.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateTargetBasisDataRoot".to_string(),
        Value::String(encrypted_aggregate_target_basis_data_root.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateReconstructionDigest".to_string(),
        Value::String(encrypted_aggregate_reconstruction_digest.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateInputLayoutDigest".to_string(),
        Value::String(encrypted_aggregate_input_layout_digest.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateShareCiphertextRoot".to_string(),
        Value::String(encrypted_aggregate_share_ciphertext_root.to_string()),
    );
    bridge_statement.insert(
        "bridgeWitnessPrivacyProfileDigest".to_string(),
        Value::String(bridge_witness_privacy_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "sampledPublicRelationCheckPolicyDigest".to_string(),
        Value::String(sampled_public_relation_check_policy_digest),
    );
    bridge_statement.insert(
        "bridgeProofTargetContractDigest".to_string(),
        Value::String(bridge_proof_target_contract_digest),
    );
    bridge_statement.insert(
        "bgvBatchEncoderDigest".to_string(),
        Value::String(bgv_batch_encoder_digest.to_string()),
    );
    bridge_statement.insert(
        "bridgeLayoutDigest".to_string(),
        Value::String(encrypted_aggregate_input_layout_digest.to_string()),
    );
    bridge_statement.insert(
        "ballotScoreEncodingProfileDigest".to_string(),
        Value::String(ballot_score_encoding_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "ballotShareLayoutProfileDigest".to_string(),
        Value::String(ballot_share_layout_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "aggregateInputEncodingProfileDigest".to_string(),
        Value::String(aggregate_input_encoding_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "encodedShareVectorLayoutDigest".to_string(),
        Value::String(encoded_share_vector_layout_digest.to_string()),
    );
    bridge_statement.insert(
        "encodedAggregateLayoutDigest".to_string(),
        Value::String(encoded_aggregate_layout_digest.to_string()),
    );
    bridge_statement.insert(
        "topKEvaluatorInputLayoutDigest".to_string(),
        Value::String(top_k_evaluator_input_layout_digest.to_string()),
    );
    bridge_statement.insert(
        "heParamDigest".to_string(),
        Value::String(he_param_digest.to_string()),
    );
    bridge_statement.insert(
        "bgvProfileDigest".to_string(),
        Value::String(bgv_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "rustBgvBackendProfileDigest".to_string(),
        Value::String(rust_bgv_backend_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "canonicalCiphertextConventionDigest".to_string(),
        Value::String(canonical_ciphertext_convention_digest.to_string()),
    );
    bridge_statement.insert(
        "collectivePublicKeyRoot".to_string(),
        Value::String(collective_public_key_root.to_string()),
    );
    bridge_statement.insert(
        "bgvPublicKeyRoot".to_string(),
        Value::String(bgv_public_key_root.to_string()),
    );
    bridge_statement.insert(
        "aggregateSelectionPolicyDigest".to_string(),
        Value::String(aggregate_selection_policy_digest.to_string()),
    );
    bridge_statement.insert(
        "ceremonyId".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "ceremonyId",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "manifestDigest".to_string(),
        Value::String(setup_manifest_digest.to_string()),
    );
    bridge_statement.insert(
        "rosterDigest".to_string(),
        Value::String(setup_roster_digest.to_string()),
    );
    bridge_statement.insert(
        "pollSpecDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "pollSpecDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "thresholdProfileDigest".to_string(),
        Value::String(setup_threshold_profile_digest.to_string()),
    );
    bridge_statement.insert(
        "setupPackageDigest".to_string(),
        Value::String(setup_package_digest.to_string()),
    );
    bridge_statement.insert(
        "participantCount".to_string(),
        json!(dimensions.participant_count),
    );
    bridge_statement.insert("optionCount".to_string(), json!(dimensions.option_count));
    bridge_statement.insert("shareVectorWidth".to_string(), json!(share_vector_width));
    bridge_statement.insert(
        "ballotSetDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "ballotSetDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "votingClosedBoardHeadDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "votingClosedBoardHeadDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "postVotingClosedContextDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "postVotingClosedContextDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "contributorIdentity".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "contributorIdentity",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "contributorRosterPosition".to_string(),
        json!(read_u64_object_field(
            component_statement,
            "contributorRosterPosition",
            "aggregateDerivationComponent.statement",
        )?),
    );
    bridge_statement.insert(
        "contributorRosterExternalAcceptanceDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "contributorRosterExternalAcceptanceDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "contributorActionContextDigest".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "contributorActionContextDigest",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "plaintextRoot".to_string(),
        Value::String(
            required_string_field(bridge_encryption, "plaintextRoot", "bridgeEncryption")?
                .to_string(),
        ),
    );
    bridge_statement.insert(
        "ciphertextRoot".to_string(),
        Value::String(
            required_string_field(bridge_encryption, "ciphertextRoot", "bridgeEncryption")?
                .to_string(),
        ),
    );
    bridge_statement.insert(
        "canonicalBytesHash512".to_string(),
        Value::String(
            required_string_field(
                bridge_encryption,
                "canonicalBytesHash512",
                "bridgeEncryption",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "canonicalByteLength".to_string(),
        json!(read_u64_object_field(
            bridge_encryption,
            "canonicalByteLength",
            "bridgeEncryption",
        )?),
    );
    bridge_statement.insert(
        "basisId".to_string(),
        Value::String(
            required_string_field(bridge_encryption, "basisId", "bridgeEncryption")?.to_string(),
        ),
    );
    bridge_statement.insert(
        "level".to_string(),
        json!(read_u64_object_field(
            bridge_encryption,
            "level",
            "bridgeEncryption",
        )?),
    );
    bridge_statement.insert(
        "coefficientCount".to_string(),
        json!(read_u64_object_field(
            bridge_encryption,
            "coefficientCount",
            "bridgeEncryption",
        )?),
    );
    bridge_statement.insert(
        "slotCount".to_string(),
        json!(read_u64_object_field(
            bridge_encryption,
            "slotCount",
            "bridgeEncryption",
        )?),
    );
    bridge_statement.insert("componentBinding".to_string(), component_binding);
    bridge_statement.insert("setupBinding".to_string(), setup_binding);
    bridge_statement.insert("contextBinding".to_string(), context_binding);
    bridge_statement.insert("ciphertextBinding".to_string(), ciphertext_binding);
    bridge_statement.insert("relationRequirements".to_string(), relation_requirements);
    bridge_statement.insert(
        "bridgeProofTargetContract".to_string(),
        bridge_proof_target_contract,
    );

    Ok(Value::Object(bridge_statement))
}

fn bridge_proof_statement_digest(bridge_proof_statement: &Value) -> CanonicalResult<String> {
    let mut digest_input = Map::new();
    digest_input.insert(
        "purpose".to_string(),
        Value::String("m9-bridge-proof-statement-v1".to_string()),
    );

    for field_name in [
        "aggregateDerivationComponentDigest",
        "aggregateInputEncodingProfileDigest",
        "aggregateSelectionPolicyDigest",
        "aggregateShareCommitmentDigest",
        "ballotScoreEncodingProfileDigest",
        "ballotSetDigest",
        "ballotShareLayoutProfileDigest",
        "basisId",
        "bgvBatchEncoderDigest",
        "bgvProfileDigest",
        "bgvPublicKeyRoot",
        "bridgeLayoutDigest",
        "bridgeProofTargetContractDigest",
        "bridgeWitnessPrivacyProfileDigest",
        "canonicalBytesHash512",
        "canonicalCiphertextConventionDigest",
        "ceremonyId",
        "ciphertextRoot",
        "collectivePublicKeyRoot",
        "contributorActionContextDigest",
        "contributorIdentity",
        "contributorRosterExternalAcceptanceDigest",
        "encodedAggregateLayoutDigest",
        "encodedShareVectorLayoutDigest",
        "encryptedAggregateBridgeDigest",
        "encryptedAggregateInputLayoutDigest",
        "encryptedAggregateReconstructionDigest",
        "encryptedAggregateShareCiphertextRoot",
        "encryptedAggregateTargetBasisDataRoot",
        "heParamDigest",
        "manifestDigest",
        "plaintextRoot",
        "pollSpecDigest",
        "postVotingClosedContextDigest",
        "rosterDigest",
        "rustBgvBackendProfileDigest",
        "sampledPublicRelationCheckPolicyDigest",
        "setupPackageDigest",
        "shareCommitmentMessageBoundCertDigest",
        "thresholdProfileDigest",
        "topKEvaluatorInputLayoutDigest",
        "votingClosedBoardHeadDigest",
    ] {
        digest_input.insert(
            field_name.to_string(),
            Value::String(
                required_string_field(bridge_proof_statement, field_name, "bridgeProofStatement")?
                    .to_string(),
            ),
        );
    }
    digest_input.insert(
        "proofProfileDigest".to_string(),
        Value::String(
            required_string_field(
                bridge_proof_statement,
                "bridgeProofProfileDigest",
                "bridgeProofStatement",
            )?
            .to_string(),
        ),
    );
    for field_name in [
        "coefficientCount",
        "contributorRosterPosition",
        "canonicalByteLength",
        "level",
        "optionCount",
        "participantCount",
        "shareVectorWidth",
        "slotCount",
    ] {
        digest_input.insert(
            field_name.to_string(),
            json!(read_u64_object_field(
                bridge_proof_statement,
                field_name,
                "bridgeProofStatement",
            )?),
        );
    }
    let relation_requirements = required_json_field(
        bridge_proof_statement,
        "relationRequirements",
        "bridgeProofStatement",
    )?;
    validate_bridge_proof_target_contract(bridge_proof_statement, relation_requirements)?;
    for field_name in [
        "sharedWitnessBindingStatus",
        "aggregateToPlaintextBindingStatus",
        "bgvEncryptionProofStatus",
        "rnsCrtConsistencyProofStatus",
        "hwangPiopStatus",
    ] {
        digest_input.insert(
            field_name.to_string(),
            Value::String(
                required_string_field(
                    relation_requirements,
                    field_name,
                    "bridgeProofStatement.relationRequirements",
                )?
                .to_string(),
            ),
        );
    }
    for field_name in [
        "aggregateReducedCoordinateCount",
        "aggregateQuotientCoordinateCount",
    ] {
        digest_input.insert(
            field_name.to_string(),
            json!(read_u64_object_field(
                relation_requirements,
                field_name,
                "bridgeProofStatement.relationRequirements",
            )?),
        );
    }
    for field_name in [
        "sharedWitnessBindingRequired",
        "sampledOnlyBridgeVerificationAccepted",
        "coefficientDomainCanonical",
    ] {
        digest_input.insert(
            field_name.to_string(),
            json!(read_bool_object_field(
                relation_requirements,
                field_name,
                "bridgeProofStatement.relationRequirements",
            )?),
        );
    }

    derive_protocol_digest("BridgeProofRecordDigest", &Value::Object(digest_input))
}

fn validate_bridge_proof_target_contract(
    bridge_proof_statement: &Value,
    relation_requirements: &Value,
) -> CanonicalResult<()> {
    let aggregate_reduced_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateReducedCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    let aggregate_quotient_coordinate_count = read_u64_object_field(
        relation_requirements,
        "aggregateQuotientCoordinateCount",
        "bridgeProofStatement.relationRequirements",
    )?;
    let expected_target_contract = bridge_proof_target_contract_value(
        aggregate_reduced_coordinate_count,
        aggregate_quotient_coordinate_count,
    )?;
    let target_contract = required_json_field(
        bridge_proof_statement,
        "bridgeProofTargetContract",
        "bridgeProofStatement",
    )?;
    if target_contract != &expected_target_contract {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof target contract does not match the relation requirements",
        ));
    }
    let expected_target_contract_digest =
        bridge_proof_target_contract_digest(&expected_target_contract)?;
    require_matching_string_field(
        bridge_proof_statement,
        "bridgeProofTargetContractDigest",
        &expected_target_contract_digest,
        "bridge proof target contract digest",
    )
}

fn validate_bridge_share_commitment_bound_cert(
    certificate: &Value,
    statement: &Value,
) -> CanonicalResult<()> {
    let certificate_object = certificate.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge share-commitment message-bound certificate must be an object",
        )
    })?;
    let mut certificate_payload = certificate_object.clone();
    let certificate_digest = certificate_payload
        .remove("shareCommitmentMessageBoundCertDigest")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge share-commitment message-bound certificate digest is missing",
            )
        })?;
    let expected_certificate_digest = derive_protocol_digest(
        "ShareCommitmentMessageBoundCertDigest",
        &Value::Object(certificate_payload),
    )?;
    let maximum_canonical_turnout = read_u64_object_field(
        certificate,
        "maximumCanonicalTurnout",
        "shareCommitmentMessageBoundCert",
    )?;
    let maximum_aggregate_integer = read_u64_object_field(
        certificate,
        "maximumAggregateInteger",
        "shareCommitmentMessageBoundCert",
    )?;
    let opening_single_bound = read_u64_object_field(
        certificate,
        "openingRandomnessSingleBound",
        "shareCommitmentMessageBoundCert",
    )?;
    let opening_aggregate_bound = read_u64_object_field(
        certificate,
        "openingRandomnessAggregateBound",
        "shareCommitmentMessageBoundCert",
    )?;
    let quotient_bound = read_u64_object_field(
        certificate,
        "quotientBoundForAggregateReduction",
        "shareCommitmentMessageBoundCert",
    )?;
    let expected_maximum_aggregate_integer = maximum_canonical_turnout
        .checked_mul(BALLOT_PRIVACY_FIELD_MODULUS - 1)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge maximum aggregate integer bound overflows",
            )
        })?;
    let expected_opening_aggregate_bound = maximum_canonical_turnout
        .checked_mul(opening_single_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "M9 bridge opening randomness aggregate bound overflows",
            )
        })?;
    let commitment_message_bound = required_string_field(
        certificate,
        "commitmentMessageBound",
        "shareCommitmentMessageBoundCert",
    )?
    .parse::<u128>()
    .map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge commitment message bound is not an integer: {error}"),
        )
    })?;
    let no_wraparound_condition = required_json_field(
        certificate,
        "noWraparoundCondition",
        "shareCommitmentMessageBoundCert",
    )?;

    if string_field(certificate, "objectType") != Some("ShareCommitmentMessageBoundCert")
        || read_u64_object_field(
            certificate,
            "objectVersion",
            "shareCommitmentMessageBoundCert",
        )? != 1
        || certificate_digest != expected_certificate_digest
        || certificate_digest
            != required_string_field(
                statement,
                "shareCommitmentMessageBoundCertDigest",
                "aggregateDerivationComponent.statement",
            )?
        || required_string_field(
            certificate,
            "shareCommitmentProfileDigest",
            "shareCommitmentMessageBoundCert",
        )? != required_string_field(
            statement,
            "shareCommitmentProfileDigest",
            "aggregateDerivationComponent.statement",
        )?
        || read_u64_object_field(
            certificate,
            "shareVectorWidth",
            "shareCommitmentMessageBoundCert",
        )? != read_u64_object_field(
            statement,
            "shareVectorWidth",
            "aggregateDerivationComponent.statement",
        )?
        || maximum_canonical_turnout
            < read_u64_object_field(
                statement,
                "canonicalTurnout",
                "aggregateDerivationComponent.statement",
            )?
        || maximum_aggregate_integer != expected_maximum_aggregate_integer
        || opening_aggregate_bound != expected_opening_aggregate_bound
        || quotient_bound != maximum_canonical_turnout
        || u128::from(maximum_aggregate_integer) >= commitment_message_bound
        || !read_bool_object_field(
            no_wraparound_condition,
            "maximumAggregateIntegerLessThanCommitmentMessageBound",
            "shareCommitmentMessageBoundCert.noWraparoundCondition",
        )?
        || !read_bool_object_field(
            no_wraparound_condition,
            "openingRandomnessAggregateBoundMatchesTurnout",
            "shareCommitmentMessageBoundCert.noWraparoundCondition",
        )?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge aggregate no-wraparound certificate is invalid or permits wraparound",
        ));
    }

    Ok(())
}

fn sampled_public_relation_check_policy_digest(policy: &Value) -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "m9-sampled-public-relation-check-policy-v1",
            "policy": policy,
        }),
    )
}

fn validate_hex_field(value: &str, field_name: &str) -> CanonicalResult<()> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidHex,
            format!("{field_name} must be non-empty even-length hex"),
        ));
    }
    decode_hex(value)?;

    Ok(())
}

fn required_protocol_digest_field<'value>(
    value: &'value Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<&'value str> {
    let digest = required_string_field(value, field_name, object_name)?;
    if !is_protocol_digest(digest) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_name}.{field_name} must be a nonzero lowercase protocol digest"),
        ));
    }

    Ok(digest)
}

fn parse_bridge_proof_value(proof_bytes_hex: &str) -> CanonicalResult<Value> {
    validate_hex_field(proof_bytes_hex, "bridgeProofBytesHex")?;
    let proof_bytes = decode_hex(proof_bytes_hex)?;
    let proof_json = std::str::from_utf8(&proof_bytes).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge proof bytes are not UTF-8 JSON: {error}"),
        )
    })?;
    let proof_value: Value = serde_json::from_str(proof_json).map_err(|error| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("M9 bridge proof bytes are not canonical JSON: {error}"),
        )
    })?;
    if canonical_json(&proof_value)?.as_bytes() != proof_bytes.as_slice() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge proof bytes must use canonical JSON encoding",
        ));
    }

    Ok(proof_value)
}

fn require_equal_string(
    value: &Value,
    field_name: &str,
    expected_value: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = required_string_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge {label} does not match the expected binding"),
        ));
    }

    Ok(())
}

fn require_equal_u64(
    value: &Value,
    field_name: &str,
    expected_value: u64,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = read_u64_object_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge {label} does not match the expected binding"),
        ));
    }

    Ok(())
}

fn require_matching_string_field(
    value: &Value,
    field_name: &str,
    expected_value: &str,
    label: &str,
) -> CanonicalResult<()> {
    let actual_value = required_string_field(value, field_name, label)?;
    if actual_value != expected_value {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("M9 bridge statement {label} does not match its source object"),
        ));
    }

    Ok(())
}

fn required_string_at_path<'a>(
    value: &'a Value,
    path: &[&str],
    object_name: &str,
) -> CanonicalResult<&'a str> {
    let mut current_value = value;
    for path_component in path {
        current_value = current_value.get(path_component).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{} is required", path.join(".")),
            )
        })?;
    }

    current_value.as_str().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_name}.{} must be a string", path.join(".")),
        )
    })
}

fn read_u64_at_path(value: &Value, path: &[&str], object_name: &str) -> CanonicalResult<u64> {
    let mut current_value = value;
    for path_component in path {
        current_value = current_value.get(path_component).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{} is required", path.join(".")),
            )
        })?;
    }

    current_value.as_u64().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "{object_name}.{} must be a non-negative integer",
                path.join(".")
            ),
        )
    })
}

fn validate_bridge_private_material_disclosure(proof_value: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    let disclosure = required_json_field(proof_value, "privateMaterialDisclosure", "bridgeProof")?;

    validate_bridge_private_material_disclosure_flags(disclosure, "bridgeProof")
}

fn validate_bridge_proof_public_shell(proof_value: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    match string_field(proof_value, "objectType") {
        Some("SealedLatticeAggregateBridgeRelationProof") => {
            required_json_field(proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
        }
        Some("SealedLatticeAggregateBridgeEncryptionEvidence") => {
            validate_bridge_relation_gap_status(proof_value)?;
        }
        _ => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge proof object type is not supported",
            ));
        }
    }
    validate_bridge_private_material_disclosure(proof_value)
}

fn validate_bridge_relation_gap_status(proof_value: &Value) -> CanonicalResult<()> {
    let relation_gap_status =
        required_json_field(proof_value, "bridgeRelationGapStatus", "bridgeProof")?;
    reject_forbidden_public_bridge_fields(
        relation_gap_status,
        "bridgeProof.bridgeRelationGapStatus",
    )?;
    if string_field(relation_gap_status, "objectType") != Some("AggregateBridgeRelationGapStatus")
        || read_u64_object_field(
            relation_gap_status,
            "objectVersion",
            "bridgeProof.bridgeRelationGapStatus",
        )? != 1
        || relation_gap_status
            .get("scopedBridgeRelationClosure")
            .and_then(Value::as_bool)
            != Some(false)
        || string_field(relation_gap_status, "sharedWitnessBindingStatus")
            != Some(SHARED_WITNESS_BINDING_PENDING_STATUS)
        || string_field(relation_gap_status, "aggregateToPlaintextBindingStatus")
            != Some(AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS)
        || string_field(relation_gap_status, "bgvEncryptionProofStatus")
            != Some(BGV_ENCRYPTION_PROOF_PENDING_STATUS)
        || string_field(relation_gap_status, "rnsCrtConsistencyProofStatus")
            != Some(RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS)
        || relation_gap_status
            .get("sampledOnlyBridgeVerificationAccepted")
            .and_then(Value::as_bool)
            != Some(false)
        || string_field(relation_gap_status, "hwangPiopStatus") != Some(HWANG_PIOP_DEFERRED_STATUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof relation gap status must remain pending until the shared-witness proof verifier closes",
        ));
    }

    Ok(())
}

fn validate_bridge_encryption_public_shell(bridge_encryption: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(bridge_encryption, "bridgeEncryption")?;
    let disclosure = required_json_field(
        bridge_encryption,
        "privateMaterialDisclosure",
        "bridgeEncryption",
    )?;
    validate_bridge_private_material_disclosure_flags(disclosure, "bridgeEncryption")?;
    let bridge_proof_verification_status =
        string_field(bridge_encryption, "bridgeProofVerificationStatus").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "bridgeEncryption.bridgeProofVerificationStatus must be a string",
            )
        })?;
    if bridge_proof_verification_status != BRIDGE_PROOF_PENDING_STATUS
        && bridge_proof_verification_status != BRIDGE_PROOF_CHECKED_STATUS
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge encryption shell has an unsupported bridge proof verification status",
        ));
    }
    validate_sampled_public_relation_check_policy(bridge_encryption)?;

    Ok(())
}

fn validate_sampled_public_relation_check_policy(bridge_encryption: &Value) -> CanonicalResult<()> {
    let relation_checks = required_json_field(
        bridge_encryption,
        "sampledPublicRelationChecks",
        "bridgeEncryption",
    )?
    .as_array()
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "bridgeEncryption.sampledPublicRelationChecks must be an array",
        )
    })?;
    for relation_check in relation_checks {
        if relation_check
            .get("relationMatches")
            .and_then(Value::as_bool)
            != Some(true)
            || relation_check
                .get("acceptedForBridgeProofVerification")
                .and_then(Value::as_bool)
                == Some(true)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge sampled public relation checks are diagnostic only and cannot accept bridge proof verification",
            ));
        }
    }

    let policy = required_json_field(
        bridge_encryption,
        "sampledPublicRelationCheckPolicy",
        "bridgeEncryption",
    )?;
    reject_forbidden_public_bridge_fields(
        policy,
        "bridgeEncryption.sampledPublicRelationCheckPolicy",
    )?;
    if string_field(policy, "objectType") != Some("M9BridgeSampledRelationCheckPolicy")
        || read_u64_object_field(
            policy,
            "objectVersion",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )? != 1
        || !read_bool_object_field(
            policy,
            "diagnosticOnly",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || read_bool_object_field(
            policy,
            "acceptedForBridgeProofVerification",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || !read_bool_object_field(
            policy,
            "fullBridgeProofRequired",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || read_bool_object_field(
            policy,
            "sampledOnlyBridgeVerificationAccepted",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )?
        || string_field(policy, "relationCheckSource") != Some("first-data-prime-diagnostic")
        || read_u64_object_field(
            policy,
            "sampledRelationCheckCount",
            "bridgeEncryption.sampledPublicRelationCheckPolicy",
        )? != relation_checks.len() as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge sampled public relation check policy must remain diagnostic-only and proof-rejecting",
        ));
    }

    Ok(())
}

fn validate_bridge_private_material_disclosure_flags(
    disclosure: &Value,
    object_name: &str,
) -> CanonicalResult<()> {
    for field_name in [
        "aggregateOpeningMaterialExported",
        "aggregateShareMaterialExported",
        "layoutMessageMaterialExported",
        "encodedMessageMaterialExported",
        "encryptionRandomizerMaterialExported",
        "noiseMaterialExported",
    ] {
        if disclosure.get(field_name).and_then(Value::as_bool) != Some(false) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "M9 bridge {object_name} private material disclosure flag {field_name} must be false"
                ),
            ));
        }
    }

    Ok(())
}

fn reject_forbidden_public_bridge_fields(value: &Value, path: &str) -> CanonicalResult<()> {
    match value {
        Value::Array(entries) => {
            for (entry_index, entry) in entries.iter().enumerate() {
                reject_forbidden_public_bridge_fields(entry, &format!("{path}[{entry_index}]"))?;
            }
        }
        Value::Object(object) => {
            for (field_name, field_value) in object {
                if forbidden_public_bridge_field_name(field_name) {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ProfileComponentMismatch,
                        format!(
                            "M9 bridge public proof object exposes forbidden field {path}.{field_name}"
                        ),
                    ));
                }
                reject_forbidden_public_bridge_fields(
                    field_value,
                    &format!("{path}.{field_name}"),
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn forbidden_public_bridge_field_name(field_name: &str) -> bool {
    matches!(
        field_name,
        "aggregateIntegerShareVector"
            | "aggregateOpeningRandomness"
            | "aggregateWitness"
            | "aggregateShareWitness"
            | "quotientWitness"
            | "layoutPlaintextWitness"
            | "bgvPlaintext"
            | "encryptionRandomness"
            | "encryptionRandomizer"
            | "encryptionError"
            | "noiseWitness"
            | "sourceWitnessCoefficients"
            | "aggregateHistogram"
            | "aggregateScore"
            | "aggregateScoreBits"
            | "comparisonInputs"
    )
}

fn read_bool_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<bool> {
    value
        .get(field_name)
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be a boolean"),
            )
        })
}

fn read_u64_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be a non-negative integer"),
            )
        })
}

fn read_usize_object_field(
    value: &Value,
    field_name: &str,
    object_name: &str,
) -> CanonicalResult<usize> {
    usize::try_from(read_u64_object_field(value, field_name, object_name)?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{object_name}.{field_name} does not fit usize"),
        )
    })
}

fn read_u64_array(value: &Value, field_name: &str, object_name: &str) -> CanonicalResult<Vec<u64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be an array"),
            )
        })?
        .iter()
        .map(|entry| {
            entry.as_u64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_name}.{field_name} entries must be non-negative integers"),
                )
            })
        })
        .collect()
}

fn read_i64_array(value: &Value, field_name: &str, object_name: &str) -> CanonicalResult<Vec<i64>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_name}.{field_name} must be an array"),
            )
        })?
        .iter()
        .map(|entry| {
            entry.as_i64().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{object_name}.{field_name} entries must be signed integers"),
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_material_disclosure() -> Value {
        json!({
            "aggregateOpeningMaterialExported": false,
            "aggregateShareMaterialExported": false,
            "layoutMessageMaterialExported": false,
            "encodedMessageMaterialExported": false,
            "encryptionRandomizerMaterialExported": false,
            "noiseMaterialExported": false,
        })
    }

    fn minimal_verify_request(bridge_encryption: Value) -> Value {
        json!({
            "aggregateDerivationComponent": {},
            "setupPackage": {},
            "bridgeEncryption": bridge_encryption,
            "aggregateSelectionPolicyDigest": "1".repeat(128),
            "bridgeWitnessPrivacyProfileDigest": "2".repeat(128),
            "heParamDigest": "3".repeat(128),
        })
    }

    fn sampled_relation_checks() -> Value {
        json!([
            {
                "position": 0,
                "modulus": 140737487306753_u64,
                "componentZeroCoefficient": 7,
                "componentOneCoefficient": 11,
                "relationMatches": true
            }
        ])
    }

    fn sampled_relation_check_policy() -> Value {
        json!({
            "objectType": "M9BridgeSampledRelationCheckPolicy",
            "objectVersion": 1,
            "diagnosticOnly": true,
            "acceptedForBridgeProofVerification": false,
            "fullBridgeProofRequired": true,
            "sampledOnlyBridgeVerificationAccepted": false,
            "relationCheckSource": "first-data-prime-diagnostic",
            "sampledRelationCheckCount": 1
        })
    }

    fn first_refusal_message(value: &Value) -> &str {
        value["refusedObjects"][0]["message"]
            .as_str()
            .expect("structural rejection should include a refusal message")
    }

    fn variant_statement(participant_count: u64, option_count: u64, width: u64) -> Value {
        json!({
            "participantCount": participant_count,
            "optionCount": option_count,
            "shareVectorWidth": width,
        })
    }

    #[test]
    fn private_evaluator_variant_dimensions_accept_matrix_edges() {
        let minimum = bridge_variant_dimensions(&variant_statement(3, 2, 22))
            .expect("minimum matrix row should be accepted");
        assert_eq!(minimum.participant_count, 3);
        assert_eq!(minimum.option_count, 2);
        assert_eq!(minimum.share_vector_width, 22);
        assert_eq!(minimum.claim_tier, "micro-roster-outside-claim");

        let maximum = bridge_variant_dimensions(&variant_statement(20, 20, 220))
            .expect("maximum matrix row should be accepted");
        assert_eq!(maximum.participant_count, 20);
        assert_eq!(maximum.option_count, 20);
        assert_eq!(maximum.share_vector_width, 220);
        assert_eq!(maximum.claim_tier, "claim-candidate");
    }

    #[test]
    fn private_evaluator_variant_dimensions_reject_outside_matrix() {
        for statement in [
            variant_statement(2, 2, 22),
            variant_statement(21, 2, 22),
            variant_statement(3, 1, 11),
            variant_statement(3, 21, 231),
            variant_statement(3, 20, 219),
        ] {
            let error = bridge_variant_dimensions(&statement)
                .expect_err("outside-matrix dimensions should reject");
            assert!(
                error.message.contains("M9 bridge"),
                "unexpected error: {error:?}"
            );
        }
    }

    #[test]
    fn private_evaluator_rejects_public_artifact_drift() {
        let expected = json!({
            "ciphertextRoot": "1".repeat(128),
            "bridgeProofRoot": "2".repeat(128),
        });
        let mut actual = expected.clone();
        actual["ciphertextRoot"] = Value::String("3".repeat(128));
        let error =
            compare_bridge_relation_public_artifacts(&actual, &expected, "bridgeEncryption")
                .expect_err("mutated public artifact should reject");
        assert!(error.message.contains("ciphertextRoot"), "{error:?}");

        let mut with_extra_field = expected.clone();
        with_extra_field["unexpectedField"] = Value::Bool(true);
        let error = compare_bridge_relation_public_artifacts(
            &with_extra_field,
            &expected,
            "bridgeEncryption",
        )
        .expect_err("extra public artifact field should reject");
        assert!(error.message.contains("unexpectedField"), "{error:?}");
    }

    #[test]
    fn bridge_proof_target_contract_is_variant_parametric() {
        for width in [22_u64, 55, 220] {
            let target_contract =
                bridge_proof_target_contract_value(width, width).expect("target contract");
            let shared_witness_layout = target_contract["sharedWitnessLayout"]
                .as_object()
                .expect("shared witness layout should be an object");
            assert_eq!(
                target_contract["aggregateReducedCoordinateCount"],
                json!(width)
            );
            assert_eq!(
                target_contract["aggregateQuotientCoordinateCount"],
                json!(width)
            );
            assert_eq!(
                shared_witness_layout["aggregateIntegerShareCoordinateCount"],
                json!(width)
            );
            assert_eq!(
                shared_witness_layout["aggregateRelationRowCount"],
                json!(SHARE_COMMITMENT_MODULE_RANK as u64 + width)
            );
            assert_eq!(
                shared_witness_layout["sharedResponseScalarCount"],
                json!(3 * width + 64 + 4 * 32_768)
            );
        }
    }

    #[test]
    fn bridge_verifier_rejects_forged_checked_status_before_root_checks() {
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bridgeProofVerificationStatus": "BridgeProofRelationChecked",
                "privateMaterialDisclosure": private_material_disclosure(),
                "sampledPublicRelationChecks": sampled_relation_checks(),
                "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("bridgeProofBytesHex"),
            "{result}"
        );
    }

    #[test]
    fn bridge_verifier_rejects_public_witness_fields_before_root_checks() {
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bgvPlaintext": [1, 2, 3],
                "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
                "privateMaterialDisclosure": private_material_disclosure(),
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("bgvPlaintext"),
            "{result}"
        );
    }

    #[test]
    fn bridge_verifier_rejects_private_material_disclosure_flags() {
        let mut disclosure = private_material_disclosure();
        disclosure["noiseMaterialExported"] = Value::Bool(true);
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
                "privateMaterialDisclosure": disclosure,
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("noiseMaterialExported"),
            "{result}"
        );
    }

    #[test]
    fn bridge_proof_shell_requires_pending_relation_gap_status() {
        let proof_value = json!({
            "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
            "privateMaterialDisclosure": private_material_disclosure(),
        });
        let error = validate_bridge_proof_public_shell(&proof_value)
            .expect_err("missing relation gap status should reject");

        assert!(
            error.message.contains("bridgeRelationGapStatus"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_target_contract_rejects_dimension_mutation() {
        let relation_requirements = json!({
            "aggregateReducedCoordinateCount": 220,
            "aggregateQuotientCoordinateCount": 220,
        });
        let target_contract =
            bridge_proof_target_contract_value(220, 220).expect("target contract");
        let target_contract_digest =
            bridge_proof_target_contract_digest(&target_contract).expect("target digest");
        let mut bridge_statement = json!({
            "bridgeProofTargetContract": target_contract,
            "bridgeProofTargetContractDigest": target_contract_digest,
        });
        bridge_statement["bridgeProofTargetContract"]["aggregateReductionRowCount"] = json!(219);

        let error =
            validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
                .expect_err("mutated target contract should reject");

        assert!(
            error.message.contains("target contract does not match"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_target_contract_rejects_digest_mutation() {
        let relation_requirements = json!({
            "aggregateReducedCoordinateCount": 220,
            "aggregateQuotientCoordinateCount": 220,
        });
        let target_contract =
            bridge_proof_target_contract_value(220, 220).expect("target contract");
        let bridge_statement = json!({
            "bridgeProofTargetContract": target_contract,
            "bridgeProofTargetContractDigest": "0".repeat(128),
        });

        let error =
            validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
                .expect_err("mutated target contract digest should reject");

        assert!(
            error
                .message
                .contains("bridge proof target contract digest"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_target_contract_rejects_separate_subproof_closure() {
        let relation_requirements = json!({
            "aggregateReducedCoordinateCount": 220,
            "aggregateQuotientCoordinateCount": 220,
        });
        let target_contract =
            bridge_proof_target_contract_value(220, 220).expect("target contract");
        let target_contract_digest =
            bridge_proof_target_contract_digest(&target_contract).expect("target digest");
        let mut bridge_statement = json!({
            "bridgeProofTargetContract": target_contract,
            "bridgeProofTargetContractDigest": target_contract_digest,
        });
        bridge_statement["bridgeProofTargetContract"]["separateSubproofsAcceptedForClosure"] =
            json!(true);

        let error =
            validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
                .expect_err("separate subproof closure shortcut should reject");

        assert!(
            error.message.contains("target contract does not match"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_target_contract_rejects_shared_witness_layout_mutation() {
        let relation_requirements = json!({
            "aggregateReducedCoordinateCount": 220,
            "aggregateQuotientCoordinateCount": 220,
        });
        let target_contract =
            bridge_proof_target_contract_value(220, 220).expect("target contract");
        let target_contract_digest =
            bridge_proof_target_contract_digest(&target_contract).expect("target digest");
        let mut bridge_statement = json!({
            "bridgeProofTargetContract": target_contract,
            "bridgeProofTargetContractDigest": target_contract_digest,
        });
        bridge_statement["bridgeProofTargetContract"]["sharedWitnessLayout"]["sharedResponseScalarCount"] =
            json!(164_563);

        let error =
            validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
                .expect_err("mutated shared-witness layout should reject");

        assert!(
            error.message.contains("target contract does not match"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_target_contract_rejects_shared_witness_layout_digest_mutation() {
        let relation_requirements = json!({
            "aggregateReducedCoordinateCount": 220,
            "aggregateQuotientCoordinateCount": 220,
        });
        let target_contract =
            bridge_proof_target_contract_value(220, 220).expect("target contract");
        let target_contract_digest =
            bridge_proof_target_contract_digest(&target_contract).expect("target digest");
        let mut bridge_statement = json!({
            "bridgeProofTargetContract": target_contract,
            "bridgeProofTargetContractDigest": target_contract_digest,
        });
        bridge_statement["bridgeProofTargetContract"]["sharedWitnessLayoutDigest"] =
            json!("0".repeat(128));

        let error =
            validate_bridge_proof_target_contract(&bridge_statement, &relation_requirements)
                .expect_err("mutated shared-witness layout digest should reject");

        assert!(
            error.message.contains("target contract does not match"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_shell_rejects_claimed_shared_witness_closure() {
        let mut relation_gap_status = bridge_relation_gap_status_value();
        relation_gap_status["sharedWitnessBindingStatus"] =
            Value::String("SharedWitnessBindingRelationChecked".to_string());
        let proof_value = json!({
            "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
            "bridgeRelationGapStatus": relation_gap_status,
            "privateMaterialDisclosure": private_material_disclosure(),
        });
        let error = validate_bridge_proof_public_shell(&proof_value)
            .expect_err("claimed shared-witness closure should reject");

        assert!(
            error
                .message
                .contains("relation gap status must remain pending"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_proof_shell_rejects_sampled_only_acceptance() {
        let mut relation_gap_status = bridge_relation_gap_status_value();
        relation_gap_status["sampledOnlyBridgeVerificationAccepted"] = Value::Bool(true);
        let proof_value = json!({
            "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
            "bridgeRelationGapStatus": relation_gap_status,
            "privateMaterialDisclosure": private_material_disclosure(),
        });
        let error = validate_bridge_proof_public_shell(&proof_value)
            .expect_err("sampled-only acceptance should reject");

        assert!(
            error
                .message
                .contains("relation gap status must remain pending"),
            "{error:?}"
        );
    }

    #[test]
    fn bridge_verifier_rejects_sampled_relation_checks_as_acceptance() {
        let mut policy = sampled_relation_check_policy();
        policy["acceptedForBridgeProofVerification"] = Value::Bool(true);
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
                "privateMaterialDisclosure": private_material_disclosure(),
                "sampledPublicRelationChecks": sampled_relation_checks(),
                "sampledPublicRelationCheckPolicy": policy,
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("diagnostic-only"),
            "{result}"
        );
    }

    #[test]
    fn bridge_verifier_rejects_failed_sampled_relation_diagnostic() {
        let mut relation_checks = sampled_relation_checks();
        relation_checks[0]["relationMatches"] = Value::Bool(false);
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bridgeProofVerificationStatus": BRIDGE_PROOF_PENDING_STATUS,
                "privateMaterialDisclosure": private_material_disclosure(),
                "sampledPublicRelationChecks": relation_checks,
                "sampledPublicRelationCheckPolicy": sampled_relation_check_policy(),
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("diagnostic only"),
            "{result}"
        );
    }
}
