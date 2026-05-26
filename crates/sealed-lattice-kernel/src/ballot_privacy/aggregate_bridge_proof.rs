use serde_json::{Map, Value, json};

use crate::{
    bgv::profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::{canonical_json, derive_protocol_digest, to_hex},
    transcript_core::decode_hex,
};

use super::protocol_constants::BALLOT_PRIVACY_FIELD_MODULUS;
use super::{
    SHARE_COMMITMENT_MODULE_RANK, SHARE_COMMITMENT_OPENING_DIMENSION,
    check_aggregate_derivation_witness_relation, is_protocol_digest, required_json_field,
    required_string_field, string_field, structural_refusal, structural_rejection,
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
const HWANG_PIOP_DEFERRED_STATUS: &str = "DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze";
const PLAINTEXT_ENCODING_RELATION: &str = "BGVBatchEncode65537InverseNegacyclicNtt";
const NAIVE_LINEAR_EXPANSION_BACKEND_STATUS: &str = "InfeasibleForClaimBearingM9";
const SAME_WITNESS_LINKAGE_MODEL: &str =
    "SingleTranscriptSharedWitnessOrExplicitSameWitnessLinkRequired";
const SEPARATE_SUBPROOFS_CLOSURE_STATUS: &str = "RejectedForM9Closure";
const PLAINTEXT_ROOT_PROOF_BINDING_PENDING_STATUS: &str = "PlaintextRootProofBindingPending";

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
    let share_vector_width = read_usize_object_field(
        statement,
        "shareVectorWidth",
        "aggregateDerivationComponent.statement",
    )?;
    let aggregate_integer_share_vector =
        read_u64_array(witness, "aggregateIntegerShareVector", "aggregateWitness")?;
    let aggregate_opening_randomness =
        read_i64_array(witness, "aggregateOpeningRandomness", "aggregateWitness")?;
    if aggregate_integer_share_vector.len() != share_vector_width {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "M9 bridge aggregate witness width does not match the accepted M6 statement",
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
    let mut encryption = crate::bgv::commands::generate_m9_bridge_ciphertext_from_slots(
        setup_package,
        contributor_identity,
        component_digest,
        statement_digest,
        post_voting_closed_context_digest,
        &witness_relation_check.reduced_field_vector,
        prover_randomness_hex,
        include_canonical_bytes_hex,
    )?;
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
    let bridge_relation_gap_status = bridge_relation_gap_status_value();
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeEncryptionEvidence",
        "objectVersion": 1,
        "profileId": BRIDGE_PROOF_PROFILE_ID,
        "bridgeProofProfileDigest": bridge_proof_profile_digest,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "bridgeRelationGapStatus": bridge_relation_gap_status,
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
        Value::String(BRIDGE_PROOF_PENDING_STATUS.to_string()),
    );

    Ok(encryption)
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
    if string_field(&proof_value, "objectType")
        != Some("SealedLatticeAggregateBridgeEncryptionEvidence")
        || read_u64_object_field(&proof_value, "objectVersion", "bridgeProof")? != 1
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

    Ok(json!({
        "ok": true,
        "backendAvailable": true,
        "operation": "verifyAggregateBridgeEncryption",
        "statusLabels": [
            "BridgeProofEvidenceChecked",
            "BridgeProofBackendStillRequired",
            "FinalBridgeTheoremPending"
        ],
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
        "bridgeProofVerificationStatus": "BridgeProofBackendPending",
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
    }))
}

fn bridge_relation_gap_status_value() -> Value {
    json!({
        "objectType": "AggregateBridgeRelationGapStatus",
        "objectVersion": 1,
        "scopedBridgeRelationClosure": false,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_PENDING_STATUS,
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
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_PENDING_STATUS,
        "sameWitnessLinkageModel": SAME_WITNESS_LINKAGE_MODEL,
        "separateSubproofsClosureStatus": SEPARATE_SUBPROOFS_CLOSURE_STATUS,
        "separateSubproofsAcceptedForClosure": false,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS,
        "proofFriendlyPlaintextBindingRequired": true,
        "plaintextRootProofBindingStatus": PLAINTEXT_ROOT_PROOF_BINDING_PENDING_STATUS,
        "publicPlaintextRootAcceptedAsClosureEvidence": false,
        "sharedWitnessLayout": shared_witness_layout,
        "sharedWitnessLayoutDigest": shared_witness_layout_digest,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_PENDING_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS,
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
    let plaintext_encoding_quotient_count = polynomial_degree;
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
        "shareVectorWidth": share_vector_width,
    });
    let setup_binding = json!({
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
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_PENDING_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_PENDING_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_PENDING_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_PENDING_STATUS,
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

fn validate_bridge_private_material_disclosure(proof_value: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    let disclosure = required_json_field(proof_value, "privateMaterialDisclosure", "bridgeProof")?;

    validate_bridge_private_material_disclosure_flags(disclosure, "bridgeProof")
}

fn validate_bridge_proof_public_shell(proof_value: &Value) -> CanonicalResult<()> {
    reject_forbidden_public_bridge_fields(proof_value, "bridgeProof")?;
    validate_bridge_relation_gap_status(proof_value)?;
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
    if string_field(bridge_encryption, "bridgeProofVerificationStatus")
        != Some(BRIDGE_PROOF_PENDING_STATUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge encryption shell must remain BridgeProofBackendPending until the shared-witness proof verifier closes",
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

    #[test]
    fn bridge_verifier_rejects_forged_checked_status_before_root_checks() {
        let result = verify_aggregate_bridge_encryption_from_command_request(
            &minimal_verify_request(json!({
                "bridgeProofVerificationStatus": "BridgeProofRelationChecked",
                "privateMaterialDisclosure": private_material_disclosure(),
            })),
        );

        assert_eq!(result["ok"], false);
        assert!(
            first_refusal_message(&result).contains("must remain BridgeProofBackendPending"),
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
