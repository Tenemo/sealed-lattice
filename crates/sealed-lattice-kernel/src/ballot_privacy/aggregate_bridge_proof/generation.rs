use super::*;
use super::{
    boundedness::{bridge_bgv_randomness_bound_status, bridge_bgv_randomness_bound_status_digest},
    dimensions::bridge_variant_dimensions,
    shared_witness::{
        BridgeSharedWitnessProverInput, bridge_shared_witness_proof_digest,
        bridge_shared_witness_zero_knowledge_status,
        bridge_shared_witness_zero_knowledge_status_digest, generate_bridge_shared_witness_proof,
    },
    statement::{
        bridge_proof_profile_digest, bridge_proof_statement_digest, build_bridge_proof_statement,
    },
    validation::{
        read_i64_array, read_u64_array, read_u64_object_field, required_protocol_digest_field,
        validate_prover_randomness_hex,
    },
};

pub(super) fn generate_aggregate_bridge_encryption(request: &Value) -> CanonicalResult<Value> {
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
    validate_prover_randomness_hex(prover_randomness_hex)?;
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
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        &encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?
    .to_string();
    encryption
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "M9 bridge encryption trace must be an object",
            )
        })?
        .insert(
            "encryptedAggregateInputRoot".to_string(),
            Value::String(encrypted_aggregate_share_ciphertext_root.clone()),
        );
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
    let shared_witness_proof_digest = bridge_shared_witness_proof_digest(&shared_witness_proof)?;
    let shared_witness_zero_knowledge_status = bridge_shared_witness_zero_knowledge_status(
        &bridge_proof_statement_digest,
        &shared_witness_proof_digest,
    );
    let shared_witness_zero_knowledge_status_digest =
        bridge_shared_witness_zero_knowledge_status_digest(&shared_witness_zero_knowledge_status)?;
    let bgv_randomness_bound_proof_status = bridge_bgv_randomness_bound_status(
        &bridge_proof_statement_digest,
        &shared_witness_proof_digest,
        &encrypted_aggregate_share_ciphertext_root,
        required_string_field(&encryption, "collectivePublicKeyRoot", "bridgeEncryption")?,
        required_string_field(&encryption, "bgvPublicKeyRoot", "bridgeEncryption")?,
    );
    let bgv_randomness_bound_proof_status_digest =
        bridge_bgv_randomness_bound_status_digest(&bgv_randomness_bound_proof_status)?;
    let proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeRelationProof",
        "objectVersion": 1,
        "profileId": BRIDGE_PROOF_PROFILE_ID,
        "bridgeProofProfileDigest": bridge_proof_profile_digest,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "bridgeSharedWitnessProof": shared_witness_proof,
        "bridgeSharedWitnessProofDigest": shared_witness_proof_digest,
        "sharedWitnessZeroKnowledgeStatusEvidence": shared_witness_zero_knowledge_status,
        "sharedWitnessZeroKnowledgeStatusDigest": shared_witness_zero_knowledge_status_digest,
        "bgvRandomnessBoundProofStatusEvidence": bgv_randomness_bound_proof_status,
        "bgvRandomnessBoundProofStatusDigest": bgv_randomness_bound_proof_status_digest,
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
        "encryptedAggregateInputRoot": encryption["encryptedAggregateShareCiphertextRoot"],
        "encryptedAggregateShareCiphertextRoot": encryption["encryptedAggregateShareCiphertextRoot"],
        "collectivePublicKeyRoot": encryption["collectivePublicKeyRoot"],
        "bgvPublicKeyRoot": encryption["bgvPublicKeyRoot"],
        "postVotingClosedContextDigest": post_voting_closed_context_digest,
        "proverRandomnessPublicDigest": derive_protocol_digest(
            "ProofBytesDigest",
            &json!({
                "purpose": "sealed-lattice-aggregate-bridge-prover-randomness-public-digest-v1",
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
        "relationScope": "sealed-lattice-aggregate-bridge-relation",
        "singleContributionBridgeRelationChecked": true,
        "scopedBridgeRelationClosure": false,
        "finalBridgeTheoremClosure": false,
        "bridgeClaimClosureVerified": false,
        "bridgeClaimVerificationStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "bridgeVariantEvidenceStatus": dimensions.evidence_tier
    });
    let proof_json = canonical_json(&proof_value)?;
    let proof_bytes_hex = to_hex(proof_json.as_bytes());
    let proof_bytes_digest = derive_protocol_digest(
        "ProofBytesDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": proof_bytes_hex,
        }),
    )?;
    let proof_root = derive_protocol_digest(
        "BridgeProofRecordDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentDigest": component_digest,
            "aggregateDerivationStatementDigest": statement_digest,
            "bridgeProofProfileDigest": proof_value["bridgeProofProfileDigest"],
            "bridgeProofStatementDigest": proof_value["bridgeProofStatementDigest"],
            "bridgeSharedWitnessProofDigest": proof_value["bridgeSharedWitnessProofDigest"],
            "sharedWitnessZeroKnowledgeStatusDigest": proof_value["sharedWitnessZeroKnowledgeStatusDigest"],
            "bgvRandomnessBoundProofStatusDigest": proof_value["bgvRandomnessBoundProofStatusDigest"],
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
        "bridgeSharedWitnessProofDigest".to_string(),
        proof_value["bridgeSharedWitnessProofDigest"].clone(),
    );
    object.insert(
        "sharedWitnessZeroKnowledgeStatusDigest".to_string(),
        proof_value["sharedWitnessZeroKnowledgeStatusDigest"].clone(),
    );
    object.insert(
        "bgvRandomnessBoundProofStatusDigest".to_string(),
        proof_value["bgvRandomnessBoundProofStatusDigest"].clone(),
    );
    object.insert(
        "encryptedAggregateInputRoot".to_string(),
        proof_value["encryptedAggregateInputRoot"].clone(),
    );
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
    object.insert("bridgeClaimClosureVerified".to_string(), Value::Bool(false));
    object.insert(
        "bridgeClaimVerificationStatus".to_string(),
        Value::String(BRIDGE_CLAIM_CLOSURE_STATUS.to_string()),
    );
    object.insert(
        "bridgeVariantEvidenceStatus".to_string(),
        Value::String(dimensions.evidence_tier.to_string()),
    );
    let mut status_labels = vec![
        "AggregateBridgePlaintextAssembled",
        "AggregateBridgeCiphertextGenerated",
        "CollectivePublicKeyRootBound",
        "CoefficientDomainCanonical",
        "BridgeProofRelationChecked",
        "BridgeProofImplementationEvidenceOnly",
        SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "BridgeProofClaimClosureMissing",
    ];
    status_labels.push(match dimensions.evidence_tier {
        "representative-row-evidence" => "RepresentativeBridgeMatrixRowEvidence",
        _ => "FullBridgeMatrixRowEvidenceMissing",
    });
    object.insert("statusLabels".to_string(), json!(status_labels));

    Ok(encryption)
}
