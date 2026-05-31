use super::*;
use super::{
    boundedness::{bridge_bgv_randomness_bound_status, bridge_bgv_randomness_bound_status_hash},
    dimensions::bridge_variant_dimensions,
    shared_witness::{
        BridgeSharedWitnessProverInput, bridge_shared_witness_proof_hash,
        bridge_shared_witness_zero_knowledge_status,
        bridge_shared_witness_zero_knowledge_status_hash, generate_bridge_shared_witness_proof,
    },
    statement::{
        BridgeProofStatementInput, bridge_proof_challenge_context_hash, bridge_proof_profile_hash,
        bridge_proof_statement_hash, build_bridge_proof_statement,
    },
    validation::{
        read_i64_array, read_u64_array, read_u64_object_field, required_protocol_hash_field,
        validate_bridge_randomness_source, validate_development_randomness_acknowledgement,
        validate_distinct_bridge_randomness_seeds, validate_encryption_randomness_seed_hex,
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
    let prover_randomness_source = required_string_field(
        request,
        "proverRandomnessSource",
        "generateAggregateBridgeEncryption",
    )?;
    validate_bridge_randomness_source(prover_randomness_source, "proverRandomnessSource")?;
    let encryption_randomness_seed_hex = required_string_field(
        request,
        "encryptionRandomnessSeedHex",
        "generateAggregateBridgeEncryption",
    )?;
    validate_encryption_randomness_seed_hex(encryption_randomness_seed_hex)?;
    let encryption_randomness_seed_source = required_string_field(
        request,
        "encryptionRandomnessSeedSource",
        "generateAggregateBridgeEncryption",
    )?;
    validate_bridge_randomness_source(
        encryption_randomness_seed_source,
        "encryptionRandomnessSeedSource",
    )?;
    validate_distinct_bridge_randomness_seeds(
        prover_randomness_hex,
        encryption_randomness_seed_hex,
    )?;
    validate_development_randomness_acknowledgement(
        request,
        prover_randomness_source,
        encryption_randomness_seed_source,
        "generateAggregateBridgeEncryption",
    )?;
    let aggregate_selection_policy_hash = required_protocol_hash_field(
        request,
        "aggregateSelectionPolicyHash",
        "generateAggregateBridgeEncryption",
    )?;
    let bridge_witness_privacy_profile_hash = required_protocol_hash_field(
        request,
        "bridgeWitnessPrivacyProfileHash",
        "generateAggregateBridgeEncryption",
    )?;
    let he_param_hash =
        required_protocol_hash_field(request, "heParamHash", "generateAggregateBridgeEncryption")?;
    let include_canonical_bytes_hex = request
        .get("includeCanonicalBytesHex")
        .and_then(Value::as_bool)
        == Some(true);

    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let proof_input = required_json_field(component, "proofInput", "aggregateDerivationComponent")?;
    let component_hash = required_string_field(
        component,
        "aggregateDerivationComponentHash",
        "aggregateDerivationComponent",
    )?;
    let statement_hash = required_string_field(
        statement,
        "aggregateDerivationStatementHash",
        "aggregateDerivationComponent.statement",
    )?;
    let contributor_identity = required_string_field(
        statement,
        "contributorIdentity",
        "aggregateDerivationComponent.statement",
    )?;
    let post_voting_closed_context_hash = required_string_field(
        statement,
        "postVotingClosedContextHash",
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
            "encrypted aggregate bridge aggregate witness width does not match the accepted variant shareVectorWidth",
        ));
    }
    if string_field(proof_input, "statementHash") != Some(statement_hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge proof input does not bind the accepted aggregate derivation statement",
        ));
    }

    let witness_relation_check = check_aggregate_derivation_witness_relation(
        proof_input,
        &aggregate_integer_share_vector,
        &aggregate_opening_randomness,
        canonical_turnout,
        prover_randomness_hex,
    )?;
    let trace = crate::bgv::commands::generate_encrypted_aggregate_bridge_ciphertext_relation_trace_from_slots(
        setup_package,
        contributor_identity,
        component_hash,
        statement_hash,
        post_voting_closed_context_hash,
        &witness_relation_check.reduced_field_vector,
        encryption_randomness_seed_hex,
        include_canonical_bytes_hex,
    )?;
    let mut encryption = trace.public_artifact.clone();
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        &encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?
    .to_string();
    let aggregate_derivation_verification_scope =
        requested_aggregate_derivation_verification_scope(
            request,
            "generateAggregateBridgeEncryption",
        )?;
    encryption
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge encryption trace must be an object",
            )
        })?
        .insert(
            "encryptedAggregateInputRoot".to_string(),
            Value::String(encrypted_aggregate_share_ciphertext_root.clone()),
        );
    let bridge_proof_profile_hash = bridge_proof_profile_hash()?;
    let bridge_proof_statement = build_bridge_proof_statement(BridgeProofStatementInput {
        component,
        setup_package,
        bridge_encryption: &encryption,
        bridge_proof_profile_hash: &bridge_proof_profile_hash,
        aggregate_selection_policy_hash,
        bridge_witness_privacy_profile_hash,
        he_param_hash,
        aggregate_derivation_verification_scope,
    })?;
    let bridge_proof_statement_hash = bridge_proof_statement_hash(&bridge_proof_statement)?;
    let bridge_proof_target_contract_hash = required_string_field(
        &bridge_proof_statement,
        "bridgeProofTargetContractHash",
        "bridgeProofStatement",
    )?;
    let bridge_proof_challenge_context_hash = bridge_proof_challenge_context_hash(
        &bridge_proof_profile_hash,
        &bridge_proof_statement_hash,
        bridge_proof_target_contract_hash,
    )?;
    let shared_witness_proof =
        generate_bridge_shared_witness_proof(BridgeSharedWitnessProverInput {
            setup_package,
            bridge_encryption: &encryption,
            proof_input,
            bridge_proof_statement_hash: &bridge_proof_statement_hash,
            bridge_proof_challenge_context_hash: &bridge_proof_challenge_context_hash,
            contributor_identity,
            aggregate_derivation_statement_hash: statement_hash,
            aggregate_integer_share_vector: &aggregate_integer_share_vector,
            aggregate_opening_randomness: &aggregate_opening_randomness,
            aggregate_reduced_coordinates: &witness_relation_check.reduced_field_vector,
            aggregate_quotient_vector: &witness_relation_check.quotient_vector,
            trace: &trace,
            prover_randomness_hex,
        })?;
    let shared_witness_proof_hash = bridge_shared_witness_proof_hash(&shared_witness_proof)?;
    let shared_witness_zero_knowledge_status = bridge_shared_witness_zero_knowledge_status(
        &bridge_proof_statement_hash,
        &shared_witness_proof_hash,
    );
    let shared_witness_zero_knowledge_status_hash =
        bridge_shared_witness_zero_knowledge_status_hash(&shared_witness_zero_knowledge_status)?;
    let bgv_randomness_bound_proof_status = bridge_bgv_randomness_bound_status(
        &bridge_proof_statement_hash,
        &shared_witness_proof_hash,
        &encrypted_aggregate_share_ciphertext_root,
        required_string_field(&encryption, "collectivePublicKeyRoot", "bridgeEncryption")?,
        required_string_field(
            &encryption,
            "collectivePublicKeyCoefficientRoot",
            "bridgeEncryption",
        )?,
        required_string_field(&encryption, "bgvPublicKeyRoot", "bridgeEncryption")?,
    );
    let bgv_randomness_bound_proof_status_hash =
        bridge_bgv_randomness_bound_status_hash(&bgv_randomness_bound_proof_status)?;
    let caller_supplied_development_randomness = prover_randomness_source
        == BRIDGE_RANDOMNESS_SOURCE_DEVELOPMENT_DETERMINISTIC
        || encryption_randomness_seed_source == BRIDGE_RANDOMNESS_SOURCE_DEVELOPMENT_DETERMINISTIC;
    let claim_bearing_entropy_evidence = prover_randomness_source
        == BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG
        && encryption_randomness_seed_source == BRIDGE_RANDOMNESS_SOURCE_FRESH_CSPRNG;
    let randomness_source_evidence = json!({
        "objectType": "AggregateBridgeRandomnessSourceEvidence",
        "objectVersion": 1,
        "proverRandomnessSource": prover_randomness_source,
        "encryptionRandomnessSeedSource": encryption_randomness_seed_source,
        "callerSuppliedDevelopmentRandomness": caller_supplied_development_randomness,
        "claimBearingEntropyEvidence": claim_bearing_entropy_evidence,
    });
    let prover_randomness_public_hash = derive_protocol_hash(
        "ProofBytesHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-prover-randomness-public-hash-v1",
            "proverRandomnessHex": prover_randomness_hex,
        }),
    )?;
    let mut proof_value = json!({
        "objectType": "SealedLatticeAggregateBridgeRelationProof",
        "objectVersion": 1,
        "profileId": BRIDGE_PROOF_PROFILE_ID,
        "bridgeProofProfileHash": bridge_proof_profile_hash,
        "proofBackend": BRIDGE_PROOF_BACKEND,
        "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        "bridgeSharedWitnessProof": shared_witness_proof,
        "bridgeSharedWitnessProofHash": shared_witness_proof_hash,
        "sharedWitnessZeroKnowledgeStatusEvidence": shared_witness_zero_knowledge_status,
        "sharedWitnessZeroKnowledgeStatusHash": shared_witness_zero_knowledge_status_hash,
        "bgvRandomnessBoundProofStatusEvidence": bgv_randomness_bound_proof_status,
        "bgvRandomnessBoundProofStatusHash": bgv_randomness_bound_proof_status_hash,
        "bridgeProofStatement": bridge_proof_statement,
        "bridgeProofStatementHash": bridge_proof_statement_hash,
        "bridgeProofChallengeContextHash": bridge_proof_challenge_context_hash,
        "bridgeProofTargetContractHash": bridge_proof_target_contract_hash
    });
    let proof_object = proof_value.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge proof value must be an object",
        )
    })?;
    for (field_name, field_value) in [
        (
            "aggregateDerivationComponentHash",
            Value::String(component_hash.to_string()),
        ),
        (
            "aggregateDerivationStatementHash",
            Value::String(statement_hash.to_string()),
        ),
        (
            "aggregateRelationSubproofHex",
            Value::String(witness_relation_check.proof_hex),
        ),
        (
            "aggregateRelationSubproofSizeBytes",
            json!(witness_relation_check.proof_size_bytes),
        ),
        (
            "aggregateRelationChallengeHex",
            Value::String(witness_relation_check.challenge_hex),
        ),
        (
            "aggregateRelationCommitmentHash",
            Value::String(witness_relation_check.relation_commitment_hash),
        ),
        (
            "aggregateReducedCoordinateCount",
            json!(witness_relation_check.reduced_field_vector.len()),
        ),
        (
            "aggregateQuotientCoordinateCount",
            json!(witness_relation_check.quotient_vector.len()),
        ),
        ("plaintextRoot", encryption["plaintextRoot"].clone()),
        ("ciphertextRoot", encryption["ciphertextRoot"].clone()),
        (
            "encryptedAggregateInputRoot",
            encryption["encryptedAggregateShareCiphertextRoot"].clone(),
        ),
        (
            "encryptedAggregateShareCiphertextRoot",
            encryption["encryptedAggregateShareCiphertextRoot"].clone(),
        ),
        (
            "collectivePublicKeyRoot",
            encryption["collectivePublicKeyRoot"].clone(),
        ),
        (
            "collectivePublicKeyCoefficientRoot",
            encryption["collectivePublicKeyCoefficientRoot"].clone(),
        ),
        ("bgvPublicKeyRoot", encryption["bgvPublicKeyRoot"].clone()),
        (
            "postVotingClosedContextHash",
            Value::String(post_voting_closed_context_hash.to_string()),
        ),
        (
            "aggregateDerivationVerificationScope",
            Value::String(aggregate_derivation_verification_scope.to_string()),
        ),
        (
            "proverRandomnessSource",
            Value::String(prover_randomness_source.to_string()),
        ),
        (
            "encryptionRandomnessSeedSource",
            Value::String(encryption_randomness_seed_source.to_string()),
        ),
        ("randomnessSourceEvidence", randomness_source_evidence),
        (
            "proverRandomnessPublicHash",
            Value::String(prover_randomness_public_hash),
        ),
        (
            "privateMaterialDisclosure",
            json!({
                "aggregateOpeningMaterialExported": false,
                "aggregateShareMaterialExported": false,
                "layoutMessageMaterialExported": false,
                "encodedMessageMaterialExported": false,
                "encryptionRandomizerMaterialExported": false,
                "noiseMaterialExported": false
            }),
        ),
        (
            "relationScope",
            Value::String("sealed-lattice-aggregate-bridge-relation".to_string()),
        ),
        ("singleContributionBridgeRelationChecked", Value::Bool(true)),
        ("scopedBridgeRelationClosure", Value::Bool(false)),
        ("finalBridgeTheoremClosure", Value::Bool(false)),
        ("bridgeClaimClosureVerified", Value::Bool(false)),
        (
            "bridgeClaimVerificationStatus",
            Value::String(BRIDGE_CLAIM_CLOSURE_STATUS.to_string()),
        ),
        (
            "bridgeVariantEvidenceStatus",
            Value::String(dimensions.evidence_tier.to_string()),
        ),
    ] {
        proof_object.insert(field_name.to_string(), field_value);
    }
    proof_object.insert(
        "bgvEncryptionKeyMaterialKind".to_string(),
        Value::String(BGV_ENCRYPTION_KEY_MATERIAL_KIND.to_string()),
    );
    proof_object.insert(
        "developmentKeyOnly".to_string(),
        Value::Bool(DEVELOPMENT_KEY_ONLY),
    );
    proof_object.insert(
        "thresholdDecryptable".to_string(),
        Value::Bool(THRESHOLD_DECRYPTABLE),
    );
    proof_object.insert(
        "claimBearingBridgeEncryption".to_string(),
        Value::Bool(CLAIM_BEARING_BRIDGE_ENCRYPTION),
    );
    let proof_json = canonical_json(&proof_value)?;
    let proof_bytes_hex = to_hex(proof_json.as_bytes());
    let proof_bytes_hash = derive_protocol_hash_for_ascii_string_payload(
        "ProofBytesHash",
        "sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1",
        "proofBytesHex",
        &proof_bytes_hex,
    )?;
    let proof_root = derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentHash": component_hash,
            "aggregateDerivationStatementHash": statement_hash,
            "bridgeProofProfileHash": proof_value["bridgeProofProfileHash"],
            "bridgeProofStatementHash": proof_value["bridgeProofStatementHash"],
            "bridgeProofChallengeContextHash": proof_value["bridgeProofChallengeContextHash"],
            "bridgeSharedWitnessProofHash": proof_value["bridgeSharedWitnessProofHash"],
            "sharedWitnessZeroKnowledgeStatusHash": proof_value["sharedWitnessZeroKnowledgeStatusHash"],
            "bgvRandomnessBoundProofStatusHash": proof_value["bgvRandomnessBoundProofStatusHash"],
            "proofBytesHash": proof_bytes_hash,
            "encryptedAggregateShareCiphertextRoot": encryption["encryptedAggregateShareCiphertextRoot"],
            "collectivePublicKeyRoot": encryption["collectivePublicKeyRoot"],
            "collectivePublicKeyCoefficientRoot": encryption["collectivePublicKeyCoefficientRoot"],
            "bgvPublicKeyRoot": encryption["bgvPublicKeyRoot"],
        }),
    )?;

    let object = encryption.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge encryption result must be an object",
        )
    })?;
    object.insert(
        "aggregateDerivationComponentHash".to_string(),
        Value::String(component_hash.to_string()),
    );
    object.insert(
        "aggregateDerivationStatementHash".to_string(),
        Value::String(statement_hash.to_string()),
    );
    object.insert(
        "bridgeProofProfileHash".to_string(),
        proof_value["bridgeProofProfileHash"].clone(),
    );
    object.insert(
        "bridgeProofStatementHash".to_string(),
        proof_value["bridgeProofStatementHash"].clone(),
    );
    object.insert(
        "bridgeProofChallengeContextHash".to_string(),
        proof_value["bridgeProofChallengeContextHash"].clone(),
    );
    object.insert(
        "bridgeProofTargetContractHash".to_string(),
        proof_value["bridgeProofTargetContractHash"].clone(),
    );
    object.insert(
        "bridgeProofBytesHex".to_string(),
        Value::String(proof_bytes_hex),
    );
    object.insert(
        "bridgeProofBytesHash".to_string(),
        Value::String(proof_bytes_hash),
    );
    object.insert("bridgeProofRoot".to_string(), Value::String(proof_root));
    object.insert(
        "bridgeSharedWitnessProofHash".to_string(),
        proof_value["bridgeSharedWitnessProofHash"].clone(),
    );
    object.insert(
        "sharedWitnessZeroKnowledgeStatusHash".to_string(),
        proof_value["sharedWitnessZeroKnowledgeStatusHash"].clone(),
    );
    object.insert(
        "bgvRandomnessBoundProofStatusHash".to_string(),
        proof_value["bgvRandomnessBoundProofStatusHash"].clone(),
    );
    object.insert(
        "encryptedAggregateInputRoot".to_string(),
        proof_value["encryptedAggregateInputRoot"].clone(),
    );
    object.insert(
        "proverRandomnessSource".to_string(),
        proof_value["proverRandomnessSource"].clone(),
    );
    object.insert(
        "encryptionRandomnessSeedSource".to_string(),
        proof_value["encryptionRandomnessSeedSource"].clone(),
    );
    object.insert(
        "randomnessSourceEvidence".to_string(),
        proof_value["randomnessSourceEvidence"].clone(),
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
        "aggregateRelationCommitmentHash".to_string(),
        proof_value["aggregateRelationCommitmentHash"].clone(),
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
        "bgvEncryptionKeyMaterialKind".to_string(),
        Value::String(BGV_ENCRYPTION_KEY_MATERIAL_KIND.to_string()),
    );
    object.insert(
        "developmentKeyOnly".to_string(),
        Value::Bool(DEVELOPMENT_KEY_ONLY),
    );
    object.insert(
        "thresholdDecryptable".to_string(),
        Value::Bool(THRESHOLD_DECRYPTABLE),
    );
    object.insert(
        "claimBearingBridgeEncryption".to_string(),
        Value::Bool(CLAIM_BEARING_BRIDGE_ENCRYPTION),
    );
    object.insert(
        "aggregateDerivationVerificationScope".to_string(),
        Value::String(aggregate_derivation_verification_scope.to_string()),
    );
    object.insert(
        "plaintextCanonicalLiftProofStatus".to_string(),
        Value::String(PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS.to_string()),
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
        "BgvPublicKeyCoefficientMaterialBound",
        DECRYPTABLE_BGV_CIPHERTEXT_CONVENTION_STATUS,
        TARGET_THRESHOLD_DECRYPTABILITY_CERTIFIED_STATUS,
        "CoefficientDomainCanonical",
        "BridgeProofRelationChecked",
        "BridgeProofImplementationEvidenceOnly",
        SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS,
        aggregate_derivation_verification_scope,
        "BridgeProofClaimClosureMissing",
    ];
    status_labels.push(match dimensions.evidence_tier {
        "representative-row-evidence" => "RepresentativeBridgeMatrixRowEvidence",
        _ => "FullBridgeMatrixRowEvidenceMissing",
    });
    object.insert("statusLabels".to_string(), json!(status_labels));

    Ok(encryption)
}
