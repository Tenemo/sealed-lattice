use super::*;
use super::{
    dimensions::bridge_variant_dimensions,
    target_contract::{
        bridge_proof_target_contract_digest, bridge_proof_target_contract_value,
        validate_bridge_proof_target_contract,
    },
    validation::{
        read_bool_object_field, read_u64_at_path, read_u64_object_field,
        require_matching_string_field, required_string_at_path,
    },
};

pub(super) fn bridge_proof_profile_digest() -> CanonicalResult<String> {
    derive_protocol_digest(
        "BridgeProofProfileDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-proof-profile-v1",
            "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
            "proofBackend": BRIDGE_PROOF_BACKEND,
            "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
        }),
    )
}

pub(super) fn build_bridge_proof_statement(
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
    let encrypted_aggregate_input_root = required_string_field(
        bridge_encryption,
        "encryptedAggregateInputRoot",
        "bridgeEncryption",
    )?;
    if encrypted_aggregate_input_root != encrypted_aggregate_share_ciphertext_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge encrypted aggregate input root does not match the aggregate-share ciphertext root for the current prototype layout",
        ));
    }
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
        "sharedWitnessChallengeBitsPerCheck": SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK,
        "sharedWitnessCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64,
        "sharedWitnessSoundnessBits": BRIDGE_SHARED_WITNESS_SOUNDNESS_BITS,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "bridgeClaimClosureStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
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
        "encryptedAggregateInputRoot".to_string(),
        Value::String(encrypted_aggregate_input_root.to_string()),
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

pub(super) fn bridge_proof_statement_digest(
    bridge_proof_statement: &Value,
) -> CanonicalResult<String> {
    let mut digest_input = Map::new();
    digest_input.insert(
        "purpose".to_string(),
        Value::String("sealed-lattice-aggregate-bridge-proof-statement-v1".to_string()),
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
        "encryptedAggregateInputRoot",
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
        "sharedWitnessZeroKnowledgeStatus",
        "aggregateToPlaintextBindingStatus",
        "bgvEncryptionProofStatus",
        "bgvRandomnessBoundProofStatus",
        "rnsCrtConsistencyProofStatus",
        "bridgeClaimClosureStatus",
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
        "sharedWitnessChallengeBitsPerCheck",
        "sharedWitnessCheckCount",
        "sharedWitnessSoundnessBits",
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
            "purpose": "sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1",
            "policy": policy,
        }),
    )
}
