use super::*;
use super::{
    dimensions::bridge_variant_dimensions,
    plaintext_lift, shared_witness,
    target_contract::{
        bridge_proof_target_contract_hash, bridge_proof_target_contract_value,
        validate_bridge_proof_target_contract,
    },
    validation::{
        read_bool_object_field, read_u64_at_path, read_u64_object_field,
        require_matching_string_field, required_string_at_path,
    },
};

pub(super) fn bridge_proof_profile_hash(
    claim_status: BridgeClaimStatus,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofProfileHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-proof-profile-v1",
            "bridgeProofProfileId": BRIDGE_PROOF_PROFILE_ID,
            "proofBackend": BRIDGE_PROOF_BACKEND,
            "bgvEncryptionProofSubrelation": BGV_ENCRYPTION_PROOF_SUBRELATION,
            "bgvEncryptionKeyMaterialKind": BGV_ENCRYPTION_KEY_MATERIAL_KIND,
            "developmentKeyOnly": DEVELOPMENT_KEY_ONLY,
            "thresholdDecryptable": THRESHOLD_DECRYPTABLE,
            "claimBearingBridgeEncryption": claim_status.claim_bearing_bridge_encryption,
        }),
    )
}

pub(super) struct BridgeProofStatementInput<'a> {
    pub(super) component: &'a Value,
    pub(super) setup_package: &'a Value,
    pub(super) bridge_encryption: &'a Value,
    pub(super) bridge_proof_profile_hash: &'a str,
    pub(super) aggregate_selection_policy_hash: &'a str,
    pub(super) bridge_witness_privacy_profile_hash: &'a str,
    pub(super) he_param_hash: &'a str,
    pub(super) aggregate_derivation_verification_scope: &'a str,
    pub(super) claim_status: BridgeClaimStatus,
}

pub(super) fn build_bridge_proof_statement(
    input: BridgeProofStatementInput<'_>,
) -> CanonicalResult<Value> {
    validate_aggregate_derivation_verification_scope(
        input.aggregate_derivation_verification_scope,
    )?;
    let component = input.component;
    let setup_package = input.setup_package;
    let bridge_encryption = input.bridge_encryption;
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
    let aggregate_derivation_component_hash = required_string_field(
        component,
        "aggregateDerivationComponentHash",
        "aggregateDerivationComponent",
    )?;
    let aggregate_derivation_statement_hash = required_string_field(
        component_statement,
        "aggregateDerivationStatementHash",
        "aggregateDerivationComponent.statement",
    )?;
    let aggregate_share_commitment_hash = required_string_field(
        aggregate_commitment,
        "aggregateShareCommitmentHash",
        "aggregateDerivationComponent.aggregateCommitment",
    )?;
    require_matching_string_field(
        component_statement,
        "aggregateShareCommitmentHash",
        aggregate_share_commitment_hash,
        "aggregate share commitment hash",
    )?;
    let share_commitment_message_bound_cert_hash = required_string_field(
        share_commitment_message_bound_cert,
        "shareCommitmentMessageBoundCertHash",
        "aggregateDerivationComponent.shareCommitmentMessageBoundCert",
    )?;
    require_matching_string_field(
        component_statement,
        "shareCommitmentMessageBoundCertHash",
        share_commitment_message_bound_cert_hash,
        "share commitment message-bound certificate hash",
    )?;
    validate_bridge_share_commitment_bound_cert(
        share_commitment_message_bound_cert,
        component_statement,
    )?;
    let setup_manifest_hash = required_string_at_path(
        setup_package,
        &["setupInputs", "manifestHash"],
        "setupPackage",
    )?;
    let setup_roster_hash = required_string_at_path(
        setup_package,
        &["setupInputs", "rosterHash"],
        "setupPackage",
    )?;
    let setup_threshold_profile_hash = required_string_at_path(
        setup_package,
        &["setupInputs", "thresholdProfileHash"],
        "setupPackage",
    )?;
    let setup_package_hash =
        required_string_field(setup_package, "setupPackageHash", "setupPackage")?;
    let setup_participant_count = read_u64_at_path(
        setup_package,
        &["setupInputs", "participantCount"],
        "setupPackage",
    )?;
    let dimensions = bridge_variant_dimensions(component_statement)?;
    if setup_participant_count != dimensions.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge setup participant count does not match the aggregate statement participantCount",
        ));
    }
    require_matching_string_field(
        component_statement,
        "manifestHash",
        setup_manifest_hash,
        "manifest hash",
    )?;
    require_matching_string_field(
        component_statement,
        "rosterHash",
        setup_roster_hash,
        "roster hash",
    )?;
    require_matching_string_field(
        component_statement,
        "thresholdProfileHash",
        setup_threshold_profile_hash,
        "threshold profile hash",
    )?;
    let share_vector_width = read_u64_object_field(
        component_statement,
        "shareVectorWidth",
        "aggregateDerivationComponent.statement",
    )?;
    let encrypted_aggregate_input_layout_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateInputLayoutHash"],
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
            "encrypted aggregate bridge encrypted aggregate input root does not match the aggregate-share ciphertext root for the current prototype layout",
        ));
    }
    let encrypted_aggregate_bridge_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateBridgeHash"],
        "setupPackage",
    )?;
    let encrypted_aggregate_target_basis_root = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateTargetBasisRoot"],
        "setupPackage",
    )?;
    let encrypted_aggregate_reconstruction_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "encryptedAggregateReconstructionHash"],
        "setupPackage",
    )?;
    let bgv_batch_encoder_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "batchEncoderHash"],
        "setupPackage",
    )?;
    let ballot_score_encoding_profile_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "ballotScoreEncodingProfileHash"],
        "setupPackage",
    )?;
    let ballot_share_layout_profile_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "ballotShareLayoutProfileHash"],
        "setupPackage",
    )?;
    let aggregate_input_encoding_profile_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "aggregateInputEncodingProfileHash"],
        "setupPackage",
    )?;
    let encoded_share_vector_layout_hash = required_string_field(
        component_statement,
        "encodedShareVectorLayoutHash",
        "aggregateDerivationComponent.statement",
    )?;
    let encoded_aggregate_layout_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "encodedAggregateLayoutHash"],
        "setupPackage",
    )?;
    let top_k_evaluator_input_layout_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "topKEvaluatorInputLayoutHash"],
        "setupPackage",
    )?;
    let bgv_profile_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "profileHash"],
        "setupPackage",
    )?;
    let rust_bgv_backend_profile_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "backendProfileHash"],
        "setupPackage",
    )?;
    let canonical_ciphertext_convention_hash = required_string_at_path(
        setup_package,
        &["profileBindings", "canonicalCiphertextConventionHash"],
        "setupPackage",
    )?;
    let collective_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
        "setupPackage",
    )?;
    let collective_public_key_coefficient_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyCoefficientRoot"],
        "setupPackage",
    )?;
    let bgv_public_key_root = required_string_at_path(
        setup_package,
        &["collectivePublicKey", "bgvPublicKeyRoot"],
        "setupPackage",
    )?;
    let component_binding = json!({
        "aggregateDerivationStatementHash": aggregate_derivation_statement_hash,
        "shareCommitmentMessageBoundCertHash": share_commitment_message_bound_cert_hash,
        "componentProofStatementHash": required_string_field(
            component_proof_input,
            "componentProofStatementHash",
            "aggregateDerivationComponent.proofInput",
        )?,
        "componentProofBytesHash": required_string_field(
            aggregate_proof_record,
            "proofBytesHash",
            "aggregateDerivationComponent.proofRecord",
        )?,
        "participantCount": dimensions.participant_count,
        "optionCount": dimensions.option_count,
        "shareVectorWidth": share_vector_width,
    });
    let setup_binding = json!({
        "setupPackageHash": setup_package_hash,
        "collectivePublicKeyCoefficientRoot": collective_public_key_coefficient_root,
        "encryptedAggregateBridgeHash": encrypted_aggregate_bridge_hash,
        "encryptedAggregateTargetBasisRoot": encrypted_aggregate_target_basis_root,
        "encryptedAggregateReconstructionHash": encrypted_aggregate_reconstruction_hash,
        "bgvBatchEncoderHash": bgv_batch_encoder_hash,
        "bridgeLayoutHash": encrypted_aggregate_input_layout_hash,
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash,
        "ballotShareLayoutProfileHash": ballot_share_layout_profile_hash,
        "aggregateInputEncodingProfileHash": aggregate_input_encoding_profile_hash,
        "encodedShareVectorLayoutHash": encoded_share_vector_layout_hash,
        "encodedAggregateLayoutHash": encoded_aggregate_layout_hash,
        "topKEvaluatorInputLayoutHash": top_k_evaluator_input_layout_hash,
        "bgvProfileHash": bgv_profile_hash,
        "rustBgvBackendProfileHash": rust_bgv_backend_profile_hash,
        "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash,
        "setupParticipantCount": setup_participant_count,
    });
    let context_binding = json!({
        "ceremonyId": required_string_field(
            component_statement,
            "ceremonyId",
            "aggregateDerivationComponent.statement",
        )?,
        "pollSpecHash": required_string_field(
            component_statement,
            "pollSpecHash",
            "aggregateDerivationComponent.statement",
        )?,
        "thresholdProfileHash": setup_threshold_profile_hash,
        "ballotSetHash": required_string_field(
            component_statement,
            "ballotSetHash",
            "aggregateDerivationComponent.statement",
        )?,
        "votingClosedBoardHeadHash": required_string_field(
            component_statement,
            "votingClosedBoardHeadHash",
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
        "contributorRosterExternalAcceptanceHash": required_string_field(
            component_statement,
            "contributorRosterExternalAcceptanceHash",
            "aggregateDerivationComponent.statement",
        )?,
        "contributorActionContextHash": required_string_field(
            component_statement,
            "contributorActionContextHash",
            "aggregateDerivationComponent.statement",
        )?,
    });
    let ciphertext_binding = json!({
        "plaintextRoot": required_string_field(bridge_encryption, "plaintextRoot", "bridgeEncryption")?,
        "ciphertextRoot": required_string_field(bridge_encryption, "ciphertextRoot", "bridgeEncryption")?,
        "plaintextCoefficientBindingCommitmentHash": required_string_field(
            bridge_encryption,
            "plaintextCoefficientBindingCommitmentHash",
            "bridgeEncryption",
        )?,
        "proofFriendlyPlaintextLiftBindingHash": required_string_field(
            bridge_encryption,
            "proofFriendlyPlaintextLiftBindingHash",
            "bridgeEncryption",
        )?,
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
    let expected_batch_encoding_bound_certificate =
        crate::bgv::encrypted_aggregate_bridge_batch_lift_bound_certificate_value(
            dimensions.share_vector_width,
        )?;
    let expected_batch_encoding_bound_certificate_hash =
        crate::bgv::encrypted_aggregate_bridge_batch_lift_bound_certificate_hash(
            &expected_batch_encoding_bound_certificate,
        )?;
    let batch_encoding_bound_certificate = required_json_field(
        bridge_encryption,
        "batchEncodingBoundCertificate",
        "bridgeEncryption",
    )?;
    if batch_encoding_bound_certificate != &expected_batch_encoding_bound_certificate {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge batch encoding bound certificate does not match the variant dimensions",
        ));
    }
    require_matching_string_field(
        bridge_encryption,
        "batchEncodingBoundCertificateHash",
        &expected_batch_encoding_bound_certificate_hash,
        "batch encoding bound certificate hash",
    )?;
    let expected_plaintext_lift_binding =
        plaintext_lift::proof_friendly_plaintext_lift_binding_value(
            setup_package,
            bridge_encryption,
        )?;
    let expected_plaintext_lift_binding_hash =
        plaintext_lift::proof_friendly_plaintext_lift_binding_hash(
            &expected_plaintext_lift_binding,
        )?;
    let plaintext_lift_binding = required_json_field(
        bridge_encryption,
        "proofFriendlyPlaintextLiftBinding",
        "bridgeEncryption",
    )?;
    if plaintext_lift_binding != &expected_plaintext_lift_binding {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge proof-friendly plaintext lift binding does not match the public inputs",
        ));
    }
    require_matching_string_field(
        bridge_encryption,
        "proofFriendlyPlaintextLiftBindingHash",
        &expected_plaintext_lift_binding_hash,
        "proof-friendly plaintext lift binding hash",
    )?;
    let sampled_public_relation_check_policy = required_json_field(
        bridge_encryption,
        "sampledPublicRelationCheckPolicy",
        "bridgeEncryption",
    )?;
    let sampled_public_relation_check_policy_hash =
        sampled_public_relation_check_policy_hash(sampled_public_relation_check_policy)?;
    let batch_encoding_bound_certificate_hash = required_string_field(
        bridge_encryption,
        "batchEncodingBoundCertificateHash",
        "bridgeEncryption",
    )?;
    let relation_requirements = json!({
        "aggregateReducedCoordinateCount": share_vector_width,
        "aggregateQuotientCoordinateCount": share_vector_width,
        "sharedWitnessBindingRequired": true,
        "sharedWitnessBindingStatus": SHARED_WITNESS_BINDING_CHECKED_STATUS,
        "sharedWitnessChallengeBitsPerCheck": SHARED_WITNESS_CHALLENGE_BITS_PER_CHECK,
        "sharedWitnessCheckCount": BRIDGE_SHARED_WITNESS_CHECK_COUNT as u64,
        "sharedWitnessChallengeEntropyBits": BRIDGE_SHARED_WITNESS_CHALLENGE_ENTROPY_BITS,
        "sharedWitnessWeakestRelation": PLAINTEXT_ENCODING_RELATION,
        "sharedWitnessWeakestRelationModuli": BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI,
        "sharedWitnessWeakestRelationModel": BRIDGE_WEAKEST_ACTIVE_RELATION_MODEL,
        "sharedWitnessWeakestRelationBitsPerCheck": BRIDGE_WEAKEST_ACTIVE_RELATION_BITS_PER_CHECK,
        "batchIntegerLiftProofModuli": BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI,
        "batchIntegerLiftProofModulusProduct": bridge_batch_integer_lift_proof_modulus_product_decimal(),
        "batchIntegerLiftProofModulusProductBitsFloor": BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT_BITS_FLOOR,
        "plaintextEncodingProofModuli": BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULI,
        "plaintextEncodingProofModulusProduct": bridge_batch_integer_lift_proof_modulus_product_decimal(),
        "plaintextEncodingProofModulusProductBitsFloor": BRIDGE_BATCH_INTEGER_LIFT_PROOF_MODULUS_PRODUCT_BITS_FLOOR,
        "plaintextEncodingBoundCertificateHash": batch_encoding_bound_certificate_hash,
        "proofFriendlyPlaintextBindingStatus": PROOF_FRIENDLY_PLAINTEXT_BINDING_STATUS,
        "proofFriendlyPlaintextLiftBindingStatus": PROOF_FRIENDLY_PLAINTEXT_LIFT_BINDING_STATUS,
        "proofFriendlyPlaintextLiftBindingHash": required_string_field(
            bridge_encryption,
            "proofFriendlyPlaintextLiftBindingHash",
            "bridgeEncryption",
        )?,
        "sharedWitnessChallengeSamplingModel": shared_witness::BRIDGE_SHARED_WITNESS_CHALLENGE_SAMPLING_MODEL,
        "sharedWitnessRejectionAttemptLimit": BRIDGE_SHARED_WITNESS_REJECTION_ATTEMPT_LIMIT as u64,
        "sharedWitnessRejectionRetryLossBits": BRIDGE_SHARED_WITNESS_REJECTION_RETRY_LOSS_BITS,
        "sharedWitnessFullMatrixUnionBoundBits": BRIDGE_FULL_MATRIX_UNION_BOUND_BITS,
        "sharedWitnessRandomOracleQueryBoundBits": BRIDGE_RANDOM_ORACLE_QUERY_BOUND_BITS,
        "sharedWitnessProofSystemLossBits": BRIDGE_PROOF_SYSTEM_LOSS_BITS,
        "sharedWitnessChallengeBiasBits": BRIDGE_CHALLENGE_BIAS_BITS,
        "sharedWitnessTargetBindingSoundnessBits": BRIDGE_TARGET_BINDING_SOUNDNESS_BITS,
        "sharedWitnessEffectiveBindingBelowTarget": BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_BELOW_TARGET,
        "sharedWitnessGrindingDiscountBitsPerCheck": SHARED_WITNESS_REJECTION_ATTEMPT_GRINDING_BITS_PER_CHECK,
        "sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor": BRIDGE_SHARED_WITNESS_UNADJUSTED_WEAKEST_RELATION_SOUNDNESS_BITS_FLOOR,
        "sharedWitnessEffectiveBindingSoundnessBitsFloor": BRIDGE_SHARED_WITNESS_EFFECTIVE_BINDING_SOUNDNESS_BITS_FLOOR,
        "sharedWitnessZeroKnowledgeStatus": SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
        "aggregateToPlaintextBindingStatus": AGGREGATE_TO_PLAINTEXT_BINDING_CHECKED_STATUS,
        "plaintextCanonicalLiftProofStatus": PLAINTEXT_CANONICAL_LIFT_PROOF_CHECKED_STATUS,
        "bgvEncryptionProofStatus": BGV_ENCRYPTION_PROOF_CHECKED_STATUS,
        "bgvEncryptionKeyMaterialKind": BGV_ENCRYPTION_KEY_MATERIAL_KIND,
        "developmentKeyOnly": DEVELOPMENT_KEY_ONLY,
        "thresholdDecryptable": THRESHOLD_DECRYPTABLE,
        "claimBearingBridgeEncryption": input.claim_status.claim_bearing_bridge_encryption,
        "bgvRandomnessBoundProofStatus": BGV_RANDOMNESS_BOUND_PROOF_STATUS,
        "rnsCrtConsistencyProofStatus": RNS_CRT_CONSISTENCY_PROOF_CHECKED_STATUS,
        "bridgeClaimClosureStatus": input.claim_status.bridge_claim_verification_status,
        "aggregateDerivationVerificationScope": input.aggregate_derivation_verification_scope,
        "sampledOnlyBridgeVerificationAccepted": false,
        "coefficientDomainCanonical": true,
        "hwangPiopStatus": HWANG_PIOP_DEFERRED_STATUS,
    });
    let bridge_proof_target_contract = bridge_proof_target_contract_value(
        share_vector_width,
        share_vector_width,
        input.aggregate_derivation_verification_scope,
        input.claim_status,
    )?;
    let bridge_proof_target_contract_hash =
        bridge_proof_target_contract_hash(&bridge_proof_target_contract)?;

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
        "bridgeProofProfileHash".to_string(),
        Value::String(input.bridge_proof_profile_hash.to_string()),
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
        "aggregateDerivationComponentHash".to_string(),
        Value::String(aggregate_derivation_component_hash.to_string()),
    );
    bridge_statement.insert(
        "aggregateShareCommitmentHash".to_string(),
        Value::String(aggregate_share_commitment_hash.to_string()),
    );
    bridge_statement.insert(
        "shareCommitmentMessageBoundCertHash".to_string(),
        Value::String(share_commitment_message_bound_cert_hash.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateBridgeHash".to_string(),
        Value::String(encrypted_aggregate_bridge_hash.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateTargetBasisRoot".to_string(),
        Value::String(encrypted_aggregate_target_basis_root.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateReconstructionHash".to_string(),
        Value::String(encrypted_aggregate_reconstruction_hash.to_string()),
    );
    bridge_statement.insert(
        "encryptedAggregateInputLayoutHash".to_string(),
        Value::String(encrypted_aggregate_input_layout_hash.to_string()),
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
        "bridgeWitnessPrivacyProfileHash".to_string(),
        Value::String(input.bridge_witness_privacy_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "sampledPublicRelationCheckPolicyHash".to_string(),
        Value::String(sampled_public_relation_check_policy_hash),
    );
    bridge_statement.insert(
        "bridgeProofTargetContractHash".to_string(),
        Value::String(bridge_proof_target_contract_hash),
    );
    bridge_statement.insert(
        "batchEncodingBoundCertificateHash".to_string(),
        Value::String(batch_encoding_bound_certificate_hash.to_string()),
    );
    bridge_statement.insert(
        "bgvBatchEncoderHash".to_string(),
        Value::String(bgv_batch_encoder_hash.to_string()),
    );
    bridge_statement.insert(
        "bridgeLayoutHash".to_string(),
        Value::String(encrypted_aggregate_input_layout_hash.to_string()),
    );
    bridge_statement.insert(
        "ballotScoreEncodingProfileHash".to_string(),
        Value::String(ballot_score_encoding_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "ballotShareLayoutProfileHash".to_string(),
        Value::String(ballot_share_layout_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "aggregateInputEncodingProfileHash".to_string(),
        Value::String(aggregate_input_encoding_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "encodedShareVectorLayoutHash".to_string(),
        Value::String(encoded_share_vector_layout_hash.to_string()),
    );
    bridge_statement.insert(
        "encodedAggregateLayoutHash".to_string(),
        Value::String(encoded_aggregate_layout_hash.to_string()),
    );
    bridge_statement.insert(
        "topKEvaluatorInputLayoutHash".to_string(),
        Value::String(top_k_evaluator_input_layout_hash.to_string()),
    );
    bridge_statement.insert(
        "heParamHash".to_string(),
        Value::String(input.he_param_hash.to_string()),
    );
    bridge_statement.insert(
        "bgvProfileHash".to_string(),
        Value::String(bgv_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "rustBgvBackendProfileHash".to_string(),
        Value::String(rust_bgv_backend_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "canonicalCiphertextConventionHash".to_string(),
        Value::String(canonical_ciphertext_convention_hash.to_string()),
    );
    bridge_statement.insert(
        "collectivePublicKeyRoot".to_string(),
        Value::String(collective_public_key_root.to_string()),
    );
    bridge_statement.insert(
        "collectivePublicKeyCoefficientRoot".to_string(),
        Value::String(collective_public_key_coefficient_root.to_string()),
    );
    bridge_statement.insert(
        "bgvPublicKeyRoot".to_string(),
        Value::String(bgv_public_key_root.to_string()),
    );
    bridge_statement.insert(
        "aggregateSelectionPolicyHash".to_string(),
        Value::String(input.aggregate_selection_policy_hash.to_string()),
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
        "manifestHash".to_string(),
        Value::String(setup_manifest_hash.to_string()),
    );
    bridge_statement.insert(
        "rosterHash".to_string(),
        Value::String(setup_roster_hash.to_string()),
    );
    bridge_statement.insert(
        "pollSpecHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "pollSpecHash",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "thresholdProfileHash".to_string(),
        Value::String(setup_threshold_profile_hash.to_string()),
    );
    bridge_statement.insert(
        "setupPackageHash".to_string(),
        Value::String(setup_package_hash.to_string()),
    );
    bridge_statement.insert(
        "participantCount".to_string(),
        json!(dimensions.participant_count),
    );
    bridge_statement.insert("optionCount".to_string(), json!(dimensions.option_count));
    bridge_statement.insert("shareVectorWidth".to_string(), json!(share_vector_width));
    bridge_statement.insert(
        "ballotSetHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "ballotSetHash",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "votingClosedBoardHeadHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "votingClosedBoardHeadHash",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "postVotingClosedContextHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "postVotingClosedContextHash",
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
        "contributorRosterExternalAcceptanceHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "contributorRosterExternalAcceptanceHash",
                "aggregateDerivationComponent.statement",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "contributorActionContextHash".to_string(),
        Value::String(
            required_string_field(
                component_statement,
                "contributorActionContextHash",
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
        "plaintextCoefficientBindingCommitmentHash".to_string(),
        Value::String(
            required_string_field(
                bridge_encryption,
                "plaintextCoefficientBindingCommitmentHash",
                "bridgeEncryption",
            )?
            .to_string(),
        ),
    );
    bridge_statement.insert(
        "proofFriendlyPlaintextLiftBindingHash".to_string(),
        Value::String(
            required_string_field(
                bridge_encryption,
                "proofFriendlyPlaintextLiftBindingHash",
                "bridgeEncryption",
            )?
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

// Canonical domain-separated hash preimage built from an explicit, alphabetically sorted field
// allowlist (top-level string then u64 groups, followed by relationRequirements string/u64/bool
// groups). Adding a statement field requires inserting it into the matching group here.
pub(super) fn bridge_proof_statement_hash(
    bridge_proof_statement: &Value,
) -> CanonicalResult<String> {
    let mut hash_input = Map::new();
    hash_input.insert(
        "purpose".to_string(),
        Value::String("sealed-lattice-aggregate-bridge-proof-statement-v1".to_string()),
    );

    for field_name in [
        "aggregateDerivationComponentHash",
        "aggregateInputEncodingProfileHash",
        "aggregateSelectionPolicyHash",
        "aggregateShareCommitmentHash",
        "ballotScoreEncodingProfileHash",
        "ballotSetHash",
        "ballotShareLayoutProfileHash",
        "basisId",
        "batchEncodingBoundCertificateHash",
        "bgvBatchEncoderHash",
        "bgvProfileHash",
        "bgvPublicKeyRoot",
        "bridgeLayoutHash",
        "bridgeProofTargetContractHash",
        "bridgeWitnessPrivacyProfileHash",
        "canonicalBytesHash512",
        "canonicalCiphertextConventionHash",
        "ceremonyId",
        "ciphertextRoot",
        "collectivePublicKeyRoot",
        "collectivePublicKeyCoefficientRoot",
        "contributorActionContextHash",
        "contributorIdentity",
        "contributorRosterExternalAcceptanceHash",
        "encodedAggregateLayoutHash",
        "encodedShareVectorLayoutHash",
        "encryptedAggregateBridgeHash",
        "encryptedAggregateInputLayoutHash",
        "encryptedAggregateInputRoot",
        "encryptedAggregateReconstructionHash",
        "encryptedAggregateShareCiphertextRoot",
        "encryptedAggregateTargetBasisRoot",
        "heParamHash",
        "plaintextCoefficientBindingCommitmentHash",
        "manifestHash",
        "plaintextRoot",
        "pollSpecHash",
        "postVotingClosedContextHash",
        "proofFriendlyPlaintextLiftBindingHash",
        "rosterHash",
        "rustBgvBackendProfileHash",
        "sampledPublicRelationCheckPolicyHash",
        "setupPackageHash",
        "shareCommitmentMessageBoundCertHash",
        "thresholdProfileHash",
        "topKEvaluatorInputLayoutHash",
        "votingClosedBoardHeadHash",
    ] {
        hash_input.insert(
            field_name.to_string(),
            Value::String(
                required_string_field(bridge_proof_statement, field_name, "bridgeProofStatement")?
                    .to_string(),
            ),
        );
    }
    hash_input.insert(
        "proofProfileHash".to_string(),
        Value::String(
            required_string_field(
                bridge_proof_statement,
                "bridgeProofProfileHash",
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
        hash_input.insert(
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
        "aggregateDerivationVerificationScope",
        "bgvEncryptionKeyMaterialKind",
        "bgvEncryptionProofStatus",
        "bgvRandomnessBoundProofStatus",
        "rnsCrtConsistencyProofStatus",
        "bridgeClaimClosureStatus",
        "hwangPiopStatus",
        "batchIntegerLiftProofModulusProduct",
        "plaintextEncodingBoundCertificateHash",
        "plaintextEncodingProofModulusProduct",
        "proofFriendlyPlaintextBindingStatus",
        "proofFriendlyPlaintextLiftBindingHash",
        "proofFriendlyPlaintextLiftBindingStatus",
        "sharedWitnessChallengeSamplingModel",
        "sharedWitnessWeakestRelation",
        "sharedWitnessWeakestRelationModel",
    ] {
        hash_input.insert(
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
        "sharedWitnessChallengeEntropyBits",
        "sharedWitnessWeakestRelationBitsPerCheck",
        "batchIntegerLiftProofModulusProductBitsFloor",
        "plaintextEncodingProofModulusProductBitsFloor",
        "sharedWitnessRejectionAttemptLimit",
        "sharedWitnessRejectionRetryLossBits",
        "sharedWitnessFullMatrixUnionBoundBits",
        "sharedWitnessRandomOracleQueryBoundBits",
        "sharedWitnessProofSystemLossBits",
        "sharedWitnessChallengeBiasBits",
        "sharedWitnessTargetBindingSoundnessBits",
        "sharedWitnessGrindingDiscountBitsPerCheck",
        "sharedWitnessUnadjustedWeakestRelationSoundnessBitsFloor",
        "sharedWitnessEffectiveBindingSoundnessBitsFloor",
    ] {
        hash_input.insert(
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
        "developmentKeyOnly",
        "thresholdDecryptable",
        "claimBearingBridgeEncryption",
        "sharedWitnessEffectiveBindingBelowTarget",
    ] {
        hash_input.insert(
            field_name.to_string(),
            json!(read_bool_object_field(
                relation_requirements,
                field_name,
                "bridgeProofStatement.relationRequirements",
            )?),
        );
    }
    for field_name in [
        "batchIntegerLiftProofModuli",
        "plaintextEncodingProofModuli",
        "sharedWitnessWeakestRelationModuli",
    ] {
        hash_input.insert(
            field_name.to_string(),
            required_json_field(
                relation_requirements,
                field_name,
                "bridgeProofStatement.relationRequirements",
            )?
            .clone(),
        );
    }

    derive_protocol_hash("BridgeProofRecordHash", &Value::Object(hash_input))
}

pub(super) struct AggregateBridgeRelationHandoffRootInput<'a> {
    pub(super) bridge_proof_statement: &'a Value,
    pub(super) bridge_public_values: &'a Value,
    pub(super) aggregate_derivation_statement_hash: &'a str,
    pub(super) aggregate_relation_challenge_hex: &'a str,
    pub(super) aggregate_relation_commitment_hash: &'a str,
    pub(super) aggregate_relation_subproof_size_bytes: u64,
    pub(super) bridge_proof_statement_hash: &'a str,
    pub(super) bridge_proof_bytes_hash: &'a str,
    pub(super) bridge_shared_witness_proof_hash: &'a str,
    pub(super) shared_witness_zero_knowledge_status_hash: &'a str,
    pub(super) bgv_randomness_bound_proof_status_hash: &'a str,
    pub(super) bridge_proof_verification_status: &'a str,
    pub(super) bgv_passive_setup_verification_precondition_checked: bool,
    pub(super) claim_bearing_bridge_encryption: bool,
    pub(super) relation_checked: bool,
    pub(super) same_witness_linkage_verified: bool,
    pub(super) effective_soundness_accepted: bool,
    pub(super) zk_distribution_accepted: bool,
    pub(super) bgv_support_bounds_verified: bool,
    pub(super) entropy_ownership_verified: bool,
    pub(super) key_status_accepted: bool,
}

pub(super) fn aggregate_bridge_relation_handoff_root(
    input: AggregateBridgeRelationHandoffRootInput<'_>,
) -> CanonicalResult<String> {
    let relation_requirements = required_json_field(
        input.bridge_proof_statement,
        "relationRequirements",
        "bridgeProofStatement",
    )?;
    let mut payload = Map::new();
    payload.insert(
        "purpose".to_string(),
        Value::String("sealed-lattice-aggregate-bridge-relation-handoff-root-v1".to_string()),
    );
    for field_name in [
        "aggregateDerivationComponentHash",
        "aggregateInputEncodingProfileHash",
        "aggregateSelectionPolicyHash",
        "aggregateShareCommitmentHash",
        "ballotScoreEncodingProfileHash",
        "ballotSetHash",
        "ballotShareLayoutProfileHash",
        "basisId",
        "bgvBatchEncoderHash",
        "bgvProfileHash",
        "bgvPublicKeyRoot",
        "bridgeLayoutHash",
        "bridgeProofProfileHash",
        "bridgeProofTargetContractHash",
        "bridgeWitnessPrivacyProfileHash",
        "canonicalBytesHash512",
        "canonicalCiphertextConventionHash",
        "ceremonyId",
        "ciphertextRoot",
        "collectivePublicKeyCoefficientRoot",
        "collectivePublicKeyRoot",
        "contributorActionContextHash",
        "contributorIdentity",
        "contributorRosterExternalAcceptanceHash",
        "encodedAggregateLayoutHash",
        "encodedShareVectorLayoutHash",
        "encryptedAggregateBridgeHash",
        "encryptedAggregateInputLayoutHash",
        "encryptedAggregateInputRoot",
        "encryptedAggregateReconstructionHash",
        "encryptedAggregateShareCiphertextRoot",
        "encryptedAggregateTargetBasisRoot",
        "heParamHash",
        "manifestHash",
        "plaintextCoefficientBindingCommitmentHash",
        "plaintextRoot",
        "pollSpecHash",
        "postVotingClosedContextHash",
        "proofFriendlyPlaintextLiftBindingHash",
        "rosterHash",
        "rustBgvBackendProfileHash",
        "setupPackageHash",
        "shareCommitmentMessageBoundCertHash",
        "thresholdProfileHash",
        "topKEvaluatorInputLayoutHash",
        "votingClosedBoardHeadHash",
    ] {
        payload.insert(
            field_name.to_string(),
            Value::String(
                required_string_field(
                    input.bridge_proof_statement,
                    field_name,
                    "bridgeProofStatement",
                )?
                .to_string(),
            ),
        );
    }
    for field_name in [
        "canonicalByteLength",
        "coefficientCount",
        "contributorRosterPosition",
        "level",
        "optionCount",
        "participantCount",
        "shareVectorWidth",
        "slotCount",
    ] {
        payload.insert(
            field_name.to_string(),
            json!(read_u64_object_field(
                input.bridge_proof_statement,
                field_name,
                "bridgeProofStatement",
            )?),
        );
    }
    for field_name in [
        "aggregateQuotientCoordinateCount",
        "aggregateReducedCoordinateCount",
        "sharedWitnessCheckCount",
        "sharedWitnessEffectiveBindingSoundnessBitsFloor",
        "sharedWitnessTargetBindingSoundnessBits",
    ] {
        payload.insert(
            field_name.to_string(),
            json!(read_u64_object_field(
                relation_requirements,
                field_name,
                "bridgeProofStatement.relationRequirements",
            )?),
        );
    }
    payload.insert(
        "encryptionRandomnessSeedSource".to_string(),
        Value::String(
            required_string_field(
                input.bridge_public_values,
                "encryptionRandomnessSeedSource",
                "bridgeProof",
            )?
            .to_string(),
        ),
    );
    payload.insert(
        "proverRandomnessSource".to_string(),
        Value::String(
            required_string_field(
                input.bridge_public_values,
                "proverRandomnessSource",
                "bridgeProof",
            )?
            .to_string(),
        ),
    );
    payload.insert(
        "randomnessSourceEvidence".to_string(),
        required_json_field(
            input.bridge_public_values,
            "randomnessSourceEvidence",
            "bridgeProof",
        )?
        .clone(),
    );
    payload.insert(
        "aggregateDerivationStatementHash".to_string(),
        Value::String(input.aggregate_derivation_statement_hash.to_string()),
    );
    payload.insert(
        "aggregateRelationChallengeHex".to_string(),
        Value::String(input.aggregate_relation_challenge_hex.to_string()),
    );
    payload.insert(
        "aggregateRelationCommitmentHash".to_string(),
        Value::String(input.aggregate_relation_commitment_hash.to_string()),
    );
    payload.insert(
        "aggregateRelationSubproofSizeBytes".to_string(),
        json!(input.aggregate_relation_subproof_size_bytes),
    );
    payload.insert(
        "bridgeProofBytesHash".to_string(),
        Value::String(input.bridge_proof_bytes_hash.to_string()),
    );
    payload.insert(
        "bridgeProofStatementHash".to_string(),
        Value::String(input.bridge_proof_statement_hash.to_string()),
    );
    payload.insert(
        "bridgeProofVerificationStatus".to_string(),
        Value::String(input.bridge_proof_verification_status.to_string()),
    );
    payload.insert(
        "bridgeSharedWitnessProofHash".to_string(),
        Value::String(input.bridge_shared_witness_proof_hash.to_string()),
    );
    payload.insert(
        "sharedWitnessZeroKnowledgeStatusHash".to_string(),
        Value::String(input.shared_witness_zero_knowledge_status_hash.to_string()),
    );
    payload.insert(
        "bgvRandomnessBoundProofStatusHash".to_string(),
        Value::String(input.bgv_randomness_bound_proof_status_hash.to_string()),
    );
    payload.insert(
        "bgvEncryptionKeyMaterialKind".to_string(),
        Value::String(BGV_ENCRYPTION_KEY_MATERIAL_KIND.to_string()),
    );
    payload.insert(
        "developmentKeyOnly".to_string(),
        Value::Bool(DEVELOPMENT_KEY_ONLY),
    );
    payload.insert(
        "thresholdDecryptable".to_string(),
        Value::Bool(THRESHOLD_DECRYPTABLE),
    );
    payload.insert(
        "claimBearingBridgeEncryption".to_string(),
        Value::Bool(input.claim_bearing_bridge_encryption),
    );
    payload.insert(
        "bgvPassiveSetupVerificationPreconditionChecked".to_string(),
        Value::Bool(input.bgv_passive_setup_verification_precondition_checked),
    );
    payload.insert(
        "relationChecked".to_string(),
        Value::Bool(input.relation_checked),
    );
    payload.insert(
        "sameWitnessLinkageVerified".to_string(),
        Value::Bool(input.same_witness_linkage_verified),
    );
    payload.insert(
        "effectiveSoundnessAccepted".to_string(),
        Value::Bool(input.effective_soundness_accepted),
    );
    payload.insert(
        "zkDistributionAccepted".to_string(),
        Value::Bool(input.zk_distribution_accepted),
    );
    payload.insert(
        "bgvSupportBoundsVerified".to_string(),
        Value::Bool(input.bgv_support_bounds_verified),
    );
    payload.insert(
        "entropyOwnershipVerified".to_string(),
        Value::Bool(input.entropy_ownership_verified),
    );
    payload.insert(
        "keyStatusAccepted".to_string(),
        Value::Bool(input.key_status_accepted),
    );

    derive_protocol_hash("BridgeProofRecordHash", &Value::Object(payload))
}

pub(super) fn bridge_proof_challenge_context_hash(
    bridge_proof_profile_hash: &str,
    bridge_proof_statement_hash: &str,
    bridge_proof_target_contract_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-proof-challenge-context-v1",
            "bridgeProofProfileHash": bridge_proof_profile_hash,
            "bridgeProofStatementHash": bridge_proof_statement_hash,
            "bridgeProofTargetContractHash": bridge_proof_target_contract_hash,
        }),
    )
}

// Enforces the no-wraparound invariant: maximumAggregateInteger = canonicalTurnout*(q-1) must
// stay < commitmentMessageBound. Every noWraparoundCondition clause must hold; any false clause
// (or a failed inequality) means modular wraparound is possible and the cert is rejected.
fn validate_bridge_share_commitment_bound_cert(
    certificate: &Value,
    statement: &Value,
) -> CanonicalResult<()> {
    let certificate_object = certificate.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted aggregate bridge share-commitment message-bound certificate must be an object",
        )
    })?;
    let mut certificate_payload = certificate_object.clone();
    let certificate_hash = certificate_payload
        .remove("shareCommitmentMessageBoundCertHash")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted aggregate bridge share-commitment message-bound certificate hash is missing",
            )
        })?;
    let expected_certificate_hash = derive_protocol_hash(
        "ShareCommitmentMessageBoundCertHash",
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
                "encrypted aggregate bridge maximum aggregate integer bound overflows",
            )
        })?;
    let expected_opening_aggregate_bound = maximum_canonical_turnout
        .checked_mul(opening_single_bound)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge opening randomness aggregate bound overflows",
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
            format!(
                "encrypted aggregate bridge commitment message bound is not an integer: {error}"
            ),
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
        || certificate_hash != expected_certificate_hash
        || certificate_hash
            != required_string_field(
                statement,
                "shareCommitmentMessageBoundCertHash",
                "aggregateDerivationComponent.statement",
            )?
        || required_string_field(
            certificate,
            "shareCommitmentProfileHash",
            "shareCommitmentMessageBoundCert",
        )? != required_string_field(
            statement,
            "shareCommitmentProfileHash",
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
            "encrypted aggregate bridge aggregate no-wraparound certificate is invalid or permits wraparound",
        ));
    }

    Ok(())
}

fn sampled_public_relation_check_policy_hash(policy: &Value) -> CanonicalResult<String> {
    derive_protocol_hash(
        "BridgeProofRecordHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-sampled-public-relation-check-policy-v1",
            "policy": policy,
        }),
    )
}
