use super::*;
use super::{
    boundedness::validate_bridge_bgv_randomness_bound_status,
    dimensions::bridge_variant_dimensions,
    shared_witness::{
        bridge_shared_witness_proof_hash, validate_bridge_shared_witness_zero_knowledge_status,
        verify_bridge_shared_witness_proof,
    },
    statement::{
        bridge_proof_profile_hash, bridge_proof_statement_hash, build_bridge_proof_statement,
    },
    validation::{
        parse_bridge_proof_value, read_u64_object_field, require_equal_string, require_equal_u64,
        required_protocol_hash_field, required_string_at_path,
        validate_bridge_encryption_public_shell, validate_bridge_proof_public_shell,
    },
};

pub(super) fn verify_aggregate_bridge_encryption(request: &Value) -> CanonicalResult<Value> {
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
    let aggregate_selection_policy_hash = required_protocol_hash_field(
        request,
        "aggregateSelectionPolicyHash",
        "verifyAggregateBridgeEncryption",
    )?;
    let bridge_witness_privacy_profile_hash = required_protocol_hash_field(
        request,
        "bridgeWitnessPrivacyProfileHash",
        "verifyAggregateBridgeEncryption",
    )?;
    let he_param_hash =
        required_protocol_hash_field(request, "heParamHash", "verifyAggregateBridgeEncryption")?;
    let bridge_proof_bytes_hex =
        required_string_field(bridge_encryption, "bridgeProofBytesHex", "bridgeEncryption")?;
    let canonical_bytes_hex =
        required_string_field(bridge_encryption, "canonicalBytesHex", "bridgeEncryption")?;
    let proof_value = parse_bridge_proof_value(bridge_proof_bytes_hex)?;
    validate_bridge_proof_public_shell(&proof_value)?;
    let bridge_proof_bytes_hash = derive_protocol_hash(
        "ProofBytesHash",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": bridge_proof_bytes_hex,
        }),
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofBytesHash",
        &bridge_proof_bytes_hash,
        "bridge proof bytes hash",
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
    if proof_is_checked_relation {
        if string_field(bridge_encryption, "bridgeProofVerificationStatus")
            != Some(BRIDGE_PROOF_CHECKED_STATUS)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "M9 bridge relation proof requires verifier-checked bridge encryption status",
            ));
        }
        for (field_name, label) in [
            ("bridgeProofProfileHash", "bridge proof profile hash"),
            ("bridgeProofStatementHash", "bridge proof statement hash"),
            (
                "bridgeProofTargetContractHash",
                "bridge proof target contract hash",
            ),
        ] {
            require_equal_string(
                bridge_encryption,
                field_name,
                required_string_field(&proof_value, field_name, "bridgeProof")?,
                label,
            )?;
        }
    } else if string_field(bridge_encryption, "bridgeProofVerificationStatus")
        == Some(BRIDGE_PROOF_CHECKED_STATUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge checked status requires a real shared-witness relation proof",
        ));
    }
    let component_hash = required_string_field(
        component,
        "aggregateDerivationComponentHash",
        "aggregateDerivationComponent",
    )?;
    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let dimensions = bridge_variant_dimensions(statement)?;
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
    if !is_protocol_hash(canonical_bytes_hash) {
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
        component_hash,
        statement_hash,
        post_voting_closed_context_hash,
        bridge_encryption,
    )?;
    let aggregate_relation_subproof_hex =
        required_string_field(&proof_value, "aggregateRelationSubproofHex", "bridgeProof")?;
    let aggregate_relation_verification =
        verify_aggregate_derivation_relation_subproof_for_component(
            component,
            aggregate_relation_subproof_hex,
        )?;
    let bridge_proof_profile_hash = bridge_proof_profile_hash()?;
    let bridge_proof_statement = build_bridge_proof_statement(
        component,
        setup_package,
        bridge_encryption,
        &bridge_proof_profile_hash,
        aggregate_selection_policy_hash,
        bridge_witness_privacy_profile_hash,
        he_param_hash,
    )?;
    let bridge_proof_statement_hash = bridge_proof_statement_hash(&bridge_proof_statement)?;
    let bridge_proof_target_contract_hash = required_string_field(
        &bridge_proof_statement,
        "bridgeProofTargetContractHash",
        "bridgeProofStatement",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofProfileHash",
        &bridge_proof_profile_hash,
        "bridge proof profile hash",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofStatementHash",
        &bridge_proof_statement_hash,
        "bridge proof statement hash",
    )?;
    require_equal_string(
        &proof_value,
        "bridgeProofTargetContractHash",
        bridge_proof_target_contract_hash,
        "bridge proof target contract hash",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofProfileHash",
        &bridge_proof_profile_hash,
        "bridge proof profile hash",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofStatementHash",
        &bridge_proof_statement_hash,
        "bridge proof statement hash",
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofTargetContractHash",
        bridge_proof_target_contract_hash,
        "bridge proof target contract hash",
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
        "aggregateRelationCommitmentHash",
        &aggregate_relation_verification.relation_commitment_hash,
        "aggregate relation commitment hash",
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
        "aggregateDerivationComponentHash",
        component_hash,
        "bridge proof component hash",
    )?;
    require_equal_string(
        &proof_value,
        "aggregateDerivationStatementHash",
        statement_hash,
        "bridge proof statement hash",
    )?;
    require_equal_string(
        &proof_value,
        "postVotingClosedContextHash",
        post_voting_closed_context_hash,
        "bridge proof post-close context hash",
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
    if read_u64_object_field(&proof_value, "objectVersion", "bridgeProof")? != 1
        || string_field(&proof_value, "profileId") != Some(BRIDGE_PROOF_PROFILE_ID)
        || string_field(&proof_value, "proofBackend") != Some(BRIDGE_PROOF_BACKEND)
        || string_field(&proof_value, "bgvEncryptionProofSubrelation")
            != Some(BGV_ENCRYPTION_PROOF_SUBRELATION)
        || string_field(&proof_value, "relationScope")
            != Some("sealed-lattice-aggregate-bridge-relation")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "M9 bridge proof shell is not the supported scoped relation",
        ));
    }
    let shared_witness_proof_hash = if proof_is_checked_relation {
        let shared_witness_proof =
            required_json_field(&proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
        let hash = bridge_shared_witness_proof_hash(shared_witness_proof)?;
        require_equal_string(
            &proof_value,
            "bridgeSharedWitnessProofHash",
            &hash,
            "shared-witness proof hash",
        )?;
        Some(hash)
    } else {
        None
    };
    let bgv_randomness_bound_proof_status_hash = if proof_is_checked_relation {
        Some(validate_bridge_bgv_randomness_bound_status(
            &proof_value,
            &bridge_proof_statement_hash,
            shared_witness_proof_hash.as_deref().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "M9 bridge checked relation requires a shared-witness proof hash",
                )
            })?,
            bridge_encryption,
        )?)
    } else {
        None
    };
    let shared_witness_zero_knowledge_status_hash =
        if let Some(shared_witness_proof_hash) = &shared_witness_proof_hash {
            Some(validate_bridge_shared_witness_zero_knowledge_status(
                &proof_value,
                &bridge_proof_statement_hash,
                shared_witness_proof_hash,
            )?)
        } else {
            None
        };
    let shared_witness_verification = if proof_is_checked_relation {
        Some(verify_bridge_shared_witness_proof(
            &proof_value,
            component,
            setup_package,
            bridge_encryption,
            &bridge_proof_statement_hash,
            contributor_identity,
            statement_hash,
            aggregate_reduced_coordinate_count,
            aggregate_quotient_coordinate_count,
        )?)
    } else {
        None
    };
    let mut proof_root_payload = json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentHash": component_hash,
            "aggregateDerivationStatementHash": statement_hash,
            "bridgeProofProfileHash": bridge_proof_profile_hash,
            "bridgeProofStatementHash": bridge_proof_statement_hash,
            "proofBytesHash": bridge_proof_bytes_hash,
            "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
            "collectivePublicKeyRoot": bridge_encryption["collectivePublicKeyRoot"],
            "bgvPublicKeyRoot": bridge_encryption["bgvPublicKeyRoot"],
    });
    let proof_root_payload_object = proof_root_payload.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "M9 bridge proof root payload must be an object",
        )
    })?;
    if let Some(hash) = &shared_witness_proof_hash {
        proof_root_payload_object.insert(
            "bridgeSharedWitnessProofHash".to_string(),
            Value::String(hash.clone()),
        );
    }
    if let Some(hash) = &shared_witness_zero_knowledge_status_hash {
        proof_root_payload_object.insert(
            "sharedWitnessZeroKnowledgeStatusHash".to_string(),
            Value::String(hash.clone()),
        );
    }
    if let Some(hash) = &bgv_randomness_bound_proof_status_hash {
        proof_root_payload_object.insert(
            "bgvRandomnessBoundProofStatusHash".to_string(),
            Value::String(hash.clone()),
        );
    }
    let bridge_proof_root = derive_protocol_hash("BridgeProofRecordHash", &proof_root_payload)?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofRoot",
        &bridge_proof_root,
        "bridge proof root",
    )?;
    if let Some(hash) = &shared_witness_proof_hash {
        require_equal_string(
            bridge_encryption,
            "bridgeSharedWitnessProofHash",
            hash,
            "shared-witness proof hash",
        )?;
    }
    if let Some(hash) = &shared_witness_zero_knowledge_status_hash {
        require_equal_string(
            bridge_encryption,
            "sharedWitnessZeroKnowledgeStatusHash",
            hash,
            "shared-witness zero-knowledge status hash",
        )?;
    }
    if let Some(hash) = &bgv_randomness_bound_proof_status_hash {
        require_equal_string(
            bridge_encryption,
            "bgvRandomnessBoundProofStatusHash",
            hash,
            "BGV randomness-bound status hash",
        )?;
    }
    let bridge_proof_verification_status = if shared_witness_verification.is_some() {
        BRIDGE_PROOF_CHECKED_STATUS
    } else {
        BRIDGE_PROOF_PENDING_STATUS
    };
    let mut status_labels = if shared_witness_verification.is_some() {
        vec![
            "BridgeProofEvidenceChecked",
            "BridgeProofRelationChecked",
            "M9SingleContributionBridgeRelationChecked",
            "BridgeProofImplementationEvidenceOnly",
            SHARED_WITNESS_ZERO_KNOWLEDGE_STATUS,
            BGV_RANDOMNESS_BOUND_PROOF_STATUS,
            PLAINTEXT_CANONICAL_LIFT_PROOF_MISSING_STATUS,
            AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
            "BridgeProofClaimClosureMissing",
            "FinalBridgeTheoremPending",
        ]
    } else {
        vec![
            "BridgeProofEvidenceChecked",
            "BridgeProofBackendStillRequired",
            "FinalBridgeTheoremPending",
        ]
    };
    status_labels.push(match dimensions.evidence_tier {
        "representative-row-evidence" => "RepresentativeBridgeMatrixRowEvidence",
        _ => "FullBridgeMatrixRowEvidenceMissing",
    });
    let encrypted_aggregate_share_ciphertext_root = required_string_field(
        bridge_encryption,
        "encryptedAggregateShareCiphertextRoot",
        "bridgeEncryption",
    )?;
    let mut accepted_hashes = vec![
        Value::String(component_hash.to_string()),
        Value::String(statement_hash.to_string()),
        Value::String(bridge_proof_profile_hash.clone()),
        Value::String(bridge_proof_statement_hash.clone()),
        Value::String(bridge_proof_target_contract_hash.to_string()),
        Value::String(bridge_proof_bytes_hash.clone()),
        Value::String(bridge_proof_root.clone()),
        Value::String(encrypted_aggregate_share_ciphertext_root.to_string()),
    ];
    if let Some(hash) = &shared_witness_proof_hash {
        accepted_hashes.push(Value::String(hash.clone()));
    }
    if let Some(hash) = &shared_witness_zero_knowledge_status_hash {
        accepted_hashes.push(Value::String(hash.clone()));
    }
    if let Some(hash) = &bgv_randomness_bound_proof_status_hash {
        accepted_hashes.push(Value::String(hash.clone()));
    }

    Ok(json!({
        "ok": true,
        "backendAvailable": true,
        "operation": "verifyAggregateBridgeEncryption",
        "statusLabels": status_labels,
        "acceptedHashes": accepted_hashes,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "bridgeProofVerificationStatus": bridge_proof_verification_status,
        "bridgeEvidenceVerificationStatus": "BridgeProofEvidenceChecked",
        "aggregateDerivationVerificationScope": AGGREGATE_DERIVATION_FULL_VERIFICATION_PRECONDITION_STATUS,
        "plaintextCanonicalLiftProofStatus": PLAINTEXT_CANONICAL_LIFT_PROOF_MISSING_STATUS,
        "bridgeClaimClosureVerified": false,
        "bridgeClaimVerificationStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "bridgeVariantEvidenceStatus": dimensions.evidence_tier,
        "bridgeProofProfileHash": bridge_proof_profile_hash,
        "bridgeProofStatementHash": bridge_proof_statement_hash,
        "bridgeProofTargetContractHash": bridge_proof_target_contract_hash,
        "bridgeProofBytesHash": bridge_proof_bytes_hash,
        "bridgeProofRoot": bridge_proof_root,
        "bridgeSharedWitnessProofHash": shared_witness_proof_hash,
        "sharedWitnessZeroKnowledgeStatusHash": shared_witness_zero_knowledge_status_hash,
        "bgvRandomnessBoundProofStatusHash": bgv_randomness_bound_proof_status_hash,
        "encryptedAggregateInputRoot": bridge_encryption["encryptedAggregateInputRoot"],
        "encryptedAggregateShareCiphertextRoot": bridge_encryption["encryptedAggregateShareCiphertextRoot"],
        "aggregateRelationSubproofSizeBytes": aggregate_relation_verification.proof_size_bytes,
        "aggregateRelationChallengeHex": aggregate_relation_verification.challenge_hex,
        "aggregateRelationCommitmentHash": aggregate_relation_verification.relation_commitment_hash,
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
