use super::*;
use super::{
    boundedness::validate_bridge_bgv_randomness_bound_status,
    dimensions::bridge_variant_dimensions,
    shared_witness::{
        bridge_shared_witness_proof_digest, validate_bridge_shared_witness_zero_knowledge_status,
        verify_bridge_shared_witness_proof,
    },
    statement::{
        bridge_proof_profile_digest, bridge_proof_statement_digest, build_bridge_proof_statement,
    },
    validation::{
        parse_bridge_proof_value, read_u64_object_field, require_equal_string, require_equal_u64,
        required_protocol_digest_field, required_string_at_path,
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
    let bridge_proof_bytes_digest = derive_protocol_digest(
        "ProofBytesDigest",
        &json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1",
            "proofBytesHex": bridge_proof_bytes_hex,
        }),
    )?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofBytesDigest",
        &bridge_proof_bytes_digest,
        "bridge proof bytes digest",
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
            ("bridgeProofProfileDigest", "bridge proof profile digest"),
            (
                "bridgeProofStatementDigest",
                "bridge proof statement digest",
            ),
            (
                "bridgeProofTargetContractDigest",
                "bridge proof target contract digest",
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
    let component_digest = required_string_field(
        component,
        "aggregateDerivationComponentDigest",
        "aggregateDerivationComponent",
    )?;
    let statement = required_json_field(component, "statement", "aggregateDerivationComponent")?;
    let dimensions = bridge_variant_dimensions(statement)?;
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
    let shared_witness_proof_digest = if proof_is_checked_relation {
        let shared_witness_proof =
            required_json_field(&proof_value, "bridgeSharedWitnessProof", "bridgeProof")?;
        let digest = bridge_shared_witness_proof_digest(shared_witness_proof)?;
        require_equal_string(
            &proof_value,
            "bridgeSharedWitnessProofDigest",
            &digest,
            "shared-witness proof digest",
        )?;
        Some(digest)
    } else {
        None
    };
    let bgv_randomness_bound_proof_status_digest = if proof_is_checked_relation {
        Some(validate_bridge_bgv_randomness_bound_status(
            &proof_value,
            &bridge_proof_statement_digest,
            shared_witness_proof_digest.as_deref().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "M9 bridge checked relation requires a shared-witness proof digest",
                )
            })?,
            bridge_encryption,
        )?)
    } else {
        None
    };
    let shared_witness_zero_knowledge_status_digest =
        if let Some(shared_witness_proof_digest) = &shared_witness_proof_digest {
            Some(validate_bridge_shared_witness_zero_knowledge_status(
                &proof_value,
                &bridge_proof_statement_digest,
                shared_witness_proof_digest,
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
            &bridge_proof_statement_digest,
            contributor_identity,
            statement_digest,
            aggregate_reduced_coordinate_count,
            aggregate_quotient_coordinate_count,
        )?)
    } else {
        None
    };
    let mut proof_root_payload = json!({
            "purpose": "sealed-lattice-aggregate-bridge-encryption-proof-root-v1",
            "aggregateDerivationComponentDigest": component_digest,
            "aggregateDerivationStatementDigest": statement_digest,
            "bridgeProofProfileDigest": bridge_proof_profile_digest,
            "bridgeProofStatementDigest": bridge_proof_statement_digest,
            "proofBytesDigest": bridge_proof_bytes_digest,
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
    if let Some(digest) = &shared_witness_proof_digest {
        proof_root_payload_object.insert(
            "bridgeSharedWitnessProofDigest".to_string(),
            Value::String(digest.clone()),
        );
    }
    if let Some(digest) = &shared_witness_zero_knowledge_status_digest {
        proof_root_payload_object.insert(
            "sharedWitnessZeroKnowledgeStatusDigest".to_string(),
            Value::String(digest.clone()),
        );
    }
    if let Some(digest) = &bgv_randomness_bound_proof_status_digest {
        proof_root_payload_object.insert(
            "bgvRandomnessBoundProofStatusDigest".to_string(),
            Value::String(digest.clone()),
        );
    }
    let bridge_proof_root = derive_protocol_digest("BridgeProofRecordDigest", &proof_root_payload)?;
    require_equal_string(
        bridge_encryption,
        "bridgeProofRoot",
        &bridge_proof_root,
        "bridge proof root",
    )?;
    if let Some(digest) = &shared_witness_proof_digest {
        require_equal_string(
            bridge_encryption,
            "bridgeSharedWitnessProofDigest",
            digest,
            "shared-witness proof digest",
        )?;
    }
    if let Some(digest) = &shared_witness_zero_knowledge_status_digest {
        require_equal_string(
            bridge_encryption,
            "sharedWitnessZeroKnowledgeStatusDigest",
            digest,
            "shared-witness zero-knowledge status digest",
        )?;
    }
    if let Some(digest) = &bgv_randomness_bound_proof_status_digest {
        require_equal_string(
            bridge_encryption,
            "bgvRandomnessBoundProofStatusDigest",
            digest,
            "BGV randomness-bound status digest",
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
    let mut accepted_digests = vec![
        Value::String(component_digest.to_string()),
        Value::String(statement_digest.to_string()),
        Value::String(bridge_proof_profile_digest.clone()),
        Value::String(bridge_proof_statement_digest.clone()),
        Value::String(bridge_proof_target_contract_digest.to_string()),
        Value::String(bridge_proof_bytes_digest.clone()),
        Value::String(bridge_proof_root.clone()),
        Value::String(encrypted_aggregate_share_ciphertext_root.to_string()),
    ];
    if let Some(digest) = &shared_witness_proof_digest {
        accepted_digests.push(Value::String(digest.clone()));
    }
    if let Some(digest) = &shared_witness_zero_knowledge_status_digest {
        accepted_digests.push(Value::String(digest.clone()));
    }
    if let Some(digest) = &bgv_randomness_bound_proof_status_digest {
        accepted_digests.push(Value::String(digest.clone()));
    }

    Ok(json!({
        "ok": true,
        "backendAvailable": true,
        "operation": "verifyAggregateBridgeEncryption",
        "statusLabels": status_labels,
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "bridgeProofVerificationStatus": bridge_proof_verification_status,
        "bridgeEvidenceVerificationStatus": "BridgeProofEvidenceChecked",
        "bridgeClaimClosureVerified": false,
        "bridgeClaimVerificationStatus": BRIDGE_CLAIM_CLOSURE_STATUS,
        "bridgeVariantEvidenceStatus": dimensions.evidence_tier,
        "bridgeProofProfileDigest": bridge_proof_profile_digest,
        "bridgeProofStatementDigest": bridge_proof_statement_digest,
        "bridgeProofTargetContractDigest": bridge_proof_target_contract_digest,
        "bridgeProofBytesDigest": bridge_proof_bytes_digest,
        "bridgeProofRoot": bridge_proof_root,
        "bridgeSharedWitnessProofDigest": shared_witness_proof_digest,
        "sharedWitnessZeroKnowledgeStatusDigest": shared_witness_zero_knowledge_status_digest,
        "bgvRandomnessBoundProofStatusDigest": bgv_randomness_bound_proof_status_digest,
        "encryptedAggregateInputRoot": bridge_encryption["encryptedAggregateInputRoot"],
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
