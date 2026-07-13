use super::*;

// Verifies the statement's structural bindings only: canonical roots,
// commitment bodies, and cross-set consistency of the published commitment
// sets. Acceptance here verifies no share-linkage proof, and for a
// threshold-aggregate statement it does not establish that the committed
// threshold share is the sum of the committed source shares; the proven
// aggregate binding is verified by `verify_vss_public_aggregate_threshold_proofs`
// on the accepted-setup material path.
pub(crate) fn verify_vss_share_linkage_bindings_request(request: &Value) -> CanonicalResult<Value> {
    let statement = value_at_path(request, &["statement"])?;
    compare_required_string(
        string_at_path(statement, &["objectType"])?,
        "VssShareLinkageStatement",
        "VSS share linkage statement objectType",
    )?;
    let setup_context_hash = hash_at_path(statement, &["setupContextHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement,
        &["ringDegree"],
        "VSS share linkage statement ringDegree",
    )?;
    let coefficient_commitment_root = hash_at_path(statement, &["coefficientCommitmentRoot"])?;
    let recipient_share_commitment_root =
        hash_at_path(statement, &["recipientShareCommitmentRoot"])?;
    let aggregate_threshold_commitment_root =
        hash_at_path(statement, &["aggregateThresholdCommitmentRoot"])?;
    let participant_count = read_positive_usize_at_path(
        statement,
        &["participantCount"],
        "VSS share linkage statement participantCount",
    )?;
    let q_share_rns_limb_count = read_positive_usize_at_path(
        statement,
        &["qShareRnsLimbCount"],
        "VSS share linkage statement qShareRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement,
        &["thresholdDegree"],
        "VSS share linkage statement thresholdDegree",
    )?;
    let statement_root = hash_at_path(statement, &["statementRoot"])?;
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
    });
    let expected_statement_root = derive_canonical_object_hash(&statement_without_root)?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS share linkage statement root does not match its bound public roots",
        ));
    }
    verify_vss_share_linkage_evidence(VssShareLinkageEvidenceInput {
        request,
        statement: VssShareLinkageStatementBinding {
            public_matrix_seed_hash,
            ring_degree,
            participant_count,
            q_share_rns_limb_count,
            threshold_degree,
            coefficient_commitment_root,
            aggregate_threshold_commitment_root,
        },
        recipient_share_commitment_root,
    })?;

    Ok(json!({
        "statementRoot": statement_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
    }))
}

pub(super) struct VssShareLinkageStatementBinding<'a> {
    public_matrix_seed_hash: &'a str,
    ring_degree: usize,
    participant_count: usize,
    q_share_rns_limb_count: usize,
    threshold_degree: usize,
    coefficient_commitment_root: &'a str,
    aggregate_threshold_commitment_root: &'a str,
}

pub(super) struct VssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: VssShareLinkageStatementBinding<'a>,
    recipient_share_commitment_root: &'a str,
}

pub(super) fn verify_vss_share_linkage_evidence(
    input: VssShareLinkageEvidenceInput<'_>,
) -> CanonicalResult<()> {
    let (
        Some(coefficient_commitment_set),
        Some(recipient_share_commitment_set),
        Some(aggregate_threshold_commitment_set),
    ) = (
        input.request.get("coefficientCommitmentSet"),
        input.request.get("recipientShareCommitmentSet"),
        input.request.get("aggregateThresholdCommitmentSet"),
    )
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage evidence verification requires coefficient, recipient-share, and aggregate-threshold commitment sets",
        ));
    };

    verify_vss_share_linkage_evidence_sets(
        input,
        coefficient_commitment_set,
        recipient_share_commitment_set,
        aggregate_threshold_commitment_set,
    )
}

pub(super) fn verify_vss_share_linkage_evidence_sets(
    input: VssShareLinkageEvidenceInput<'_>,
    coefficient_commitment_set: &Value,
    recipient_share_commitment_set: &Value,
    aggregate_threshold_commitment_set: &Value,
) -> CanonicalResult<()> {
    let coefficient_commitment_root = verify_vss_public_coefficient_commitment_set(
        coefficient_commitment_set,
        &VssPublicCoefficientCommitmentSetContext {
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            threshold_degree: input.statement.threshold_degree,
            ring_degree: input.statement.ring_degree,
        },
    )?;
    let recipient_share_commitment_root = verify_vss_public_recipient_share_commitment_set(
        recipient_share_commitment_set,
        &VssPublicRecipientShareCommitmentSetContext {
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            ring_degree: input.statement.ring_degree,
        },
    )?;
    let aggregate_threshold_commitment_root = verify_vss_public_aggregate_threshold_commitment_set(
        aggregate_threshold_commitment_set,
        &VssPublicAggregateThresholdCommitmentSetContext {
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            ring_degree: input.statement.ring_degree,
        },
    )?;

    compare_required_string(
        &coefficient_commitment_root,
        input.statement.coefficient_commitment_root,
        "VSS share linkage evidence coefficientCommitmentRoot",
    )?;
    compare_required_string(
        &recipient_share_commitment_root,
        input.recipient_share_commitment_root,
        "VSS share linkage evidence recipientShareCommitmentRoot",
    )?;
    compare_required_string(
        &aggregate_threshold_commitment_root,
        input.statement.aggregate_threshold_commitment_root,
        "VSS share linkage evidence aggregateThresholdCommitmentRoot",
    )?;
    // The proven "T = sum" aggregate binding is verified separately, on the
    // accepted-setup material-verification path, not here: the statement
    // evidence check binds only the committed roots across the sets.
    let coefficient_source_records =
        array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let recipient_source_records =
        array_at_path(recipient_share_commitment_set, &["sourceTrusteeRecords"])?;
    if coefficient_source_records.len() != input.statement.participant_count
        || recipient_source_records.len() != input.statement.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage evidence source records must cover every participant",
        ));
    }
    for expected_source_position in 0..input.statement.participant_count {
        let coefficient_source_record = &coefficient_source_records[expected_source_position];
        let recipient_source_record = &recipient_source_records[expected_source_position];
        compare_required_string(
            string_at_path(coefficient_source_record, &["sourceTrusteeIdentity"])?,
            string_at_path(recipient_source_record, &["sourceTrusteeIdentity"])?,
            "VSS share linkage evidence sourceTrusteeIdentity",
        )?;
    }

    Ok(())
}

// For every aggregate record, verify the unit-evaluation-point share-linkage
// relation binding the committed threshold share T_{j,l} to the modular sum of
// the committed source recipient shares sigma_{i->j,l}. The statement roots are
// bound canonically to the recipient-share and aggregate commitment sets.
pub(crate) struct VssAggregateThresholdProofContext<'a> {
    pub(crate) setup_context_hash: String,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) ring_degree: usize,
    pub(crate) participant_count: usize,
    pub(crate) rns_limb_count: usize,
}

pub(in crate::bgv::setup) fn vss_aggregate_threshold_statement_from_commitment_records(
    public_matrix_seed_hash: &str,
    participant_count: usize,
    rns_limb_count: usize,
    coefficient_source_records: &[Value],
    recipient_source_records: &[Value],
    aggregate_record: &Value,
    aggregate_record_index: usize,
) -> CanonicalResult<Value> {
    if rns_limb_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proof requires at least one RNS limb",
        ));
    }
    if coefficient_source_records.len() != participant_count
        || recipient_source_records.len() != participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proof source records must cover every participant",
        ));
    }

    let recipient_roster_position = aggregate_record_index / rns_limb_count;
    let rns_limb_index = aggregate_record_index % rns_limb_count;
    let source_message_modulus = DATA_PRIMES.get(rns_limb_index).copied().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proof RNS limb is outside the data basis",
        )
    })?;
    let coefficient_source_record = coefficient_source_records
        .get(recipient_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS coefficient set is missing the aggregate proof metadata source record",
            )
        })?;
    let recipient_source_record = recipient_source_records
        .get(recipient_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS recipient-share set is missing the aggregate proof metadata source record",
            )
        })?;

    let mut coefficient_commitment_roots = Vec::with_capacity(participant_count);
    let mut coefficient_commitments = Vec::with_capacity(participant_count);
    for source_record in recipient_source_records {
        let recipient_share_record = array_at_path(source_record, &["recipientShareCommitments"])?
            .get(aggregate_record_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS aggregate proof references a missing recipient-share commitment",
                )
            })?;
        coefficient_commitment_roots
            .push(value_at_path(recipient_share_record, &["shareCommitmentRoot"])?.clone());
        coefficient_commitments
            .push(value_at_path(recipient_share_record, &["commitment"])?.clone());
    }

    let recipient_identity = string_at_path(aggregate_record, &["recipientIdentity"])?;
    let mut statement = json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeIdentity": recipient_identity,
        "sourceTrusteeRosterPosition": recipient_roster_position,
        "sourceCoefficientCommitmentRoot": hash_at_path(
            coefficient_source_record,
            &["sourceCoefficientCommitmentRoot"],
        )?,
        "sourceRecipientShareCommitmentRoot": hash_at_path(
            recipient_source_record,
            &["sourceRecipientShareCommitmentRoot"],
        )?,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "sourceMessageModulus": source_message_modulus,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": hash_at_path(
            aggregate_record,
            &["aggregateCommitmentRoot"],
        )?,
        "recipientShareCommitment": value_at_path(aggregate_record, &["commitment"])?,
        "additionalLinkageItems": [],
    });
    let statement_root = derive_canonical_object_hash(&statement)?;
    statement["shareLinkageStatementRoot"] = Value::String(statement_root);
    Ok(statement)
}

pub(crate) fn verify_vss_public_aggregate_threshold_proofs(
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
    coefficient_commitment_set: &Value,
    recipient_share_commitment_set: &Value,
    aggregate_threshold_commitment_set: &Value,
    context: &VssAggregateThresholdProofContext<'_>,
) -> CanonicalResult<()> {
    let participant_count = context.participant_count;
    let rns_limb_count = context.rns_limb_count;
    let recipient_source_records =
        array_at_path(recipient_share_commitment_set, &["sourceTrusteeRecords"])?;
    let coefficient_source_records =
        array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    let aggregate_recipient_records =
        array_at_path(aggregate_threshold_commitment_set, &["recipientRecords"])?;
    let aggregate_proofs = array_at_path(
        aggregate_threshold_commitment_set,
        &["aggregateThresholdProofs"],
    )?;
    if aggregate_proofs.len() != aggregate_recipient_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proofs must cover every aggregate record",
        ));
    }
    let mut seen_proof_material_roots = std::collections::BTreeSet::new();
    for (aggregate_record_index, (aggregate_record, proof)) in aggregate_recipient_records
        .iter()
        .zip(aggregate_proofs)
        .enumerate()
    {
        compare_required_string(
            string_at_path(proof, &["objectType"])?,
            "VssAggregateThresholdProofRecord",
            "VSS aggregate threshold proof objectType",
        )?;
        let proof_bytes_hash = hash_at_path(proof, &["proofBytesHash"])?;
        let proof_material_root = hash_at_path(proof, &["proofMaterialRoot"])?;
        if !seen_proof_material_roots.insert(proof_material_root) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold proofs must reference unique proof material",
            ));
        }
        compare_required_string(
            proof_material_root,
            &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY,
                proof_bytes_hash,
            )?,
            "VSS aggregate threshold proof material root",
        )?;
        let vss_aggregate = vss_aggregate_threshold_statement_from_commitment_records(
            context.public_matrix_seed_hash,
            participant_count,
            rns_limb_count,
            coefficient_source_records,
            recipient_source_records,
            aggregate_record,
            aggregate_record_index,
        )?;
        let expected_share_linkage_statement_root =
            hash_at_path(&vss_aggregate, &["shareLinkageStatementRoot"])?.to_string();
        // Verify the unit-point share-linkage proof that T_{j,l} is the modular
        // sum of the bound source shares. An incremental setup session may have
        // already checked these bytes against this exact request and released
        // them; otherwise the source-aware decoder consumes the authenticated
        // canonical stream chunks now.
        let proof_request = json!({
            "context": {
                "setupContextHash": &context.setup_context_hash,
                "trusteeIdentity": "vss-aggregate-threshold",
                "trusteeRosterPosition": 0,
                "shareLinkageStatementRoot": &expected_share_linkage_statement_root,
            },
            "ringDegree": context.ring_degree,
            "vssShareLinkage": &vss_aggregate,
        });
        let proof_material_root = hash_at_path(proof, &["proofMaterialRoot"])?;
        let verification_binding_hash = crate::bgv::setup::trustee_evaluation_key_proof::vss_share_linkage_proof_verification_binding_hash(
            proof_material_root,
            &proof_request,
        )?;
        let consumed_preverified_binding =
            if let Some(proof_binding_session) = proof_binding_session {
                crate::bgv::setup::consume_accepted_setup_proof_binding(
                    proof_binding_session.session_handle,
                    crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY,
                    proof_material_root,
                    &verification_binding_hash,
                )?
            } else {
                false
            };
        if !consumed_preverified_binding {
            let proof_bytes = crate::bgv::setup::trustee_evaluation_key_proof::verified_vss_share_linkage_proof_material_bytes(
                proof_material_root,
                hash_at_path(proof, &["proofBytesHash"])?,
                proof_binding_session,
            )?;
            crate::bgv::setup::trustee_evaluation_key_proof::verify_vss_share_linkage_proof_source_from_request(
                &proof_request,
                proof_bytes.as_ref(),
            )?;
        }
    }

    Ok(())
}
