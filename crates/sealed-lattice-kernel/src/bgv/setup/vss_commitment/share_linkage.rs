use super::*;

// Verifies the structural bindings only: canonical set roots, commitment
// bodies, and cross-set consistency. Acceptance here verifies no
// share-linkage proof, and for a
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
    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let source_records = array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    if source_records.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage requires at least one coefficient source record",
        ));
    }
    let participant_count = source_records.len();
    let q_share_rns_limb_count = DATA_PRIMES.len();
    let coefficient_count = array_at_path(&source_records[0], &["coefficientCommitments"])?.len();
    if coefficient_count == 0 || !coefficient_count.is_multiple_of(q_share_rns_limb_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage coefficient records must cover complete non-empty Q_share threshold coordinates",
        ));
    }
    let threshold_degree = coefficient_count / q_share_rns_limb_count;
    let evidence_roots = verify_vss_share_linkage_evidence(VssShareLinkageEvidenceInput {
        request,
        statement: VssShareLinkageStatementBinding {
            setup_context_hash,
            public_matrix_seed_hash,
            ring_degree,
            participant_count,
            q_share_rns_limb_count,
            threshold_degree,
        },
    })?;

    Ok(json!({
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": evidence_roots.coefficient_commitment_root,
        "recipientShareCommitmentRoot": evidence_roots.recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": evidence_roots.aggregate_threshold_commitment_root,
    }))
}

pub(super) struct VssShareLinkageStatementBinding<'a> {
    setup_context_hash: &'a str,
    public_matrix_seed_hash: &'a str,
    ring_degree: usize,
    participant_count: usize,
    q_share_rns_limb_count: usize,
    threshold_degree: usize,
}

pub(super) struct VssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: VssShareLinkageStatementBinding<'a>,
}

pub(super) struct VssShareLinkageEvidenceRoots {
    coefficient_commitment_root: String,
    recipient_share_commitment_root: String,
    aggregate_threshold_commitment_root: String,
}

pub(super) fn verify_vss_share_linkage_evidence(
    input: VssShareLinkageEvidenceInput<'_>,
) -> CanonicalResult<VssShareLinkageEvidenceRoots> {
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
) -> CanonicalResult<VssShareLinkageEvidenceRoots> {
    let coefficient_commitment_root = verify_vss_public_coefficient_commitment_set(
        coefficient_commitment_set,
        &VssPublicCoefficientCommitmentSetContext {
            setup_context_hash: input.statement.setup_context_hash,
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
            setup_context_hash: input.statement.setup_context_hash,
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            ring_degree: input.statement.ring_degree,
        },
    )?;
    let aggregate_threshold_commitment_root = verify_vss_public_aggregate_threshold_commitment_set(
        aggregate_threshold_commitment_set,
        &VssPublicAggregateThresholdCommitmentSetContext {
            setup_context_hash: input.statement.setup_context_hash,
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            ring_degree: input.statement.ring_degree,
        },
    )?;

    // The proven "T = sum" aggregate binding is verified separately, on the
    // accepted-setup material-verification path, not here.
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

    Ok(VssShareLinkageEvidenceRoots {
        coefficient_commitment_root,
        recipient_share_commitment_root,
        aggregate_threshold_commitment_root,
    })
}

// Each aggregate proof binds the committed threshold share to the modular sum
// of its source recipient shares at the unit evaluation point.
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
        coefficient_commitment_roots.push(Value::String(vss_public_commitment_body_root(
            recipient_share_record,
        )?));
        coefficient_commitments
            .push(value_at_path(recipient_share_record, &["commitment"])?.clone());
    }

    let recipient_identity = string_at_path(aggregate_record, &["recipientIdentity"])?;
    Ok(json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeIdentity": recipient_identity,
        "sourceTrusteeRosterPosition": recipient_roster_position,
        "sourceCoefficientCommitmentRoot":
            vss_public_source_coefficient_record_root(coefficient_source_record)?,
        "sourceRecipientShareCommitmentRoot":
            vss_public_source_recipient_share_record_root(recipient_source_record)?,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "sourceMessageModulus": source_message_modulus,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": vss_public_commitment_body_root(aggregate_record)?,
        "recipientShareCommitment": value_at_path(aggregate_record, &["commitment"])?,
        "additionalLinkageItems": [],
    }))
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
    let mut seen_proof_bytes_hashes = std::collections::BTreeSet::new();
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
        if !seen_proof_bytes_hashes.insert(proof_bytes_hash.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold proofs must reference unique proof material",
            ));
        }
        let vss_aggregate = vss_aggregate_threshold_statement_from_commitment_records(
            context.public_matrix_seed_hash,
            participant_count,
            rns_limb_count,
            coefficient_source_records,
            recipient_source_records,
            aggregate_record,
            aggregate_record_index,
        )?;
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
            },
            "ringDegree": context.ring_degree,
            "vssShareLinkage": &vss_aggregate,
        });
        let verification_binding_hash = crate::bgv::setup::trustee_evaluation_key_proof::vss_share_linkage_proof_verification_binding_hash(
            proof_bytes_hash,
            &proof_request,
        )?;
        let consumed_preverified_binding =
            if let Some(proof_binding_session) = proof_binding_session {
                crate::bgv::setup::consume_accepted_setup_proof_binding(
                    proof_binding_session.session_handle,
                    crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY,
                    proof_bytes_hash,
                    &verification_binding_hash,
                )?
            } else {
                false
            };
        if !consumed_preverified_binding {
            let proof_bytes = crate::bgv::setup::trustee_evaluation_key_proof::verified_vss_share_linkage_proof_material_bytes(
                proof_bytes_hash,
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
