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
    let ceremony_id = read_non_empty_string(statement, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement, &["rosterHash"])?;
    let setup_parameters_hash = hash_at_path(statement, &["setupParametersHash"])?;
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
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
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
    let coefficient_verification = verify_vss_public_coefficient_commitment_set_request(&json!({
        "coefficientCommitmentSet": coefficient_commitment_set,
    }))?;
    let recipient_verification =
        verify_vss_public_recipient_share_commitment_set_request(&json!({
            "recipientShareCommitmentSet": recipient_share_commitment_set,
        }))?;
    let aggregate_verification =
        verify_vss_public_aggregate_threshold_commitment_set_request(&json!({
            "aggregateThresholdCommitmentSet": aggregate_threshold_commitment_set,
        }))?;

    compare_required_string(
        hash_at_path(&coefficient_verification, &["coefficientCommitmentRoot"])?,
        input.statement.coefficient_commitment_root,
        "VSS share linkage evidence coefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(&recipient_verification, &["recipientShareCommitmentRoot"])?,
        input.recipient_share_commitment_root,
        "VSS share linkage evidence recipientShareCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(
            &aggregate_verification,
            &["aggregateThresholdCommitmentRoot"],
        )?,
        input.statement.aggregate_threshold_commitment_root,
        "VSS share linkage evidence aggregateThresholdCommitmentRoot",
    )?;
    for (verification, description) in [
        (&recipient_verification, "recipient-share"),
        (&aggregate_verification, "aggregate-threshold"),
    ] {
        compare_required_string(
            hash_at_path(verification, &["publicMatrixSeedHash"])?,
            input.statement.public_matrix_seed_hash,
            &format!("VSS share linkage evidence {description} publicMatrixSeedHash"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["participantCount"])?,
            input.statement.participant_count as u64,
            &format!("VSS share linkage evidence {description} participantCount"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["ringDegree"])?,
            input.statement.ring_degree as u64,
            &format!("VSS share linkage evidence {description} ringDegree"),
        )?;
        compare_required_u64(
            unsigned_at_path(verification, &["rnsLimbCount"])?,
            input.statement.q_share_rns_limb_count as u64,
            &format!("VSS share linkage evidence {description} rnsLimbCount"),
        )?;
    }
    compare_required_string(
        hash_at_path(&coefficient_verification, &["publicMatrixSeedHash"])?,
        input.statement.public_matrix_seed_hash,
        "VSS share linkage evidence coefficient publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["participantCount"])?,
        input.statement.participant_count as u64,
        "VSS share linkage evidence coefficient participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["ringDegree"])?,
        input.statement.ring_degree as u64,
        "VSS share linkage evidence coefficient ringDegree",
    )?;
    let coefficient_rns_limb_count = usize_at_path(&coefficient_verification, &["rnsLimbCount"])?;
    if coefficient_rns_limb_count < input.statement.q_share_rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage coefficient evidence must cover Q_share",
        ));
    }
    compare_required_u64(
        unsigned_at_path(&coefficient_verification, &["thresholdDegree"])?,
        input.statement.threshold_degree as u64,
        "VSS share linkage evidence coefficient thresholdDegree",
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
        compare_required_u64(
            unsigned_at_path(coefficient_source_record, &["sourceTrusteeRosterPosition"])?,
            expected_source_position as u64,
            "VSS share linkage evidence coefficient sourceTrusteeRosterPosition",
        )?;
        compare_required_u64(
            unsigned_at_path(recipient_source_record, &["sourceTrusteeRosterPosition"])?,
            expected_source_position as u64,
            "VSS share linkage evidence recipient sourceTrusteeRosterPosition",
        )?;
    }

    Ok(())
}

// For every aggregate record, verify the unit-evaluation-point share-linkage
// relation binding the committed threshold share T_{j,l} to the modular sum of
// the committed source recipient shares sigma_{i->j,l}. The statement roots are
// bound canonically to the recipient-share and aggregate commitment sets.
pub(crate) struct VssAggregateThresholdProofContext<'a> {
    pub(crate) ceremony_id: &'a str,
    pub(crate) manifest_hash: &'a str,
    pub(crate) roster_hash: &'a str,
    pub(crate) setup_epoch: &'a str,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) ring_degree: usize,
    pub(crate) participant_count: usize,
    pub(crate) rns_limb_count: usize,
}

pub(super) fn verify_vss_aggregate_threshold_statement_root(
    vss_aggregate: &Value,
) -> CanonicalResult<String> {
    compare_required_string(
        string_at_path(vss_aggregate, &["objectType"])?,
        "VssShareLinkageStatement",
        "VSS aggregate proof statement objectType",
    )?;
    if vss_aggregate
        .get("isThresholdAggregate")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS aggregate proof statement must set isThresholdAggregate",
        ));
    }
    let additional_linkage_items = array_at_path(vss_aggregate, &["additionalLinkageItems"])?;
    if !additional_linkage_items.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate proof must not contain additional linkage items",
        ));
    }

    // Rebuild the aggregate statement from every field consumed by the proof
    // parser and verifier before deriving its named root.
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": hash_at_path(vss_aggregate, &["publicMatrixSeedHash"] )?,
        "sourceTrusteeIdentity": string_at_path(vss_aggregate, &["sourceTrusteeIdentity"] )?,
        "sourceTrusteeRosterPosition": unsigned_at_path(
            vss_aggregate,
            &["sourceTrusteeRosterPosition"],
        )?,
        "sourceCoefficientCommitmentRoot": hash_at_path(
            vss_aggregate,
            &["sourceCoefficientCommitmentRoot"],
        )?,
        "sourceRecipientShareCommitmentRoot": hash_at_path(
            vss_aggregate,
            &["sourceRecipientShareCommitmentRoot"],
        )?,
        "recipientIdentity": string_at_path(vss_aggregate, &["recipientIdentity"] )?,
        "recipientRosterPosition": unsigned_at_path(
            vss_aggregate,
            &["recipientRosterPosition"],
        )?,
        "sourceRnsLimbIndex": unsigned_at_path(vss_aggregate, &["sourceRnsLimbIndex"] )?,
        "sourceMessageModulus": unsigned_at_path(vss_aggregate, &["sourceMessageModulus"] )?,
        "coefficientCommitmentRoots": array_at_path(
            vss_aggregate,
            &["coefficientCommitmentRoots"],
        )?,
        "coefficientCommitments": array_at_path(
            vss_aggregate,
            &["coefficientCommitments"],
        )?,
        "recipientShareCommitmentRoot": hash_at_path(
            vss_aggregate,
            &["recipientShareCommitmentRoot"],
        )?,
        "recipientShareCommitment": value_at_path(
            vss_aggregate,
            &["recipientShareCommitment"],
        )?,
        "additionalLinkageItems": additional_linkage_items,
    });
    let expected_statement_root = derive_canonical_object_hash(&statement_without_root)?;
    compare_required_string(
        hash_at_path(vss_aggregate, &["shareLinkageStatementRoot"])?,
        &expected_statement_root,
        "VSS aggregate proof share-linkage statement root",
    )?;

    Ok(expected_statement_root)
}

pub(crate) fn verify_vss_public_aggregate_threshold_proofs(
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
    proof_material_request: &Value,
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
    let mut seen_proof_coordinates = std::collections::BTreeSet::new();
    for proof in aggregate_proofs {
        compare_required_string(
            string_at_path(proof, &["objectType"])?,
            "VssAggregateThresholdProofRecord",
            "VSS aggregate threshold proof objectType",
        )?;
        let proof_bytes_hash = hash_at_path(proof, &["proofBytesHash"])?;
        let proof_material_root = hash_at_path(proof, &["proofMaterialRoot"])?;
        compare_required_string(
            proof_material_root,
            &crate::bgv::setup::setup_proof::setup_proof_material_reference_root(
                crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY,
                proof_bytes_hash,
            )?,
            "VSS aggregate threshold proof material root",
        )?;
        let proof_recipient_roster_position =
            unsigned_at_path(proof, &["recipientRosterPosition"])?;
        let proof_rns_limb_index = unsigned_at_path(proof, &["rnsLimbIndex"])?;
        if !seen_proof_coordinates.insert((proof_recipient_roster_position, proof_rns_limb_index)) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold proofs must contain one proof per recipient limb",
            ));
        }
    }
    for aggregate_record in aggregate_recipient_records {
        let recipient_roster_position =
            unsigned_at_path(aggregate_record, &["recipientRosterPosition"])?;
        let rns_limb_index =
            usize::try_from(unsigned_at_path(aggregate_record, &["rnsLimbIndex"])?).map_err(
                |_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS aggregate RNS limb index does not fit usize",
                    )
                },
            )?;
        let recipient_share_record_index = usize::try_from(recipient_roster_position)
            .ok()
            .and_then(|position| position.checked_mul(rns_limb_count))
            .and_then(|offset| offset.checked_add(rns_limb_index))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS aggregate recipient-share record index overflowed",
                )
            })?;
        let proof = aggregate_proofs
            .iter()
            .find(|proof| {
                unsigned_at_path(proof, &["recipientRosterPosition"]).ok()
                    == Some(recipient_roster_position)
                    && unsigned_at_path(proof, &["rnsLimbIndex"]).ok()
                        == Some(rns_limb_index as u64)
            })
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS aggregate threshold record is missing its proof",
                )
            })?;
        let vss_aggregate = value_at_path(proof, &["vssShareLinkage"])?;
        let expected_share_linkage_statement_root =
            verify_vss_aggregate_threshold_statement_root(vss_aggregate)?;
        compare_required_string(
            hash_at_path(vss_aggregate, &["publicMatrixSeedHash"])?,
            context.public_matrix_seed_hash,
            "VSS aggregate proof public matrix seed hash",
        )?;
        let recipient_identity = string_at_path(aggregate_record, &["recipientIdentity"])?;
        compare_required_string(
            string_at_path(vss_aggregate, &["sourceTrusteeIdentity"])?,
            recipient_identity,
            "VSS aggregate proof source trustee identity",
        )?;
        compare_required_u64(
            unsigned_at_path(vss_aggregate, &["sourceTrusteeRosterPosition"])?,
            recipient_roster_position,
            "VSS aggregate proof source trustee roster position",
        )?;
        compare_required_string(
            string_at_path(vss_aggregate, &["recipientIdentity"])?,
            recipient_identity,
            "VSS aggregate proof recipient identity",
        )?;
        compare_required_u64(
            unsigned_at_path(vss_aggregate, &["recipientRosterPosition"])?,
            recipient_roster_position,
            "VSS aggregate proof recipient roster position",
        )?;
        compare_required_u64(
            unsigned_at_path(vss_aggregate, &["sourceRnsLimbIndex"])?,
            rns_limb_index as u64,
            "VSS aggregate proof source RNS limb index",
        )?;
        compare_required_u64(
            unsigned_at_path(vss_aggregate, &["sourceMessageModulus"])?,
            unsigned_at_path(aggregate_record, &["rnsPrime"])?,
            "VSS aggregate proof source message modulus",
        )?;
        let metadata_source_position =
            usize::try_from(recipient_roster_position).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS aggregate recipient roster position does not fit usize",
                )
            })?;
        let coefficient_source_record = coefficient_source_records
            .get(metadata_source_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS coefficient set is missing the aggregate proof metadata source record",
                )
            })?;
        let recipient_source_record = recipient_source_records
            .get(metadata_source_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS recipient-share set is missing the aggregate proof metadata source record",
                )
            })?;
        compare_required_string(
            hash_at_path(vss_aggregate, &["sourceCoefficientCommitmentRoot"])?,
            hash_at_path(
                coefficient_source_record,
                &["sourceCoefficientCommitmentRoot"],
            )?,
            "VSS aggregate proof source coefficient commitment root",
        )?;
        compare_required_string(
            hash_at_path(vss_aggregate, &["sourceRecipientShareCommitmentRoot"])?,
            hash_at_path(
                recipient_source_record,
                &["sourceRecipientShareCommitmentRoot"],
            )?,
            "VSS aggregate proof source recipient-share commitment root",
        )?;
        // The proof's recipient share is the committed threshold share T_{j,l}.
        compare_required_string(
            hash_at_path(vss_aggregate, &["recipientShareCommitmentRoot"])?,
            hash_at_path(aggregate_record, &["aggregateCommitmentRoot"])?,
            "VSS aggregate proof threshold-share commitment root",
        )?;
        compare_required_string(
            hash_at_path(vss_aggregate, &["recipientShareOpeningRoot"])?,
            hash_at_path(aggregate_record, &["aggregateOpeningRoot"])?,
            "VSS aggregate proof threshold-share opening root",
        )?;
        if value_at_path(vss_aggregate, &["recipientShareCommitment"])?
            != value_at_path(aggregate_record, &["commitment"])?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "VSS aggregate proof threshold-share commitment body does not match the aggregate record",
            ));
        }
        // The proof's coefficients are the committed source recipient shares
        // sigma_{i->j,l}, in source order, matching the recipient-share set.
        let coefficient_commitment_roots =
            array_at_path(vss_aggregate, &["coefficientCommitmentRoots"])?;
        let coefficient_commitments = array_at_path(vss_aggregate, &["coefficientCommitments"])?;
        if coefficient_commitment_roots.len() != participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate proof must sum one source share per participant",
            ));
        }
        if coefficient_commitments.len() != participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate proof source share commitments must cover every participant",
            ));
        }
        for (source_roster_position, coefficient_commitment_root) in
            coefficient_commitment_roots.iter().enumerate()
        {
            let source_record = recipient_source_records
                .get(source_roster_position)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS recipient-share set is missing a source record",
                    )
                })?;
            let recipient_share_records =
                array_at_path(source_record, &["recipientShareCommitments"])?;
            let recipient_share_record = recipient_share_records
                .get(recipient_share_record_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS aggregate proof references a missing recipient-share commitment",
                    )
                })?;
            let expected_root = hash_at_path(recipient_share_record, &["shareCommitmentRoot"])?;
            let bound_root = coefficient_commitment_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS aggregate proof source share commitment root must be a string",
                )
            })?;
            compare_required_string(
                bound_root,
                expected_root,
                "VSS aggregate proof source share commitment root",
            )?;
            if &coefficient_commitments[source_roster_position]
                != value_at_path(recipient_share_record, &["commitment"])?
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "VSS aggregate proof source share commitment body does not match the recipient-share record",
                ));
            }
        }
        // Verify the unit-point share-linkage proof that T_{j,l} is the modular
        // sum of the bound source shares. An incremental setup session may have
        // already checked these bytes against this exact request and released
        // them; otherwise the source-aware decoder consumes the authenticated
        // canonical stream chunks now.
        let proof_request = json!({
            "context": {
                "ceremonyId": context.ceremony_id,
                "manifestHash": context.manifest_hash,
                "rosterHash": context.roster_hash,
                "trusteeIdentity": "vss-aggregate-threshold",
                "trusteeRosterPosition": 0,
                "setupEpoch": context.setup_epoch,
                "shareLinkageStatementRoot": expected_share_linkage_statement_root,
            },
            "ringDegree": context.ring_degree,
            "vssShareLinkage": vss_aggregate,
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
                    &proof_binding_session.capability,
                    crate::bgv::setup::trustee_evaluation_key_proof::VSS_SHARE_LINKAGE_PROOF_FAMILY,
                    proof_material_root,
                    &verification_binding_hash,
                )?
            } else {
                false
            };
        if !consumed_preverified_binding {
            let proof_bytes = crate::bgv::setup::trustee_evaluation_key_proof::verified_vss_share_linkage_proof_material_bytes(
                proof_material_request,
                proof_material_root,
                hash_at_path(proof, &["proofBytesHash"] )?,
            )?;
            crate::bgv::setup::trustee_evaluation_key_proof::verify_vss_share_linkage_proof_source_from_request(
                &proof_request,
                proof_bytes.as_ref(),
            )?;
        }
    }

    Ok(())
}
