use super::*;

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
    let target_basis_hash = hash_at_path(statement, &["targetBasisHash"])?;
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
    let target_rns_limb_count = read_positive_usize_at_path(
        statement,
        &["targetRnsLimbCount"],
        "VSS share linkage statement targetRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement,
        &["thresholdDegree"],
        "VSS share linkage statement thresholdDegree",
    )?;
    let source_statement_records = array_at_path(statement, &["sourceStatementRecords"])?;
    if source_statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage statement must contain one source statement per participant",
        ));
    }
    let mut verified_source_statement_records = Vec::with_capacity(source_statement_records.len());
    for (expected_source_position, source_statement_record) in
        source_statement_records.iter().enumerate()
    {
        verified_source_statement_records.push(verify_vss_share_linkage_source_statement(
            VssShareLinkageSourceStatementInput {
                source_statement_record,
                expected_source_position,
                statement: VssShareLinkageStatementBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                    target_basis_hash,
                    ring_degree,
                    participant_count,
                    target_rns_limb_count,
                    threshold_degree,
                    coefficient_commitment_root,
                    aggregate_threshold_commitment_root,
                },
            },
        )?);
    }
    let statement_root = hash_at_path(statement, &["statementRoot"])?;
    let statement_without_root = json!({
        "objectType": "VssShareLinkageStatement",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "sourceStatementRecords": verified_source_statement_records,
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
            ceremony_id,
            manifest_hash,
            roster_hash,
            setup_parameters_hash,
            setup_epoch,
            public_matrix_seed_hash,
            target_basis_hash,
            ring_degree,
            participant_count,
            target_rns_limb_count,
            threshold_degree,
            coefficient_commitment_root,
            aggregate_threshold_commitment_root,
        },
        recipient_share_commitment_root,
        verified_source_statement_records: &verified_source_statement_records,
    })?;

    Ok(json!({
        "ok": true,
        "operation": "verifyVssShareLinkageBindings",
        "statementRoot": statement_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
    }))
}

pub(super) struct VssShareLinkageStatementBinding<'a> {
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_parameters_hash: &'a str,
    setup_epoch: &'a str,
    public_matrix_seed_hash: &'a str,
    target_basis_hash: &'a str,
    ring_degree: usize,
    participant_count: usize,
    target_rns_limb_count: usize,
    threshold_degree: usize,
    coefficient_commitment_root: &'a str,
    aggregate_threshold_commitment_root: &'a str,
}

pub(super) struct VssShareLinkageSourceStatementInput<'a> {
    source_statement_record: &'a Value,
    expected_source_position: usize,
    statement: VssShareLinkageStatementBinding<'a>,
}

pub(super) struct VssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: VssShareLinkageStatementBinding<'a>,
    recipient_share_commitment_root: &'a str,
    verified_source_statement_records: &'a [Value],
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
            input.statement.target_rns_limb_count as u64,
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
    if coefficient_rns_limb_count < input.statement.target_rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage coefficient evidence must cover the target basis",
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
        || input.verified_source_statement_records.len() != input.statement.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage evidence source records must cover every participant",
        ));
    }
    for expected_source_position in 0..input.statement.participant_count {
        let source_statement = &input.verified_source_statement_records[expected_source_position];
        let coefficient_source_record = &coefficient_source_records[expected_source_position];
        let recipient_source_record = &recipient_source_records[expected_source_position];
        let source_trustee_identity = string_at_path(source_statement, &["sourceTrusteeIdentity"])?;
        compare_required_string(
            string_at_path(coefficient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "VSS share linkage evidence coefficient sourceTrusteeIdentity",
        )?;
        compare_required_string(
            string_at_path(recipient_source_record, &["sourceTrusteeIdentity"])?,
            source_trustee_identity,
            "VSS share linkage evidence recipient sourceTrusteeIdentity",
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
        compare_required_string(
            hash_at_path(
                coefficient_source_record,
                &["sourceCoefficientCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceCoefficientCommitmentRoot"])?,
            "VSS share linkage evidence sourceCoefficientCommitmentRoot",
        )?;
        compare_required_string(
            hash_at_path(
                recipient_source_record,
                &["sourceRecipientShareCommitmentRoot"],
            )?,
            hash_at_path(source_statement, &["sourceRecipientShareCommitmentRoot"])?,
            "VSS share linkage evidence sourceRecipientShareCommitmentRoot",
        )?;
        let coefficient_records =
            array_at_path(coefficient_source_record, &["coefficientCommitments"])?;
        let source_statement_coefficient_opening_roots =
            array_at_path(source_statement, &["coefficientOpeningRoots"])?;
        let target_coefficient_record_count = input
            .statement
            .target_rns_limb_count
            .checked_mul(input.statement.threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS share linkage target coefficient count overflowed",
                )
            })?;
        if source_statement_coefficient_opening_roots.len() != target_coefficient_record_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS share linkage evidence coefficient opening roots must cover the source statement",
            ));
        }
        for (opening_root_index, coefficient_record) in coefficient_records
            .iter()
            .take(target_coefficient_record_count)
            .enumerate()
        {
            let expected_opening_root =
                hash_at_path(coefficient_record, &["coefficientOpeningRoot"])?;
            let source_statement_opening_root = source_statement_coefficient_opening_roots
                .get(opening_root_index)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS share linkage source coefficient opening root must be a string",
                    )
                })?;
            compare_required_string(
                source_statement_opening_root,
                expected_opening_root,
                "VSS share linkage evidence coefficientOpeningRoots",
            )?;
        }
        let recipient_share_records =
            array_at_path(recipient_source_record, &["recipientShareCommitments"])?;
        let source_statement_recipient_share_opening_roots =
            array_at_path(source_statement, &["recipientShareOpeningRoots"])?;
        if recipient_share_records.len() != source_statement_recipient_share_opening_roots.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS share linkage evidence recipient-share opening roots must cover the source statement",
            ));
        }
        for (opening_root_index, recipient_share_record) in
            recipient_share_records.iter().enumerate()
        {
            let expected_opening_root =
                hash_at_path(recipient_share_record, &["shareOpeningRoot"])?;
            let source_statement_opening_root = source_statement_recipient_share_opening_roots
                .get(opening_root_index)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS share linkage source recipient-share opening root must be a string",
                    )
                })?;
            compare_required_string(
                source_statement_opening_root,
                expected_opening_root,
                "VSS share linkage evidence recipientShareOpeningRoots",
            )?;
        }
    }

    Ok(())
}

// Verify the proven threshold-share aggregate binding: for every aggregate
// record, a unit-evaluation-point share-linkage proof shows the committed
// threshold share T_{j,l} is the modular sum of the committed source recipient
// shares sigma_{i->j,l}. Replaces the removed public homomorphic coordinate-sum.
// Acceptance is by the proof plus the canonical binding of its statement's
// committed roots to the recipient-share and aggregate commitment sets, never by
// any self-attested field.
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

pub(crate) fn verify_vss_public_aggregate_threshold_proofs(
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
        compare_required_string(
            string_at_path(proof, &["proofFamily"])?,
            "vss-share-linkage",
            "VSS aggregate threshold proof family",
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
        if !array_at_path(vss_aggregate, &["additionalLinkageItems"])?.is_empty() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate proof must not contain additional linkage items",
            ));
        }
        // The proof's coefficients are the committed source recipient shares
        // sigma_{i->j,l}, in source order, matching the recipient-share set.
        let coefficient_commitment_roots =
            array_at_path(vss_aggregate, &["coefficientCommitmentRoots"])?;
        let coefficient_opening_roots = array_at_path(vss_aggregate, &["coefficientOpeningRoots"])?;
        let coefficient_commitments = array_at_path(vss_aggregate, &["coefficientCommitments"])?;
        if coefficient_commitment_roots.len() != participant_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate proof must sum one source share per participant",
            ));
        }
        if coefficient_opening_roots.len() != participant_count
            || coefficient_commitments.len() != participant_count
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate proof source share openings and commitments must cover every participant",
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
            let bound_opening_root = coefficient_opening_roots[source_roster_position]
                .as_str()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "VSS aggregate proof source share opening root must be a string",
                    )
                })?;
            compare_required_string(
                bound_opening_root,
                hash_at_path(recipient_share_record, &["shareOpeningRoot"])?,
                "VSS aggregate proof source share opening root",
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
        // sum of the bound source shares.
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            string_at_path(proof, &["proofBytesBase64"])?,
            "VSS aggregate proof proofBytesBase64",
        )?;
        let proof_bytes_hex = crate::transcript_core::encode_hex(&proof_bytes);
        crate::bgv::setup::verify_vss_share_linkage_proof_from_request(&json!({
            "context": {
                "ceremonyId": context.ceremony_id,
                "manifestHash": context.manifest_hash,
                "rosterHash": context.roster_hash,
                "trusteeIdentity": "vss-aggregate-threshold",
                "trusteeRosterPosition": 0,
                "setupEpoch": context.setup_epoch,
                "shareLinkageStatementRoot": vss_aggregate["shareLinkageStatementRoot"],
            },
            "ringDegree": context.ring_degree,
            "vssShareLinkage": vss_aggregate,
            "proofBytesHex": proof_bytes_hex,
        }))?;
    }

    Ok(())
}

pub(super) fn verify_vss_share_linkage_source_statement(
    input: VssShareLinkageSourceStatementInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_statement_record, &["objectType"])?,
        "VssShareLinkageSourceStatement",
        "VSS share linkage source statement objectType",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["ceremonyId"])?,
        input.statement.ceremony_id,
        "VSS share linkage source statement ceremonyId",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["manifestHash"])?,
        input.statement.manifest_hash,
        "VSS share linkage source statement manifestHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["rosterHash"])?,
        input.statement.roster_hash,
        "VSS share linkage source statement rosterHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["setupParametersHash"])?,
        input.statement.setup_parameters_hash,
        "VSS share linkage source statement setupParametersHash",
    )?;
    compare_required_string(
        string_at_path(input.source_statement_record, &["setupEpoch"])?,
        input.statement.setup_epoch,
        "VSS share linkage source statement setupEpoch",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["publicMatrixSeedHash"])?,
        input.statement.public_matrix_seed_hash,
        "VSS share linkage source statement publicMatrixSeedHash",
    )?;
    compare_required_string(
        hash_at_path(input.source_statement_record, &["targetBasisHash"])?,
        input.statement.target_basis_hash,
        "VSS share linkage source statement targetBasisHash",
    )?;
    let source_trustee_identity =
        read_non_empty_string(input.source_statement_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(
            input.source_statement_record,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.expected_source_position as u64,
        "VSS share linkage source statement sourceTrusteeRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["participantCount"])?,
        input.statement.participant_count as u64,
        "VSS share linkage source statement participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["ringDegree"])?,
        input.statement.ring_degree as u64,
        "VSS share linkage source statement ringDegree",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["targetRnsLimbCount"])?,
        input.statement.target_rns_limb_count as u64,
        "VSS share linkage source statement targetRnsLimbCount",
    )?;
    compare_required_u64(
        unsigned_at_path(input.source_statement_record, &["thresholdDegree"])?,
        input.statement.threshold_degree as u64,
        "VSS share linkage source statement thresholdDegree",
    )?;
    compare_required_string(
        hash_at_path(
            input.source_statement_record,
            &["coefficientCommitmentRoot"],
        )?,
        input.statement.coefficient_commitment_root,
        "VSS share linkage source statement coefficientCommitmentRoot",
    )?;
    let source_coefficient_commitment_root = hash_at_path(
        input.source_statement_record,
        &["sourceCoefficientCommitmentRoot"],
    )?;
    let source_recipient_share_commitment_root = hash_at_path(
        input.source_statement_record,
        &["sourceRecipientShareCommitmentRoot"],
    )?;
    let expected_coefficient_opening_root_count = input
        .statement
        .target_rns_limb_count
        .checked_mul(input.statement.threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS source statement coefficient opening root count overflowed",
            )
        })?;
    let coefficient_opening_roots =
        array_at_path(input.source_statement_record, &["coefficientOpeningRoots"])?;
    if coefficient_opening_roots.len() != expected_coefficient_opening_root_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage source statement coefficientOpeningRoots must cover every target limb and coefficient",
        ));
    }
    let verified_coefficient_opening_roots = coefficient_opening_roots
        .iter()
        .enumerate()
        .map(|(opening_root_index, opening_root)| {
            let root = opening_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "VSS share linkage source statement coefficientOpeningRoots.{opening_root_index} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "VSS share linkage source statement coefficientOpeningRoots.{opening_root_index}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_recipient_share_opening_root_count = input
        .statement
        .participant_count
        .checked_mul(input.statement.target_rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS source statement recipient-share opening root count overflowed",
            )
        })?;
    let recipient_share_opening_roots = array_at_path(
        input.source_statement_record,
        &["recipientShareOpeningRoots"],
    )?;
    if recipient_share_opening_roots.len() != expected_recipient_share_opening_root_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage source statement recipientShareOpeningRoots must cover every recipient and target limb",
        ));
    }
    let verified_recipient_share_opening_roots = recipient_share_opening_roots
        .iter()
        .enumerate()
        .map(|(opening_root_index, opening_root)| {
            let root = opening_root.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "VSS share linkage source statement recipientShareOpeningRoots.{opening_root_index} must be a string"
                    ),
                )
            })?;
            validate_hash_string(
                root,
                &format!(
                    "VSS share linkage source statement recipientShareOpeningRoots.{opening_root_index}"
                ),
            )?;

            Ok(Value::String(root.to_string()))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    compare_required_string(
        hash_at_path(
            input.source_statement_record,
            &["aggregateThresholdCommitmentRoot"],
        )?,
        input.statement.aggregate_threshold_commitment_root,
        "VSS share linkage source statement aggregateThresholdCommitmentRoot",
    )?;
    let expected_source_statement = json!({
        "objectType": "VssShareLinkageSourceStatement",
        "ceremonyId": input.statement.ceremony_id,
        "manifestHash": input.statement.manifest_hash,
        "rosterHash": input.statement.roster_hash,
        "setupParametersHash": input.statement.setup_parameters_hash,
        "setupEpoch": input.statement.setup_epoch,
        "publicMatrixSeedHash": input.statement.public_matrix_seed_hash,
        "targetBasisHash": input.statement.target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_position,
        "ringDegree": input.statement.ring_degree,
        "participantCount": input.statement.participant_count,
        "targetRnsLimbCount": input.statement.target_rns_limb_count,
        "thresholdDegree": input.statement.threshold_degree,
        "coefficientCommitmentRoot": input.statement.coefficient_commitment_root,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        "coefficientOpeningRoots": verified_coefficient_opening_roots,
        "recipientShareOpeningRoots": verified_recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": input.statement.aggregate_threshold_commitment_root,
    });
    let source_statement_root =
        hash_at_path(input.source_statement_record, &["sourceStatementRoot"])?;
    let expected_source_statement_root = derive_canonical_object_hash(&expected_source_statement)?;
    if expected_source_statement_root != source_statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS share linkage source statement root does not match its bound roots",
        ));
    }

    let mut verified_source_statement = expected_source_statement;
    verified_source_statement["sourceStatementRoot"] = json!(source_statement_root);

    Ok(verified_source_statement)
}
