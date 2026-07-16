use super::*;

// Verifies the structural bindings only: canonical set roots, commitment
// bodies, and cross-set consistency. Acceptance here verifies no
// share-linkage proof, and for a
// threshold-aggregate statement it does not establish that the committed
// threshold share is the sum of the committed source shares; the proven
// aggregate binding is verified by `verify_vss_public_aggregate_threshold_proofs`
// on the accepted-setup material path.
pub(crate) struct VerifiedVssShareLinkageBindings {
    pub(crate) public_matrix_seed_hash: String,
    pub(crate) ring_degree: usize,
    #[cfg(test)]
    pub(crate) coefficient_commitment_root: String,
    #[cfg(test)]
    pub(crate) recipient_share_commitment_root: String,
    #[cfg(test)]
    pub(crate) aggregate_threshold_commitment_root: String,
}

pub(crate) fn verify_vss_share_linkage_bindings_request(
    request: &Value,
    trustee_identities: &[String],
) -> CanonicalResult<VerifiedVssShareLinkageBindings> {
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
    if trustee_identities.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage trustee identities must cover the canonical roster",
        ));
    }
    let q_share_rns_limb_count = DATA_PRIMES.len();
    let coefficient_count = array_at_path(&source_records[0], &["coefficientCommitments"])?.len();
    if coefficient_count == 0 || !coefficient_count.is_multiple_of(q_share_rns_limb_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share linkage coefficient records must cover complete non-empty Q_share threshold coordinates",
        ));
    }
    let threshold_degree = coefficient_count / q_share_rns_limb_count;
    if threshold_degree != decryption_threshold_for_roster_length(participant_count)? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS share-linkage coefficient records do not match the roster-derived threshold degree",
        ));
    }
    let evidence_roots = verify_vss_share_linkage_evidence(VssShareLinkageEvidenceInput {
        request,
        statement: VssShareLinkageStatementBinding {
            setup_context_hash,
            public_matrix_seed_hash,
            participant_count,
            q_share_rns_limb_count,
            threshold_degree,
            trustee_identities,
        },
    })?;
    #[cfg(not(test))]
    let _verified_evidence_roots = evidence_roots;

    Ok(VerifiedVssShareLinkageBindings {
        public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
        ring_degree,
        #[cfg(test)]
        coefficient_commitment_root: evidence_roots.coefficient_commitment_root,
        #[cfg(test)]
        recipient_share_commitment_root: evidence_roots.recipient_share_commitment_root,
        #[cfg(test)]
        aggregate_threshold_commitment_root: evidence_roots.aggregate_threshold_commitment_root,
    })
}

pub(super) struct VssShareLinkageStatementBinding<'a> {
    setup_context_hash: &'a str,
    public_matrix_seed_hash: &'a str,
    participant_count: usize,
    q_share_rns_limb_count: usize,
    threshold_degree: usize,
    trustee_identities: &'a [String],
}

pub(super) struct VssShareLinkageEvidenceInput<'a> {
    request: &'a Value,
    statement: VssShareLinkageStatementBinding<'a>,
}

pub(super) struct VssShareLinkageEvidenceRoots {
    #[cfg(test)]
    coefficient_commitment_root: String,
    #[cfg(test)]
    recipient_share_commitment_root: String,
    #[cfg(test)]
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
    let _coefficient_commitment_root = verify_vss_public_coefficient_commitment_set(
        coefficient_commitment_set,
        &VssPublicCoefficientCommitmentSetContext {
            setup_context_hash: input.statement.setup_context_hash,
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            trustee_identities: input.statement.trustee_identities,
            rns_limb_count: input.statement.q_share_rns_limb_count,
            threshold_degree: input.statement.threshold_degree,
        },
    )?;
    let _recipient_share_commitment_root = verify_vss_public_recipient_share_commitment_set(
        recipient_share_commitment_set,
        &VssPublicRecipientShareCommitmentSetContext {
            setup_context_hash: input.statement.setup_context_hash,
            public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
            participant_count: input.statement.participant_count,
            trustee_identities: input.statement.trustee_identities,
            rns_limb_count: input.statement.q_share_rns_limb_count,
        },
    )?;
    let _aggregate_threshold_commitment_root =
        verify_vss_public_aggregate_threshold_commitment_set(
            aggregate_threshold_commitment_set,
            &VssPublicAggregateThresholdCommitmentSetContext {
                setup_context_hash: input.statement.setup_context_hash,
                public_matrix_seed_hash: input.statement.public_matrix_seed_hash,
                participant_count: input.statement.participant_count,
                trustee_identities: input.statement.trustee_identities,
                rns_limb_count: input.statement.q_share_rns_limb_count,
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
    Ok(VssShareLinkageEvidenceRoots {
        #[cfg(test)]
        coefficient_commitment_root: _coefficient_commitment_root,
        #[cfg(test)]
        recipient_share_commitment_root: _recipient_share_commitment_root,
        #[cfg(test)]
        aggregate_threshold_commitment_root: _aggregate_threshold_commitment_root,
    })
}

// Each aggregate proof binds the committed threshold share to the modular sum
// of its source recipient shares at the unit evaluation point.
#[cfg(test)]
pub(crate) struct VssAggregateThresholdProofContext<'a> {
    pub(crate) setup_context_hash: String,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) ring_degree: usize,
    pub(crate) participant_count: usize,
    pub(crate) rns_limb_count: usize,
    pub(crate) trustee_identities: &'a [String],
}

#[cfg(test)]
pub(in crate::bgv::setup) struct VssAggregateThresholdStatementInput<'a> {
    pub(in crate::bgv::setup) public_matrix_seed_hash: &'a str,
    pub(in crate::bgv::setup) participant_count: usize,
    pub(in crate::bgv::setup) rns_limb_count: usize,
    pub(in crate::bgv::setup) coefficient_source_records: &'a [Value],
    pub(in crate::bgv::setup) recipient_source_records: &'a [Value],
    pub(in crate::bgv::setup) aggregate_record: &'a Value,
    pub(in crate::bgv::setup) aggregate_record_index: usize,
    pub(in crate::bgv::setup) trustee_identities: &'a [String],
}

#[cfg(test)]
pub(in crate::bgv::setup) fn vss_aggregate_threshold_statement_from_commitment_records(
    input: VssAggregateThresholdStatementInput<'_>,
) -> CanonicalResult<Value> {
    let VssAggregateThresholdStatementInput {
        public_matrix_seed_hash,
        participant_count,
        rns_limb_count,
        coefficient_source_records,
        recipient_source_records,
        aggregate_record,
        aggregate_record_index,
        trustee_identities,
    } = input;
    if rns_limb_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proof requires at least one RNS limb",
        ));
    }
    if coefficient_source_records.len() != participant_count
        || recipient_source_records.len() != participant_count
        || trustee_identities.len() != participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold proof source records must cover every participant",
        ));
    }

    let recipient_roster_position = aggregate_record_index / rns_limb_count;
    let rns_limb_index = aggregate_record_index % rns_limb_count;
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
        coefficient_commitments.push(recipient_share_record.clone());
    }

    let recipient_identity = trustee_identities
        .get(recipient_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold proof recipient exceeds the canonical trustee roster",
            )
        })?;
    Ok(json!({
        "objectType": "VssShareLinkageStatement",
        "isThresholdAggregate": true,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRosterPosition": recipient_roster_position,
        "sourceCoefficientCommitmentRoot":
            vss_public_source_coefficient_record_root(
                coefficient_source_record,
                recipient_identity,
            )?,
        "sourceRecipientShareCommitmentRoot":
            vss_public_source_recipient_share_record_root(
                recipient_source_record,
                recipient_identity,
                trustee_identities,
            )?,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "coefficientCommitmentRoots": coefficient_commitment_roots,
        "coefficientCommitments": coefficient_commitments,
        "recipientShareCommitmentRoot": vss_public_commitment_body_root(
            value_at_path(aggregate_record, &["commitment"])?,
        )?,
        "recipientShareCommitment": value_at_path(aggregate_record, &["commitment"])?,
        "additionalLinkageItems": [],
    }))
}

#[cfg(test)]
pub(crate) fn verify_vss_public_aggregate_threshold_proofs(
    _proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
    _coefficient_commitment_set: &Value,
    _recipient_share_commitment_set: &Value,
    _aggregate_threshold_commitment_set: &Value,
    _context: &VssAggregateThresholdProofContext<'_>,
) -> CanonicalResult<()> {
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "aggregate threshold-share acceptance requires verification by the common proof suite",
    ))
}
