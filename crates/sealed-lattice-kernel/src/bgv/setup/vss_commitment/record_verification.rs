use super::*;

fn committed_material_context_hash(
    commitment_role: &str,
    commitment_context: Value,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "VssCommittedMaterialCommitmentContext",
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
    }))
}

pub(crate) fn vss_public_commitment_body_root(commitment: &Value) -> CanonicalResult<String> {
    let commitment =
        validate_standalone_vss_committed_material_commitment(commitment, "VSS public commitment")?;
    derive_canonical_object_hash(&commitment)
}

fn canonical_vss_public_source_coefficient_record(
    source_record: &Value,
    source_trustee_identity: &str,
) -> CanonicalResult<Value> {
    let coefficient_commitments = array_at_path(source_record, &["coefficientCommitments"])?
        .iter()
        .map(|commitment| {
            Ok(json!({
                "objectType": "VssPublicCoefficientCommitment",
                "commitment": validate_standalone_vss_committed_material_commitment(
                    commitment,
                    "VSS public coefficient commitment",
                )?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    Ok(json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "coefficientCommitments": coefficient_commitments,
    }))
}

pub(crate) fn vss_public_source_coefficient_record_root(
    source_record: &Value,
    source_trustee_identity: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&canonical_vss_public_source_coefficient_record(
        source_record,
        source_trustee_identity,
    )?)
}

pub(crate) fn vss_public_coefficient_commitment_set_root(
    coefficient_set: &Value,
    trustee_identities: &[String],
) -> CanonicalResult<String> {
    let serialized_source_trustee_records =
        array_at_path(coefficient_set, &["sourceTrusteeRecords"])?;
    if serialized_source_trustee_records.len() != trustee_identities.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitment set must align with the canonical trustee roster",
        ));
    }
    let source_trustee_records = serialized_source_trustee_records
        .iter()
        .zip(trustee_identities)
        .map(|(record, identity)| canonical_vss_public_source_coefficient_record(record, identity))
        .collect::<CanonicalResult<Vec<_>>>()?;
    derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": hash_at_path(coefficient_set, &["publicMatrixSeedHash"])?,
        "sourceTrusteeRecords": source_trustee_records,
    }))
}

pub(crate) fn vss_public_source_recipient_share_record_root(
    source_record: &Value,
    source_trustee_identity: &str,
    trustee_identities: &[String],
) -> CanonicalResult<String> {
    let serialized_recipient_share_commitments =
        array_at_path(source_record, &["recipientShareCommitments"])?;
    let expected_record_count = trustee_identities
        .len()
        .checked_mul(DATA_PRIMES.len())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS recipient-share commitment count overflowed",
            )
        })?;
    if serialized_recipient_share_commitments.len() != expected_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS recipient-share commitments must align with the canonical trustee roster",
        ));
    }
    let recipient_share_commitments = serialized_recipient_share_commitments
        .iter()
        .enumerate()
        .map(|(record_index, commitment)| {
            let recipient_roster_position = record_index / DATA_PRIMES.len();
            let recipient_identity = trustee_identities
                .get(recipient_roster_position)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "VSS recipient-share commitments exceed the canonical trustee roster",
                    )
                })?;
            Ok(json!({
                "objectType": "VssPublicRecipientShareCommitment",
                "recipientIdentity": recipient_identity,
                "commitment": validate_standalone_vss_committed_material_commitment(
                    commitment,
                    "VSS public recipient-share commitment",
                )?,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    derive_canonical_object_hash(&json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "recipientShareCommitments": recipient_share_commitments,
    }))
}

pub(super) struct VssPublicSourceCoefficientRecordInput<'a> {
    pub(super) source_record: &'a Value,
    pub(super) setup_context_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) source_trustee_roster_position: usize,
    pub(super) expected_coefficient_count: usize,
    pub(super) threshold_degree: usize,
}

pub(super) fn verify_vss_public_source_coefficient_record(
    input: VssPublicSourceCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "VssPublicSourceCoefficientCommitments",
        "VSS source coefficient commitments objectType",
    )?;
    let coefficient_commitments = array_at_path(input.source_record, &["coefficientCommitments"])?;
    if coefficient_commitments.len() != input.expected_coefficient_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS source coefficient commitments must cover every RNS limb and Shamir coefficient",
        ));
    }

    let mut verified_coefficient_commitments = Vec::with_capacity(coefficient_commitments.len());
    for (coefficient_record_index, coefficient_record) in coefficient_commitments.iter().enumerate()
    {
        verified_coefficient_commitments.push(verify_vss_public_coefficient_record(
            VssPublicCoefficientRecordInput {
                coefficient_record,
                setup_context_hash: input.setup_context_hash,
                source_trustee_identity: input.source_trustee_identity,
                source_trustee_roster_position: input.source_trustee_roster_position,
                shamir_coefficient_index: coefficient_record_index % input.threshold_degree,
                expected_rns_limb_index: coefficient_record_index / input.threshold_degree,
            },
        )?);
    }

    Ok(json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "coefficientCommitments": verified_coefficient_commitments,
    }))
}

pub(super) struct VssPublicCoefficientRecordInput<'a> {
    coefficient_record: &'a Value,
    setup_context_hash: &'a str,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    shamir_coefficient_index: usize,
    expected_rns_limb_index: usize,
}

pub(super) struct VssCommittedMaterialRecordCommitmentInput<'a> {
    commitment: &'a Value,
    expected_commitment_context_hash: &'a str,
    field_name: &'a str,
}

pub(crate) fn validate_standalone_vss_committed_material_commitment(
    commitment: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(commitment, &["objectType"])?,
        "VssCommittedMaterialCommitment",
        &format!("{field_name} objectType"),
    )?;
    let commitment_context_hash = hash_at_path(commitment, &["commitmentContextHash"])?;
    let material_root_hex = string_at_path(commitment, &["materialRootHex"])?;
    if !is_lowercase_protocol_hash(material_root_hex) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{field_name} materialRootHex must be a 64-byte lowercase hex digest"),
        ));
    }
    Ok(json!({
        "objectType": "VssCommittedMaterialCommitment",
        "commitmentContextHash": commitment_context_hash,
        "materialRootHex": material_root_hex,
    }))
}

pub(super) fn verify_vss_committed_material_record_commitment(
    input: VssCommittedMaterialRecordCommitmentInput<'_>,
) -> CanonicalResult<Value> {
    let commitment =
        validate_standalone_vss_committed_material_commitment(input.commitment, input.field_name)?;
    compare_required_string(
        hash_at_path(&commitment, &["commitmentContextHash"])?,
        input.expected_commitment_context_hash,
        &format!("{} commitmentContextHash", input.field_name),
    )?;
    Ok(commitment)
}

pub(super) fn verify_vss_public_coefficient_record(
    input: VssPublicCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    let rns_prime = DATA_PRIMES
        .get(input.expected_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS coefficient commitment coordinate exceeds the canonical Q_share basis",
            )
        })?;
    let expected_commitment_context_hash = committed_material_context_hash(
        "coefficient",
        json!({
            "objectType": "VssPublicCoefficientCommitmentContext",
            "setupContextHash": input.setup_context_hash,
            "sourceTrusteeIdentity": input.source_trustee_identity,
            "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
            "rnsLimbIndex": input.expected_rns_limb_index,
            "rnsPrime": rns_prime,
            "shamirCoefficientIndex": input.shamir_coefficient_index,
        }),
    )?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: input.coefficient_record,
            expected_commitment_context_hash: &expected_commitment_context_hash,
            field_name: "VSS coefficient commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicCoefficientCommitment",
        "commitment": commitment,
    }))
}

pub(super) struct VssPublicSourceRecipientShareRecordInput<'a> {
    pub(super) source_record: &'a Value,
    pub(super) setup_context_hash: &'a str,
    pub(super) source_trustee_identity: &'a str,
    pub(super) trustee_identities: &'a [String],
    pub(super) source_trustee_roster_position: usize,
    pub(super) expected_recipient_share_count: usize,
    pub(super) rns_limb_count: usize,
}

pub(super) fn verify_vss_public_source_recipient_share_record(
    input: VssPublicSourceRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "VssPublicSourceRecipientShareCommitments",
        "VSS source recipient-share commitments objectType",
    )?;
    let recipient_share_commitments =
        array_at_path(input.source_record, &["recipientShareCommitments"])?;
    if recipient_share_commitments.len() != input.expected_recipient_share_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS source recipient-share commitments must cover every recipient and RNS limb",
        ));
    }

    let mut verified_recipient_share_commitments =
        Vec::with_capacity(recipient_share_commitments.len());
    for (recipient_share_record_index, recipient_share_record) in
        recipient_share_commitments.iter().enumerate()
    {
        verified_recipient_share_commitments.push(verify_vss_public_recipient_share_record(
            VssPublicRecipientShareRecordInput {
                recipient_share_record,
                setup_context_hash: input.setup_context_hash,
                source_trustee_identity: input.source_trustee_identity,
                recipient_identity: &input.trustee_identities
                    [recipient_share_record_index / input.rns_limb_count],
                source_trustee_roster_position: input.source_trustee_roster_position,
                expected_recipient_roster_position: recipient_share_record_index
                    / input.rns_limb_count,
                expected_rns_limb_index: recipient_share_record_index % input.rns_limb_count,
            },
        )?);
    }

    Ok(json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "recipientShareCommitments": verified_recipient_share_commitments,
    }))
}

pub(super) struct VssPublicRecipientShareRecordInput<'a> {
    recipient_share_record: &'a Value,
    setup_context_hash: &'a str,
    source_trustee_identity: &'a str,
    recipient_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
}

pub(super) fn verify_vss_public_recipient_share_record(
    input: VssPublicRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    let rns_prime = DATA_PRIMES
        .get(input.expected_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS recipient-share commitment coordinate exceeds the canonical Q_share basis",
            )
        })?;
    let expected_commitment_context_hash = committed_material_context_hash(
        "recipient-share",
        json!({
            "objectType": "VssPublicRecipientShareCommitmentContext",
            "setupContextHash": input.setup_context_hash,
            "sourceTrusteeIdentity": input.source_trustee_identity,
            "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
            "recipientIdentity": input.recipient_identity,
            "recipientRosterPosition": input.expected_recipient_roster_position,
            "rnsLimbIndex": input.expected_rns_limb_index,
            "rnsPrime": rns_prime,
        }),
    )?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: input.recipient_share_record,
            expected_commitment_context_hash: &expected_commitment_context_hash,
            field_name: "VSS recipient-share commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "recipientIdentity": input.recipient_identity,
        "commitment": commitment,
    }))
}

pub(super) struct VssPublicAggregateThresholdRecordInput<'a> {
    pub(super) recipient_record: &'a Value,
    pub(super) setup_context_hash: &'a str,
    pub(super) expected_recipient_roster_position: usize,
    pub(super) recipient_identity: &'a str,
    pub(super) expected_rns_limb_index: usize,
}

pub(super) fn verify_vss_public_aggregate_threshold_record(
    input: VssPublicAggregateThresholdRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_record, &["objectType"])?,
        "VssPublicAggregateThresholdCommitment",
        "VSS aggregate threshold commitment objectType",
    )?;
    let rns_prime = DATA_PRIMES
        .get(input.expected_rns_limb_index)
        .copied()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold commitment coordinate exceeds the canonical Q_share basis",
            )
        })?;
    let aggregate_opening_root = hash_at_path(input.recipient_record, &["aggregateOpeningRoot"])?;
    let expected_commitment_context_hash = committed_material_context_hash(
        "aggregate-threshold-share",
        json!({
            "objectType": "VssPublicAggregateThresholdCommitmentContext",
            "setupContextHash": input.setup_context_hash,
            "recipientIdentity": input.recipient_identity,
            "recipientRosterPosition": input.expected_recipient_roster_position,
            "rnsLimbIndex": input.expected_rns_limb_index,
            "rnsPrime": rns_prime,
        }),
    )?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: value_at_path(input.recipient_record, &["commitment"])?,
            expected_commitment_context_hash: &expected_commitment_context_hash,
            field_name: "VSS aggregate threshold commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "recipientIdentity": input.recipient_identity,
        "aggregateOpeningRoot": aggregate_opening_root,
        "commitment": commitment,
    }))
}
