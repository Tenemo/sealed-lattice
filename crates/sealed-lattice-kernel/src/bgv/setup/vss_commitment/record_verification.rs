use super::readers::*;
use super::*;

pub(super) struct VssPublicSourceCoefficientRecordInput<'a> {
    pub(super) source_record: &'a Value,
    pub(super) expected_roster_position: usize,
    pub(super) expected_coefficient_count: usize,
    pub(super) threshold_degree: usize,
    pub(super) public_matrix_seed_hash: &'a str,
}

pub(super) fn verify_vss_public_source_coefficient_record(
    input: VssPublicSourceCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.source_record, &["objectType"])?,
        "VssPublicSourceCoefficientCommitments",
        "VSS source coefficient commitments objectType",
    )?;
    let source_trustee_identity =
        read_non_empty_string(input.source_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["sourceTrusteeRosterPosition"])?,
        input.expected_roster_position as u64,
        "VSS source coefficient commitments sourceTrusteeRosterPosition",
    )?;
    compare_required_string(
        hash_at_path(input.source_record, &["publicMatrixSeedHash"])?,
        input.public_matrix_seed_hash,
        "VSS source coefficient commitments publicMatrixSeedHash",
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
                source_trustee_identity,
                source_trustee_roster_position: input.expected_roster_position,
                expected_rns_limb_index: coefficient_record_index / input.threshold_degree,
                expected_shamir_coefficient_index: coefficient_record_index
                    % input.threshold_degree,
                public_matrix_seed_hash: input.public_matrix_seed_hash,
            },
        )?);
    }

    let expected_source_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "coefficientCommitments": verified_coefficient_commitments,
    }))?;
    let source_coefficient_commitment_root =
        hash_at_path(input.source_record, &["sourceCoefficientCommitmentRoot"])?;
    if expected_source_root != source_coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS source coefficient commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "coefficientCommitments": verified_coefficient_commitments,
        "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
    }))
}

pub(super) struct VssPublicCoefficientRecordInput<'a> {
    coefficient_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_rns_limb_index: usize,
    expected_shamir_coefficient_index: usize,
    public_matrix_seed_hash: &'a str,
}

pub(super) struct VssCommittedMaterialRecordCommitmentInput<'a> {
    commitment: &'a Value,
    expected_commitment_role: &'a str,
    expected_commitment_root: &'a str,
    expected_rns_limb_index: usize,
    expected_rns_prime: u64,
    field_name: &'a str,
}

pub(crate) fn validate_standalone_vss_public_commitment_body(
    commitment: &Value,
    field_name: &str,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(commitment, &["objectType"])?,
        "VssCommittedMaterialCommitment",
        &format!("{field_name} objectType"),
    )?;
    validate_vss_public_commitment_role(string_at_path(commitment, &["commitmentRole"])?)?;
    let _commitment_context_hash = hash_at_path(commitment, &["commitmentContextHash"])?;
    let _rns_limb_index = usize_at_path(commitment, &["rnsLimbIndex"])?;
    let _rns_prime =
        read_positive_u64_at_path(commitment, &["rnsPrime"], &format!("{field_name} rnsPrime"))?;
    let _ring_degree = read_positive_usize_at_path(
        commitment,
        &["ringDegree"],
        &format!("{field_name} ringDegree"),
    )?;
    let _material_column_mask_degree = unsigned_at_path(commitment, &["materialColumnMaskDegree"])?;
    let commitment_fields = array_at_path(commitment, &["commitmentFields"])?;
    if commitment_fields.len() != VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} commitmentFields must cover the commitment modulus limbs"),
        ));
    }
    for (field_position, commitment_field) in commitment_fields.iter().enumerate() {
        let expected_commitment_modulus_index =
            VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES[field_position];
        compare_required_u64(
            unsigned_at_path(commitment_field, &["commitmentModulusIndex"])?,
            expected_commitment_modulus_index as u64,
            &format!("{field_name} commitmentFields.{field_position}.commitmentModulusIndex"),
        )?;
        compare_required_u64(
            unsigned_at_path(commitment_field, &["modulus"])?,
            DATA_PRIMES[expected_commitment_modulus_index],
            &format!("{field_name} commitmentFields.{field_position}.modulus"),
        )?;
        // The material root is a fixed-width Merkle digest (32 bytes) in
        // lowercase hex. Binding is checked by the canonical-root comparison in
        // the caller and by the succinct proof's material openings; here it is
        // only a well-formedness check.
        let material_root_hex = string_at_path(commitment_field, &["materialRootHex"])?;
        if material_root_hex.len() != 64
            || !material_root_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "{field_name} commitmentFields.{field_position}.materialRootHex must be a 32-byte lowercase hex digest"
                ),
            ));
        }
    }

    Ok(commitment.clone())
}

pub(super) fn verify_vss_committed_material_record_commitment(
    input: VssCommittedMaterialRecordCommitmentInput<'_>,
) -> CanonicalResult<Value> {
    let commitment =
        validate_standalone_vss_public_commitment_body(input.commitment, input.field_name)?;
    compare_required_string(
        string_at_path(&commitment, &["commitmentRole"])?,
        input.expected_commitment_role,
        &format!("{} commitmentRole", input.field_name),
    )?;
    compare_required_u64(
        unsigned_at_path(&commitment, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        &format!("{} rnsLimbIndex", input.field_name),
    )?;
    compare_required_u64(
        unsigned_at_path(&commitment, &["rnsPrime"])?,
        input.expected_rns_prime,
        &format!("{} rnsPrime", input.field_name),
    )?;
    let commitment_root = derive_canonical_object_hash(&commitment)?;
    if commitment_root != input.expected_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "{} canonical root must match the containing record",
                input.field_name
            ),
        ));
    }

    Ok(commitment)
}

pub(super) fn verify_vss_public_coefficient_record(
    input: VssPublicCoefficientRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.coefficient_record, &["objectType"])?,
        "VssPublicCoefficientCommitment",
        "VSS coefficient commitment objectType",
    )?;
    compare_required_string(
        string_at_path(input.coefficient_record, &["sourceTrusteeIdentity"])?,
        input.source_trustee_identity,
        "VSS coefficient commitment sourceTrusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["sourceTrusteeRosterPosition"])?,
        input.source_trustee_roster_position as u64,
        "VSS coefficient commitment sourceTrusteeRosterPosition",
    )?;
    compare_required_string(
        hash_at_path(input.coefficient_record, &["publicMatrixSeedHash"])?,
        input.public_matrix_seed_hash,
        "VSS coefficient commitment publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "VSS coefficient commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.coefficient_record,
        &["rnsPrime"],
        "VSS coefficient commitment rnsPrime",
    )?;
    compare_required_u64(
        unsigned_at_path(input.coefficient_record, &["shamirCoefficientIndex"])?,
        input.expected_shamir_coefficient_index as u64,
        "VSS coefficient commitment shamirCoefficientIndex",
    )?;
    let coefficient_commitment_root =
        hash_at_path(input.coefficient_record, &["coefficientCommitmentRoot"])?;
    let coefficient_opening_root =
        hash_at_path(input.coefficient_record, &["coefficientOpeningRoot"])?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: value_at_path(input.coefficient_record, &["commitment"])?,
            expected_commitment_role: "coefficient",
            expected_commitment_root: coefficient_commitment_root,
            expected_rns_limb_index: input.expected_rns_limb_index,
            expected_rns_prime: rns_prime,
            field_name: "VSS coefficient commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicCoefficientCommitment",
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": input.expected_shamir_coefficient_index,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "coefficientOpeningRoot": coefficient_opening_root,
        "commitment": commitment,
    }))
}

pub(super) struct VssPublicSourceRecipientShareRecordInput<'a> {
    pub(super) source_record: &'a Value,
    pub(super) expected_source_roster_position: usize,
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
    let source_trustee_identity =
        read_non_empty_string(input.source_record, "sourceTrusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.source_record, &["sourceTrusteeRosterPosition"])?,
        input.expected_source_roster_position as u64,
        "VSS source recipient-share commitments sourceTrusteeRosterPosition",
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
                source_trustee_identity,
                source_trustee_roster_position: input.expected_source_roster_position,
                expected_recipient_roster_position: recipient_share_record_index
                    / input.rns_limb_count,
                expected_rns_limb_index: recipient_share_record_index % input.rns_limb_count,
            },
        )?);
    }

    let expected_source_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_roster_position,
        "recipientShareCommitments": verified_recipient_share_commitments,
    }))?;
    let source_recipient_share_commitment_root =
        hash_at_path(input.source_record, &["sourceRecipientShareCommitmentRoot"])?;
    if expected_source_root != source_recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS source recipient-share commitment root does not match its records",
        ));
    }

    Ok(json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": input.expected_source_roster_position,
        "recipientShareCommitments": verified_recipient_share_commitments,
        "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
    }))
}

pub(super) struct VssPublicRecipientShareRecordInput<'a> {
    recipient_share_record: &'a Value,
    source_trustee_identity: &'a str,
    source_trustee_roster_position: usize,
    expected_recipient_roster_position: usize,
    expected_rns_limb_index: usize,
}

pub(super) fn verify_vss_public_recipient_share_record(
    input: VssPublicRecipientShareRecordInput<'_>,
) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.recipient_share_record, &["objectType"])?,
        "VssPublicRecipientShareCommitment",
        "VSS recipient-share commitment objectType",
    )?;
    compare_required_string(
        string_at_path(input.recipient_share_record, &["sourceTrusteeIdentity"])?,
        input.source_trustee_identity,
        "VSS recipient-share commitment sourceTrusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(
            input.recipient_share_record,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.source_trustee_roster_position as u64,
        "VSS recipient-share commitment sourceTrusteeRosterPosition",
    )?;
    let recipient_identity =
        read_non_empty_string(input.recipient_share_record, "recipientIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["recipientRosterPosition"])?,
        input.expected_recipient_roster_position as u64,
        "VSS recipient-share commitment recipientRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["recipientTrusteePoint"])?,
        (input.expected_recipient_roster_position + 1) as u64,
        "VSS recipient-share commitment recipientTrusteePoint",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_share_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "VSS recipient-share commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.recipient_share_record,
        &["rnsPrime"],
        "VSS recipient-share commitment rnsPrime",
    )?;
    let share_commitment_root =
        hash_at_path(input.recipient_share_record, &["shareCommitmentRoot"])?;
    let share_opening_root = hash_at_path(input.recipient_share_record, &["shareOpeningRoot"])?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: value_at_path(input.recipient_share_record, &["commitment"])?,
            expected_commitment_role: "recipient-share",
            expected_commitment_root: share_commitment_root,
            expected_rns_limb_index: input.expected_rns_limb_index,
            expected_rns_prime: rns_prime,
            field_name: "VSS recipient-share commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "sourceTrusteeIdentity": input.source_trustee_identity,
        "sourceTrusteeRosterPosition": input.source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": input.expected_recipient_roster_position,
        "recipientTrusteePoint": input.expected_recipient_roster_position + 1,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "shareCommitmentRoot": share_commitment_root,
        "shareOpeningRoot": share_opening_root,
        "commitment": commitment,
    }))
}

pub(super) struct VssPublicAggregateThresholdRecordInput<'a> {
    pub(super) recipient_record: &'a Value,
    pub(super) expected_recipient_roster_position: usize,
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
    let recipient_identity = read_non_empty_string(input.recipient_record, "recipientIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["recipientRosterPosition"])?,
        input.expected_recipient_roster_position as u64,
        "VSS aggregate threshold commitment recipientRosterPosition",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["recipientTrusteePoint"])?,
        (input.expected_recipient_roster_position + 1) as u64,
        "VSS aggregate threshold commitment recipientTrusteePoint",
    )?;
    compare_required_u64(
        unsigned_at_path(input.recipient_record, &["rnsLimbIndex"])?,
        input.expected_rns_limb_index as u64,
        "VSS aggregate threshold commitment rnsLimbIndex",
    )?;
    let rns_prime = read_positive_u64_at_path(
        input.recipient_record,
        &["rnsPrime"],
        "VSS aggregate threshold commitment rnsPrime",
    )?;
    let aggregate_commitment_root =
        hash_at_path(input.recipient_record, &["aggregateCommitmentRoot"])?;
    let aggregate_opening_root = hash_at_path(input.recipient_record, &["aggregateOpeningRoot"])?;
    let commitment = verify_vss_committed_material_record_commitment(
        VssCommittedMaterialRecordCommitmentInput {
            commitment: value_at_path(input.recipient_record, &["commitment"])?,
            expected_commitment_role: "aggregate-threshold-share",
            expected_commitment_root: aggregate_commitment_root,
            expected_rns_limb_index: input.expected_rns_limb_index,
            expected_rns_prime: rns_prime,
            field_name: "VSS aggregate threshold commitment commitment",
        },
    )?;

    Ok(json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": input.expected_recipient_roster_position,
        "recipientTrusteePoint": input.expected_recipient_roster_position + 1,
        "rnsLimbIndex": input.expected_rns_limb_index,
        "rnsPrime": rns_prime,
        "aggregateCommitmentRoot": aggregate_commitment_root,
        "aggregateOpeningRoot": aggregate_opening_root,
        "commitment": commitment,
    }))
}
