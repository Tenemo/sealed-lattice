use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) fn verify_vss_coefficient_commitments(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(commitment_set) = setup_package.get("vssCoefficientCommitments") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !commitment_set.is_object() {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentsNotObject",
            "vssCoefficientCommitments must be a root-bound object, not an array or scalar",
            "setupPackage.vssCoefficientCommitments",
        )?));
    }
    if commitment_set.get("objectType").and_then(Value::as_str)
        != Some("VssCoefficientCommitmentSet")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSetTypeMismatch",
            "vssCoefficientCommitments.objectType must be VssCoefficientCommitmentSet",
            "setupPackage.vssCoefficientCommitments.objectType",
        )?));
    }
    if commitment_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSetVersionMismatch",
            "vssCoefficientCommitments.objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS commitment verification",
        )
    })?;
    if let Err(error) = verify_vss_commitment_context(commitment_set, setup_context) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentContextMismatch",
            error.message,
            "setupPackage.vssCoefficientCommitments",
        )?));
    }
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before VSS commitment verification",
            )
        })?;
    if commitment_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCommitmentPublicMatrixSeedMismatch",
            "vssCoefficientCommitments.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.vssCoefficientCommitments.publicMatrixSeedHash",
        )?));
    }
    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let Some(source_trustee_records) = commitment_set
        .get("sourceTrusteeRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.sourceTrusteeRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let roster = super::accepted_roster_from_package(setup_package);
    if source_trustee_records.len() != roster.participant_count as usize {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentCountMismatch",
            "vssCoefficientCommitments.sourceTrusteeRecords must contain one record for every trustee",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for source_trustee_record in source_trustee_records {
        if let Some(response) = verify_vss_source_trustee_commitment_record(
            source_trustee_record,
            setup_context,
            &expected_trustees,
            public_matrix_seed_hash,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(commitment_root) = commitment_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitments.vssCoefficientCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        commitment_root,
        "vssCoefficientCommitments.vssCoefficientCommitmentRoot",
    )?;
    let mut root_input = commitment_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS commitment set object was checked")
        .remove("vssCoefficientCommitmentRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if commitment_root != expected_root {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRootMismatch",
            "vssCoefficientCommitmentRoot does not match the canonical VSS commitment set",
            "setupPackage.vssCoefficientCommitments.vssCoefficientCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_commitment_context(
    commitment_set: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if commitment_set.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("vssCoefficientCommitments.{field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

pub(super) fn verify_vss_coefficient_commitment_material(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(material_set) = setup_package.get("vssCoefficientCommitmentMaterial") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec!["vssCoefficientCommitmentMaterial".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !material_set.is_object() {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialNotObject",
            "vssCoefficientCommitmentMaterial must be a root-bound object, not an array or scalar",
            "setupPackage.vssCoefficientCommitmentMaterial",
        )?));
    }
    if material_set.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_SET_OBJECT_TYPE)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialSetTypeMismatch",
            "vssCoefficientCommitmentMaterial.objectType must be VssCoefficientCommitmentMaterialSet",
            "setupPackage.vssCoefficientCommitmentMaterial.objectType",
        )?));
    }
    if material_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialSetVersionMismatch",
            "vssCoefficientCommitmentMaterial.objectVersion must be 1",
            "setupPackage.vssCoefficientCommitmentMaterial.objectVersion",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before VSS coefficient commitment material verification",
        )
    })?;
    if let Err(error) = verify_vss_commitment_context(material_set, setup_context) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialContextMismatch",
            error.message,
            "setupPackage.vssCoefficientCommitmentMaterial",
        )?));
    }
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.materialEncoding is required",
            )
        })?;
    if !matches!(
        material_encoding,
        "full-public-setup-commitment-values"
            | "binary-chunked-full-public-setup-commitment-values"
    ) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialEncodingMismatch",
            "vssCoefficientCommitmentMaterial.materialEncoding must be embedded full public values or binary-chunked full public values",
            "setupPackage.vssCoefficientCommitmentMaterial.materialEncoding",
        )?));
    }

    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before VSS coefficient commitment material verification",
            )
        })?;
    if material_set
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialPublicMatrixSeedMismatch",
            "vssCoefficientCommitmentMaterial.publicMatrixSeedHash must match commonRandomness.publicMatrixSeedHash",
            "setupPackage.vssCoefficientCommitmentMaterial.publicMatrixSeedHash",
        )?));
    }
    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitments.vssCoefficientCommitmentRoot was required before VSS coefficient commitment material verification",
            )
        })?;
    if material_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRootBindingMismatch",
            "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot must match accepted VSS coefficient commitments",
            "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot",
        )?));
    }
    let roster = super::accepted_roster_from_package(setup_package);
    if material_set.get("participantCount").and_then(Value::as_u64)
        != Some(roster.participant_count)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialParticipantCountMismatch",
            "vssCoefficientCommitmentMaterial.participantCount must match the accepted setup parameters",
            "setupPackage.vssCoefficientCommitmentMaterial.participantCount",
        )?));
    }
    if material_set.get("thresholdDegree").and_then(Value::as_u64)
        != Some(roster.decryption_threshold)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialThresholdMismatch",
            "vssCoefficientCommitmentMaterial.thresholdDegree must match the accepted setup parameters",
            "setupPackage.vssCoefficientCommitmentMaterial.thresholdDegree",
        )?));
    }
    if material_set.get("rnsLimbCount").and_then(Value::as_u64) != Some(DATA_PRIMES.len() as u64) {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialLimbCountMismatch",
            "vssCoefficientCommitmentMaterial.rnsLimbCount must match the accepted Q_share limb count",
            "setupPackage.vssCoefficientCommitmentMaterial.rnsLimbCount",
        )?));
    }
    let expected_material_count =
        (roster.participant_count * roster.decryption_threshold) as usize * DATA_PRIMES.len();
    if material_set
        .get("materialRecordCount")
        .and_then(Value::as_u64)
        != Some(expected_material_count as u64)
    {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRecordCountMismatch",
            "vssCoefficientCommitmentMaterial.materialRecordCount must match coefficientCommitments length",
            "setupPackage.vssCoefficientCommitmentMaterial.materialRecordCount",
        )?));
    }
    if material_encoding == "full-public-setup-commitment-values" {
        let Some(coefficient_commitments) = material_set
            .get("coefficientCommitments")
            .and_then(Value::as_array)
        else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("vssCoefficientCommitments"),
                vec!["vssCoefficientCommitmentMaterial.coefficientCommitments".to_string()],
                Vec::new(),
                Vec::new(),
            )?));
        };
        if coefficient_commitments.len() != expected_material_count {
            return Ok(Some(vss_material_refusal(
                "vssCoefficientCommitmentMaterialCountMismatch",
                "vssCoefficientCommitmentMaterial.coefficientCommitments must cover every source trustee, Q_share limb, and Shamir coefficient",
                "setupPackage.vssCoefficientCommitmentMaterial.coefficientCommitments",
            )?));
        }
    } else {
        if material_set.get("coefficientCommitments").is_some() {
            return Ok(Some(vss_material_refusal(
                "vssCoefficientCommitmentMaterialEmbeddedMaterialInBinaryTransport",
                "binary-chunked VSS material must not embed coefficientCommitments in the setup package",
                "setupPackage.vssCoefficientCommitmentMaterial.coefficientCommitments",
            )?));
        }
        verify_binary_vss_material_transport_metadata(material_set)?;
    }

    let Some(material_root) = material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot".to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        material_root,
        "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
    )?;
    let mut root_input = material_set.clone();
    root_input
        .as_object_mut()
        .expect("VSS coefficient commitment material set object was checked")
        .remove("vssCoefficientCommitmentMaterialRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if material_root != expected_root {
        return Ok(Some(vss_material_refusal(
            "vssCoefficientCommitmentMaterialRootMismatch",
            "vssCoefficientCommitmentMaterialRoot does not match the canonical material set",
            "setupPackage.vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot",
        )?));
    }

    Ok(None)
}

fn vss_material_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn verify_binary_vss_material_transport_metadata(material_set: &Value) -> CanonicalResult<()> {
    if material_set.get("binaryFormat").and_then(Value::as_str)
        != Some("sealed-lattice-vss-coefficient-commitment-material-binary-v1")
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material must declare the accepted binary format",
        ));
    }
    let Some(transport) = material_set.get("transport") else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material must include transport metadata",
        ));
    };
    if !transport.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material transport metadata must be an object",
        ));
    }
    if transport.get("chunkSizeBytes").and_then(Value::as_u64)
        != Some(SETUP_TRANSPORT_CHUNK_SIZE_BYTES)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "binary VSS material chunkSizeBytes must match the accepted setup transport parameters",
        ));
    }
    for field_name in ["chunkCount", "totalByteLength"] {
        let Some(value) = transport.get(field_name).and_then(Value::as_u64) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("binary VSS material transport.{field_name} is required"),
            ));
        };
        if value == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("binary VSS material transport.{field_name} must be positive"),
            ));
        }
    }
    for field_name in ["fullObjectHash", "chunkRoot"] {
        let hash = transport
            .get(field_name)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("binary VSS material transport.{field_name} is required"),
                )
            })?;
        validate_hash_string(
            hash,
            &format!("vssCoefficientCommitmentMaterial.transport.{field_name}"),
        )?;
    }

    Ok(())
}

fn verify_vss_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    expected_trustees: &BTreeMap<u64, String>,
    public_matrix_seed_hash: &str,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some("VssSourceTrusteeCoefficientCommitments")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentTypeMismatch",
            "source trustee VSS commitment record objectType must be VssSourceTrusteeCoefficientCommitments",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.objectType",
        )?));
    }
    if source_trustee_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentVersionMismatch",
            "source trustee VSS commitment record objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if source_trustee_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_commitment_refusal(
                "vssSourceTrusteeCommitmentContextMismatch",
                format!("source trustee VSS commitment {field_name} must match setupContext"),
                format!("setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.{field_name}"),
            )?));
        }
    }
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentPublicMatrixSeedMismatch",
            "source trustee VSS commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.publicMatrixSeedHash",
        )?));
    }
    let Some(source_trustee_identity) = source_trustee_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeIdentityMissing",
            "source trustee VSS commitment record must bind sourceTrusteeIdentity",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeIdentity",
        )?));
    };
    let Some(source_trustee_roster_position) = source_trustee_record
        .get("sourceTrusteeRosterPosition")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeRosterPositionMissing",
            "source trustee VSS commitment record must bind sourceTrusteeRosterPosition",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeRosterPosition",
        )?));
    };
    if !seen_roster_positions.insert(source_trustee_roster_position) {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentDuplicate",
            "source trustee VSS commitment records must have distinct roster positions",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords",
        )?));
    }
    if expected_trustees
        .get(&source_trustee_roster_position)
        .map(String::as_str)
        != Some(source_trustee_identity)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentTrusteeMismatch",
            "source trustee VSS commitment record must match the phase transcript trustee identity",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeIdentity",
        )?));
    }

    let Some(coefficient_commitments) = source_trustee_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments".to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    let roster = super::accepted_roster_from_setup_context(setup_context);
    let expected_coefficient_count = DATA_PRIMES.len() * roster.decryption_threshold as usize;
    if coefficient_commitments.len() != expected_coefficient_count {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentCountMismatch",
            "source trustee VSS commitment record must contain every Q_share limb and Shamir coefficient",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments",
        )?));
    }
    let mut seen_coefficients = BTreeSet::new();
    for coefficient_record in coefficient_commitments {
        if let Some(response) = verify_vss_coefficient_commitment_record(
            coefficient_record,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_identity,
            source_trustee_roster_position,
            &mut seen_coefficients,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(source_trustee_commitment_root) = source_trustee_record
        .get("sourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("vssCoefficientCommitments"),
            vec![
                "vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot"
                    .to_string(),
            ],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        source_trustee_commitment_root,
        "vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot",
    )?;
    // Self-hash: the root commits to the record minus its own root field, so the canonical JSON encoding of the remaining fields is what the bound root covers.
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("VSS source trustee commitment object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if source_trustee_commitment_root != expected_root {
        return Ok(Some(vss_commitment_refusal(
            "vssSourceTrusteeCommitmentRootMismatch",
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee commitment record",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.sourceTrusteeCommitmentRoot",
        )?));
    }

    Ok(None)
}

fn verify_vss_coefficient_commitment_record(
    coefficient_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    seen_coefficients: &mut BTreeSet<(u64, u64)>,
) -> CanonicalResult<Option<Value>> {
    if coefficient_record.get("objectType").and_then(Value::as_str)
        != Some("VssCoefficientCommitment")
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentTypeMismatch",
            "VSS coefficient commitment objectType must be VssCoefficientCommitment",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.objectType",
        )?));
    }
    if coefficient_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentVersionMismatch",
            "VSS coefficient commitment objectVersion must be 1",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.objectVersion",
        )?));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupParametersHash",
        "setupEpoch",
    ] {
        if coefficient_record.get(field_name) != setup_context.get(field_name) {
            return Ok(Some(vss_commitment_refusal(
                "vssCoefficientCommitmentContextMismatch",
                format!("VSS coefficient commitment {field_name} must match setupContext"),
                format!(
                    "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
                ),
            )?));
        }
    }
    if coefficient_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentPublicMatrixSeedMismatch",
            "VSS coefficient commitment publicMatrixSeedHash must match common randomness",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.publicMatrixSeedHash",
        )?));
    }
    if coefficient_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
        != Some(source_trustee_identity)
        || coefficient_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(source_trustee_roster_position)
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentSourceTrusteeMismatch",
            "VSS coefficient commitment must bind its source trustee record",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.sourceTrusteeIdentity",
        )?));
    }
    let Some(rns_limb_index) = coefficient_record
        .get("rnsLimbIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbMissing",
            "VSS coefficient commitment must bind rnsLimbIndex",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsLimbIndex",
        )?));
    };
    let Ok(rns_limb_index_usize) = usize::try_from(rns_limb_index) else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsLimbInvalid",
            "VSS coefficient commitment rnsLimbIndex does not fit usize",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsLimbIndex",
        )?));
    };
    if DATA_PRIMES.get(rns_limb_index_usize)
        != coefficient_record
            .get("rnsPrime")
            .and_then(Value::as_u64)
            .as_ref()
    {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentRnsPrimeMismatch",
            "VSS coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.rnsPrime",
        )?));
    }
    let Some(shamir_coefficient_index) = coefficient_record
        .get("shamirCoefficientIndex")
        .and_then(Value::as_u64)
    else {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexMissing",
            "VSS coefficient commitment must bind shamirCoefficientIndex",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    };
    let roster = super::accepted_roster_from_setup_context(setup_context);
    if shamir_coefficient_index >= roster.decryption_threshold {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentShamirIndexInvalid",
            "VSS coefficient commitment shamirCoefficientIndex is outside the first-roster threshold degree",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.shamirCoefficientIndex",
        )?));
    }
    if !seen_coefficients.insert((rns_limb_index, shamir_coefficient_index)) {
        return Ok(Some(vss_commitment_refusal(
            "vssCoefficientCommitmentDuplicate",
            "source trustee VSS coefficient commitments must have distinct limb/coefficient coordinates",
            "setupPackage.vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments",
        )?));
    }
    for field_name in [
        "commitmentRoot",
        "commitmentChunkRoot",
        "coefficientVectorHash512",
    ] {
        let Some(hash) = coefficient_record.get(field_name).and_then(Value::as_str) else {
            return Ok(Some(verification_response(
                VerifierStatus::Pending,
                Some("vssCoefficientCommitments"),
                vec![format!(
                    "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
                )],
                Vec::new(),
                Vec::new(),
            )?));
        };
        validate_hash_string(
            hash,
            &format!(
                "vssCoefficientCommitments.sourceTrusteeRecords.coefficientCommitments.{field_name}"
            ),
        )?;
    }

    Ok(None)
}

pub(super) fn expected_trustees_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before VSS commitment verification",
            )
        })?;
    let Some(first_phase) = phase_transcript.first() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "phaseTranscript was required before VSS commitment verification",
        ));
    };
    let participants = first_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant objects were required before VSS commitment verification",
            )
        })?;
    let mut trustees = BTreeMap::new();
    for participant in participants {
        let Some(roster_position) = participant.get("rosterPosition").and_then(Value::as_u64)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind rosterPosition",
            ));
        };
        let Some(trustee_identity) = participant.get("trusteeIdentity").and_then(Value::as_str)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind trusteeIdentity",
            ));
        };
        trustees.insert(roster_position, trustee_identity.to_string());
    }

    Ok(trustees)
}

fn vss_commitment_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("vssCoefficientCommitments"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}
