use super::*;

use crate::hashing::derive_canonical_object_hash;

#[derive(Clone)]
pub(super) struct SourceTrusteeCommitmentBinding {
    pub(super) source_trustee_identity: String,
    pub(super) source_trustee_roster_position: u64,
    pub(super) coefficient_commitment_roots: BTreeMap<(usize, u64), String>,
}

#[derive(Clone)]
pub(super) struct CoefficientCommitmentBinding {
    pub(super) source_trustee_roster_position: u64,
    pub(super) rns_limb_index: usize,
    pub(super) shamir_coefficient_index: u64,
    pub(super) commitment_root: String,
    pub(super) commitment: SetupCommitmentValue,
}

pub(super) fn verify_source_trustee_commitment_records(
    source_trustee_records: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<BTreeMap<u64, SourceTrusteeCommitmentBinding>> {
    if source_trustee_records.len() != roster.participant_count as usize {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecords must contain one record for every accepted trustee",
        ));
    }

    let mut source_trustee_bindings = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let source_trustee_binding = verify_source_trustee_commitment_record(
            source_trustee_record,
            setup_context,
            public_matrix_seed_hash,
            roster,
        )?;
        if source_trustee_bindings
            .insert(
                source_trustee_binding.source_trustee_roster_position,
                source_trustee_binding,
            )
            .is_some()
        {
            return Err(invalid_threshold_commitment_input(
                "sourceTrusteeCoefficientCommitmentRecords contains duplicate source trustee roster positions",
            ));
        }
    }
    for roster_position in 0..roster.participant_count {
        if !source_trustee_bindings.contains_key(&roster_position) {
            return Err(invalid_threshold_commitment_input(
                "sourceTrusteeCoefficientCommitmentRecords must cover the full accepted roster",
            ));
        }
    }

    Ok(source_trustee_bindings)
}

fn verify_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    roster: &AcceptedRosterParameters,
) -> CanonicalResult<SourceTrusteeCommitmentBinding> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.objectType must be VssSourceTrusteeCoefficientCommitments",
        ));
    }
    if source_trustee_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.objectVersion must be 1",
        ));
    }
    compare_context_fields(
        source_trustee_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentRecord",
    )?;
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
    }
    let source_trustee_identity =
        string_field(source_trustee_record, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position =
        u64_field(source_trustee_record, "sourceTrusteeRosterPosition")?;
    if source_trustee_roster_position >= roster.participant_count {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition is outside the accepted roster",
        ));
    }

    let coefficient_commitments = array_field(source_trustee_record, "coefficientCommitments")?;
    if coefficient_commitments.len() != DATA_PRIMES.len() * roster.decryption_threshold as usize {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments must contain every Q_share limb and Shamir coefficient",
        ));
    }
    let mut seen_coordinates = BTreeSet::new();
    let mut coefficient_commitment_roots = BTreeMap::new();
    for coefficient_record in coefficient_commitments {
        let (rns_limb_index, shamir_coefficient_index, commitment_root) =
            verify_coefficient_record(
                coefficient_record,
                setup_context,
                public_matrix_seed_hash,
                &source_trustee_identity,
                source_trustee_roster_position,
                roster.decryption_threshold,
            )?;
        if !seen_coordinates.insert((rns_limb_index, shamir_coefficient_index)) {
            return Err(invalid_threshold_commitment_input(
                "source trustee coefficient commitments must have distinct limb/coefficient coordinates",
            ));
        }
        coefficient_commitment_roots
            .insert((rns_limb_index, shamir_coefficient_index), commitment_root);
    }

    let source_trustee_commitment_root =
        hash_string_field(source_trustee_record, "sourceTrusteeCommitmentRoot")?;
    validate_hash_string(
        source_trustee_commitment_root,
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
    )?;
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("source trustee commitment record object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_source_trustee_commitment_root = derive_canonical_object_hash(&root_input)?;
    if source_trustee_commitment_root != expected_source_trustee_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee coefficient commitment record",
        ));
    }

    Ok(SourceTrusteeCommitmentBinding {
        source_trustee_identity,
        source_trustee_roster_position,
        coefficient_commitment_roots,
    })
}

fn verify_coefficient_record(
    coefficient_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    decryption_threshold: u64,
) -> CanonicalResult<(usize, u64, String)> {
    if coefficient_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment objectType must be VssCoefficientCommitment",
        ));
    }
    if coefficient_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment objectVersion must be 1",
        ));
    }
    compare_context_fields(coefficient_record, setup_context, "coefficientCommitment")?;
    if coefficient_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
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
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment source trustee binding must match its source trustee record",
        ));
    }
    let rns_limb_index = usize_field(coefficient_record, "rnsLimbIndex")?;
    let rns_prime = u64_field(coefficient_record, "rnsPrime")?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let shamir_coefficient_index = u64_field(coefficient_record, "shamirCoefficientIndex")?;
    if shamir_coefficient_index >= decryption_threshold {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment shamirCoefficientIndex is outside the accepted threshold degree",
        ));
    }
    let commitment_root = hash_string_field(coefficient_record, "commitmentRoot")?;
    validate_hash_string(commitment_root, "coefficientCommitment.commitmentRoot")?;
    for field_name in ["commitmentChunkRoot", "coefficientVectorHash512"] {
        validate_hash_string(
            hash_string_field(coefficient_record, field_name)?,
            &format!("coefficientCommitment.{field_name}"),
        )?;
    }

    Ok((
        rns_limb_index,
        shamir_coefficient_index,
        commitment_root.to_string(),
    ))
}

pub(super) fn verify_coefficient_commitment_material(
    commitment_material_values: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    roster: &AcceptedRosterParameters,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
) -> CanonicalResult<BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>> {
    let expected_count = roster.participant_count as usize
        * DATA_PRIMES.len()
        * roster.decryption_threshold as usize;
    if commitment_material_values.len() != expected_count {
        return Err(invalid_threshold_commitment_input(
            "coefficientCommitments must contain full public commitment material for every source trustee, Q_share limb, and Shamir coefficient",
        ));
    }

    let mut commitment_bindings = BTreeMap::new();
    let mut ring_degree: Option<usize> = None;
    for material_value in commitment_material_values {
        let commitment_binding = verify_coefficient_commitment_material_record(
            material_value,
            setup_context,
            public_matrix_seed_hash,
            roster.decryption_threshold,
            source_trustee_bindings,
        )?;
        match ring_degree {
            Some(expected_ring_degree)
                if expected_ring_degree != commitment_binding.commitment.ring_degree =>
            {
                return Err(invalid_threshold_commitment_input(
                    "all coefficient commitments must use the same ring degree",
                ));
            }
            Some(_) => {}
            None => ring_degree = Some(commitment_binding.commitment.ring_degree),
        }

        let coordinate = (
            commitment_binding.source_trustee_roster_position,
            commitment_binding.rns_limb_index,
            commitment_binding.shamir_coefficient_index,
        );
        if commitment_bindings
            .insert(coordinate, commitment_binding)
            .is_some()
        {
            return Err(invalid_threshold_commitment_input(
                "coefficientCommitments contains duplicate source trustee/limb/coefficient material",
            ));
        }
    }

    for source_trustee_roster_position in 0..roster.participant_count {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..roster.decryption_threshold {
                if !commitment_bindings.contains_key(&(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                )) {
                    return Err(invalid_threshold_commitment_input(
                        "coefficientCommitments must cover every accepted coordinate",
                    ));
                }
            }
        }
    }

    Ok(commitment_bindings)
}

fn verify_coefficient_commitment_material_record(
    material_value: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    decryption_threshold: u64,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
) -> CanonicalResult<CoefficientCommitmentBinding> {
    if material_value.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material objectType must be VssCoefficientCommitmentMaterial",
        ));
    }
    if material_value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material objectVersion must be 1",
        ));
    }
    compare_context_fields(
        material_value,
        setup_context,
        "coefficientCommitmentMaterial",
    )?;
    if material_value
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
    }

    let source_trustee_identity =
        string_field(material_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = u64_field(material_value, "sourceTrusteeRosterPosition")?;
    let source_trustee_binding = source_trustee_bindings
        .get(&source_trustee_roster_position)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "coefficient commitment material references an unknown source trustee",
            )
        })?;
    if source_trustee_binding.source_trustee_identity != source_trustee_identity {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material source trustee identity must match the source trustee record",
        ));
    }

    let rns_limb_index = usize_field(material_value, "rnsLimbIndex")?;
    let rns_prime = u64_field(material_value, "rnsPrime")?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let shamir_coefficient_index = u64_field(material_value, "shamirCoefficientIndex")?;
    if shamir_coefficient_index >= decryption_threshold {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material shamirCoefficientIndex is outside the accepted threshold degree",
        ));
    }
    let commitment_root = hash_string_field(material_value, "commitmentRoot")?;
    validate_hash_string(
        commitment_root,
        "coefficientCommitmentMaterial.commitmentRoot",
    )?;
    let expected_commitment_root = source_trustee_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "coefficient commitment material coordinate is absent from the source trustee record",
            )
        })?;
    if commitment_root != expected_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material root must match the source trustee coefficient commitment record",
        ));
    }

    let commitment_value = material_value.get("commitment").ok_or_else(|| {
        invalid_threshold_commitment_input(
            "coefficient commitment material must include the full public commitment",
        )
    })?;
    let commitment = parse_setup_commitment_full_value(commitment_value)?;
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.source_message_modulus != rns_prime
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Err(invalid_threshold_commitment_input(
            "full setup commitment domain must match its material wrapper",
        ));
    }
    let computed_commitment_root = setup_commitment_root(&commitment)?;
    if commitment_root != computed_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "full setup commitment material does not match commitmentRoot",
        ));
    }

    Ok(CoefficientCommitmentBinding {
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        commitment_root: commitment_root.to_string(),
        commitment,
    })
}
