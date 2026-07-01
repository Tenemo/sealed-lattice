use super::*;

pub(in super::super) fn same_secret_statement_records_by_roster_position(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, Value>> {
    let statement_records = setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("statementRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretConsistency.statementRecords were required before same-secret proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for statement_record in statement_records {
        let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
        if records
            .insert(trustee_roster_position, statement_record.clone())
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret statements contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

pub(in super::super) fn same_secret_proof_set_root_from_package(
    setup_package: &Value,
) -> CanonicalResult<String> {
    setup_package
        .get("sameSecretProofs")
        .and_then(|proof_set| proof_set.get("sameSecretProofSetRoot"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretProofSetRoot was required before public-key proof verification",
            )
        })
}

pub(in super::super) fn same_secret_proof_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, SameSecretProofBinding>> {
    let proof_records = setup_package
        .get("sameSecretProofs")
        .and_then(|proof_set| proof_set.get("proofRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretProofs.proofRecords were required before public-key proof verification",
            )
        })?;
    let mut records = BTreeMap::new();
    for proof_record in proof_records {
        let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
        let binding = SameSecretProofBinding {
            trustee_identity: value_string(proof_record, "trusteeIdentity")?.to_string(),
            trustee_secret_commitment_root: value_string(
                proof_record,
                "trusteeSecretCommitmentRoot",
            )?
            .to_string(),
            same_secret_statement_root: value_string(proof_record, "sameSecretStatementRoot")?
                .to_string(),
            same_secret_proof_family_binding_root: value_string(
                proof_record,
                "sameSecretProofFamilyBindingRoot",
            )?
            .to_string(),
            same_secret_proof_root: value_string(proof_record, "sameSecretProofRoot")?.to_string(),
        };
        if records.insert(trustee_roster_position, binding).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof records contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(records)
}

pub(in super::super) fn same_secret_transported_constant_commitments_by_roster_position(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Arc<BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    if material_set.get("materialEncoding").and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Arc::new(BTreeMap::new()));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before transported same-secret proof verification",
        )
    })?;
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before transported same-secret proof verification",
            )
        })?;
    let vss_coefficient_commitment_root = material_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.vssCoefficientCommitmentRoot was required before transported same-secret proof verification",
            )
        })?;
    if let Some(verified_material_reference) =
        request.get("verifiedVssCoefficientCommitmentMaterial")
    {
        return with_verified_transported_vss_material(
            verified_material_reference,
            |verified_material| {
                validate_verified_vss_material_matches_package(
                    verified_material,
                    setup_context,
                    public_matrix_seed_hash,
                    vss_coefficient_commitment_root,
                    material_set,
                )?;

                Ok(Arc::clone(
                    &verified_material.constant_commitments_by_source_trustee,
                ))
            },
        );
    }
    let transported_material = request
        .get("transportedVssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "verifiedVssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    if transported_material.get("chunks").is_none() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "stream-verified VSS material was required before same-secret proof verification",
        ));
    }
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before transported same-secret proof verification",
            )
        })?;
    let verified_transport = verify_constant_vss_commitments_from_transport_request(&json!({
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "sourceTrusteeCoefficientCommitmentRecords": source_trustee_records,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))?;
    let derived_material_root = verified_transport
        .material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret material verification did not return a material root",
            )
        })?;
    let package_material_root = material_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "package material root was required before transported same-secret proof verification",
            )
        })?;
    if derived_material_root != package_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported VSS material root must match setupPackage.vssCoefficientCommitmentMaterial before same-secret proof verification",
        ));
    }

    Ok(verified_transport.constant_commitments_by_source_trustee)
}

pub(in super::super) fn same_secret_constant_commitment_values_from_material(
    setup_package: &Value,
    trustee_roster_position: u64,
    transported_constant_commitments: &BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
) -> CanonicalResult<Vec<super::commitment::SetupCommitmentValue>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before same-secret proof verification",
            )
        })?;
    let material_encoding = material_set
        .get("materialEncoding")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.materialEncoding was required before same-secret proof verification",
            )
        })?;
    if material_encoding == "binary-chunked-full-public-setup-commitment-values" {
        return transported_constant_commitments
            .get(&trustee_roster_position)
            .cloned()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "transported same-secret proof material is missing trustee constant commitments",
                )
            });
    }
    if material_encoding != "full-public-setup-commitment-values" {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret anchor proof verification requires embedded or binary-transported public VSS commitment material",
        ));
    }
    let material_records = material_set
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial.coefficientCommitments were required before same-secret proof verification",
            )
        })?;
    let mut commitments_by_limb = BTreeMap::new();
    for material_record in material_records {
        if material_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(trustee_roster_position)
            || material_record
                .get("shamirCoefficientIndex")
                .and_then(Value::as_u64)
                != Some(0)
        {
            continue;
        }
        let rns_limb_index = value_u64(material_record, "rnsLimbIndex")?;
        let commitment_value = material_record.get("commitment").ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material record is missing commitment",
            )
        })?;
        let commitment = parse_setup_commitment_full_value(commitment_value)?;
        let commitment_root = setup_commitment_root(&commitment)?;
        if material_record
            .get("commitmentRoot")
            .and_then(Value::as_str)
            != Some(commitment_root.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof commitment material root does not match its public commitment",
            ));
        }
        if commitments_by_limb
            .insert(rns_limb_index, commitment)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material contains duplicate constant commitment limbs",
            ));
        }
    }
    let mut commitments = Vec::with_capacity(DATA_PRIMES.len());
    for rns_limb_index in 0..DATA_PRIMES.len() as u64 {
        let commitment = commitments_by_limb.remove(&rns_limb_index).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof material is missing a constant commitment limb",
            )
        })?;
        commitments.push(commitment);
    }

    Ok(commitments)
}

pub(in super::super) fn same_secret_consistency_root_from_package(
    setup_package: &Value,
) -> CanonicalResult<String> {
    setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("sameSecretConsistencyRoot"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "sameSecretConsistencyRoot was required before public-key share verification",
            )
        })
}

pub(in super::super) fn same_secret_statement_bindings_from_package(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, SameSecretStatementBinding>> {
    let statement_records = setup_package
        .get("sameSecretConsistency")
        .and_then(|same_secret| same_secret.get("statementRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret statement records were required before public-key share verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for statement_record in statement_records {
        let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
        if bindings
            .insert(
                trustee_roster_position,
                SameSecretStatementBinding {
                    trustee_identity: value_string(statement_record, "trusteeIdentity")?
                        .to_string(),
                    trustee_secret_commitment_root: value_string(
                        statement_record,
                        "trusteeSecretCommitmentRoot",
                    )?
                    .to_string(),
                    same_secret_statement_root: value_string(
                        statement_record,
                        "sameSecretStatementRoot",
                    )?
                    .to_string(),
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret statement records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}
