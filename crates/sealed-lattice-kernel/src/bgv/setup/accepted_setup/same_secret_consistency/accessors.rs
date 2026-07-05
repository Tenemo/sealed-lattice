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
