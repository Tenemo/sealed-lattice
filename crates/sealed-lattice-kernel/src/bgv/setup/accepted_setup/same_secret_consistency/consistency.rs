use super::family_binding::*;

use super::*;
use crate::hashing::derive_canonical_object_hash;

use crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY;

pub(in super::super) fn verify_same_secret_consistency(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(statement_set) = setup_package.get("sameSecretConsistency") else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if !statement_set.is_object() {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyNotObject",
            "sameSecretConsistency must be a root-bound object, not an array or scalar",
            "setupPackage.sameSecretConsistency",
        )?));
    }
    if statement_set.get("objectType").and_then(Value::as_str)
        != Some(SAME_SECRET_CONSISTENCY_OBJECT_TYPE)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyTypeMismatch",
            "sameSecretConsistency.objectType must be SameSecretConsistencyStatementSet",
            "setupPackage.sameSecretConsistency.objectType",
        )?));
    }

    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before same-secret statement verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(statement_set, setup_context) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyContextMismatch",
            error.message,
            "setupPackage.sameSecretConsistency",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY)] {
        if statement_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyParametersMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }
    let roster = super::accepted_roster_from_package(setup_package);
    for (field_name, expected_value) in [
        ("participantCount", roster.participant_count),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
        ("thresholdDegree", roster.decryption_threshold),
    ] {
        if statement_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyCountMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }

    let vss_coefficient_commitment_root =
        super::super::accepted_vss_coefficient_commitment_root(setup_package).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "an accepted VSS coefficient commitment root was required before same-secret statement verification",
            )
        })?;
    if statement_set
        .get("vssCoefficientCommitmentRoot")
        .and_then(Value::as_str)
        != Some(vss_coefficient_commitment_root)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretVssCommitmentRootMismatch",
            "sameSecretConsistency.vssCoefficientCommitmentRoot must match the accepted VSS coefficient commitment set",
            "setupPackage.sameSecretConsistency.vssCoefficientCommitmentRoot",
        )?));
    }
    let expected_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    if statement_set
        .get("sameSecretProofFamilyBindingRoot")
        .and_then(Value::as_str)
        != Some(expected_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretProofFamilyBindingRootMismatch",
            "sameSecretConsistency.sameSecretProofFamilyBindingRoot must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.sameSecretProofFamilyBindingRoot",
        )?));
    }

    let expected_trustees = expected_trustees_from_phase_transcript(setup_package)?;
    let trustee_bindings =
        same_secret_trustee_bindings_from_vss(setup_package, &expected_trustees)?;
    let Some(statement_records) = statement_set
        .get("statementRecords")
        .and_then(Value::as_array)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if statement_records.len() != roster.participant_count as usize {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementCountMismatch",
            "sameSecretConsistency.statementRecords must contain one statement per trustee",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    for statement_record in statement_records {
        if let Some(response) = verify_same_secret_statement_record(
            statement_record,
            setup_context,
            &trustee_bindings,
            &mut seen_roster_positions,
        )? {
            return Ok(Some(response));
        }
    }

    let Some(same_secret_consistency_root) = statement_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.sameSecretConsistencyRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        same_secret_consistency_root,
        "sameSecretConsistency.sameSecretConsistencyRoot",
    )?;
    let mut root_input = statement_set.clone();
    root_input
        .as_object_mut()
        .expect("same-secret statement set object was checked")
        .remove("sameSecretConsistencyRoot");
    let expected_root = derive_canonical_object_hash(&root_input)?;
    if same_secret_consistency_root != expected_root {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyRootMismatch",
            "sameSecretConsistencyRoot does not match the canonical same-secret statement set",
            "setupPackage.sameSecretConsistency.sameSecretConsistencyRoot",
        )?));
    }

    Ok(None)
}

fn verify_same_secret_statement_record(
    statement_record: &Value,
    setup_context: &Value,
    trustee_bindings: &BTreeMap<u64, SameSecretTrusteeBinding>,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<Option<Value>> {
    if !statement_record.is_object() {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementNotObject",
            "same-secret statement records must be objects",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    if statement_record.get("objectType").and_then(Value::as_str)
        != Some(SAME_SECRET_STATEMENT_OBJECT_TYPE)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTypeMismatch",
            "same-secret statement objectType must be SameSecretConsistencyStatement",
            "setupPackage.sameSecretConsistency.statementRecords.objectType",
        )?));
    }
    if let Err(error) = verify_same_secret_context(statement_record, setup_context) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementContextMismatch",
            error.message,
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    for (field_name, expected_value) in [("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY)] {
        if statement_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretStatementParametersMismatch",
                format!("same-secret statement {field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.statementRecords.{field_name}"),
            )?));
        }
    }
    if statement_record.get("boundSecretDependentProofFamilies")
        != Some(&expected_same_secret_bound_proof_families_value())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretBoundProofFamiliesMismatch",
            "same-secret statement must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.statementRecords.boundSecretDependentProofFamilies",
        )?));
    }
    let expected_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    if statement_record
        .get("sameSecretProofFamilyBindingRoot")
        .and_then(Value::as_str)
        != Some(expected_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretProofFamilyBindingRootMismatch",
            "same-secret statement sameSecretProofFamilyBindingRoot must bind the accepted secret-dependent setup proof families",
            "setupPackage.sameSecretConsistency.statementRecords.sameSecretProofFamilyBindingRoot",
        )?));
    }

    let trustee_identity = value_string(statement_record, "trusteeIdentity")?;
    let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementDuplicate",
            "same-secret statement records must have distinct trustee roster positions",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    let Some(binding) = trustee_bindings.get(&trustee_roster_position) else {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTrusteeOutsideParameters",
            "same-secret statement trusteeRosterPosition is outside the accepted roster",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeRosterPosition",
        )?));
    };
    if binding.trustee_identity != trustee_identity {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementTrusteeMismatch",
            "same-secret statement trusteeIdentity must match the accepted VSS source trustee",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeIdentity",
        )?));
    }
    if statement_record
        .get("vssSourceTrusteeCommitmentRoot")
        .and_then(Value::as_str)
        != Some(binding.vss_source_trustee_commitment_root.as_str())
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretVssSourceTrusteeRootMismatch",
            "same-secret statement vssSourceTrusteeCommitmentRoot must match the accepted source trustee VSS commitments",
            "setupPackage.sameSecretConsistency.statementRecords.vssSourceTrusteeCommitmentRoot",
        )?));
    }
    if statement_record.get("constantCoefficientCommitmentRoots")
        != Some(&Value::Array(binding.constant_commitment_roots.clone()))
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretConstantCommitmentRootMismatch",
            "same-secret statement constant coefficient roots must match C_i,l,0 from VSS commitments",
            "setupPackage.sameSecretConsistency.statementRecords.constantCoefficientCommitmentRoots",
        )?));
    }

    let Some(trustee_secret_commitment_root) = statement_record
        .get("trusteeSecretCommitmentRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        trustee_secret_commitment_root,
        "sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot",
    )?;
    // Recompute the trustee secret commitment from the setup context and the ordered VSS constant commitments so it cannot be detached from this ceremony's dealing.
    let expected_trustee_secret_commitment_root =
        derive_canonical_object_hash(&trustee_secret_commitment_payload(setup_context, binding)?)?;
    if trustee_secret_commitment_root != expected_trustee_secret_commitment_root {
        return Ok(Some(same_secret_refusal(
            "trusteeSecretCommitmentRootMismatch",
            "trusteeSecretCommitmentRoot does not match the VSS constant coefficient commitments",
            "setupPackage.sameSecretConsistency.statementRecords.trusteeSecretCommitmentRoot",
        )?));
    }

    let Some(same_secret_statement_root) = statement_record
        .get("sameSecretStatementRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords.sameSecretStatementRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(
        same_secret_statement_root,
        "sameSecretConsistency.statementRecords.sameSecretStatementRoot",
    )?;
    let mut statement_root_input = statement_record.clone();
    statement_root_input
        .as_object_mut()
        .expect("same-secret statement object was checked")
        .remove("sameSecretStatementRoot");
    let expected_statement_root = derive_canonical_object_hash(&statement_root_input)?;
    if same_secret_statement_root != expected_statement_root {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementRootMismatch",
            "sameSecretStatementRoot does not match the canonical same-secret statement",
            "setupPackage.sameSecretConsistency.statementRecords.sameSecretStatementRoot",
        )?));
    }

    Ok(None)
}

fn same_secret_trustee_bindings_from_vss(
    setup_package: &Value,
    expected_trustees: &BTreeMap<u64, String>,
) -> CanonicalResult<BTreeMap<u64, SameSecretTrusteeBinding>> {
    // The constant coefficient commitments live in the commitment set: the
    // per-source-trustee root is the source record root, and each commitment
    // binds its root under coefficientCommitmentRoot.
    let (commitment_set_field, source_root_field, commitment_root_field) = (
        "vssPublicCoefficientCommitmentSet",
        "sourceCoefficientCommitmentRoot",
        "coefficientCommitmentRoot",
    );
    let source_trustee_records = setup_package
        .get(commitment_set_field)
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee records were required before same-secret statement verification",
            )
        })?;
    let mut bindings = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let trustee_roster_position =
            value_u64(source_trustee_record, "sourceTrusteeRosterPosition")?;
        let trustee_identity =
            value_string(source_trustee_record, "sourceTrusteeIdentity")?.to_string();
        if expected_trustees
            .get(&trustee_roster_position)
            .map(String::as_str)
            != Some(trustee_identity.as_str())
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "VSS source trustee record does not match the accepted setup roster",
            ));
        }
        let vss_source_trustee_commitment_root =
            value_string(source_trustee_record, source_root_field)?.to_string();
        let constant_commitment_roots = same_secret_constant_commitment_roots_from_source_trustee(
            source_trustee_record,
            commitment_root_field,
        )?;
        if bindings
            .insert(
                trustee_roster_position,
                SameSecretTrusteeBinding {
                    trustee_identity,
                    trustee_roster_position,
                    vss_source_trustee_commitment_root,
                    constant_commitment_roots,
                },
            )
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "VSS source trustee records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn same_secret_constant_commitment_roots_from_source_trustee(
    source_trustee_record: &Value,
    commitment_root_field: &str,
) -> CanonicalResult<Vec<Value>> {
    let coefficient_commitments = source_trustee_record
        .get("coefficientCommitments")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS coefficient commitments were required before same-secret statement verification",
            )
        })?;
    let mut roots = Vec::with_capacity(DATA_PRIMES.len());
    // Only the constant Shamir coefficient (index 0, the secret) is opened, and limbs must be contiguous and ordered because the anchor relation indexes commitments by limb position.
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let coefficient_record = coefficient_commitments
            .iter()
            .find(|coefficient_record| {
                coefficient_record
                    .get("rnsLimbIndex")
                    .and_then(Value::as_u64)
                    == Some(rns_limb_index as u64)
                    && coefficient_record
                        .get("shamirCoefficientIndex")
                        .and_then(Value::as_u64)
                        == Some(0)
            })
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "VSS constant coefficient commitment was required before same-secret statement verification",
                )
            })?;
        if coefficient_record.get("rnsPrime").and_then(Value::as_u64) != Some(rns_prime) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "VSS constant coefficient commitment RNS prime does not match Q_share",
            ));
        }
        roots.push(json!({
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shamirCoefficientIndex": 0,
            "commitmentRoot": value_string(coefficient_record, commitment_root_field)?,
        }));
    }

    Ok(roots)
}

fn trustee_secret_commitment_payload(
    setup_context: &Value,
    binding: &SameSecretTrusteeBinding,
) -> CanonicalResult<Value> {
    Ok(json!({
        "objectType": TRUSTEE_SECRET_COMMITMENT_OBJECT_TYPE,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupParametersHash": value_string(setup_context, "setupParametersHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "vssSourceTrusteeCommitmentRoot": binding.vss_source_trustee_commitment_root,
        "constantCoefficientCommitmentRoots": binding.constant_commitment_roots,
    }))
}
