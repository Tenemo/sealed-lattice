use super::*;

use crate::bgv::setup::trustee_evaluation_key_proof::{
    SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY, SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS,
    SAME_SECRET_LINKAGE_ANCHOR_PROOF_VERIFICATION_STATUS, SameSecretLinkageStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement, decode_trustee_evaluation_key_proof,
    same_secret_anchor_proof_bytes_hash, succinct_same_secret_linkage_anchor_accounting_hash,
    verify_evaluation_key_share,
};

struct SameSecretTrusteeBinding {
    trustee_identity: String,
    trustee_roster_position: u64,
    vss_source_trustee_commitment_root: String,
    constant_commitment_roots: Vec<Value>,
}

pub(super) struct SameSecretStatementBinding {
    pub(super) trustee_identity: String,
    pub(super) trustee_secret_commitment_root: String,
    pub(super) same_secret_statement_root: String,
}

pub(super) struct SameSecretProofBinding {
    pub(super) trustee_identity: String,
    pub(super) trustee_secret_commitment_root: String,
    pub(super) same_secret_statement_root: String,
    pub(super) same_secret_proof_family_binding_root: String,
    pub(super) same_secret_proof_root: String,
}

pub(super) fn verify_same_secret_consistency(
    setup_package: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(statement_set) = setup_package.get("sameSecretConsistency") else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
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
    if let Some(unexpected_field) = unexpected_same_secret_set_field(statement_set) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyUnexpectedField",
            format!("sameSecretConsistency contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretConsistency.{unexpected_field}"),
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
    if statement_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(same_secret_refusal(
            "sameSecretConsistencyVersionMismatch",
            "sameSecretConsistency.objectVersion must be 1",
            "setupPackage.sameSecretConsistency.objectVersion",
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
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            "anchor-proof-verification-pending",
        ),
    ] {
        if statement_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyProfileMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
        ("thresholdDegree", FIRST_PROFILE_DECRYPTION_THRESHOLD),
    ] {
        if statement_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretConsistencyCountMismatch",
                format!("sameSecretConsistency.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretConsistency.{field_name}"),
            )?));
        }
    }

    let vss_coefficient_commitment_root = setup_package
        .get("vssCoefficientCommitments")
        .and_then(|commitments| commitments.get("vssCoefficientCommitmentRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentRoot was required before same-secret statement verification",
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
            VerifierStatus::Pending,
            Some("publicKeyShareProofs"),
            vec!["sameSecretConsistency.statementRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if statement_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementCountMismatch",
            "sameSecretConsistency.statementRecords must contain one statement per trustee",
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }

    let mut seen_roster_positions = BTreeSet::new();
    let mut trustee_secret_commitment_roots = Vec::new();
    for statement_record in statement_records {
        let trustee_secret_commitment_root = match verify_same_secret_statement_record(
            statement_record,
            setup_context,
            &trustee_bindings,
            &mut seen_roster_positions,
        )? {
            Some(response) => return Ok(Some(response)),
            None => statement_record
                .get("trusteeSecretCommitmentRoot")
                .and_then(Value::as_str)
                .expect("trustee secret commitment root was verified")
                .to_string(),
        };
        trustee_secret_commitment_roots.push(json!({
            "trusteeIdentity": value_string(statement_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(statement_record, "trusteeRosterPosition")?,
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        }));
    }

    if statement_set.get("trusteeSecretCommitmentRoots")
        != Some(&Value::Array(trustee_secret_commitment_roots))
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretTrusteeRootListMismatch",
            "sameSecretConsistency.trusteeSecretCommitmentRoots must match the ordered statement records",
            "setupPackage.sameSecretConsistency.trusteeSecretCommitmentRoots",
        )?));
    }

    let Some(same_secret_consistency_root) = statement_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
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
    let expected_root = derive_protocol_hash("SameSecretConsistencyRoot", &root_input)?;
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
    if let Some(unexpected_field) = unexpected_same_secret_statement_field(statement_record) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementUnexpectedField",
            format!("same-secret statement contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretConsistency.statementRecords.{unexpected_field}"),
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
    if statement_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementVersionMismatch",
            "same-secret statement objectVersion must be 1",
            "setupPackage.sameSecretConsistency.statementRecords.objectVersion",
        )?));
    }
    if let Err(error) = verify_same_secret_context(statement_record, setup_context) {
        return Ok(Some(same_secret_refusal(
            "sameSecretStatementContextMismatch",
            error.message,
            "setupPackage.sameSecretConsistency.statementRecords",
        )?));
    }
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            "anchor-proof-verification-pending",
        ),
        (
            "sameSecretRelation",
            "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        ),
        (
            "genericKeySwitchBindingPolicy",
            "absent-unless-frozen-schedule-requires-proof-family",
        ),
        (
            "targetDecryptionBindingPolicy",
            "later-target-share-must-bind-threshold-share-commitment",
        ),
    ] {
        if statement_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_refusal(
                "sameSecretStatementProfileMismatch",
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
            "sameSecretStatementTrusteeOutsideProfile",
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
            VerifierStatus::Pending,
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
    let expected_trustee_secret_commitment_root = derive_protocol_hash(
        "TrusteeSecretCommitmentRoot",
        &trustee_secret_commitment_payload(setup_context, binding)?,
    )?;
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
            VerifierStatus::Pending,
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
    let expected_statement_root =
        derive_protocol_hash("SameSecretConsistencyRoot", &statement_root_input)?;
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
    let source_trustee_records = setup_package
        .get("vssCoefficientCommitments")
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS source trustee record does not match the accepted setup roster",
            ));
        }
        let vss_source_trustee_commitment_root =
            value_string(source_trustee_record, "sourceTrusteeCommitmentRoot")?.to_string();
        let constant_commitment_roots =
            same_secret_constant_commitment_roots_from_source_trustee(source_trustee_record)?;
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS source trustee records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}

fn same_secret_constant_commitment_roots_from_source_trustee(
    source_trustee_record: &Value,
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "VSS constant coefficient commitment RNS prime does not match Q_share",
            ));
        }
        roots.push(json!({
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "shamirCoefficientIndex": 0,
            "commitmentRoot": value_string(coefficient_record, "commitmentRoot")?,
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
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "ceremonyId": value_string(setup_context, "ceremonyId")?,
        "manifestHash": value_string(setup_context, "manifestHash")?,
        "rosterHash": value_string(setup_context, "rosterHash")?,
        "setupProfileHash": value_string(setup_context, "setupProfileHash")?,
        "qShareHash": value_string(setup_context, "qShareHash")?,
        "carryAwareVssShareRelationProfileHash": value_string(
            setup_context,
            "carryAwareVssShareRelationProfileHash",
        )?,
        "commitmentProfileHash": value_string(setup_context, "commitmentProfileHash")?,
        "setupEpoch": value_string(setup_context, "setupEpoch")?,
        "trusteeIdentity": binding.trustee_identity,
        "trusteeRosterPosition": binding.trustee_roster_position,
        "vssSourceTrusteeCommitmentRoot": binding.vss_source_trustee_commitment_root,
        "secretCommitmentSource": "vss-constant-coefficient-commitments",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "constantCoefficientCommitmentRoots": binding.constant_commitment_roots,
    }))
}

pub(super) fn verify_optional_same_secret_proofs(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(proof_set) = setup_package.get("sameSecretProofs") else {
        return Ok(None);
    };
    if !proof_set.is_object() {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofsNotObject",
            "sameSecretProofs must be a root-bound object",
            "setupPackage.sameSecretProofs",
        )?));
    }
    if let Some(unexpected_field) = unexpected_same_secret_proof_set_field(proof_set) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetUnexpectedField",
            format!("sameSecretProofs contains unexpected field {unexpected_field}"),
            format!("setupPackage.sameSecretProofs.{unexpected_field}"),
        )?));
    }
    if proof_set.get("objectType").and_then(Value::as_str) != Some("SameSecretProofSet") {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetTypeMismatch",
            "sameSecretProofs.objectType must be SameSecretProofSet",
            "setupPackage.sameSecretProofs.objectType",
        )?));
    }
    if proof_set.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetVersionMismatch",
            "sameSecretProofs.objectVersion must be 1",
            "setupPackage.sameSecretProofs.objectVersion",
        )?));
    }
    let setup_context = setup_package.get("setupContext").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "setupContext was required before same-secret proof verification",
        )
    })?;
    if let Err(error) = verify_same_secret_context(proof_set, setup_context) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetContextMismatch",
            error.message,
            "setupPackage.sameSecretProofs",
        )?));
    }
    let anchor_accounting_hash = succinct_same_secret_linkage_anchor_accounting_hash()?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_VERIFICATION_STATUS,
        ),
        (
            "proofModelStatus",
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS,
        ),
        ("proofAccountingHash", anchor_accounting_hash.as_str()),
    ] {
        if proof_set.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetProfileMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    for (field_name, expected_value) in [
        ("participantCount", FIRST_PROFILE_PARTICIPANT_COUNT),
        ("rnsLimbCount", DATA_PRIMES.len() as u64),
    ] {
        if proof_set.get(field_name).and_then(Value::as_u64) != Some(expected_value) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofSetCountMismatch",
                format!("sameSecretProofs.{field_name} must be {expected_value}"),
                format!("setupPackage.sameSecretProofs.{field_name}"),
            )?));
        }
    }
    let expected_same_secret_proof_family_binding_root = same_secret_proof_family_binding_root()?;
    let same_secret_consistency_root = same_secret_consistency_root_from_package(setup_package)?;
    if proof_set
        .get("sameSecretConsistencyRoot")
        .and_then(Value::as_str)
        != Some(same_secret_consistency_root.as_str())
        || proof_set
            .get("sameSecretProofFamilyBindingRoot")
            .and_then(Value::as_str)
            != Some(expected_same_secret_proof_family_binding_root.as_str())
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofConsistencyRootMismatch",
            "sameSecretProofs must match accepted same-secret statements and proof-family binding",
            "setupPackage.sameSecretProofs",
        )?));
    }
    let material_root = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .and_then(|material| material.get("vssCoefficientCommitmentMaterialRoot"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterialRoot was required before same-secret proof verification",
            )
        })?;
    if proof_set
        .get("vssCoefficientCommitmentMaterialRoot")
        .and_then(Value::as_str)
        != Some(material_root)
    {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofMaterialRootMismatch",
            "sameSecretProofs.vssCoefficientCommitmentMaterialRoot must match accepted public VSS material",
            "setupPackage.sameSecretProofs.vssCoefficientCommitmentMaterialRoot",
        )?));
    }

    let statement_records = same_secret_statement_records_by_roster_position(setup_package)?;
    let transported_constant_commitments =
        same_secret_transported_constant_commitments_by_roster_position(setup_package, request)?;
    let Some(proof_records) = proof_set.get("proofRecords").and_then(Value::as_array) else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs.proofRecords".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    if proof_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT as usize {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofCountMismatch",
            "sameSecretProofs.proofRecords must contain one proof per trustee",
            "setupPackage.sameSecretProofs.proofRecords",
        )?));
    }
    let public_matrix_seed_hash = setup_package
        .get("commonRandomness")
        .and_then(|common_randomness| common_randomness.get("publicMatrixSeedHash"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "commonRandomness.publicMatrixSeedHash was required before same-secret proof verification",
            )
        })?;
    let mut seen_roster_positions = BTreeSet::new();
    let mut proof_roots = Vec::new();
    let verification_context = SameSecretAnchorProofVerificationContext {
        setup_package,
        request,
        setup_context,
        public_matrix_seed_hash,
        vss_coefficient_commitment_material_root: material_root,
        statement_records: &statement_records,
        transported_constant_commitments: &transported_constant_commitments,
    };
    for proof_record in proof_records {
        if let Err(error) = verify_same_secret_anchor_proof_record(
            &verification_context,
            proof_record,
            &mut seen_roster_positions,
        ) {
            return Ok(Some(same_secret_proof_refusal(
                "sameSecretProofVerificationFailed",
                error.message,
                "setupPackage.sameSecretProofs.proofRecords",
            )?));
        }
        proof_roots.push(json!({
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "sameSecretProofRoot": value_string(proof_record, "sameSecretProofRoot")?,
        }));
    }
    if proof_set.get("sameSecretProofRoots") != Some(&Value::Array(proof_roots)) {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofRootListMismatch",
            "sameSecretProofs.sameSecretProofRoots must match the ordered proof records",
            "setupPackage.sameSecretProofs.sameSecretProofRoots",
        )?));
    }

    let Some(proof_set_root) = proof_set
        .get("sameSecretProofSetRoot")
        .and_then(Value::as_str)
    else {
        return Ok(Some(verification_response(
            VerifierStatus::Pending,
            Some("proofVerification"),
            vec!["sameSecretProofs.sameSecretProofSetRoot".to_string()],
            Vec::new(),
            Vec::new(),
        )?));
    };
    validate_hash_string(proof_set_root, "sameSecretProofs.sameSecretProofSetRoot")?;
    let mut root_input = proof_set.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof set object was checked")
        .remove("sameSecretProofSetRoot");
    let expected_root = derive_protocol_hash("SameSecretProofRoot", &root_input)?;
    if proof_set_root != expected_root {
        return Ok(Some(same_secret_proof_refusal(
            "sameSecretProofSetRootMismatch",
            "sameSecretProofSetRoot does not match the canonical same-secret proof set",
            "setupPackage.sameSecretProofs.sameSecretProofSetRoot",
        )?));
    }

    Ok(None)
}

struct SameSecretAnchorProofVerificationContext<'a> {
    setup_package: &'a Value,
    request: &'a Value,
    setup_context: &'a Value,
    public_matrix_seed_hash: &'a str,
    vss_coefficient_commitment_material_root: &'a str,
    statement_records: &'a BTreeMap<u64, Value>,
    transported_constant_commitments:
        &'a BTreeMap<u64, Vec<super::commitment::SetupCommitmentValue>>,
}

fn verify_same_secret_anchor_proof_record(
    context: &SameSecretAnchorProofVerificationContext<'_>,
    proof_record: &Value,
    seen_roster_positions: &mut BTreeSet<u64>,
) -> CanonicalResult<()> {
    if !proof_record.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must be objects",
        ));
    }
    if let Some(unexpected_field) = unexpected_same_secret_proof_record_field(proof_record) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("same-secret proof contains unexpected field {unexpected_field}"),
        ));
    }
    if proof_record.get("objectType").and_then(Value::as_str) != Some("SameSecretProof") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectType must be SameSecretProof",
        ));
    }
    if proof_record.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof objectVersion must be 1",
        ));
    }
    verify_same_secret_context(proof_record, context.setup_context)?;
    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("commitmentProfileId", SETUP_COMMITMENT_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
        (
            "proofVerificationStatus",
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_VERIFICATION_STATUS,
        ),
        (
            "proofModelStatus",
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_MODEL_STATUS,
        ),
    ] {
        if proof_record.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must be {expected_value}"),
            ));
        }
    }
    let trustee_roster_position = value_u64(proof_record, "trusteeRosterPosition")?;
    if !seen_roster_positions.insert(trustee_roster_position) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof records must have distinct trustee roster positions",
        ));
    }
    let statement_record = context
        .statement_records
        .get(&trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof trusteeRosterPosition must reference an accepted statement",
            )
        })?;
    for field_name in [
        "trusteeIdentity",
        "trusteeSecretCommitmentRoot",
        "sameSecretStatementRoot",
        "sameSecretProofFamilyBindingRoot",
    ] {
        if proof_record.get(field_name) != statement_record.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proof {field_name} must match the accepted statement"),
            ));
        }
    }

    let proof_bytes = same_secret_proof_bytes_from_record(proof_record, context.request)?;
    let proof_size_bytes = u64::try_from(proof_bytes.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof byte length does not fit u64",
        )
    })?;
    if proof_record.get("proofSizeBytes").and_then(Value::as_u64) != Some(proof_size_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofSizeBytes must match proofBytesHex",
        ));
    }
    let proof_bytes_hash = value_string(proof_record, "proofBytesHash")?;
    if proof_bytes_hash != same_secret_anchor_proof_bytes_hash(&proof_bytes) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesHash must match proofBytesHex",
        ));
    }
    let constant_commitments = same_secret_constant_commitment_values_from_material(
        context.setup_package,
        trustee_roster_position,
        context.transported_constant_commitments,
    )?;
    let ring_degree = constant_commitments
        .first()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proof verification requires constant commitments",
            )
        })?
        .ring_degree;
    let statement = TrusteeEvaluationKeyStatement {
        context: SuccinctSetupProofContext {
            proof_family: SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY.to_string(),
            ceremony_id: value_string(context.setup_context, "ceremonyId")?.to_string(),
            manifest_hash: value_string(context.setup_context, "manifestHash")?.to_string(),
            roster_hash: value_string(context.setup_context, "rosterHash")?.to_string(),
            trustee_identity: value_string(proof_record, "trusteeIdentity")?.to_string(),
            trustee_roster_position,
            setup_epoch: value_string(context.setup_context, "setupEpoch")?.to_string(),
            binding_roots: vec![(
                "vssCoefficientCommitmentMaterialRoot".to_string(),
                context.vss_coefficient_commitment_material_root.to_string(),
            )],
        },
        ring_degree,
        keys: Vec::new(),
        same_secret_linkage: Some(SameSecretLinkageStatement {
            public_matrix_seed_hash: context.public_matrix_seed_hash.to_string(),
            commitments: constant_commitments,
        }),
    };
    let statement_hash_hex = statement
        .statement_hash()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if proof_record.get("statementHash").and_then(Value::as_str)
        != Some(statement_hash_hex.as_str())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof statementHash must match the rebuilt anchor statement",
        ));
    }
    let proof = decode_trustee_evaluation_key_proof(&statement, &proof_bytes)?;
    verify_evaluation_key_share(&statement, &proof)?;
    let proof_root = value_string(proof_record, "sameSecretProofRoot")?;
    let mut root_input = proof_record.clone();
    root_input
        .as_object_mut()
        .expect("same-secret proof record object was checked")
        .remove("sameSecretProofRoot");
    let expected_root = derive_protocol_hash("SameSecretProofRoot", &root_input)?;
    if proof_root != expected_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "sameSecretProofRoot does not match the canonical same-secret proof record",
        ));
    }

    Ok(())
}

fn same_secret_proof_bytes_from_record(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<Vec<u8>> {
    let has_embedded_proof_bytes = proof_record.get("proofBytesHex").is_some();
    let has_transport_reference = [
        "proofBytesEncoding",
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some());

    if has_embedded_proof_bytes && has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof must not mix embedded proofBytesHex with transported proof material",
        ));
    }
    if has_embedded_proof_bytes {
        return decode_hex(value_string(proof_record, "proofBytesHex")?);
    }
    if !has_transport_reference {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proof requires proofBytesHex or transported proof material",
        ));
    }

    let proof_bytes_encoding = value_string(proof_record, "proofBytesEncoding")?;
    if proof_bytes_encoding != SETUP_PROOF_MATERIAL_ENCODING {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofBytesEncoding must be binary-chunked-proof-bytes",
        ));
    }
    let proof_material_root = value_string(proof_record, "proofMaterialRoot")?;
    validate_hash_string(proof_material_root, "sameSecretProof.proofMaterialRoot")?;
    let chunks = transported_same_secret_proof_material_chunks(request, proof_material_root)?;
    let transport_hashes = setup_proof_material_transport_hashes(
        SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        &chunks,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    )?;
    verify_same_secret_proof_transport_reference(proof_record, &transport_hashes)?;
    let expected_material_root =
        same_secret_anchor_proof_material_root(proof_record, &transport_hashes)?;
    if proof_material_root != expected_material_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofMaterialRoot must match the canonical transported proof material reference",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(
        usize::try_from(transport_hashes.total_byte_length).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret transported proof material length does not fit usize",
            )
        })?,
    );
    for chunk in chunks {
        proof_bytes.extend_from_slice(&chunk);
    }

    Ok(proof_bytes)
}

pub(in crate::bgv::setup) fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SameSecretLinkageAnchorProofMaterialRoot",
        &json!({
            "objectType": "SameSecretLinkageAnchorProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            "trusteeIdentity": value_string(proof_record, "trusteeIdentity")?,
            "trusteeRosterPosition": value_u64(proof_record, "trusteeRosterPosition")?,
            "statementHash": value_string(proof_record, "statementHash")?,
            "proofSizeBytes": value_u64(proof_record, "proofSizeBytes")?,
            "proofBytesHash": value_string(proof_record, "proofBytesHash")?,
            "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_hashes.chunk_hashes.len(),
            "totalByteLength": transport_hashes.total_byte_length,
            "fullObjectHash": transport_hashes.full_object_hash,
            "chunkRoot": transport_hashes.chunk_root,
            "chunkHashes": transport_hashes.chunk_hashes,
        }),
    )
}

fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(proof_record, "proofChunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count =
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret proof material chunk count does not fit u64",
            )
        })?;
    if value_u64(proof_record, "proofChunkCount")? != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkCount must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofTotalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofTotalByteLength must match transported proof chunks",
        ));
    }
    if value_u64(proof_record, "proofSizeBytes")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofSizeBytes must match transported proof byte length",
        ));
    }
    if value_string(proof_record, "proofFullObjectHash")?
        != transport_hashes.full_object_hash.as_str()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofFullObjectHash must match transported proof chunks",
        ));
    }
    if value_string(proof_record, "proofChunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkRoot must match the canonical proof chunk manifest",
        ));
    }
    let Some(chunk_hash_values) = proof_record
        .get("proofChunkHashes")
        .and_then(Value::as_array)
    else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkHashes must list every transported proof chunk",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "same-secret proofChunkHashes length must match transported proof chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("same-secret proofChunkHashes[{chunk_index}] must be a hash string"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("sameSecretProof.proofChunkHashes[{chunk_index}]"),
        )?;
        if chunk_hash != expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "same-secret proofChunkHashes must match transported proof chunks",
            ));
        }
    }

    Ok(())
}

fn transported_same_secret_proof_material_chunks(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let material_set = request
        .get("transportedSameSecretProofMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial was required by transported same-secret proof records",
            )
        })?;
    verify_transported_same_secret_proof_material_set_header(material_set)?;
    let Some(proof_materials) = material_set.get("proofMaterials").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.proofMaterials must list transported proof material objects",
        ));
    };
    let mut matching_chunks = None;
    for proof_material in proof_materials {
        verify_transported_same_secret_proof_material_header(proof_material)?;
        let proof_material_root = value_string(proof_material, "proofMaterialRoot")?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_chunks.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = transported_same_secret_proof_chunks(proof_material)?;
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_proof_material_hashes(proof_material, &transport_hashes)?;
        matching_chunks = Some(chunks);
    }

    matching_chunks.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) =
        unexpected_transported_same_secret_proof_material_set_field(value)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transportedSameSecretProofMaterial contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("transportedSameSecretProofMaterial.{field_name} must be {expected_value}"),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedSameSecretProofMaterial.objectVersion must be 1",
        ));
    }

    Ok(())
}

fn verify_transported_same_secret_proof_material_header(value: &Value) -> CanonicalResult<()> {
    if let Some(unexpected_field) = unexpected_transported_same_secret_proof_material_field(value) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!(
                "transported same-secret proof material contains unexpected field {unexpected_field}"
            ),
        ));
    }
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY),
    ] {
        if value.get(field_name).and_then(Value::as_str) != Some(expected_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported same-secret proof material {field_name} must be {expected_value}"
                ),
            ));
        }
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material objectVersion must be 1",
        ));
    }
    validate_hash_string(
        value_string(value, "proofMaterialRoot")?,
        "transportedSameSecretProofMaterial.proofMaterialRoot",
    )?;

    Ok(())
}

fn transported_same_secret_proof_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunkSizeBytes must match the setup proof transport profile",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunkCount does not fit usize",
        )
    })?;
    let Some(chunk_values) = value.get("chunks").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunks are required",
        ));
    };
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if let Some(unexpected_field) =
            unexpected_transported_same_secret_proof_chunk_field(chunk_value)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "transported same-secret proof chunk contains unexpected field {unexpected_field}"
                ),
            ));
        }
        let observed_chunk_index = value_u64(chunk_value, "chunkIndex")?;
        if observed_chunk_index != expected_chunk_index as u64 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret proof chunks must be supplied in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

fn verify_transported_same_secret_proof_material_hashes(
    value: &Value,
    transport_hashes: &super::setup_proof::SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    if value_u64(value, "totalByteLength")? != transport_hashes.total_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof totalByteLength must match supplied chunks",
        ));
    }
    if value_string(value, "fullObjectHash")? != transport_hashes.full_object_hash.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof fullObjectHash must match supplied chunks",
        ));
    }
    if value_string(value, "chunkRoot")? != transport_hashes.chunk_root.as_str() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkRoot must match supplied chunks",
        ));
    }
    let Some(chunk_hash_values) = value.get("chunkHashes").and_then(Value::as_array) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkHashes are required",
        ));
    };
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transported same-secret proof chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
    {
        if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported same-secret proof chunkHashes must match supplied chunks",
            ));
        }
    }

    Ok(())
}

pub(super) fn same_secret_statement_records_by_roster_position(
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

pub(super) fn same_secret_proof_set_root_from_package(
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

pub(super) fn same_secret_proof_bindings_from_package(
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

pub(super) fn same_secret_transported_constant_commitments_by_roster_position(
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

pub(super) fn same_secret_constant_commitment_values_from_material(
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

pub(super) fn verify_same_secret_context(
    value: &Value,
    setup_context: &Value,
) -> CanonicalResult<()> {
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ] {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("same-secret {field_name} must match setupContext"),
            ));
        }
    }

    Ok(())
}

fn expected_same_secret_bound_proof_families_value() -> Value {
    Value::Array(
        SAME_SECRET_BOUND_PROOF_FAMILIES
            .iter()
            .map(|family| Value::String((*family).to_string()))
            .collect(),
    )
}

fn same_secret_proof_family_binding_value() -> Value {
    json!({
        "objectType": SAME_SECRET_PROOF_FAMILY_BINDING_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": "same-secret-linkage-anchor",
        "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        "anchorArgument": "one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values",
        "boundSecretDependentProofFamilies": expected_same_secret_bound_proof_families_value(),
        "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
        "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
    })
}

pub(super) fn same_secret_proof_family_binding_root() -> CanonicalResult<String> {
    derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &same_secret_proof_family_binding_value(),
    )
}

fn unexpected_same_secret_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "thresholdDegree",
            "vssCoefficientCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "trusteeSecretCommitmentRoots",
            "statementRecords",
            "sameSecretConsistencyRoot",
            "proofAccountingHash",
        ],
    )
}

fn unexpected_same_secret_statement_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "vssSourceTrusteeCommitmentRoot",
            "constantCoefficientCommitmentRoots",
            "trusteeSecretCommitmentRoot",
            "boundSecretDependentProofFamilies",
            "genericKeySwitchBindingPolicy",
            "targetDecryptionBindingPolicy",
            "sameSecretProofFamilyBindingRoot",
            "sameSecretRelation",
            "sameSecretStatementRoot",
        ],
    )
}

fn unexpected_same_secret_proof_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "proofAccountingHash",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "participantCount",
            "rnsLimbCount",
            "sameSecretConsistencyRoot",
            "sameSecretProofFamilyBindingRoot",
            "vssCoefficientCommitmentMaterialRoot",
            "sameSecretProofRoots",
            "proofRecords",
            "sameSecretProofSetRoot",
        ],
    )
}

fn unexpected_same_secret_proof_record_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "commitmentProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofVerificationStatus",
            "proofModelStatus",
            "ceremonyId",
            "manifestHash",
            "rosterHash",
            "setupProfileHash",
            "qShareHash",
            "carryAwareVssShareRelationProfileHash",
            "commitmentProfileHash",
            "setupEpoch",
            "trusteeIdentity",
            "trusteeRosterPosition",
            "sameSecretStatementRoot",
            "trusteeSecretCommitmentRoot",
            "sameSecretProofFamilyBindingRoot",
            "statementHash",
            "proofSizeBytes",
            "proofBytesHash",
            "proofBytesEncoding",
            "proofMaterialRoot",
            "proofChunkSizeBytes",
            "proofChunkCount",
            "proofTotalByteLength",
            "proofFullObjectHash",
            "proofChunkRoot",
            "proofChunkHashes",
            "proofBytesHex",
            "sameSecretProofRoot",
        ],
    )
}

fn unexpected_transported_same_secret_proof_material_set_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterials",
        ],
    )
}

fn unexpected_transported_same_secret_proof_material_field(value: &Value) -> Option<String> {
    unexpected_field(
        value,
        &[
            "objectType",
            "objectVersion",
            "setupProfileId",
            "setupProofProfileId",
            "proofFamily",
            "proofMaterialRoot",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ],
    )
}

fn unexpected_transported_same_secret_proof_chunk_field(value: &Value) -> Option<String> {
    unexpected_field(value, &["chunkIndex", "bytesHex"])
}

fn same_secret_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("publicKeyShareProofs"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

fn same_secret_proof_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        VerifierStatus::Refused,
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

pub(super) fn same_secret_consistency_root_from_package(
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

pub(super) fn same_secret_statement_bindings_from_package(
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "same-secret statement records contain a duplicate roster position",
            ));
        }
    }

    Ok(bindings)
}
