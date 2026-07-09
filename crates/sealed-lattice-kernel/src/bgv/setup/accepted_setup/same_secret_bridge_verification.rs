use super::*;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    SameSecretBridgeStatement, VssPublicCommandCommitmentExpectation,
    vss_share_linkage_commitment_from_value,
};

const SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD: &str = "sameSecretBridgeStatementSet";
const SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD: &str = "sameSecretBridgeProofMaterialSet";

pub(super) enum SameSecretBridgeVerification {
    Absent,
    Verified(VerifiedSameSecretBridgeMaterial),
    Refused(Value),
}

#[derive(Clone)]
pub(in crate::bgv::setup) struct VerifiedSameSecretBridgeMaterial {
    statements_by_roster_position: BTreeMap<u64, SameSecretBridgeStatementBinding>,
}

impl VerifiedSameSecretBridgeMaterial {
    pub(in crate::bgv::setup) fn statement_for_roster_position(
        &self,
        trustee_roster_position: u64,
    ) -> CanonicalResult<&SameSecretBridgeStatementBinding> {
        self.statements_by_roster_position
            .get(&trustee_roster_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "same-secret bridge material does not cover the trustee roster position",
                )
            })
    }
}

#[derive(Clone)]
pub(in crate::bgv::setup) struct SameSecretBridgeStatementBinding {
    pub(in crate::bgv::setup) trustee_identity: String,
    pub(in crate::bgv::setup) trustee_secret_commitment_root: String,
    pub(in crate::bgv::setup) same_secret_statement_root: String,
    pub(in crate::bgv::setup) same_secret_proof_root: String,
    pub(in crate::bgv::setup) same_secret_proof_family_binding_root: String,
    pub(in crate::bgv::setup) statement: SameSecretBridgeStatement,
}

pub(super) fn verify_optional_same_secret_bridge_statement_set(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<SameSecretBridgeVerification> {
    let bridge_material_fields = [
        SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD,
        SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD,
    ];
    let present_bridge_field_count = bridge_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    if present_bridge_field_count == 0 {
        return Ok(SameSecretBridgeVerification::Absent);
    }

    let required_bridge_material_fields = [
        SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD,
        SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD,
        "sameSecretConsistency",
        "sameSecretProofs",
    ];
    let present_field_count = required_bridge_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();

    if present_field_count != required_bridge_material_fields.len() {
        let missing_fields = required_bridge_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(SameSecretBridgeVerification::Refused(
            same_secret_bridge_refusal(
                "sameSecretBridgeEvidenceIncomplete",
                format!(
                    "same-secret bridge material requires the statement set, proof material set, same-secret statements, and same-secret proofs; missing {missing_fields}"
                ),
                "setupPackage",
            )?,
        ));
    }

    match verified_same_secret_bridge_material_from_package(setup_package, request) {
        Ok(verified_material) => Ok(SameSecretBridgeVerification::Verified(verified_material)),
        Err(error) => Ok(SameSecretBridgeVerification::Refused(
            same_secret_bridge_refusal(
                "sameSecretBridgeMalformed",
                format!(
                    "same-secret bridge material is malformed: {}",
                    error.message
                ),
                "setupPackage",
            )?,
        )),
    }
}

fn verify_same_secret_bridge_setup_binding(
    setup_package: &Value,
    statement_set: &Value,
    statement_verification: &Value,
    same_secret_consistency: &Value,
    same_secret_proofs: &Value,
) -> CanonicalResult<()> {
    let setup_context = setup_package
        .get("setupContext")
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge requires setup context"))?;
    let common_randomness = setup_package
        .get("commonRandomness")
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge requires common randomness"))?;
    let coefficient_commitment_set = setup_package
        .get("vssPublicCoefficientCommitmentSet")
        .ok_or_else(|| {
            same_secret_bridge_error("same-secret bridge requires the coefficient commitment set")
        })?;

    compare_setup_context_binding(
        setup_context,
        statement_set,
        "same-secret bridge statement set",
    )?;
    compare_setup_context_participant_count(
        setup_context,
        statement_verification,
        "same-secret bridge statement set",
    )?;
    compare_setup_context_threshold_degree(
        setup_context,
        statement_verification,
        "same-secret bridge statement set",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["publicMatrixSeedHash"])?,
        hash_at_path(common_randomness, &["publicMatrixSeedHash"])?,
        "same-secret bridge statement set publicMatrixSeedHash",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["coefficientCommitmentRoot"])?,
        hash_at_path(coefficient_commitment_set, &["coefficientCommitmentRoot"])?,
        "same-secret bridge statement set coefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["sameSecretConsistencyRoot"])?,
        hash_at_path(same_secret_consistency, &["sameSecretConsistencyRoot"])?,
        "same-secret bridge statement set sameSecretConsistencyRoot",
    )?;
    compare_required_string(
        hash_at_path(statement_verification, &["sameSecretProofSetRoot"])?,
        hash_at_path(same_secret_proofs, &["sameSecretProofSetRoot"])?,
        "same-secret bridge statement set sameSecretProofSetRoot",
    )?;

    Ok(())
}

pub(in crate::bgv::setup) fn verified_same_secret_bridge_material_from_package(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<VerifiedSameSecretBridgeMaterial> {
    let statement_set = setup_package
        .get(SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD)
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge statement set"))?;
    let same_secret_consistency = setup_package
        .get("sameSecretConsistency")
        .ok_or_else(|| same_secret_bridge_error("same-secret consistency"))?;
    let same_secret_proofs = setup_package
        .get("sameSecretProofs")
        .ok_or_else(|| same_secret_bridge_error("same-secret proofs"))?;
    let statement_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(
            &same_secret_bridge_verification_request(
                statement_set,
                same_secret_consistency,
                same_secret_proofs,
                None,
                request,
            ),
        )?;
    verify_same_secret_bridge_setup_binding(
        setup_package,
        statement_set,
        &statement_verification,
        same_secret_consistency,
        same_secret_proofs,
    )?;
    let proof_material_set = setup_package
        .get(SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge proof material set"))?;
    crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
        &same_secret_bridge_verification_request(
            statement_set,
            same_secret_consistency,
            same_secret_proofs,
            Some(proof_material_set),
            request,
        ),
    )?;

    let ring_degree = usize::try_from(value_u64(statement_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge ringDegree does not fit usize",
        )
    })?;
    let public_matrix_seed_hash = value_string(statement_set, "publicMatrixSeedHash")?;
    compare_required_string(
        public_matrix_seed_hash,
        hash_at_path(&statement_verification, &["publicMatrixSeedHash"])?,
        "same-secret bridge publicMatrixSeedHash",
    )?;
    let target_basis_hash = value_string(statement_set, "targetBasisHash")?;
    let statement_records = array_value(statement_set, "statementRecords")?;
    let mut statements_by_roster_position = BTreeMap::new();
    for statement_record in statement_records {
        let trustee_roster_position = value_u64(statement_record, "trusteeRosterPosition")?;
        let target_constant_root_records =
            array_value(statement_record, "targetConstantCoefficientCommitmentRoots")?;
        let target_constant_commitment_records =
            array_value(statement_record, "targetConstantCoefficientCommitments")?;
        if target_constant_root_records.len() != target_constant_commitment_records.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret bridge target roots and commitments must be aligned",
            ));
        }
        let mut target_rns_primes = Vec::with_capacity(target_constant_root_records.len());
        let mut target_constant_commitment_roots =
            Vec::with_capacity(target_constant_root_records.len());
        let mut target_constant_commitments =
            Vec::with_capacity(target_constant_root_records.len());
        for (target_rns_limb_index, (target_root_record, target_commitment_record)) in
            target_constant_root_records
                .iter()
                .zip(target_constant_commitment_records.iter())
                .enumerate()
        {
            if value_u64(target_root_record, "rnsLimbIndex")? != target_rns_limb_index as u64
                || value_u64(target_commitment_record, "rnsLimbIndex")?
                    != target_rns_limb_index as u64
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "same-secret bridge target commitments must be ordered by limb",
                ));
            }
            let target_rns_prime = value_u64(target_root_record, "rnsPrime")?;
            if value_u64(target_commitment_record, "rnsPrime")? != target_rns_prime
                || DATA_PRIMES.get(target_rns_limb_index).copied() != Some(target_rns_prime)
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "same-secret bridge target prime must match the canonical target basis",
                ));
            }
            if value_u64(target_root_record, "shamirCoefficientIndex")? != 0
                || value_u64(target_commitment_record, "shamirCoefficientIndex")? != 0
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "same-secret bridge target commitment must bind the constant coefficient",
                ));
            }
            let target_commitment_root =
                value_string(target_root_record, "coefficientCommitmentRoot")?;
            let commitment_value = target_commitment_record.get("commitment").ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "same-secret bridge target commitment body is missing",
                )
            })?;
            let commitment = vss_share_linkage_commitment_from_value(
                commitment_value,
                VssPublicCommandCommitmentExpectation {
                    field_name: format!(
                        "sameSecretBridgeStatementSet.statementRecords.{trustee_roster_position}.targetConstantCoefficientCommitments.{target_rns_limb_index}"
                    ),
                    root: target_commitment_root,
                    role: "coefficient",
                    rns_limb_index: target_rns_limb_index,
                    rns_prime: target_rns_prime,
                    ring_degree,
                },
            )?;
            target_rns_primes.push(target_rns_prime);
            target_constant_commitment_roots.push(target_commitment_root.to_string());
            target_constant_commitments.push(commitment);
        }

        let trustee_identity = value_string(statement_record, "trusteeIdentity")?.to_string();
        let binding = SameSecretBridgeStatementBinding {
            trustee_identity: trustee_identity.clone(),
            trustee_secret_commitment_root: value_string(
                statement_record,
                "trusteeSecretCommitmentRoot",
            )?
            .to_string(),
            same_secret_statement_root: value_string(statement_record, "sameSecretStatementRoot")?
                .to_string(),
            same_secret_proof_root: value_string(statement_record, "sameSecretProofRoot")?
                .to_string(),
            same_secret_proof_family_binding_root: value_string(
                statement_record,
                "sameSecretProofFamilyBindingRoot",
            )?
            .to_string(),
            statement: SameSecretBridgeStatement {
                public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                source_trustee_identity: trustee_identity,
                source_trustee_roster_position: trustee_roster_position,
                target_basis_hash: target_basis_hash.to_string(),
                target_rns_primes,
                target_constant_commitment_roots,
                target_constant_commitments,
            },
        };
        if statements_by_roster_position
            .insert(trustee_roster_position, binding)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret bridge statements contain duplicate trustee roster positions",
            ));
        }
    }

    Ok(VerifiedSameSecretBridgeMaterial {
        statements_by_roster_position,
    })
}

fn same_secret_bridge_verification_request(
    statement_set: &Value,
    same_secret_consistency: &Value,
    same_secret_proofs: &Value,
    proof_material_set: Option<&Value>,
    request: &Value,
) -> Value {
    let mut verification_request = serde_json::Map::from_iter([
        ("statementSet".to_string(), statement_set.clone()),
        (
            "sameSecretConsistency".to_string(),
            same_secret_consistency.clone(),
        ),
        ("sameSecretProofs".to_string(), same_secret_proofs.clone()),
    ]);
    if let Some(proof_material_set) = proof_material_set {
        verification_request.insert("proofMaterialSet".to_string(), proof_material_set.clone());
    }
    for field_name in [
        "transportedSameSecretProofMaterial",
        "transportedSameSecretBridgeProofMaterial",
        "verifiedSetupProofMaterials",
    ] {
        if let Some(value) = request.get(field_name) {
            verification_request.insert(field_name.to_string(), value.clone());
        }
    }

    Value::Object(verification_request)
}

fn same_secret_bridge_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn same_secret_bridge_refusal(
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Value> {
    verification_response(
        Some("proofVerification"),
        Vec::new(),
        vec![Refusal::new(reason_code, message, object_path)],
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_same_secret_bridge_is_absent_by_default() -> CanonicalResult<()> {
        let response = verify_optional_same_secret_bridge_statement_set(&json!({}), &json!({}))?;

        assert!(matches!(response, SameSecretBridgeVerification::Absent));
        Ok(())
    }

    #[test]
    fn ordinary_same_secret_fields_do_not_enable_bridge() -> CanonicalResult<()> {
        let response = verify_optional_same_secret_bridge_statement_set(
            &json!({
                "sameSecretConsistency": {},
                "sameSecretProofs": {},
            }),
            &json!({}),
        )?;

        assert!(matches!(response, SameSecretBridgeVerification::Absent));
        Ok(())
    }

    #[test]
    fn optional_same_secret_bridge_refuses_proof_material_without_statement_set()
    -> CanonicalResult<()> {
        let response = verify_optional_same_secret_bridge_statement_set(
            &json!({
                "sameSecretBridgeProofMaterialSet": {},
            }),
            &json!({}),
        )?
        .refusal_for_test("bridge proof material without statement set must refuse");

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("sameSecretBridgeEvidenceIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_same_secret_bridge_refuses_statement_set_without_proof_material()
    -> CanonicalResult<()> {
        let response = verify_optional_same_secret_bridge_statement_set(
            &json!({
                "sameSecretBridgeStatementSet": {},
            }),
            &json!({}),
        )?
        .refusal_for_test("bridge statement set must refuse");

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("sameSecretBridgeEvidenceIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_same_secret_bridge_rejects_malformed_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_same_secret_bridge_statement_set(
            &json!({
                "sameSecretBridgeStatementSet": {},
                "sameSecretBridgeProofMaterialSet": {},
                "sameSecretConsistency": {},
                "sameSecretProofs": {},
            }),
            &json!({}),
        )
        .expect("complete bridge refusal")
        .refusal_for_test("complete bridge evidence must refuse");

        assert_eq!(response["isValid"], json!(false));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("sameSecretBridgeMalformed")
        );
        Ok(())
    }

    trait SameSecretBridgeVerificationTestExt {
        fn refusal_for_test(self, message: &str) -> Value;
    }

    impl SameSecretBridgeVerificationTestExt for SameSecretBridgeVerification {
        fn refusal_for_test(self, message: &str) -> Value {
            match self {
                SameSecretBridgeVerification::Refused(response) => response,
                SameSecretBridgeVerification::Absent => {
                    panic!("{message}: bridge evidence was absent")
                }
                SameSecretBridgeVerification::Verified(_) => {
                    panic!("{message}: bridge evidence verified")
                }
            }
        }
    }
}
