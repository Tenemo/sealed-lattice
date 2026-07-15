use super::*;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    SameSecretBridgeStatement, SameSecretLinkageStatement, VssPublicCommandCommitmentExpectation,
    vss_share_linkage_commitment_from_value,
};

const SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD: &str = "sameSecretBridgeStatementSet";
const SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD: &str = "sameSecretBridgeProofMaterialSet";

pub(super) enum SameSecretBridgeVerification {
    Verified(VerifiedSameSecretBridgeMaterial),
    Refused(Refusals),
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
    pub(in crate::bgv::setup) source_linkage: SameSecretLinkageStatement,
    pub(in crate::bgv::setup) statement: SameSecretBridgeStatement,
}

pub(super) fn verify_same_secret_bridge_statement_set(
    setup_package: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<SameSecretBridgeVerification> {
    let required_bridge_material_fields = [
        SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD,
        SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD,
        "vssPublicCoefficientCommitmentSet",
        "vssCoefficientCommitments",
    ];
    let missing_fields = required_bridge_material_fields
        .into_iter()
        .filter(|field_name| setup_package.get(*field_name).is_none())
        .map(|field_name| format!("setupPackage.{field_name}"))
        .collect::<Vec<_>>();
    if !missing_fields.is_empty() {
        return Ok(SameSecretBridgeVerification::Refused(
            same_secret_bridge_refusal(
                crate::foundation::RefusalReason::MissingPrerequisite,
                "sameSecretBridgeEvidenceIncomplete",
                format!(
                    "same-secret bridge material is required; missing {}",
                    missing_fields.join(", ")
                ),
                "setupPackage",
            )?,
        ));
    }

    match verified_same_secret_bridge_material_from_package(setup_package, proof_binding_session) {
        Ok(verified_material) => Ok(SameSecretBridgeVerification::Verified(verified_material)),
        Err(error) => Ok(SameSecretBridgeVerification::Refused(
            same_secret_bridge_refusal(
                crate::foundation::RefusalReason::MalformedEncoding,
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
    verified_statement_set: &crate::bgv::setup::same_secret_bridge::VerifiedSameSecretBridgeStatementSet,
) -> CanonicalResult<()> {
    let setup_context = setup_package
        .get("setupContext")
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge requires setup context"))?;
    let common_randomness = setup_package
        .get("commonRandomness")
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge requires common randomness"))?;
    compare_setup_context_binding(
        setup_context,
        statement_set,
        "same-secret bridge statement set",
    )?;
    let derived_profile = json!({
        "participantCount": verified_statement_set.participant_count,
        "qShareRnsLimbCount": verified_statement_set.q_share_rns_limb_count,
        "thresholdDegree": verified_statement_set.threshold_degree,
    });
    compare_setup_context_participant_count(
        setup_context,
        &derived_profile,
        "same-secret bridge statement set",
    )?;
    compare_setup_context_threshold_degree(
        setup_context,
        &derived_profile,
        "same-secret bridge statement set",
    )?;
    compare_complete_q_share_limb_count(&derived_profile, "same-secret bridge statement set")?;
    compare_required_string(
        hash_at_path(statement_set, &["publicMatrixSeedHash"])?,
        hash_at_path(common_randomness, &["publicMatrixSeedHash"])?,
        "same-secret bridge statement set publicMatrixSeedHash",
    )?;
    Ok(())
}

pub(in crate::bgv::setup) fn verified_same_secret_bridge_material_from_package(
    setup_package: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<VerifiedSameSecretBridgeMaterial> {
    let statement_set = setup_package
        .get(SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD)
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge statement set"))?;
    let verified_statement_set =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(
            &same_secret_bridge_verification_request(statement_set, None, setup_package),
        )?;
    verify_same_secret_bridge_setup_binding(setup_package, statement_set, &verified_statement_set)?;
    let proof_material_set = setup_package
        .get(SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
        .ok_or_else(|| same_secret_bridge_error("same-secret bridge proof material set"))?;
    crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
        &same_secret_bridge_verification_request(
            statement_set,
            Some(proof_material_set),
            setup_package,
        ),
        proof_binding_session,
    )?;

    let ring_degree = usize::try_from(value_u64(statement_set, "ringDegree")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge ringDegree does not fit usize",
        )
    })?;
    let q_share_rns_limb_count = verified_statement_set.q_share_rns_limb_count;
    let threshold_degree = verified_statement_set.threshold_degree;
    let public_matrix_seed_hash = value_string(statement_set, "publicMatrixSeedHash")?;
    let statement_records = array_value(statement_set, "statementRecords")?;
    let proof_bytes_hashes = array_value(proof_material_set, "proofBytesHashes")?;
    if proof_bytes_hashes.len() != statement_records.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge statements and proof hashes must be aligned",
        ));
    }
    let vss_coefficient_commitments =
        setup_package
            .get("vssCoefficientCommitments")
            .ok_or_else(|| {
                same_secret_bridge_error("same-secret bridge VSS coefficient commitments")
            })?;
    let coefficient_commitment_set = setup_package
        .get("vssPublicCoefficientCommitmentSet")
        .ok_or_else(|| {
            same_secret_bridge_error("same-secret bridge public coefficient commitments")
        })?;
    let trustee_identities = expected_trustees_from_setup_intent(
        &setup_intent::setup_intent_trustee_registrations_from_package(setup_package)?,
    );
    let mut statements_by_roster_position = BTreeMap::new();
    for (trustee_roster_position, statement_record) in statement_records.iter().enumerate() {
        let trustee_roster_position = trustee_roster_position as u64;
        let trustee_identity = trustee_identities
            .get(&trustee_roster_position)
            .cloned()
            .ok_or_else(|| same_secret_bridge_error("same-secret bridge proof source"))?;
        let authoritative_targets =
            crate::bgv::setup::same_secret_bridge::authoritative_same_secret_bridge_targets(
                coefficient_commitment_set,
                trustee_roster_position as usize,
                q_share_rns_limb_count,
                threshold_degree,
                ring_degree,
            )?;
        let mut bridge_rns_primes = Vec::with_capacity(authoritative_targets.len());
        let mut target_constant_commitment_roots = Vec::with_capacity(authoritative_targets.len());
        let mut target_constant_commitments = Vec::with_capacity(authoritative_targets.len());
        for (target_rns_limb_index, target) in authoritative_targets.iter().enumerate() {
            let target_rns_prime = DATA_PRIMES[target_rns_limb_index];
            let target_constant_commitment_root =
                crate::hashing::derive_canonical_object_hash(target.commitment_body)?;
            let commitment = vss_share_linkage_commitment_from_value(
                target.commitment_body,
                VssPublicCommandCommitmentExpectation {
                    field_name: format!(
                        "vssPublicCoefficientCommitmentSet.sourceTrusteeRecords.{trustee_roster_position}.coefficientCommitments.{}",
                        target_rns_limb_index * threshold_degree,
                    ),
                    root: &target_constant_commitment_root,
                    role: "coefficient",
                    rns_limb_index: target_rns_limb_index,
                    rns_prime: target_rns_prime,
                    ring_degree,
                },
            )?;
            bridge_rns_primes.push(target_rns_prime);
            target_constant_commitment_roots.push(target_constant_commitment_root);
            target_constant_commitments.push(commitment);
        }

        let source_constant_commitments = super::super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
            vss_coefficient_commitments,
            statement_record,
            &trustee_identity,
            trustee_roster_position,
            public_matrix_seed_hash,
            ring_degree,
        )?;
        let binding = SameSecretBridgeStatementBinding {
            trustee_identity: trustee_identity.clone(),
            source_linkage: SameSecretLinkageStatement {
                public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                commitments: source_constant_commitments.commitments,
            },
            statement: SameSecretBridgeStatement {
                public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                source_trustee_identity: trustee_identity,
                source_trustee_roster_position: trustee_roster_position,
                bridge_rns_primes,
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
    proof_material_set: Option<&Value>,
    setup_package: &Value,
) -> Value {
    let mut verification_request =
        serde_json::Map::from_iter([("statementSet".to_string(), statement_set.clone())]);
    if let Some(value) = setup_package.get("vssPublicCoefficientCommitmentSet") {
        verification_request.insert("coefficientCommitmentSet".to_string(), value.clone());
    }
    for field_name in ["vssCoefficientCommitments"] {
        if let Some(value) = setup_package.get(field_name) {
            verification_request.insert(field_name.to_string(), value.clone());
        }
    }
    if let Some(proof_material_set) = proof_material_set {
        verification_request.insert("proofMaterialSet".to_string(), proof_material_set.clone());
    }
    Value::Object(verification_request)
}

fn same_secret_bridge_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn same_secret_bridge_refusal(
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: impl Into<String>,
    object_path: impl Into<String>,
) -> CanonicalResult<Refusals> {
    Ok(setup_refusals(
        Vec::new(),
        vec![Refusal::new(
            refusal_reason,
            reason_code,
            message,
            object_path,
        )],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_same_secret_bridge_rejects_malformed_records() -> CanonicalResult<()> {
        let response = verify_same_secret_bridge_statement_set(
            &json!({
                "sameSecretBridgeStatementSet": {},
                "sameSecretBridgeProofMaterialSet": {},
                "vssPublicCoefficientCommitmentSet": {},
                "vssCoefficientCommitments": {},
            }),
            None,
        )
        .expect("complete bridge refusal")
        .refusal_for_test("complete bridge evidence must refuse");

        assert_eq!(
            response.first().map(|refusal| refusal.reason_code),
            Some("sameSecretBridgeMalformed")
        );
        Ok(())
    }

    trait SameSecretBridgeVerificationTestExt {
        fn refusal_for_test(self, message: &str) -> Refusals;
    }

    impl SameSecretBridgeVerificationTestExt for SameSecretBridgeVerification {
        fn refusal_for_test(self, message: &str) -> Refusals {
            match self {
                SameSecretBridgeVerification::Refused(response) => response,
                SameSecretBridgeVerification::Verified(_) => {
                    panic!("{message}: bridge evidence verified")
                }
            }
        }
    }
}
