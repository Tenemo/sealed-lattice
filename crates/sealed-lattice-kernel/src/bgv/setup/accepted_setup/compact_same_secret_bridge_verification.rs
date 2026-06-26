use super::*;
use crate::bgv::setup::compact_same_secret_bridge::{
    verify_compact_vss_same_secret_bridge_proof_material_set_request,
    verify_compact_vss_same_secret_bridge_statement_set_request,
};

const COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD: &str = "compactSameSecretBridgeStatementSet";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD: &str =
    "compactSameSecretBridgeProofMaterialSet";

pub(super) fn verify_optional_compact_same_secret_bridge_statement_set(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let Some(statement_set) = setup_package.get(COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD)
    else {
        if setup_package
            .get(COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
            .is_some()
        {
            return Ok(Some(compact_same_secret_bridge_refusal(
                "compactSameSecretBridgeEvidenceIncomplete",
                "compact same-secret bridge proof material requires the matching bridge statement set",
                format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD}"),
            )?));
        }
        return Ok(None);
    };

    let (same_secret_consistency, same_secret_proofs) = match (
        setup_package.get("sameSecretConsistency"),
        setup_package.get("sameSecretProofs"),
    ) {
        (Some(same_secret_consistency), Some(same_secret_proofs)) => {
            (same_secret_consistency, same_secret_proofs)
        }
        (None, None) => {
            return Ok(Some(compact_same_secret_bridge_refusal(
                "compactSameSecretBridgeEvidenceMissing",
                "compact same-secret bridge verification requires matching sameSecretConsistency and sameSecretProofs package evidence",
                format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD}"),
            )?));
        }
        _ => {
            return Ok(Some(compact_same_secret_bridge_refusal(
                "compactSameSecretBridgeEvidenceIncomplete",
                "compact same-secret bridge verification requires both sameSecretConsistency and sameSecretProofs package evidence",
                format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD}"),
            )?));
        }
    };

    let mut bridge_request = json!({
        "statementSet": statement_set,
        "sameSecretConsistency": same_secret_consistency,
        "sameSecretProofs": same_secret_proofs,
    });
    let bridge_request_object = bridge_request
        .as_object_mut()
        .expect("compact bridge request is a JSON object");
    if let Some(transported_same_secret_proof_material) =
        request.get("transportedSameSecretProofMaterial")
    {
        bridge_request_object.insert(
            "transportedSameSecretProofMaterial".to_string(),
            transported_same_secret_proof_material.clone(),
        );
    }

    if let Err(error) = verify_compact_vss_same_secret_bridge_statement_set_request(&bridge_request)
    {
        return Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeStatementSetInvalid",
            error.message,
            format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_STATEMENT_SET_FIELD}"),
        )?));
    }

    let Some(proof_material_set) =
        setup_package.get(COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD)
    else {
        return Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeProofMaterialMissing",
            "compact same-secret bridge verification requires proof material for accepted setup verification",
            format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD}"),
        )?));
    };

    let mut proof_material_request = bridge_request;
    let proof_material_request_object = proof_material_request
        .as_object_mut()
        .expect("compact bridge proof material request is a JSON object");
    proof_material_request_object
        .insert("proofMaterialSet".to_string(), proof_material_set.clone());

    match verify_compact_vss_same_secret_bridge_proof_material_set_request(&proof_material_request)
    {
        Ok(_) => Ok(None),
        Err(error) => Ok(Some(compact_same_secret_bridge_refusal(
            "compactSameSecretBridgeProofMaterialInvalid",
            error.message,
            format!("setupPackage.{COMPACT_SAME_SECRET_BRIDGE_PROOF_MATERIAL_SET_FIELD}"),
        )?)),
    }
}

fn compact_same_secret_bridge_refusal(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::profile::DATA_PRIMES;
    use crate::bgv::setup::compact_vss_commitment::{
        COMPACT_VSS_RANDOMNESS_COLUMN_COUNT, CompactVssCommitmentOpeningInput,
        compute_compact_vss_commitment_from_opening,
    };
    use crate::bgv::setup::trustee_evaluation_key_proof::generate_compact_same_secret_bridge_proof_from_request;

    #[test]
    fn optional_compact_same_secret_bridge_is_absent_by_default() -> CanonicalResult<()> {
        let response =
            verify_optional_compact_same_secret_bridge_statement_set(&json!({}), &json!({}))?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_statement_set_without_same_secret_evidence()
    -> CanonicalResult<()> {
        let statement_set = compact_same_secret_bridge_statement_set()?;
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
            }),
            &json!({}),
        )?
        .expect("compact bridge statement set without same-secret evidence must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeEvidenceMissing")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeStatementSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_incomplete_same_secret_evidence()
    -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, _) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
            }),
            &json!({}),
        )?
        .expect("compact bridge statement set with partial same-secret evidence must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeEvidenceIncomplete")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeStatementSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_statement_set_without_proof_material()
    -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }),
            &json!({}),
        )?
        .expect("compact bridge statement set without proof material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeProofMaterialMissing")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeProofMaterialSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_proof_material_without_packaged_statements()
    -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let proof_material_set = compact_same_secret_bridge_proof_material_set(&statement_set)?;
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "compactSameSecretBridgeProofMaterialSet": proof_material_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }),
            &json!({}),
        )?
        .expect("compact bridge proof material without packaged statements must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeProofMaterialInvalid")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeProofMaterialSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_empty_packaged_statement_list()
    -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let mut proof_material_set = compact_same_secret_bridge_proof_material_set(&statement_set)?;
        proof_material_set["proofStatements"] = json!([]);
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "compactSameSecretBridgeProofMaterialSet": proof_material_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }),
            &json!({}),
        )?
        .expect("empty compact bridge packaged proof statement list must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeProofMaterialInvalid")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeProofMaterialSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_accepts_verified_packaged_proof_material()
    -> CanonicalResult<()> {
        let fixture = compact_same_secret_bridge_verified_proof_material_fixture()?;
        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &fixture.setup_package,
            &json!({}),
        )?;

        assert!(
            response.is_none(),
            "valid compact same-secret bridge proof material was refused: {response:?}"
        );
        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_packaged_proof_statement_mismatches()
    -> CanonicalResult<()> {
        let fixture = compact_same_secret_bridge_verified_proof_material_fixture()?;

        let mut wrong_same_secret_statement_root = fixture.setup_package.clone();
        wrong_same_secret_statement_root["compactSameSecretBridgeProofMaterialSet"]["proofStatements"]
            [0]["compactSameSecretBridge"]["sameSecretStatementRoot"] = json!("0".repeat(128));
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_same_secret_statement_root,
            "sameSecretStatementRoot",
        )?;

        let mut wrong_same_secret_proof_root = fixture.setup_package.clone();
        wrong_same_secret_proof_root["compactSameSecretBridgeProofMaterialSet"]["proofStatements"]
            [0]["compactSameSecretBridge"]["sameSecretProofRoot"] = json!("0".repeat(128));
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_same_secret_proof_root,
            "sameSecretProofRoot",
        )?;

        let mut wrong_target_basis_hash = fixture.setup_package.clone();
        wrong_target_basis_hash["compactSameSecretBridgeProofMaterialSet"]["proofStatements"][0]
            ["compactSameSecretBridge"]["targetBasisHash"] = json!("0".repeat(128));
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_target_basis_hash,
            "targetBasisHash",
        )?;

        let mut wrong_target_prime = fixture.setup_package.clone();
        wrong_target_prime["compactSameSecretBridgeProofMaterialSet"]["proofStatements"][0]["compactSameSecretBridge"]
            ["targetRnsPrimes"][0] = json!(DATA_PRIMES[1]);
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_target_prime,
            "target prime",
        )?;

        let mut wrong_target_constant_root = fixture.setup_package.clone();
        wrong_target_constant_root["compactSameSecretBridgeProofMaterialSet"]["proofStatements"]
            [0]["compactSameSecretBridge"]["targetConstantCommitmentRoots"][0] =
            json!("0".repeat(128));
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_target_constant_root,
            "target commitment root",
        )?;

        let mut wrong_target_commitment_body = fixture.setup_package;
        let target_commitment = &mut wrong_target_commitment_body["compactSameSecretBridgeProofMaterialSet"]
            ["proofStatements"][0]["compactSameSecretBridge"]["targetConstantCommitments"][0];
        let modulus = target_commitment["commitmentLimbs"][0]["modulus"]
            .as_u64()
            .expect("target commitment modulus");
        let coordinate = target_commitment["commitmentLimbs"][0]["coordinates"][0]
            .as_u64()
            .expect("target commitment coordinate");
        target_commitment["commitmentLimbs"][0]["coordinates"][0] =
            json!((coordinate + 1) % modulus);
        assert_compact_same_secret_bridge_proof_material_refusal(
            wrong_target_commitment_body,
            "root does not match its compact commitment object",
        )?;

        Ok(())
    }

    #[test]
    fn optional_compact_same_secret_bridge_refuses_wrong_statement_set_root() -> CanonicalResult<()>
    {
        let (mut statement_set, same_secret_consistency, same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!("0".repeat(128));

        let response = verify_optional_compact_same_secret_bridge_statement_set(
            &json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }),
            &json!({}),
        )?
        .expect("wrong compact bridge statement set root must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeStatementSetInvalid")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeStatementSet")
        );
        Ok(())
    }

    fn assert_compact_same_secret_bridge_proof_material_refusal(
        setup_package: Value,
        expected_message_fragment: &str,
    ) -> CanonicalResult<()> {
        let response =
            verify_optional_compact_same_secret_bridge_statement_set(&setup_package, &json!({}))?
                .expect("compact bridge proof material mismatch must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactSameSecretBridgeProofMaterialInvalid")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactSameSecretBridgeProofMaterialSet")
        );
        let message = response["refusedObjects"][0]["message"]
            .as_str()
            .expect("compact bridge refusal message");
        assert!(
            message.contains(expected_message_fragment),
            "expected compact bridge refusal message to contain {expected_message_fragment:?}, got {message:?}"
        );

        Ok(())
    }

    fn compact_same_secret_bridge_statement_set_with_evidence()
    -> CanonicalResult<(Value, Value, Value)> {
        let same_secret_consistency = same_secret_consistency_statement_set()?;
        let same_secret_proofs = same_secret_proof_set(&same_secret_consistency)?;
        let statement_records = [0_usize, 1_usize]
            .into_iter()
            .map(|trustee_roster_position| {
                let mut statement =
                    compact_same_secret_bridge_statement_record(trustee_roster_position)?;
                statement["sameSecretStatementRoot"] = same_secret_consistency["statementRecords"]
                    [trustee_roster_position]["sameSecretStatementRoot"]
                    .clone();
                statement["sameSecretProofRoot"] = same_secret_proofs["proofRecords"]
                    [trustee_roster_position]["sameSecretProofRoot"]
                    .clone();
                statement["trusteeSecretCommitmentRoot"] = same_secret_consistency
                    ["statementRecords"][trustee_roster_position]
                    ["trusteeSecretCommitmentRoot"]
                    .clone();
                statement["sameSecretProofFamilyBindingRoot"] = same_secret_consistency
                    ["statementRecords"][trustee_roster_position]
                    ["sameSecretProofFamilyBindingRoot"]
                    .clone();
                rebind_bridge_statement_root(&mut statement)?;
                Ok(statement)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let mut statement_set = compact_same_secret_bridge_statement_set_with_records(
            statement_records,
            same_secret_consistency["sameSecretConsistencyRoot"].clone(),
            same_secret_proofs["sameSecretProofSetRoot"].clone(),
        )?;
        rebind_bridge_statement_set_root(&mut statement_set)?;

        Ok((statement_set, same_secret_consistency, same_secret_proofs))
    }

    fn compact_same_secret_bridge_statement_set() -> CanonicalResult<Value> {
        let statement_records = [0_usize, 1_usize]
            .into_iter()
            .map(compact_same_secret_bridge_statement_record)
            .collect::<CanonicalResult<Vec<_>>>()?;
        compact_same_secret_bridge_statement_set_with_records(
            statement_records,
            json!("a".repeat(128)),
            json!("b".repeat(128)),
        )
    }

    fn compact_same_secret_bridge_proof_material_set(
        statement_set: &Value,
    ) -> CanonicalResult<Value> {
        let statement_records = statement_set["statementRecords"]
            .as_array()
            .expect("compact bridge statement records");
        let proof_records = statement_records
            .iter()
            .enumerate()
            .map(|(proof_record_index, statement_record)| {
                let proof_bytes = [proof_record_index as u8 + 1];
                let proof_record_without_root = json!({
                    "objectType": "CompactVssSameSecretBridgeProofRecord",
                    "objectVersion": 1,
                    "proofFamily": "compact-same-secret-bridge",
                    "compactSameSecretBridgeStatementRoot": statement_record["compactSameSecretBridgeStatementRoot"],
                    "proofStatementHash": if proof_record_index == 0 {
                        "1".repeat(128)
                    } else {
                        "2".repeat(128)
                    },
                    "proofByteLength": proof_bytes.len(),
                    "proofBytesHash": crate::hashing::hash512_hex(
                        "sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1",
                        &[&proof_bytes],
                    ),
                    "proofBytesHex": crate::hashing::to_hex(&proof_bytes),
                });
                let mut proof_record = proof_record_without_root;
                proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
                    "SetupProofRecordBindingHash",
                    &proof_record,
                )?);
                Ok(proof_record)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let proof_material_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "compact-same-secret-bridge",
            "ceremonyId": statement_set["ceremonyId"],
            "manifestHash": statement_set["manifestHash"],
            "rosterHash": statement_set["rosterHash"],
            "setupProfileHash": statement_set["setupProfileHash"],
            "qShareHash": statement_set["qShareHash"],
            "carryAwareVssShareRelationProfileHash": statement_set["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": statement_set["commitmentProfileHash"],
            "setupEpoch": statement_set["setupEpoch"],
            "targetBasisHash": statement_set["targetBasisHash"],
            "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
            "participantCount": statement_set["participantCount"],
            "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
            "thresholdDegree": statement_set["thresholdDegree"],
            "compactCoefficientCommitmentRoot": statement_set["compactCoefficientCommitmentRoot"],
            "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
            "compactSameSecretBridgeStatementSetRoot": statement_set["compactSameSecretBridgeStatementSetRoot"],
            "proofRecords": proof_records,
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material_set,
        )?);

        Ok(proof_material_set)
    }

    struct CompactSameSecretBridgeVerifiedProofMaterialFixture {
        setup_package: Value,
    }

    fn compact_same_secret_bridge_verified_proof_material_fixture()
    -> CanonicalResult<CompactSameSecretBridgeVerifiedProofMaterialFixture> {
        let ring_degree = 128_usize;
        let target_rns_prime = DATA_PRIMES[0];
        let public_matrix_seed_hash = "8".repeat(128);
        let target_basis_hash = "7".repeat(128);
        let secret_coefficients = (0..ring_degree)
            .map(|coefficient_index| match coefficient_index % 3 {
                0 => -1,
                1 => 0,
                _ => 1,
            })
            .collect::<Vec<_>>();
        let negative_indicator_coefficients = secret_coefficients
            .iter()
            .map(|coefficient| i64::from(*coefficient < 0))
            .collect::<Vec<_>>();
        let opening_randomness = compact_same_secret_bridge_randomness_columns(ring_degree, 17);
        let target_message_coefficients = compact_same_secret_bridge_message_coefficients(
            &secret_coefficients,
            &negative_indicator_coefficients,
            target_rns_prime,
        );
        let target_commitment_computation =
            compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
                commitment_role: "coefficient",
                commitment_context: &json!({
                    "objectType": "CompactSameSecretBridgeAcceptedProofTargetConstantContext",
                    "objectVersion": 1,
                    "targetRnsLimbIndex": 0,
                }),
                public_matrix_seed_hash: &public_matrix_seed_hash,
                rns_limb_index: 0,
                rns_prime: target_rns_prime,
                ring_degree,
                message_coefficients: &target_message_coefficients,
                message_coefficient_bound: target_rns_prime,
                randomness_by_column: &opening_randomness,
            })?;

        let same_secret_consistency = single_participant_same_secret_consistency_statement_set()?;
        let same_secret_proofs =
            single_participant_same_secret_proof_set(&same_secret_consistency)?;
        let statement_set = single_participant_compact_same_secret_bridge_statement_set(
            &same_secret_consistency,
            &same_secret_proofs,
            &public_matrix_seed_hash,
            &target_basis_hash,
            target_rns_prime,
            &target_commitment_computation.commitment_root,
        )?;
        let bridge_statement = &statement_set["statementRecords"][0];
        let compact_same_secret_bridge_statement = json!({
            "compactSameSecretBridgeStatementRoot": bridge_statement["compactSameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": bridge_statement["sameSecretStatementRoot"],
            "sameSecretProofRoot": bridge_statement["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": bridge_statement["sameSecretProofFamilyBindingRoot"],
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceTrusteeIdentity": "trustee-0",
            "sourceTrusteeRosterPosition": 0,
            "targetBasisHash": target_basis_hash,
            "targetRnsPrimes": [target_rns_prime],
            "targetConstantCommitmentRoots": [target_commitment_computation.commitment_root],
            "targetConstantCommitments": [target_commitment_computation.commitment],
        });
        let context = json!({
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "trusteeIdentity": "trustee-0",
            "trusteeRosterPosition": 0,
            "setupEpoch": "setup-epoch",
            "compactSameSecretBridgeStatementRoot": bridge_statement["compactSameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": bridge_statement["sameSecretStatementRoot"],
            "sameSecretProofRoot": bridge_statement["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": bridge_statement["sameSecretProofFamilyBindingRoot"],
        });
        let generation_request = json!({
            "context": context,
            "ringDegree": ring_degree,
            "compactSameSecretBridge": compact_same_secret_bridge_statement,
            "secretCoefficients": secret_coefficients,
            "negativeIndicatorCoefficients": negative_indicator_coefficients,
            "openingRandomnessByLimb": [opening_randomness],
            "proofRandomnessSource": "development-deterministic-fixture",
            "proofRandomnessSeedHex": "ab".repeat(64),
            "proofRandomnessNonceHex": "cd".repeat(64),
        });
        let generation =
            generate_compact_same_secret_bridge_proof_from_request(&generation_request)?;
        let proof_statement = json!({
            "proofStatementHash": generation["statementHash"],
            "context": generation_request["context"],
            "ringDegree": generation_request["ringDegree"],
            "compactSameSecretBridge": generation_request["compactSameSecretBridge"],
        });
        let proof_material_set = single_participant_compact_same_secret_bridge_proof_material_set(
            &statement_set,
            proof_statement,
            generation["proofBytesHex"].as_str().expect("proof bytes"),
        )?;

        Ok(CompactSameSecretBridgeVerifiedProofMaterialFixture {
            setup_package: json!({
                "compactSameSecretBridgeStatementSet": statement_set,
                "compactSameSecretBridgeProofMaterialSet": proof_material_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }),
        })
    }

    fn compact_same_secret_bridge_message_coefficients(
        secret_coefficients: &[i64],
        negative_indicator_coefficients: &[i64],
        target_rns_prime: u64,
    ) -> Vec<u64> {
        secret_coefficients
            .iter()
            .zip(negative_indicator_coefficients.iter())
            .map(|(secret_coefficient, negative_indicator)| {
                let lifted = i128::from(*secret_coefficient)
                    + i128::from(*negative_indicator) * i128::from(target_rns_prime);
                u64::try_from(lifted).expect("compact bridge message is canonical")
            })
            .collect()
    }

    fn compact_same_secret_bridge_randomness_columns(
        ring_degree: usize,
        seed_offset: i64,
    ) -> Vec<Vec<i64>> {
        (0..COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
            .map(|column_index| {
                (0..ring_degree)
                    .map(|coefficient_index| {
                        ((seed_offset + column_index as i64 * 11 + coefficient_index as i64 * 13)
                            .rem_euclid(3))
                            - 1
                    })
                    .collect()
            })
            .collect()
    }

    fn single_participant_same_secret_consistency_statement_set() -> CanonicalResult<Value> {
        let statement_record = same_secret_consistency_statement_record(0)?;
        let statement_set_without_root = json!({
            "objectType": "SameSecretConsistencyStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 1,
            "rnsLimbCount": 1,
            "thresholdDegree": 1,
            "vssCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "trusteeSecretCommitmentRoots": [{
                "trusteeIdentity": "trustee-0",
                "trusteeRosterPosition": 0,
                "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            }],
            "statementRecords": [statement_record],
        });
        let mut statement_set = statement_set_without_root;
        statement_set["sameSecretConsistencyRoot"] = json!(derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &statement_set,
        )?);

        Ok(statement_set)
    }

    fn single_participant_same_secret_proof_set(
        same_secret_consistency: &Value,
    ) -> CanonicalResult<Value> {
        let proof_record =
            same_secret_proof_record(0, &same_secret_consistency["statementRecords"][0])?;
        let proof_set_without_root = json!({
            "objectType": "SameSecretProofSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofAccountingHash": "d".repeat(128),
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 1,
            "rnsLimbCount": 1,
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "vssCoefficientCommitmentMaterialRoot": "e".repeat(128),
            "sameSecretProofRoots": [{
                "trusteeIdentity": "trustee-0",
                "trusteeRosterPosition": 0,
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
            }],
            "proofRecords": [proof_record],
        });
        let mut proof_set = proof_set_without_root;
        proof_set["sameSecretProofSetRoot"] =
            json!(derive_protocol_hash("SameSecretProofRoot", &proof_set)?);

        Ok(proof_set)
    }

    fn single_participant_compact_same_secret_bridge_statement_set(
        same_secret_consistency: &Value,
        same_secret_proofs: &Value,
        public_matrix_seed_hash: &str,
        target_basis_hash: &str,
        target_rns_prime: u64,
        target_commitment_root: &str,
    ) -> CanonicalResult<Value> {
        let statement_record_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "trusteeIdentity": "trustee-0",
            "trusteeRosterPosition": 0,
            "sameSecretStatementRoot": same_secret_consistency["statementRecords"][0]["sameSecretStatementRoot"],
            "sameSecretProofRoot": same_secret_proofs["proofRecords"][0]["sameSecretProofRoot"],
            "trusteeSecretCommitmentRoot": same_secret_consistency["statementRecords"][0]["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "dataBasisRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "targetConstantCoefficientCommitmentRoots": [{
                "rnsLimbIndex": 0,
                "rnsPrime": target_rns_prime,
                "shamirCoefficientIndex": 0,
                "coefficientCommitmentRoot": target_commitment_root,
            }],
            "relation": "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof",
        });
        let mut statement_record = statement_record_without_root;
        statement_record["compactSameSecretBridgeStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement_record,
        )?);
        let statement_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": 1,
            "targetRnsLimbCount": 1,
            "thresholdDegree": 1,
            "compactCoefficientCommitmentRoot": target_commitment_root,
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": same_secret_proofs["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": [statement_record],
        });
        let mut statement_set = statement_set_without_root;
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement_set,
        )?);

        Ok(statement_set)
    }

    fn single_participant_compact_same_secret_bridge_proof_material_set(
        statement_set: &Value,
        proof_statement: Value,
        proof_bytes_hex: &str,
    ) -> CanonicalResult<Value> {
        let proof_statement_hash = proof_statement["proofStatementHash"]
            .as_str()
            .expect("proof statement hash");
        let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
        let proof_record_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeProofRecord",
            "objectVersion": 1,
            "proofFamily": "compact-same-secret-bridge",
            "compactSameSecretBridgeStatementRoot": statement_set["statementRecords"][0]["compactSameSecretBridgeStatementRoot"],
            "proofStatementHash": proof_statement_hash,
            "proofByteLength": proof_bytes.len(),
            "proofBytesHash": crate::hashing::hash512_hex(
                "sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1",
                &[&proof_bytes],
            ),
            "proofBytesHex": proof_bytes_hex,
        });
        let mut proof_record = proof_record_without_root;
        proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_record,
        )?);
        let proof_material_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "compact-same-secret-bridge",
            "ceremonyId": statement_set["ceremonyId"],
            "manifestHash": statement_set["manifestHash"],
            "rosterHash": statement_set["rosterHash"],
            "setupProfileHash": statement_set["setupProfileHash"],
            "qShareHash": statement_set["qShareHash"],
            "carryAwareVssShareRelationProfileHash": statement_set["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": statement_set["commitmentProfileHash"],
            "setupEpoch": statement_set["setupEpoch"],
            "targetBasisHash": statement_set["targetBasisHash"],
            "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
            "participantCount": statement_set["participantCount"],
            "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
            "thresholdDegree": statement_set["thresholdDegree"],
            "compactCoefficientCommitmentRoot": statement_set["compactCoefficientCommitmentRoot"],
            "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
            "compactSameSecretBridgeStatementSetRoot": statement_set["compactSameSecretBridgeStatementSetRoot"],
            "proofRecords": [proof_record],
            "proofStatements": [proof_statement],
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material_set,
        )?);

        Ok(proof_material_set)
    }

    fn compact_same_secret_bridge_statement_set_with_records(
        statement_records: Vec<Value>,
        same_secret_consistency_root: Value,
        same_secret_proof_set_root: Value,
    ) -> CanonicalResult<Value> {
        let mut statement_set = json!({
            "objectType": "CompactVssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 4,
            "compactCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretConsistencyRoot": same_secret_consistency_root,
            "sameSecretProofSetRoot": same_secret_proof_set_root,
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": statement_records,
        });
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement_set,
        )?);

        Ok(statement_set)
    }

    fn same_secret_consistency_statement_set() -> CanonicalResult<Value> {
        let statement_records = [0_usize, 1_usize]
            .into_iter()
            .map(same_secret_consistency_statement_record)
            .collect::<CanonicalResult<Vec<_>>>()?;
        let trustee_secret_commitment_roots = statement_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, statement_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
                })
            })
            .collect::<Vec<_>>();
        let mut statement_set = json!({
            "objectType": "SameSecretConsistencyStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "thresholdDegree": 4,
            "vssCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "trusteeSecretCommitmentRoots": trustee_secret_commitment_roots,
            "statementRecords": statement_records,
        });
        statement_set["sameSecretConsistencyRoot"] = json!(derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &statement_set
        )?);

        Ok(statement_set)
    }

    fn same_secret_consistency_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let mut statement = json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "constantCoefficientCommitmentRoots": [],
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share"
            ],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        statement["sameSecretStatementRoot"] = json!(derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &statement
        )?);

        Ok(statement)
    }

    fn same_secret_proof_set(same_secret_consistency: &Value) -> CanonicalResult<Value> {
        let proof_records = [0_usize, 1_usize]
            .into_iter()
            .map(|trustee_roster_position| {
                same_secret_proof_record(
                    trustee_roster_position,
                    &same_secret_consistency["statementRecords"][trustee_roster_position],
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let same_secret_proof_roots = proof_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, proof_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                })
            })
            .collect::<Vec<_>>();
        let mut proof_set = json!({
            "objectType": "SameSecretProofSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofAccountingHash": "d".repeat(128),
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "vssCoefficientCommitmentMaterialRoot": "e".repeat(128),
            "sameSecretProofRoots": same_secret_proof_roots,
            "proofRecords": proof_records,
        });
        proof_set["sameSecretProofSetRoot"] =
            json!(derive_protocol_hash("SameSecretProofRoot", &proof_set)?);

        Ok(proof_set)
    }

    fn same_secret_proof_record(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
    ) -> CanonicalResult<Value> {
        let proof_bytes = [0_u8];
        let mut proof_record = json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "ringDegree": 8,
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
            "statementHash": if trustee_roster_position == 0 {
                "1".repeat(128)
            } else {
                "2".repeat(128)
            },
            "proofSizeBytes": proof_bytes.len(),
            "proofBytesHash": crate::hashing::hash512_hex(
                "sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1",
                &[&proof_bytes],
            ),
            "proofBytesHex": "00",
        });
        proof_record["sameSecretProofRoot"] =
            json!(derive_protocol_hash("SameSecretProofRoot", &proof_record)?);

        Ok(proof_record)
    }

    fn rebind_bridge_statement_root(statement: &mut Value) -> CanonicalResult<()> {
        statement["compactSameSecretBridgeStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &value_without_root_field(
                statement,
                "compactSameSecretBridgeStatementRoot",
                "compact same-secret bridge statement",
            )?,
        )?);

        Ok(())
    }

    fn rebind_bridge_statement_set_root(statement_set: &mut Value) -> CanonicalResult<()> {
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &value_without_root_field(
                statement_set,
                "compactSameSecretBridgeStatementSetRoot",
                "compact same-secret bridge statement set",
            )?,
        )?);

        Ok(())
    }

    fn value_without_root_field(
        value: &Value,
        root_field_name: &str,
        description: &str,
    ) -> CanonicalResult<Value> {
        let object = value.as_object().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{description} must be a JSON object"),
            )
        })?;
        if !object.contains_key(root_field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{description} must include {root_field_name}"),
            ));
        }
        let mut object_without_root = object.clone();
        object_without_root.remove(root_field_name);

        Ok(Value::Object(object_without_root))
    }

    fn compact_same_secret_bridge_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let target_constant_coefficient_commitment_roots = [0_usize, 1_usize]
            .into_iter()
            .map(|rns_limb_index| {
                json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": DATA_PRIMES[rns_limb_index],
                    "shamirCoefficientIndex": 0,
                    "coefficientCommitmentRoot": compact_same_secret_bridge_root(
                        trustee_roster_position,
                        rns_limb_index,
                    ),
                })
            })
            .collect::<Vec<_>>();
        let mut statement = json!({
            "objectType": "CompactVssSameSecretBridgeStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "sameSecretProofRoot": if trustee_roster_position == 0 {
                "c".repeat(128)
            } else {
                "d".repeat(128)
            },
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "dataBasisRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "targetConstantCoefficientCommitmentRoots": target_constant_coefficient_commitment_roots,
            "relation": "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof",
        });
        statement["compactSameSecretBridgeStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement,
        )?);

        Ok(statement)
    }

    fn compact_same_secret_bridge_root(
        trustee_roster_position: usize,
        rns_limb_index: usize,
    ) -> String {
        match (trustee_roster_position, rns_limb_index) {
            (0, 0) => "d".repeat(128),
            (0, _) => "e".repeat(128),
            (_, 0) => "f".repeat(128),
            _ => "0".repeat(128),
        }
    }
}
