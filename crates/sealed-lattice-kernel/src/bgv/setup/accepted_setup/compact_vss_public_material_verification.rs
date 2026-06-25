use super::*;
use crate::bgv::setup::compact_vss_commitment::{
    verify_compact_vss_share_linkage_proof_material_set_request,
    verify_compact_vss_share_linkage_statement_request,
};

const COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD: &str = "compactVssCoefficientCommitmentSet";
const COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD: &str =
    "compactVssRecipientShareCommitmentSet";
const COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD: &str =
    "compactVssAggregateThresholdCommitmentSet";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD: &str = "compactVssShareLinkageStatement";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD: &str =
    "compactVssShareLinkageProofMaterialSet";
const COMPACT_VSS_RESTRICTED_PROOF_STATEMENTS_FIELD: &str = "compactVssRestrictedProofStatements";

pub(super) fn verify_optional_compact_vss_public_material(
    setup_package: &Value,
    request: &Value,
) -> CanonicalResult<Option<Value>> {
    let compact_public_material_fields = [
        COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD,
        COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD,
        COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD,
        COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD,
    ];
    let present_field_count = compact_public_material_fields
        .iter()
        .filter(|field_name| setup_package.get(**field_name).is_some())
        .count();
    let proof_material_set = setup_package.get(COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD);
    if present_field_count == 0 && proof_material_set.is_none() {
        return Ok(None);
    }

    if present_field_count != compact_public_material_fields.len() {
        let missing_fields = compact_public_material_fields
            .into_iter()
            .filter(|field_name| setup_package.get(*field_name).is_none())
            .map(|field_name| format!("setupPackage.{field_name}"))
            .collect::<Vec<_>>()
            .join(", ");

        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssPublicMaterialIncomplete",
            format!(
                "compact VSS public material requires all compact commitment sets and the share-linkage statement; missing {missing_fields}"
            ),
            "setupPackage",
        )?));
    }

    let coefficient_commitment_set = setup_package
        .get(COMPACT_VSS_COEFFICIENT_COMMITMENT_SET_FIELD)
        .expect("field count confirmed compact VSS coefficient set is present");
    let recipient_share_commitment_set = setup_package
        .get(COMPACT_VSS_RECIPIENT_SHARE_COMMITMENT_SET_FIELD)
        .expect("field count confirmed compact VSS recipient-share set is present");
    let aggregate_threshold_commitment_set = setup_package
        .get(COMPACT_VSS_AGGREGATE_THRESHOLD_COMMITMENT_SET_FIELD)
        .expect("field count confirmed compact VSS aggregate set is present");
    let share_linkage_statement = setup_package
        .get(COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD)
        .expect("field count confirmed compact VSS share-linkage statement is present");

    let statement_verification_request = json!({
        "statement": share_linkage_statement,
        "coefficientCommitmentSet": coefficient_commitment_set,
        "recipientShareCommitmentSet": recipient_share_commitment_set,
        "aggregateThresholdCommitmentSet": aggregate_threshold_commitment_set,
    });
    if let Err(error) =
        verify_compact_vss_share_linkage_statement_request(&statement_verification_request)
    {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssPublicMaterialInvalid",
            error.message,
            format!("setupPackage.{COMPACT_VSS_SHARE_LINKAGE_STATEMENT_FIELD}"),
        )?));
    }

    let Some(proof_material_set) = proof_material_set else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialMissing",
            "compact VSS public material requires share-linkage proof material for accepted setup verification",
            format!("setupPackage.{COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD}"),
        )?));
    };

    let Some(restricted_proof_statements) =
        request.get(COMPACT_VSS_RESTRICTED_PROOF_STATEMENTS_FIELD)
    else {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofStatementsMissing",
            "compact VSS share-linkage proof material requires matching restricted proof statements for accepted setup verification",
            format!("request.{COMPACT_VSS_RESTRICTED_PROOF_STATEMENTS_FIELD}"),
        )?));
    };
    if !matches!(restricted_proof_statements, Value::Array(values) if !values.is_empty()) {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofStatementsMissing",
            "compact VSS share-linkage proof material requires at least one matching restricted proof statement for accepted setup verification",
            format!("request.{COMPACT_VSS_RESTRICTED_PROOF_STATEMENTS_FIELD}"),
        )?));
    }

    let proof_material_verification_request = json!({
        "statement": share_linkage_statement,
        "proofMaterialSet": proof_material_set,
        "restrictedProofStatements": restricted_proof_statements,
    });
    if let Err(error) = verify_compact_vss_share_linkage_proof_material_set_request(
        &proof_material_verification_request,
    ) {
        return Ok(Some(compact_vss_public_material_refusal(
            "compactVssShareLinkageProofMaterialInvalid",
            error.message,
            format!("setupPackage.{COMPACT_VSS_SHARE_LINKAGE_PROOF_MATERIAL_SET_FIELD}"),
        )?));
    }

    Ok(None)
}

fn compact_vss_public_material_refusal(
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
    use crate::bgv::setup::compact_vss_commitment::tests::{
        compact_aggregate_threshold_commitment_set_from_recipient_set,
        compact_coefficient_commitment_set, compact_recipient_share_commitment_set,
        compact_share_linkage_statement_from_evidence,
    };
    use crate::bgv::setup::compact_vss_commitment::{
        CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
    };
    use crate::bgv::setup::trustee_evaluation_key_proof::generate_compact_vss_share_linkage_proof_from_request;
    use crate::hashing::hash512_hex;

    #[test]
    fn optional_compact_vss_public_material_is_absent_by_default() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(&json!({}), &json!({}))?;

        assert!(response.is_none());
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_requires_complete_field_group() -> CanonicalResult<()> {
        let response = verify_optional_compact_vss_public_material(
            &json!({
                "compactVssCoefficientCommitmentSet": compact_coefficient_commitment_set()?,
            }),
            &json!({}),
        )?
        .expect("partial compact VSS public material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialIncomplete")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_statement_without_proof_material()
    -> CanonicalResult<()> {
        let fixture = compact_vss_public_material_fixture()?;
        let response =
            verify_optional_compact_vss_public_material(&fixture.setup_package, &json!({}))?
                .expect("compact VSS public material without proof material must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofMaterialMissing")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactVssShareLinkageProofMaterialSet")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_mismatched_statement_root()
    -> CanonicalResult<()> {
        let mut fixture = compact_vss_public_material_fixture()?;
        fixture.setup_package["compactVssShareLinkageStatement"]["statementRoot"] =
            json!("0".repeat(128));
        let response =
            verify_optional_compact_vss_public_material(&fixture.setup_package, &json!({}))?
                .expect("wrong compact VSS statement root must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssPublicMaterialInvalid")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("setupPackage.compactVssShareLinkageStatement")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_proof_material_without_restricted_statements()
    -> CanonicalResult<()> {
        let mut fixture = compact_vss_public_material_fixture()?;
        fixture.setup_package["compactVssShareLinkageProofMaterialSet"] =
            compact_vss_share_linkage_proof_material_set(&fixture.share_linkage_statement)?;
        let response =
            verify_optional_compact_vss_public_material(&fixture.setup_package, &json!({}))?
                .expect("compact VSS proof material without restricted statements must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofStatementsMissing")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("request.compactVssRestrictedProofStatements")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_refuses_empty_restricted_statement_list()
    -> CanonicalResult<()> {
        let mut fixture = compact_vss_public_material_fixture()?;
        fixture.setup_package["compactVssShareLinkageProofMaterialSet"] =
            compact_vss_share_linkage_proof_material_set(&fixture.share_linkage_statement)?;

        let response = verify_optional_compact_vss_public_material(
            &fixture.setup_package,
            &json!({
                "compactVssRestrictedProofStatements": [],
            }),
        )?
        .expect("empty restricted compact VSS proof statement list must refuse");

        assert_eq!(response["verifierStatus"], json!("refused"));
        assert_eq!(
            response["refusedObjects"][0]["reasonCode"],
            json!("compactVssShareLinkageProofStatementsMissing")
        );
        assert_eq!(
            response["refusedObjects"][0]["objectPath"],
            json!("request.compactVssRestrictedProofStatements")
        );
        Ok(())
    }

    #[test]
    fn optional_compact_vss_public_material_accepts_verified_restricted_proof_material()
    -> CanonicalResult<()> {
        let fixture = compact_vss_verified_proof_material_fixture()?;
        let response = verify_optional_compact_vss_public_material(
            &fixture.setup_package,
            &json!({
                "compactVssRestrictedProofStatements": fixture.restricted_proof_statements,
            }),
        )?;

        assert!(
            response.is_none(),
            "valid compact VSS proof material was refused: {response:?}"
        );
        Ok(())
    }

    struct CompactVssPublicMaterialFixture {
        setup_package: Value,
        share_linkage_statement: Value,
    }

    struct CompactVssVerifiedProofMaterialFixture {
        setup_package: Value,
        restricted_proof_statements: Vec<Value>,
    }

    fn compact_vss_public_material_fixture() -> CanonicalResult<CompactVssPublicMaterialFixture> {
        let coefficient_commitment_set = compact_coefficient_commitment_set()?;
        let recipient_share_commitment_set = compact_recipient_share_commitment_set()?;
        let aggregate_threshold_commitment_set =
            compact_aggregate_threshold_commitment_set_from_recipient_set(
                &recipient_share_commitment_set,
            )?;
        let share_linkage_statement = compact_share_linkage_statement_from_evidence(
            &coefficient_commitment_set,
            &recipient_share_commitment_set,
            &aggregate_threshold_commitment_set,
        );

        Ok(CompactVssPublicMaterialFixture {
            setup_package: json!({
                "compactVssCoefficientCommitmentSet": coefficient_commitment_set,
                "compactVssRecipientShareCommitmentSet": recipient_share_commitment_set,
                "compactVssAggregateThresholdCommitmentSet": aggregate_threshold_commitment_set,
                "compactVssShareLinkageStatement": share_linkage_statement.clone(),
            }),
            share_linkage_statement,
        })
    }

    fn compact_vss_verified_proof_material_fixture()
    -> CanonicalResult<CompactVssVerifiedProofMaterialFixture> {
        let proof_fixture = compact_vss_restricted_proof_fixture()?;
        let coefficient_commitment_set =
            compact_vss_single_source_coefficient_commitment_set(&proof_fixture)?;
        let recipient_share_commitment_set =
            compact_vss_single_source_recipient_share_commitment_set(&proof_fixture)?;
        let aggregate_threshold_commitment_set =
            compact_vss_single_recipient_aggregate_threshold_commitment_set(&proof_fixture)?;
        let share_linkage_statement = compact_vss_single_source_share_linkage_statement(
            &coefficient_commitment_set,
            &recipient_share_commitment_set,
            &aggregate_threshold_commitment_set,
        )?;
        let source_statement = &share_linkage_statement["sourceStatementRecords"][0];
        let proof_material_set = compact_vss_verified_share_linkage_proof_material_set(
            &share_linkage_statement,
            source_statement,
            &proof_fixture,
        )?;

        Ok(CompactVssVerifiedProofMaterialFixture {
            setup_package: json!({
                "compactVssCoefficientCommitmentSet": coefficient_commitment_set,
                "compactVssRecipientShareCommitmentSet": recipient_share_commitment_set,
                "compactVssAggregateThresholdCommitmentSet": aggregate_threshold_commitment_set,
                "compactVssShareLinkageStatement": share_linkage_statement,
                "compactVssShareLinkageProofMaterialSet": proof_material_set,
            }),
            restricted_proof_statements: vec![json!({
                "proofStatementHash": proof_fixture.proof_statement_hash,
                "context": proof_fixture.context,
                "ringDegree": proof_fixture.ring_degree,
                "compactVssShareLinkage": proof_fixture.compact_share_linkage_statement,
            })],
        })
    }

    struct CompactVssRestrictedProofFixture {
        ring_degree: usize,
        rns_prime: u64,
        coefficient_commitments: Vec<Value>,
        coefficient_commitment_roots: Vec<String>,
        recipient_share_commitment: Value,
        recipient_share_commitment_root: String,
        aggregate_threshold_commitment: Value,
        aggregate_threshold_commitment_root: String,
        context: Value,
        compact_share_linkage_statement: Value,
        proof_statement_hash: String,
        proof_bytes_hex: String,
    }

    fn compact_vss_restricted_proof_fixture() -> CanonicalResult<CompactVssRestrictedProofFixture> {
        let ring_degree = 128_usize;
        let rns_prime = DATA_PRIMES[0];
        let threshold_degree = 3_usize;
        let public_matrix_seed_hash = compact_vss_verified_public_matrix_seed_hash();
        let coefficient_messages_by_shamir_index =
            compact_vss_verified_coefficient_messages(threshold_degree, ring_degree, rns_prime);
        let coefficient_opening_randomness_by_shamir_index = (0..threshold_degree)
            .map(|shamir_coefficient_index| {
                compact_vss_verified_ternary_randomness(
                    ring_degree,
                    10 + shamir_coefficient_index as i64,
                )
            })
            .collect::<Vec<_>>();
        let recipient_share_opening_randomness =
            compact_vss_verified_ternary_randomness(ring_degree, 41);

        let mut recipient_share_messages = Vec::with_capacity(ring_degree);
        let mut carry_witnesses = Vec::with_capacity(ring_degree);
        for coefficient_index in 0..ring_degree {
            let lifted_share = coefficient_messages_by_shamir_index
                .iter()
                .fold(0_u128, |sum, messages| {
                    sum + u128::from(messages[coefficient_index])
                });
            recipient_share_messages.push((lifted_share % u128::from(rns_prime)) as u64);
            carry_witnesses.push((lifted_share / u128::from(rns_prime)) as i64);
        }

        let mut coefficient_commitments = Vec::with_capacity(threshold_degree);
        let mut coefficient_commitment_roots = Vec::with_capacity(threshold_degree);
        for shamir_coefficient_index in 0..threshold_degree {
            let computation = compact_vss_verified_commitment(
                "coefficient",
                json!({
                    "objectType": "CompactVssAcceptedSetupProofCoefficientContext",
                    "objectVersion": 1,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                }),
                &public_matrix_seed_hash,
                rns_prime,
                ring_degree,
                &coefficient_messages_by_shamir_index[shamir_coefficient_index],
                &coefficient_opening_randomness_by_shamir_index[shamir_coefficient_index],
            )?;
            coefficient_commitments.push(computation.commitment);
            coefficient_commitment_roots.push(computation.commitment_root);
        }

        let recipient_computation = compact_vss_verified_commitment(
            "recipient-share",
            json!({
                "objectType": "CompactVssAcceptedSetupProofRecipientShareContext",
                "objectVersion": 1,
                "recipientRosterPosition": 0,
            }),
            &public_matrix_seed_hash,
            rns_prime,
            ring_degree,
            &recipient_share_messages,
            &recipient_share_opening_randomness,
        )?;
        let aggregate_computation = compact_vss_verified_commitment(
            "aggregate-threshold-share",
            json!({
                "objectType": "CompactVssAcceptedSetupProofAggregateThresholdContext",
                "objectVersion": 1,
                "recipientRosterPosition": 0,
            }),
            &public_matrix_seed_hash,
            rns_prime,
            ring_degree,
            &recipient_share_messages,
            &recipient_share_opening_randomness,
        )?;

        let source_coefficient_commitment_root =
            compact_vss_verified_source_coefficient_commitment_root(
                &coefficient_commitments,
                &coefficient_commitment_roots,
                rns_prime,
            )?;
        let source_recipient_share_commitment_root =
            compact_vss_verified_source_recipient_share_commitment_root(
                &recipient_computation.commitment,
                &recipient_computation.commitment_root,
                rns_prime,
            )?;
        let context = json!({
            "ceremonyId": "compact-vss-accepted-proof-test",
            "manifestHash": compact_vss_verified_hash("11"),
            "rosterHash": compact_vss_verified_hash("22"),
            "trusteeIdentity": "source-0",
            "trusteeRosterPosition": 0,
            "setupEpoch": "setup-epoch",
            "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
            "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
        });
        let compact_share_linkage_statement = json!({
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "recipientIdentity": "recipient-0",
            "recipientRosterPosition": 0,
            "sourceCoefficientCommitmentRoot": source_coefficient_commitment_root,
            "sourceRecipientShareCommitmentRoot": source_recipient_share_commitment_root,
            "sourceRnsLimbIndex": 0,
            "sourceMessageModulus": rns_prime,
            "coefficientCommitmentRoots": coefficient_commitment_roots,
            "coefficientCommitments": coefficient_commitments,
            "recipientShareCommitmentRoot": recipient_computation.commitment_root,
            "recipientShareCommitment": recipient_computation.commitment,
        });
        let generation_request = json!({
            "context": context,
            "ringDegree": ring_degree,
            "compactVssShareLinkage": compact_share_linkage_statement,
            "coefficientMessagesByShamirIndex": coefficient_messages_by_shamir_index
                .iter()
                .map(|messages| {
                    messages
                        .iter()
                        .map(|message| i64::try_from(*message).expect("message fits i64"))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
            "recipientShareMessages": recipient_share_messages
                .iter()
                .map(|message| i64::try_from(*message).expect("recipient share fits i64"))
                .collect::<Vec<_>>(),
            "coefficientOpeningRandomnessByShamirIndex": coefficient_opening_randomness_by_shamir_index,
            "recipientShareOpeningRandomness": recipient_share_opening_randomness,
            "carryWitnesses": carry_witnesses,
            "proofRandomnessSource": "development-deterministic-fixture",
            "proofRandomnessSeedHex": "ab".repeat(64),
            "proofRandomnessNonceHex": "cd".repeat(64),
        });
        let generation =
            generate_compact_vss_share_linkage_proof_from_request(&generation_request)?;

        Ok(CompactVssRestrictedProofFixture {
            ring_degree,
            rns_prime,
            coefficient_commitments:
                generation_request["compactVssShareLinkage"]["coefficientCommitments"]
                    .as_array()
                    .expect("coefficient commitments")
                    .clone(),
            coefficient_commitment_roots:
                generation_request["compactVssShareLinkage"]["coefficientCommitmentRoots"]
                    .as_array()
                    .expect("coefficient roots")
                    .iter()
                    .map(|entry| entry.as_str().expect("coefficient root").to_string())
                    .collect(),
            recipient_share_commitment:
                generation_request["compactVssShareLinkage"]["recipientShareCommitment"].clone(),
            recipient_share_commitment_root:
                generation_request["compactVssShareLinkage"]["recipientShareCommitmentRoot"]
                    .as_str()
                    .expect("recipient share root")
                    .to_string(),
            aggregate_threshold_commitment: aggregate_computation.commitment,
            aggregate_threshold_commitment_root: aggregate_computation.commitment_root,
            context: generation_request["context"].clone(),
            compact_share_linkage_statement: generation_request["compactVssShareLinkage"].clone(),
            proof_statement_hash: generation["statementHash"]
                .as_str()
                .expect("generated statement hash")
                .to_string(),
            proof_bytes_hex: generation["proofBytesHex"]
                .as_str()
                .expect("generated proof bytes")
                .to_string(),
        })
    }

    fn compact_vss_verified_source_coefficient_commitment_root(
        coefficient_commitments: &[Value],
        coefficient_commitment_roots: &[String],
        rns_prime: u64,
    ) -> CanonicalResult<String> {
        let coefficient_records = coefficient_commitments
            .iter()
            .enumerate()
            .map(|(shamir_coefficient_index, commitment)| {
                json!({
                    "objectType": "CompactVssCoefficientCommitment",
                    "objectVersion": 1,
                    "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
                    "developmentScope": "development-only-not-certified-for-production-use",
                    "sourceTrusteeIdentity": "source-0",
                    "sourceTrusteeRosterPosition": 0,
                    "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
                    "rnsLimbIndex": 0,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "coefficientCommitmentRoot": coefficient_commitment_roots[shamir_coefficient_index],
                    "coefficientVectorHash512": commitment["messageVectorHash512"].clone(),
                    "commitment": commitment.clone(),
                })
            })
            .collect::<Vec<_>>();
        let source_record = json!({
            "objectType": "CompactVssSourceCoefficientCommitments",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "coefficientCommitments": coefficient_records,
        });

        derive_protocol_hash("VssCoefficientCommitmentRoot", &source_record)
    }

    fn compact_vss_verified_source_recipient_share_commitment_root(
        recipient_share_commitment: &Value,
        recipient_share_commitment_root: &str,
        rns_prime: u64,
    ) -> CanonicalResult<String> {
        let recipient_share_record = json!({
            "objectType": "CompactVssRecipientShareCommitment",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "recipientIdentity": "recipient-0",
            "recipientRosterPosition": 0,
            "recipientTrusteePoint": 1,
            "rnsLimbIndex": 0,
            "rnsPrime": rns_prime,
            "shareCommitmentRoot": recipient_share_commitment_root,
            "shareOpeningRoot": derive_protocol_hash(
                "SetupCommitmentRoot",
                &json!({
                    "fixture": "compact-vss-accepted-proof-recipient-opening",
                }),
            )?,
            "shareVectorHash512": recipient_share_commitment["messageVectorHash512"].clone(),
            "commitment": recipient_share_commitment.clone(),
        });
        let source_record = json!({
            "objectType": "CompactVssSourceRecipientShareCommitments",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "recipientShareCommitments": [recipient_share_record],
        });

        derive_protocol_hash("ThresholdShareCommitmentRoot", &source_record)
    }

    fn compact_vss_single_source_coefficient_commitment_set(
        fixture: &CompactVssRestrictedProofFixture,
    ) -> CanonicalResult<Value> {
        let coefficient_commitments = fixture
            .coefficient_commitments
            .iter()
            .enumerate()
            .map(|(shamir_coefficient_index, commitment)| {
                json!({
                    "objectType": "CompactVssCoefficientCommitment",
                    "objectVersion": 1,
                    "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
                    "developmentScope": "development-only-not-certified-for-production-use",
                    "sourceTrusteeIdentity": "source-0",
                    "sourceTrusteeRosterPosition": 0,
                    "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
                    "rnsLimbIndex": 0,
                    "rnsPrime": fixture.rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "coefficientCommitmentRoot": fixture.coefficient_commitment_roots[shamir_coefficient_index],
                    "coefficientVectorHash512": commitment["messageVectorHash512"].clone(),
                    "commitment": commitment.clone(),
                })
            })
            .collect::<Vec<_>>();
        let mut source_record = json!({
            "objectType": "CompactVssSourceCoefficientCommitments",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "coefficientCommitments": coefficient_commitments,
        });
        source_record["sourceCoefficientCommitmentRoot"] = json!(derive_protocol_hash(
            "VssCoefficientCommitmentRoot",
            &source_record,
        )?);
        let mut coefficient_set = json!({
            "objectType": "CompactVssCoefficientCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "participantCount": 1,
            "rnsLimbCount": 1,
            "thresholdDegree": fixture.coefficient_commitments.len(),
            "ringDegree": fixture.ring_degree,
            "sourceTrusteeRecords": [source_record],
        });
        coefficient_set["coefficientCommitmentRoot"] = json!(derive_protocol_hash(
            "VssCoefficientCommitmentRoot",
            &coefficient_set,
        )?);

        Ok(coefficient_set)
    }

    fn compact_vss_single_source_recipient_share_commitment_set(
        fixture: &CompactVssRestrictedProofFixture,
    ) -> CanonicalResult<Value> {
        let recipient_share_record = json!({
            "objectType": "CompactVssRecipientShareCommitment",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "recipientIdentity": "recipient-0",
            "recipientRosterPosition": 0,
            "recipientTrusteePoint": 1,
            "rnsLimbIndex": 0,
            "rnsPrime": fixture.rns_prime,
            "shareCommitmentRoot": fixture.recipient_share_commitment_root,
            "shareOpeningRoot": derive_protocol_hash(
                "SetupCommitmentRoot",
                &json!({
                    "fixture": "compact-vss-accepted-proof-recipient-opening",
                }),
            )?,
            "shareVectorHash512": fixture.recipient_share_commitment["messageVectorHash512"].clone(),
            "commitment": fixture.recipient_share_commitment.clone(),
        });
        let mut source_record = json!({
            "objectType": "CompactVssSourceRecipientShareCommitments",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "recipientShareCommitments": [recipient_share_record],
        });
        source_record["sourceRecipientShareCommitmentRoot"] = json!(derive_protocol_hash(
            "ThresholdShareCommitmentRoot",
            &source_record,
        )?);
        let mut recipient_set = json!({
            "objectType": "CompactVssRecipientShareCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "participantCount": 1,
            "rnsLimbCount": 1,
            "ringDegree": fixture.ring_degree,
            "sourceTrusteeRecords": [source_record],
        });
        recipient_set["recipientShareCommitmentRoot"] = json!(derive_protocol_hash(
            "ThresholdShareCommitmentRoot",
            &recipient_set,
        )?);

        Ok(recipient_set)
    }

    fn compact_vss_single_recipient_aggregate_threshold_commitment_set(
        fixture: &CompactVssRestrictedProofFixture,
    ) -> CanonicalResult<Value> {
        let aggregate_record = json!({
            "objectType": "CompactVssAggregateThresholdCommitment",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "recipientIdentity": "recipient-0",
            "recipientRosterPosition": 0,
            "recipientTrusteePoint": 1,
            "rnsLimbIndex": 0,
            "rnsPrime": fixture.rns_prime,
            "aggregateCommitmentRoot": fixture.aggregate_threshold_commitment_root,
            "aggregateOpeningRoot": derive_protocol_hash(
                "SetupCommitmentRoot",
                &json!({
                    "fixture": "compact-vss-accepted-proof-aggregate-opening",
                }),
            )?,
            "commitment": fixture.aggregate_threshold_commitment.clone(),
            "sourceShareCommitmentRoots": [fixture.recipient_share_commitment_root],
        });
        let mut aggregate_set = json!({
            "objectType": "CompactVssAggregateThresholdCommitmentSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "participantCount": 1,
            "rnsLimbCount": 1,
            "ringDegree": fixture.ring_degree,
            "recipientRecords": [aggregate_record],
        });
        aggregate_set["aggregateThresholdCommitmentRoot"] = json!(derive_protocol_hash(
            "ThresholdShareCommitmentRoot",
            &aggregate_set,
        )?);

        Ok(aggregate_set)
    }

    fn compact_vss_single_source_share_linkage_statement(
        coefficient_set: &Value,
        recipient_set: &Value,
        aggregate_set: &Value,
    ) -> CanonicalResult<Value> {
        let source_statement_without_root = json!({
            "objectType": "CompactVssShareLinkageSourceStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "ceremonyId": "compact-vss-accepted-proof-test",
            "manifestHash": compact_vss_verified_hash("11"),
            "rosterHash": compact_vss_verified_hash("22"),
            "setupProfileHash": compact_vss_verified_hash("33"),
            "qShareHash": compact_vss_verified_hash("44"),
            "carryAwareVssShareRelationProfileHash": compact_vss_verified_hash("55"),
            "commitmentProfileHash": compact_vss_verified_hash("66"),
            "setupEpoch": "setup-epoch",
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "targetBasisHash": compact_vss_verified_hash("88"),
            "sourceTrusteeIdentity": "source-0",
            "sourceTrusteeRosterPosition": 0,
            "participantCount": 1,
            "targetRnsLimbCount": 1,
            "thresholdDegree": 3,
            "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
            "sourceCoefficientCommitmentRoot": coefficient_set["sourceTrusteeRecords"][0]["sourceCoefficientCommitmentRoot"].clone(),
            "sourceRecipientShareCommitmentRoot": recipient_set["sourceTrusteeRecords"][0]["sourceRecipientShareCommitmentRoot"].clone(),
            "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
            "relation": "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments",
            "proofBatchingRule": "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source",
            "shamirEvaluationRule": "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point",
            "aggregateThresholdRule": "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb",
            "commonKeyRule": "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile",
            "recipientApprovalBoundary": "recipient signatures or acknowledgements are not accepted as evidence for an invalid public recipient-share commitment",
            "proofBoundary": "statement binding only; zero-knowledge linkage proof backend is not implemented yet",
        });
        let mut source_statement = source_statement_without_root;
        source_statement["sourceStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &source_statement,
        )?);
        let statement_without_root = json!({
            "objectType": "CompactVssShareLinkageStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "ceremonyId": "compact-vss-accepted-proof-test",
            "manifestHash": compact_vss_verified_hash("11"),
            "rosterHash": compact_vss_verified_hash("22"),
            "setupProfileHash": compact_vss_verified_hash("33"),
            "qShareHash": compact_vss_verified_hash("44"),
            "carryAwareVssShareRelationProfileHash": compact_vss_verified_hash("55"),
            "commitmentProfileHash": compact_vss_verified_hash("66"),
            "setupEpoch": "setup-epoch",
            "publicMatrixSeedHash": compact_vss_verified_public_matrix_seed_hash(),
            "targetBasisHash": compact_vss_verified_hash("88"),
            "participantCount": 1,
            "targetRnsLimbCount": 1,
            "thresholdDegree": 3,
            "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"].clone(),
            "recipientShareCommitmentRoot": recipient_set["recipientShareCommitmentRoot"].clone(),
            "aggregateThresholdCommitmentRoot": aggregate_set["aggregateThresholdCommitmentRoot"].clone(),
            "relation": "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments",
            "proofBatchingRule": "one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source",
            "shamirEvaluationRule": "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point",
            "aggregateThresholdRule": "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb",
            "commonKeyRule": "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile",
            "recipientApprovalBoundary": "recipient signatures or acknowledgements are not accepted as evidence for an invalid public recipient-share commitment",
            "proofBoundary": "statement binding only; zero-knowledge linkage proof backend is not implemented yet",
            "sourceStatementRecords": [source_statement],
        });
        let mut statement = statement_without_root;
        statement["statementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement,
        )?);

        Ok(statement)
    }

    fn compact_vss_verified_share_linkage_proof_material_set(
        statement: &Value,
        source_statement: &Value,
        proof_fixture: &CompactVssRestrictedProofFixture,
    ) -> CanonicalResult<Value> {
        let proof_bytes = crate::transcript_core::decode_hex(&proof_fixture.proof_bytes_hex)?;
        let proof_record_without_root = json!({
            "objectType": "CompactVssShareLinkageProofRecord",
            "objectVersion": 1,
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "sourceStatementRoot": source_statement["sourceStatementRoot"].clone(),
            "proofStatementHash": proof_fixture.proof_statement_hash,
            "proofByteLength": proof_bytes.len(),
            "proofBytesHash": hash512_hex(
                "sealed-lattice-compact-vss-share-linkage-proof-bytes-v1",
                &[&proof_bytes],
            ),
            "proofBytesHex": proof_fixture.proof_bytes_hex,
        });
        let mut proof_record = proof_record_without_root;
        proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_record,
        )?);
        let proof_material_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "ceremonyId": statement["ceremonyId"].clone(),
            "manifestHash": statement["manifestHash"].clone(),
            "rosterHash": statement["rosterHash"].clone(),
            "setupProfileHash": statement["setupProfileHash"].clone(),
            "qShareHash": statement["qShareHash"].clone(),
            "carryAwareVssShareRelationProfileHash": statement["carryAwareVssShareRelationProfileHash"].clone(),
            "commitmentProfileHash": statement["commitmentProfileHash"].clone(),
            "setupEpoch": statement["setupEpoch"].clone(),
            "sourceTrusteeIdentity": source_statement["sourceTrusteeIdentity"].clone(),
            "sourceTrusteeRosterPosition": source_statement["sourceTrusteeRosterPosition"].clone(),
            "shareLinkageStatementRoot": statement["statementRoot"].clone(),
            "sourceStatementRoot": source_statement["sourceStatementRoot"].clone(),
            "proofRecords": [proof_record],
        });
        let mut proof_material = proof_material_without_root;
        proof_material["proofMaterialRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material,
        )?);
        let proof_material_set_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "ceremonyId": statement["ceremonyId"].clone(),
            "manifestHash": statement["manifestHash"].clone(),
            "rosterHash": statement["rosterHash"].clone(),
            "setupProfileHash": statement["setupProfileHash"].clone(),
            "qShareHash": statement["qShareHash"].clone(),
            "carryAwareVssShareRelationProfileHash": statement["carryAwareVssShareRelationProfileHash"].clone(),
            "commitmentProfileHash": statement["commitmentProfileHash"].clone(),
            "setupEpoch": statement["setupEpoch"].clone(),
            "participantCount": statement["participantCount"].clone(),
            "shareLinkageStatementRoot": statement["statementRoot"].clone(),
            "proofMaterials": [proof_material],
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material_set,
        )?);

        Ok(proof_material_set)
    }

    fn compact_vss_verified_commitment(
        commitment_role: &str,
        commitment_context: Value,
        public_matrix_seed_hash: &str,
        rns_prime: u64,
        ring_degree: usize,
        message_coefficients: &[u64],
        randomness_by_column: &[Vec<i64>],
    ) -> CanonicalResult<crate::bgv::setup::compact_vss_commitment::CompactVssCommitmentComputation>
    {
        compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
            commitment_role,
            commitment_context: &commitment_context,
            public_matrix_seed_hash,
            rns_limb_index: 0,
            rns_prime,
            ring_degree,
            message_coefficients,
            message_coefficient_bound: rns_prime,
            randomness_by_column,
        })
    }

    fn compact_vss_verified_coefficient_messages(
        threshold_degree: usize,
        ring_degree: usize,
        modulus: u64,
    ) -> Vec<Vec<u64>> {
        (0..threshold_degree)
            .map(|shamir_coefficient_index| {
                (0..ring_degree)
                    .map(|coefficient_index| {
                        if coefficient_index % 11 == shamir_coefficient_index {
                            modulus - 4 - shamir_coefficient_index as u64
                        } else {
                            (17 + 19 * shamir_coefficient_index as u64
                                + 23 * coefficient_index as u64)
                                % modulus
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn compact_vss_verified_ternary_randomness(
        ring_degree: usize,
        seed_offset: i64,
    ) -> Vec<Vec<i64>> {
        (0..2_usize)
            .map(|column_index| {
                (0..ring_degree)
                    .map(|coefficient_index| {
                        ((seed_offset + column_index as i64 * 5 + coefficient_index as i64 * 7)
                            .rem_euclid(3))
                            - 1
                    })
                    .collect()
            })
            .collect()
    }

    fn compact_vss_verified_public_matrix_seed_hash() -> String {
        compact_vss_verified_hash("77")
    }

    fn compact_vss_verified_hash(byte_pair: &str) -> String {
        byte_pair.repeat(64)
    }

    fn compact_vss_share_linkage_proof_material_set(statement: &Value) -> CanonicalResult<Value> {
        let source_statements =
            statement["sourceStatementRecords"]
                .as_array()
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        "compact VSS fixture source statements must be an array",
                    )
                })?;
        let proof_materials = source_statements
            .iter()
            .map(|source_statement| {
                compact_vss_share_linkage_proof_material(statement, source_statement)
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let proof_material_set_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "ceremonyId": statement["ceremonyId"].clone(),
            "manifestHash": statement["manifestHash"].clone(),
            "rosterHash": statement["rosterHash"].clone(),
            "setupProfileHash": statement["setupProfileHash"].clone(),
            "qShareHash": statement["qShareHash"].clone(),
            "carryAwareVssShareRelationProfileHash": statement["carryAwareVssShareRelationProfileHash"].clone(),
            "commitmentProfileHash": statement["commitmentProfileHash"].clone(),
            "setupEpoch": statement["setupEpoch"].clone(),
            "participantCount": statement["participantCount"].clone(),
            "shareLinkageStatementRoot": statement["statementRoot"].clone(),
            "proofMaterials": proof_materials,
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material_set,
        )?);

        Ok(proof_material_set)
    }

    fn compact_vss_share_linkage_proof_material(
        statement: &Value,
        source_statement: &Value,
    ) -> CanonicalResult<Value> {
        let proof_records = [compact_vss_share_linkage_proof_record(source_statement)?];
        let proof_material_without_root = json!({
            "objectType": "CompactVssShareLinkageProofMaterial",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "ceremonyId": statement["ceremonyId"].clone(),
            "manifestHash": statement["manifestHash"].clone(),
            "rosterHash": statement["rosterHash"].clone(),
            "setupProfileHash": statement["setupProfileHash"].clone(),
            "qShareHash": statement["qShareHash"].clone(),
            "carryAwareVssShareRelationProfileHash": statement["carryAwareVssShareRelationProfileHash"].clone(),
            "commitmentProfileHash": statement["commitmentProfileHash"].clone(),
            "setupEpoch": statement["setupEpoch"].clone(),
            "sourceTrusteeIdentity": source_statement["sourceTrusteeIdentity"].clone(),
            "sourceTrusteeRosterPosition": source_statement["sourceTrusteeRosterPosition"].clone(),
            "shareLinkageStatementRoot": statement["statementRoot"].clone(),
            "sourceStatementRoot": source_statement["sourceStatementRoot"].clone(),
            "proofRecords": proof_records,
        });
        let mut proof_material = proof_material_without_root;
        proof_material["proofMaterialRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material,
        )?);

        Ok(proof_material)
    }

    fn compact_vss_share_linkage_proof_record(source_statement: &Value) -> CanonicalResult<Value> {
        let source_statement_root = source_statement["sourceStatementRoot"]
            .as_str()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS source statement root must be a string",
                )
            })?;
        let source_position_digit = source_statement["sourceTrusteeRosterPosition"]
            .as_u64()
            .map(|position| format!("{:x}", (position + 1) % 16))
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS source statement roster position must be an unsigned integer",
                )
            })?;
        let proof_statement_hash = source_position_digit.repeat(128);
        let proof_bytes = [1_u8, 2_u8, 3_u8, 5_u8, 8_u8];
        let proof_bytes_hex = crate::transcript_core::encode_hex(&proof_bytes);
        let proof_bytes_hash = crate::hashing::hash512_hex(
            "sealed-lattice-compact-vss-share-linkage-proof-bytes-v1",
            &[&proof_bytes],
        );
        let proof_record_without_root = json!({
            "objectType": "CompactVssShareLinkageProofRecord",
            "objectVersion": 1,
            "proofFamily": "compact-vss-share-linkage",
            "proofBoundary": "restricted native compact share-linkage proof over ternary opening randomness; not a target-ready compact proof backend",
            "sourceStatementRoot": source_statement_root,
            "proofStatementHash": proof_statement_hash,
            "proofByteLength": proof_bytes.len(),
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": proof_bytes_hex,
        });
        let mut proof_record = proof_record_without_root;
        proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_record,
        )?);

        Ok(proof_record)
    }
}
