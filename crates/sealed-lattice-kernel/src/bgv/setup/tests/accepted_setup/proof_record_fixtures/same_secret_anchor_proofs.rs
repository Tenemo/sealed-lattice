use super::super::*;
use super::*;
use rayon::prelude::*;

use crate::hashing::derive_canonical_object_hash;

pub(in super::super) fn same_secret_proofs_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = package["sameSecretConsistency"]["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let participant_count = participant_count_from_package(package);
    let proof_records = (0..participant_count)
        .into_par_iter()
        .map(|trustee_roster_position| {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let statement_record = &statement_records[trustee_roster_position as usize];
        let constant_commitments =
            same_secret_constant_commitments_from_fixture_package(package, trustee_roster_position);
        let ring_degree = constant_commitments
            .first()
            .expect("constant commitment")
            .ring_degree;
        let statement = crate::bgv::setup::trustee_evaluation_key_proof::TrusteeEvaluationKeyStatement {
            context: crate::bgv::setup::trustee_evaluation_key_proof::SuccinctSetupProofContext {
                proof_family:
                    crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY
                        .to_string(),
                ceremony_id: setup_context["ceremonyId"]
                    .as_str()
                    .expect("ceremony id")
                    .to_string(),
                manifest_hash: setup_context["manifestHash"]
                    .as_str()
                    .expect("manifest hash")
                    .to_string(),
                roster_hash: setup_context["rosterHash"]
                    .as_str()
                    .expect("roster hash")
                    .to_string(),
                trustee_identity: trustee_identity.clone(),
                trustee_roster_position,
                setup_epoch: setup_context["setupEpoch"]
                    .as_str()
                    .expect("setup epoch")
                    .to_string(),
                binding_roots: vec![(
                    "vssCoefficientCommitmentMaterialRoot".to_string(),
                    package["vssCoefficientCommitmentMaterial"]
                        ["vssCoefficientCommitmentMaterialRoot"]
                        .as_str()
                        .expect("vss material root")
                        .to_string(),
                )],
            },
            ring_degree,
            keys: Vec::new(),
            vss_share_linkage: None,
        same_secret_bridge: None,
        same_secret_linkage: Some(
                crate::bgv::setup::trustee_evaluation_key_proof::SameSecretLinkageStatement {
                    public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
                    commitments: constant_commitments,
                },
            ),
            private_vss_share: None,
            target_decryption_share: None,
        };
        let witness = TrusteeEvaluationKeyWitness {
            secret_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    accepted_vss_secret_coefficient_fixture(
                        trustee_roster_position,
                        coefficient_position,
                    )
                })
                .collect(),
            error_coefficients_by_key: Vec::new(),
            negative_indicator_coefficients: (0..ring_degree)
                .map(|coefficient_position| {
                    i64::from(
                        accepted_vss_secret_coefficient_fixture(
                            trustee_roster_position,
                            coefficient_position,
                        ) < 0,
                    )
                })
                .collect(),
            opening_randomness_by_limb: (0..DATA_PRIMES.len())
                .map(|rns_limb_index| {
                    accepted_vss_randomness_fixture(
                        trustee_roster_position,
                        rns_limb_index,
                        0,
                        ring_degree,
                    )
                    .into_iter()
                    .map(|column| {
                        column
                            .into_iter()
                            .map(|value| {
                                i64::try_from(value).expect("ternary randomness fits i64")
                            })
                            .collect()
                    })
                    .collect()
                })
                .collect(),
            private_vss_coefficient_messages_by_shamir_index: Vec::new(),
            private_vss_opening_randomness_by_shamir_index: Vec::new(),
            private_vss_carry_witnesses: Vec::new(),
            vss_public_coefficient_messages_by_shamir_index: Vec::new(),
            vss_public_recipient_share_messages: Vec::new(),
            vss_public_coefficient_opening_randomness_by_shamir_index: Vec::new(),
            vss_public_recipient_share_opening_randomness: Vec::new(),
            vss_public_carry_witnesses: Vec::new(),
            vss_public_recipient_share_messages_by_item: Vec::new(),
            vss_public_recipient_share_opening_randomness_by_item: Vec::new(),
            vss_public_carry_witnesses_by_item: Vec::new(),
            target_decryption_message_vectors: Vec::new(),
            target_decryption_opening_randomness_by_commitment: Vec::new(),
        };
        let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "SameSecretProofRoot",
            "fixture": "same-secret-internal-proof-randomness",
            "trusteeRosterPosition": trustee_roster_position,
        }))
        .expect("same-secret proof randomness seed");
        let statement_hash_hex = to_hex(&statement.statement_hash());
        let proof_bytes = checkpointed_anchor_proof_bytes(
            SAME_SECRET_ANCHOR_PROOF_CHECKPOINT_DIRECTORY,
            &statement_hash_hex,
            || {
                let proof =
                    prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex)
                        .expect("same-secret anchor proof");
                encode_trustee_evaluation_key_proof(&proof)
            },
        );
        let proof_bytes_hash =
            crate::bgv::setup::trustee_evaluation_key_proof::same_secret_anchor_proof_bytes_hash(
                &proof_bytes,
            );
        let mut proof_record = serde_json::json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "proofFamily":
                crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "setupParametersHash": setup_context["setupParametersHash"],
            "setupEpoch": setup_context["setupEpoch"],
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "ringDegree": ring_degree,
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
            "statementHash": statement_hash_hex,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": to_hex(&proof_bytes),
        });
        proof_record["sameSecretProofRoot"] = serde_json::json!(
            derive_canonical_object_hash(&proof_record)
                .expect("same-secret proof root")
        );
        final_package_phase(&format!(
            "generated same-secret proof trustee {trustee_roster_position}"
        ));

        proof_record
        })
        .collect::<Vec<_>>();
    let mut proof_set = serde_json::json!({
        "objectType": "SameSecretProofSet",
        "objectVersion": 1,
        "proofFamily":
            crate::bgv::setup::trustee_evaluation_key_proof::SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "vssCoefficientCommitmentMaterialRoot": package["vssCoefficientCommitmentMaterial"]["vssCoefficientCommitmentMaterialRoot"],
        "proofRecords": proof_records,
    });
    proof_set["sameSecretProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_set).expect("same-secret proof set root")
    );

    proof_set
}

pub(in super::super) fn same_secret_constant_commitments_from_fixture_package(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<crate::bgv::setup::commitment::SetupCommitmentValue> {
    let material_set = &package["vssCoefficientCommitmentMaterial"];
    let Some(material_records) = material_set
        .get("coefficientCommitments")
        .and_then(serde_json::Value::as_array)
    else {
        return same_secret_constant_commitments_from_deterministic_fixture(
            package,
            trustee_roster_position,
        );
    };
    let mut commitments_by_limb = BTreeMap::new();
    for material_record in material_records {
        if material_record["sourceTrusteeRosterPosition"].as_u64() != Some(trustee_roster_position)
            || material_record["shamirCoefficientIndex"].as_u64() != Some(0)
        {
            continue;
        }
        let rns_limb_index = material_record["rnsLimbIndex"]
            .as_u64()
            .expect("RNS limb index");
        let commitment = crate::bgv::setup::commitment::parse_setup_commitment_full_value(
            &material_record["commitment"],
        )
        .expect("constant commitment value");
        assert!(
            commitments_by_limb
                .insert(rns_limb_index, commitment)
                .is_none(),
            "duplicate constant commitment limb"
        );
    }
    (0..DATA_PRIMES.len() as u64)
        .map(|rns_limb_index| {
            commitments_by_limb
                .remove(&rns_limb_index)
                .expect("constant commitment limb")
        })
        .collect()
}

fn same_secret_constant_commitments_from_deterministic_fixture(
    package: &serde_json::Value,
    trustee_roster_position: u64,
) -> Vec<crate::bgv::setup::commitment::SetupCommitmentValue> {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    // These fixtures take their ring degree from the public coefficient
    // commitment set. The deterministic reconstruction is material-independent:
    // commitments come from accepted_vss_coefficient_message_fixture.
    let ring_degree = package["vssCoefficientCommitmentMaterial"]["ringDegree"]
        .as_u64()
        .or_else(|| package["vssPublicCoefficientCommitmentSet"]["ringDegree"].as_u64())
        .expect("VSS material or public coefficient ring degree") as usize;
    DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .map(|(rns_limb_index, rns_prime)| {
            let coefficient_message = accepted_vss_coefficient_message_fixture(
                trustee_roster_position,
                rns_limb_index,
                0,
                rns_prime,
                ring_degree,
            );
            let coefficient_message_wide = coefficient_message
                .iter()
                .map(|coefficient| u128::from(*coefficient))
                .collect::<Vec<_>>();
            let randomness_by_column = accepted_vss_randomness_fixture(
                trustee_roster_position,
                rns_limb_index,
                0,
                ring_degree,
            );
            compute_setup_commitment_for_tests(
                public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                0,
                &coefficient_message_wide,
                &randomness_by_column,
                ring_degree,
            )
            .expect("deterministic setup commitment")
        })
        .collect()
}
