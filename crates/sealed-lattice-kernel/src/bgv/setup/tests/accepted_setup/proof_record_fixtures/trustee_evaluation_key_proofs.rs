use super::super::*;
use super::*;
use rayon::prelude::*;

use crate::bgv::setup::accepted_setup::{
    TrusteeEvaluationKeyStatementInputs, accepted_key_switch_decomposition_hash,
    trustee_evaluation_key_statement_from_package,
    verified_same_secret_bridge_material_from_package,
};
use crate::bgv::setup::evaluation_key_share_material::EvaluationKeyShareProofFamily;
use crate::bgv::setup::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    setup_proof_material_transport_hashes,
};
use crate::bgv::setup::trustee_evaluation_key_proof::prove_trustee_evaluation_key_proof_bytes;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, TRUSTEE_EVALUATION_KEY_PROOF_FAMILY, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, trustee_evaluation_key_proof_bytes_hash,
};
use crate::hashing::{derive_canonical_object_hash, to_hex};

pub(in super::super) struct TrusteeEvaluationKeyProofFixture {
    pub(in super::super) proof_set: serde_json::Value,
    pub(in super::super) transported_proof_material: serde_json::Value,
}

pub(in super::super) fn trustee_evaluation_key_proof_material_root_from_fixture_record(
    proof_record: &serde_json::Value,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofMaterialReference",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "trusteeIdentity": proof_record["trusteeIdentity"],
        "trusteeRosterPosition": proof_record["trusteeRosterPosition"],
        "statementHash": proof_record["statementHash"],
        "proofBytesHash": proof_record["proofBytesHash"],
    }))
    .expect("trustee evaluation-key proof material root")
}

// Builds the trustee evaluation-key succinct proof set, one proof per trustee
// covering the whole scheduled relinearization and Galois key material, bound to
// the same-secret bridge. Each statement is rebuilt through the same
// `trustee_evaluation_key_statement_from_package` the accepted-setup verifier
// calls, so a proof verifies against the exact records, aggregates, and bridge
// the verifier reconstructs. Generated proof bytes are retained in the same
// authenticated material store used by the production generator; package
// records and the verification request carry only canonical material references.
fn trustee_proof_batch_size(value: Option<&str>, proof_count: usize) -> Result<usize, String> {
    match value {
        None => Ok(proof_count.max(1)),
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|batch_size| *batch_size > 0)
            .ok_or_else(|| {
                "SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE must be a positive integer".to_string()
            }),
    }
}

pub(in super::super) fn trustee_evaluation_key_proofs_object(
    package: &serde_json::Value,
    round_one_aggregate_diagonals_by_level: &BTreeMap<u64, Vec<Vec<u64>>>,
) -> TrusteeEvaluationKeyProofFixture {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let participant_count = participant_count_from_package(package);
    let trustee_roster_positions = (0..participant_count).collect::<Vec<_>>();
    // The bridge material the verifier reconstructs; the package embeds it so an
    // empty transport request reconstructs it.
    let verified_same_secret_bridge = package.get("sameSecretBridgeStatementSet").map(|_| {
        verified_same_secret_bridge_material_from_package(package, &serde_json::json!({}))
            .expect("same-secret bridge material")
    });
    assert!(
        verified_same_secret_bridge.is_some(),
        "the trustee evaluation-key fixture is the same-secret-bridge-bound terminal path"
    );
    let ring_degree = package["sameSecretBridgeStatementSet"]["ringDegree"]
        .as_u64()
        .expect("same-secret bridge ring degree") as usize;

    let batch_size = trustee_proof_batch_size(
        std::env::var("SEALED_LATTICE_TRUSTEE_PROOF_BATCH_SIZE")
            .ok()
            .as_deref(),
        trustee_roster_positions.len(),
    )
    .expect("valid trustee proof batch size");
    let mut per_trustee_records = Vec::with_capacity(trustee_roster_positions.len());
    for proof_batch in trustee_roster_positions.chunks(batch_size) {
        let mut batch_records = proof_batch
            .par_iter()
            .map(|trustee_roster_position| {
                let trustee_roster_position = *trustee_roster_position;
                let trustee_identity = format!("trustee-{trustee_roster_position}");
                let statement = trustee_evaluation_key_statement_from_package(
                    &TrusteeEvaluationKeyStatementInputs {
                        setup_package: package,
                        transported_key_switch_component_material: None,
                        verified_same_secret_bridge: verified_same_secret_bridge.as_ref(),
                        round_one_aggregate_diagonals_by_level,
                        trustee_roster_position,
                    },
                )
                .expect("trustee evaluation-key statement");
                let witness = trustee_evaluation_key_witness_for_fixture(
                    trustee_roster_position,
                    ring_degree,
                    &statement,
                );
                let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "TrusteeEvaluationKeyProofRandomness",
                    "fixture": "trustee-evaluation-key-proof-randomness",
                    "trusteeRosterPosition": trustee_roster_position,
                }))
                .expect("trustee proof randomness seed");
                let statement_hash_hex = to_hex(&statement.statement_hash());
                let source_constant_coefficient_commitment_root = statement
                    .context
                    .binding_roots
                    .iter()
                    .find_map(|(field_name, root)| {
                        (field_name == "sourceConstantCoefficientCommitmentRoot")
                            .then_some(root.as_str())
                    })
                    .expect("source constant coefficient commitment root");
                // The checkpoint key carries the schedule container tag plus a
                // prover-revision suffix so stale bytes (same statement hash) never
                // collide across format or prover changes. Bump the revision when
                // the atom prover's transcript changes; slksats4 binds the combined
                // source-constant relation directly.
                let checkpoint_key = format!("{statement_hash_hex}-slksats4");
                let proof_bytes = checkpointed_proof_bytes(
                    TRUSTEE_EVALUATION_KEY_PROOF_CHECKPOINT_DIRECTORY,
                    &checkpoint_key,
                    || {
                        prove_trustee_evaluation_key_proof_bytes(
                            &statement,
                            &witness,
                            &proof_randomness_seed_hex,
                        )
                        .expect("trustee evaluation-key proof bytes")
                    },
                );
                let proof_bytes_hash = trustee_evaluation_key_proof_bytes_hash(&proof_bytes);
                let mut record = serde_json::json!({
                    "objectType": "TrusteeEvaluationKeyProof",
                    "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                    "ceremonyId": setup_context["ceremonyId"],
                    "manifestHash": setup_context["manifestHash"],
                    "rosterHash": setup_context["rosterHash"],
                    "setupParametersHash": setup_context["setupParametersHash"],
                    "setupEpoch": setup_context["setupEpoch"],
                    "trusteeIdentity": trustee_identity.as_str(),
                    "trusteeRosterPosition": trustee_roster_position,
                    "sourceConstantCoefficientCommitmentRoot": source_constant_coefficient_commitment_root,
                    "statementHash": statement_hash_hex,
                    "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
                    "proofBytesHash": proof_bytes_hash,
                });
                let proof_material_root =
                    trustee_evaluation_key_proof_material_root_from_fixture_record(&record);
                let transport_hashes = setup_proof_material_transport_hashes(
                    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                    &proof_bytes,
                    SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
                )
                .expect("trustee evaluation-key proof transport hashes");
                crate::bgv::setup::retain_generated_canonical_proof_material(
                    TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                    proof_material_root.clone(),
                    proof_bytes,
                )
                .expect("retain trustee evaluation-key proof material");
                record["proofMaterialRoot"] = serde_json::json!(proof_material_root);
                record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
                    derive_canonical_object_hash(&record)
                        .expect("trustee evaluation-key proof root")
                );
                let transported_proof_material = serde_json::json!({
                    "objectType": "SetupTransportedEvaluationKeyShareProofMaterial",
                    "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                    "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
                    "proofMaterialRoot": proof_material_root,
                    "proofChunkCount": transport_hashes.chunk_hashes.len(),
                    "proofTotalByteLength": transport_hashes.total_byte_length,
                    "proofFullObjectHash": transport_hashes.full_object_hash,
                    "proofChunkRoot": transport_hashes.chunk_root,
                    "proofChunkHashes": transport_hashes.chunk_hashes,
                });
                final_package_phase(&format!(
                    "generated trustee evaluation-key proof trustee {trustee_roster_position}"
                ));

                (
                    trustee_roster_position,
                    record,
                    transported_proof_material,
                )
            })
            .collect::<Vec<_>>();
        per_trustee_records.append(&mut batch_records);
    }
    let mut ordered_records = per_trustee_records;
    ordered_records.sort_by_key(|(trustee_roster_position, _, _)| *trustee_roster_position);
    let proof_records = ordered_records
        .iter()
        .map(|(_, record, _)| record.clone())
        .collect::<Vec<_>>();
    let transported_proof_materials = ordered_records
        .into_iter()
        .map(|(_, _, transported_proof_material)| transported_proof_material)
        .collect::<Vec<_>>();

    let mut galois_batches = package["galoisKeyShareBatches"]
        .as_array()
        .expect("Galois key share batches")
        .iter()
        .collect::<Vec<_>>();
    galois_batches.sort_by_key(|batch| {
        batch["trusteeRosterPosition"]
            .as_u64()
            .expect("trustee roster position")
    });
    let galois_key_share_batch_roots = galois_batches
        .iter()
        .map(|batch| {
            serde_json::json!({
                "trusteeIdentity": batch["trusteeIdentity"],
                "trusteeRosterPosition": batch["trusteeRosterPosition"],
                "galoisKeyShareBatchRoot": batch["galoisKeyShareBatchRoot"],
            })
        })
        .collect::<Vec<_>>();
    let mut proof_set = serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofSet",
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "keySwitchDecompositionHash": accepted_key_switch_decomposition_hash()
            .expect("key-switch decomposition hash"),
        "publicKeyShareSetRoot": package["publicKeyShares"]["publicKeyShareSetRoot"],
        "publicKeyShareSuccinctProofSetRoot": package["publicKeyShareSuccinctProofs"]["publicKeyShareSuccinctProofSetRoot"],
        "relinearizationCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["relinearizationCrpRoot"],
        "galoisKeyCrpRoot": package["commonRandomness"]["publicDerivations"]["crpRoots"]["galoisKeyCrpRoot"],
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "relinearizationKeyShareRoundsRoot": package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"],
        "galoisKeyShareBatchRoots": galois_key_share_batch_roots,
        "proofRecords": proof_records,
    });
    proof_set["trusteeEvaluationKeyProofSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_set).expect("trustee evaluation-key proof set root")
    );

    TrusteeEvaluationKeyProofFixture {
        proof_set,
        transported_proof_material: serde_json::json!({
            "objectType": "SetupTransportedEvaluationKeyShareProofMaterialSet",
            "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
            "proofMaterials": transported_proof_materials,
        }),
    }
}

// The deterministic fixture witness for one trustee's batched statement: the
// shared VSS secret, per-key fixture errors in statement order, and the
// same-secret bridge openings. The public-key-share and target-decryption
// witness fields the DEV prototype carried are absent from the LIVE relation, so
// this witness only populates the key-relation and linkage columns.
pub(in super::super) fn trustee_evaluation_key_witness_for_fixture(
    trustee_roster_position: u64,
    ring_degree: usize,
    statement: &TrusteeEvaluationKeyStatement,
) -> TrusteeEvaluationKeyWitness {
    let secret_coefficients =
        evaluation_key_secret_coefficients_for_fixture(trustee_roster_position, ring_degree);
    let error_coefficients_by_key = statement
        .keys
        .iter()
        .map(|key| {
            let (proof_family, rotation) = match key.kind {
                EvaluationKeyShareKind::RelinearizationRoundOne
                | EvaluationKeyShareKind::RelinearizationRoundTwo => {
                    (EvaluationKeyShareProofFamily::Relinearization, None)
                }
                EvaluationKeyShareKind::GaloisRotation { galois_element } => (
                    EvaluationKeyShareProofFamily::Galois,
                    Some(u64::try_from(galois_element).expect("rotation fits u64")),
                ),
                EvaluationKeyShareKind::PublicKeyShare => {
                    unreachable!(
                        "the evaluation-key witness fixture never carries a public-key share key"
                    );
                }
            };
            (0..=key.level)
                .map(|digit_index| {
                    evaluation_key_error_coefficients_for_fixture(
                        proof_family,
                        trustee_roster_position,
                        key.level,
                        rotation,
                        digit_index,
                        ring_degree,
                    )
                })
                .collect()
        })
        .collect();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect();
    // The atom opens one original BDLOP source constant commitment. Its five
    // ternary randomness columns are the exact opening used to construct the
    // accepted VSS coefficient commitment at source limb zero.
    let opening_randomness_by_limb = statement
        .same_secret_linkage
        .as_ref()
        .map(|_| {
            vec![
                accepted_vss_randomness_fixture(trustee_roster_position, 0, 0, ring_degree)
                    .into_iter()
                    .map(|column| {
                        column
                            .into_iter()
                            .map(|value| i64::try_from(value).expect("ternary randomness fits i64"))
                            .collect()
                    })
                    .collect(),
            ]
        })
        .unwrap_or_default();

    TrusteeEvaluationKeyWitness {
        secret_coefficients,
        error_coefficients_by_key,
        negative_indicator_coefficients,
        opening_randomness_by_limb,
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
        vss_committed_material_seeds_by_bound_message: Vec::new(),
        vss_committed_material_context_hashes_by_bound_message: Vec::new(),
    }
}

#[test]
fn trustee_proof_batch_size_requires_a_positive_integer() {
    assert_eq!(trustee_proof_batch_size(None, 10), Ok(10));
    assert_eq!(trustee_proof_batch_size(Some("3"), 10), Ok(3));
    assert!(trustee_proof_batch_size(Some("0"), 10).is_err());
    assert!(trustee_proof_batch_size(Some("not-a-number"), 10).is_err());
}
