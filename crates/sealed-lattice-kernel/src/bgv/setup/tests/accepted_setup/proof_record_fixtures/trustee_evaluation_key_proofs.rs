use super::super::*;
use super::*;
use rayon::prelude::*;

use super::vss_public_material::vss_public_coefficient_randomness_i64_fixture;

use crate::bgv::setup::accepted_setup::{
    TrusteeEvaluationKeyStatementInputs, accepted_key_switch_decomposition_hash,
    trustee_evaluation_key_statement_from_package,
    verified_same_secret_bridge_material_from_package,
};
use crate::bgv::setup::evaluation_key_share_material::EvaluationKeyShareProofFamily;
use crate::bgv::setup::trustee_evaluation_key_proof::prove_evaluation_key_share;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    EvaluationKeyShareKind, TRUSTEE_EVALUATION_KEY_PROOF_FAMILY, TrusteeEvaluationKeyStatement,
    TrusteeEvaluationKeyWitness, encode_trustee_evaluation_key_proof,
    trustee_evaluation_key_proof_bytes_hash,
};
use crate::hashing::{derive_canonical_object_hash, to_hex};

// Builds the trustee evaluation-key succinct proof set, one proof per trustee
// covering the whole scheduled relinearization and Galois key material, bound to
// the compact same-secret bridge. Each statement is rebuilt through the same
// `trustee_evaluation_key_statement_from_package` the accepted-setup verifier
// calls, so a proof verifies against the exact records, aggregates, and compact
// bridge the verifier reconstructs. Proof bytes are embedded (the accepted-setup
// verifier accepts `proofBytesHex`), and every root is a canonical object hash.
pub(in super::super) fn trustee_evaluation_key_proofs_object(
    package: &serde_json::Value,
    round_one_aggregate_diagonals_by_level: &BTreeMap<u64, Vec<Vec<u64>>>,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let schedule = &package["evaluatorKeySchedule"];
    let same_secret_proofs = package["sameSecretProofs"]["proofRecords"]
        .as_array()
        .expect("same-secret proof records");
    // The compact bridge material the verifier reconstructs; the compact package
    // embeds it so an empty transport request reconstructs it.
    let verified_same_secret_bridge = package.get("sameSecretBridgeStatementSet").map(|_| {
        verified_same_secret_bridge_material_from_package(package, &serde_json::json!({}))
            .expect("compact same-secret bridge material")
    });
    assert!(
        verified_same_secret_bridge.is_some(),
        "the trustee evaluation-key fixture is the compact-bridge-bound terminal path"
    );
    let ring_degree = package["sameSecretBridgeStatementSet"]["ringDegree"]
        .as_u64()
        .expect("compact bridge ring degree") as usize;

    let per_trustee_records = same_secret_proofs
        .par_iter()
        .map(|proof_record| {
            let trustee_roster_position = proof_record["trusteeRosterPosition"]
                .as_u64()
                .expect("trustee roster position");
            let trustee_identity = proof_record["trusteeIdentity"]
                .as_str()
                .expect("trustee identity");
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
            let proof_bytes = checkpointed_anchor_proof_bytes(
                TRUSTEE_EVALUATION_KEY_ANCHOR_PROOF_CHECKPOINT_DIRECTORY,
                &statement_hash_hex,
                || {
                    let proof = prove_evaluation_key_share(
                        &statement,
                        &witness,
                        &proof_randomness_seed_hex,
                    )
                    .expect("trustee evaluation-key succinct proof");
                    encode_trustee_evaluation_key_proof(&proof)
                },
            );
            let proof_bytes_hash = trustee_evaluation_key_proof_bytes_hash(&proof_bytes);
            let mut record = serde_json::json!({
                "objectType": "TrusteeEvaluationKeyProof",
                "objectVersion": 1,
                "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
                "ceremonyId": setup_context["ceremonyId"],
                "manifestHash": setup_context["manifestHash"],
                "rosterHash": setup_context["rosterHash"],
                "setupParametersHash": setup_context["setupParametersHash"],
                "setupEpoch": setup_context["setupEpoch"],
                "trusteeIdentity": trustee_identity,
                "trusteeRosterPosition": trustee_roster_position,
                "sameSecretStatementRoot": proof_record["sameSecretStatementRoot"],
                "trusteeSecretCommitmentRoot": proof_record["trusteeSecretCommitmentRoot"],
                "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                "statementHash": statement_hash_hex,
                "keyCount": statement.keys.len(),
                "proofSizeBytes": proof_bytes.len(),
                "proofBytesHash": proof_bytes_hash,
                "proofBytesHex": to_hex(&proof_bytes),
            });
            record["trusteeEvaluationKeyProofRoot"] = serde_json::json!(
                derive_canonical_object_hash(&record).expect("trustee evaluation-key proof root")
            );
            final_package_phase(&format!(
                "generated trustee evaluation-key proof trustee {trustee_roster_position}"
            ));

            (trustee_roster_position, record)
        })
        .collect::<Vec<_>>();
    let mut ordered_records = per_trustee_records;
    ordered_records.sort_by_key(|(trustee_roster_position, _)| *trustee_roster_position);
    let proof_records = ordered_records
        .into_iter()
        .map(|(_, record)| record)
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
        "objectVersion": 1,
        "proofFamily": TRUSTEE_EVALUATION_KEY_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "participantCount": participant_count_from_package(package),
        "rnsLimbCount": DATA_PRIMES.len(),
        "evaluatorKeyScheduleRoot": schedule["evaluatorKeyScheduleRoot"],
        "requiredGaloisSetHash": schedule["requiredGaloisSetHash"],
        "keySwitchDecompositionHash": accepted_key_switch_decomposition_hash()
            .expect("key-switch decomposition hash"),
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
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

    proof_set
}

// The deterministic fixture witness for one trustee's batched statement: the
// shared VSS secret, per-key fixture errors in statement order, and the compact
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
    // On the compact bridge path the openings cover one column set per bound
    // target-basis limb, using the same deterministic coefficient randomness the
    // compact coefficient commitments were built with.
    let opening_randomness_by_limb = statement
        .same_secret_bridge
        .as_ref()
        .map(|bridge| {
            (0..bridge.target_rns_primes.len())
                .map(|target_rns_limb_index| {
                    vss_public_coefficient_randomness_i64_fixture(
                        trustee_roster_position,
                        target_rns_limb_index,
                        0,
                        ring_degree,
                    )
                })
                .collect::<Vec<_>>()
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
    }
}
