use std::sync::OnceLock;

mod aggregation_and_evaluator;
mod command_report;
mod proof_transport;
mod relation_proof_checks;
mod request_validation;

use serde_json::json;

use crate::hashing::derive_protocol_hash;

use super::*;

const DIRECT_BALLOT_TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";

struct DirectBallotRelationProofFixture {
    setup_package: Value,
    evaluator_key: DevelopmentBgvKey,
    encrypted_ballot: DirectEncryptedBallot,
    proof_generation: DirectBallotRelationProofGeneration,
}

fn direct_ballot_relation_proof_fixture() -> &'static DirectBallotRelationProofFixture {
    static FIXTURE: OnceLock<DirectBallotRelationProofFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let setup_package = setup_package();
        let evaluator_key = development_evaluator_key_from_passive_setup_package(
            &setup_package,
            DIRECT_BALLOT_TEST_SETUP_SEED,
        )
        .expect("evaluator key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &evaluator_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        DirectBallotRelationProofFixture {
            setup_package,
            evaluator_key,
            encrypted_ballot,
            proof_generation,
        }
    })
}

fn direct_ballot_test_proof_mask_randomness(ballot_count: usize) -> Value {
    json!({
        "source": DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE,
        "ballotProofRandomnessHexes": (0..ballot_count)
            .map(|index| direct_ballot_test_randomness_hex("ballot-proof", index))
            .collect::<Vec<_>>()
    })
}

fn direct_ballot_test_ballot_encryption_randomness(ballot_count: usize) -> Value {
    json!({
        "source": DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE,
        "encryptionSeedHexes": (0..ballot_count)
            .map(|index| direct_ballot_test_randomness_hex("ballot-encryption", index))
            .collect::<Vec<_>>()
    })
}

fn direct_ballot_test_ballot_json(voter_identity: &str, ballot_index: usize) -> Value {
    json!({
        "voterIdentity": voter_identity,
        "actionContextHash": derive_protocol_hash(
            "ActionContextHash",
            &json!({
                "action": "direct encrypted ballot randomness rejection test",
                "ballotIndex": ballot_index
            }),
        ).expect("action hash"),
        "scores": [
            10, 9, 8, 7, 6,
            5, 4, 3, 2, 1,
            1, 2, 3, 4, 5,
            6, 7, 8, 9, 10
        ]
    })
}

fn direct_ballot_test_randomness_hex(label: &str, index: usize) -> String {
    let randomness_hex = hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/test-randomness-v1",
        &[
            DIRECT_BALLOT_TEST_SETUP_SEED.as_bytes(),
            label.as_bytes(),
            index.to_string().as_bytes(),
        ],
    );
    randomness_hex[..DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_HEX_BYTES * 2].to_string()
}

fn valid_ballot_input() -> DirectBallotInput {
    DirectBallotInput {
        voter_identity: "voter-validation".to_string(),
        action_context_hash: "a".repeat(128),
        scores: vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        one_hot_witnesses: None,
        encryption_seed_hex: direct_ballot_test_randomness_hex("ballot-encryption", 0),
    }
}

fn one_hot_witnesses_for_scores(scores: &[u64]) -> Vec<Vec<u64>> {
    scores
        .iter()
        .map(|score| {
            let mut row = vec![0_u64; 10];
            row[usize::try_from(score - 1).expect("score index fits usize")] = 1;
            row
        })
        .collect()
}

fn direct_ballot_relation_response_offset(proof_bytes: &[u8]) -> usize {
    proof_bytes.len() - super::relation_proof::direct_ballot_relation_response_bytes()
}

fn direct_ballot_relation_commitment_offset(proof_bytes: &[u8]) -> usize {
    direct_ballot_relation_response_offset(proof_bytes)
        - super::relation_proof::direct_ballot_relation_commitment_bytes()
}

fn direct_ballot_response_coefficient_bytes() -> usize {
    super::relation_proof::direct_ballot_relation_response_bytes()
        / (4 * POLYNOMIAL_DEGREE
            + super::relation_proof::direct_ballot_relation_response_scalar_count())
}

fn direct_ballot_score_response_offset(proof_bytes: &[u8]) -> usize {
    direct_ballot_relation_response_offset(proof_bytes)
        + 4 * POLYNOMIAL_DEGREE * direct_ballot_response_coefficient_bytes()
}

fn setup_package() -> Value {
    static SETUP_PACKAGE: OnceLock<Value> = OnceLock::new();
    SETUP_PACKAGE
        .get_or_init(|| setup_package_with_seed(DIRECT_BALLOT_TEST_SETUP_SEED))
        .clone()
}

fn setup_package_not_reached() -> Value {
    json!({})
}

fn setup_package_with_seed(setup_seed: &str) -> Value {
    crate::bgv::commands::generate_bgv_passive_setup_from_request(&json!({
        "ceremonyId": "direct-encrypted-ballot-test-ceremony",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &json!({ "manifest": "direct encrypted ballot test" }),
        ).expect("manifest hash"),
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &json!({ "roster": "direct encrypted ballot test" }),
        ).expect("roster hash"),
        "thresholdParametersHash": derive_protocol_hash(
            "ThresholdParametersHash",
            &json!({ "threshold": "direct encrypted ballot test" }),
        ).expect("threshold hash"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 0 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
        ],
        "setupSeed": setup_seed
    }))
    .expect("setup package")
}
