use std::sync::OnceLock;

mod aggregation_and_evaluator;
mod command_report;
mod proof_transport;
mod relation_proof_checks;
mod request_validation;

use serde_json::json;

use crate::bgv::{
    coefficient_codec::{coefficient_vector_hash512, coefficient_vector_le_hex},
    setup::derive_collective_bgv_setup_public_derivations_from_request,
};
use crate::hashing::derive_protocol_hash;

use super::*;

const DIRECT_BALLOT_TEST_SETUP_SEED: &str = "direct-encrypted-ballot-test-setup-seed";
const PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN: &str =
    "sealed-lattice-bgv-rns/public-key-share-coefficient-vector-v1";

struct DirectBallotRelationProofFixture {
    setup_package: Value,
    public_key: BgvPublicKey,
    encrypted_ballot: DirectEncryptedBallot,
    proof_generation: DirectBallotRelationProofGeneration,
}

struct AcceptedDirectBallotPublicMaterialFixture {
    accepted_public_key_material: Value,
    accepted_setup_handoff: Value,
    public_key: BgvPublicKey,
}

struct DirectBallotAcceptedPackageFixture {
    accepted_public_key_material: Value,
    accepted_setup_handoff: Value,
    public_key: BgvPublicKey,
    encrypted_ballot: DirectEncryptedBallot,
    proof_generation: DirectBallotRelationProofGeneration,
}

fn direct_ballot_relation_proof_fixture() -> &'static DirectBallotRelationProofFixture {
    static FIXTURE: OnceLock<DirectBallotRelationProofFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let setup_package = setup_package();
        let public_key =
            public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
        let encrypted_ballot =
            encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
                .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &setup_package,
            &public_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        DirectBallotRelationProofFixture {
            setup_package,
            public_key,
            encrypted_ballot,
            proof_generation,
        }
    })
}

fn accepted_direct_ballot_public_material_fixture(
    setup_public_material: &Value,
) -> AcceptedDirectBallotPublicMaterialFixture {
    let mut accepted_public_key_material =
        accepted_public_key_material_for_setup_public_material(setup_public_material);
    let accepted_setup_handoff =
        accepted_setup_handoff_for_accepted_public_key_material(&accepted_public_key_material);
    accepted_public_key_material["acceptedSetupHandoffRoot"] = json!(
        required_string_field(&accepted_setup_handoff, "acceptedSetupHandoffRoot")
            .expect("accepted setup handoff root")
    );
    let public_key =
        public_bgv_key_from_accepted_setup_public_key_material(&accepted_public_key_material)
            .expect("accepted public key");

    AcceptedDirectBallotPublicMaterialFixture {
        accepted_public_key_material,
        accepted_setup_handoff,
        public_key,
    }
}

fn direct_ballot_accepted_package_fixture() -> &'static DirectBallotAcceptedPackageFixture {
    static FIXTURE: OnceLock<DirectBallotAcceptedPackageFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let setup_package = setup_package();
        let public_material_fixture =
            accepted_direct_ballot_public_material_fixture(&setup_package);
        let encrypted_ballot = encrypt_direct_ballot(
            &public_material_fixture.accepted_public_key_material,
            &public_material_fixture.public_key,
            valid_ballot_input(),
        )
        .expect("encrypted ballot");
        let proof_randomness_seed_hex =
            direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
        let proof_generation = generate_direct_ballot_relation_proof(
            &public_material_fixture.accepted_public_key_material,
            &public_material_fixture.public_key,
            &encrypted_ballot,
            &proof_randomness_seed_hex,
        )
        .expect("proof generation");

        DirectBallotAcceptedPackageFixture {
            accepted_public_key_material: public_material_fixture.accepted_public_key_material,
            accepted_setup_handoff: public_material_fixture.accepted_setup_handoff,
            public_key: public_material_fixture.public_key,
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
        "voterRosterPosition": ballot_index,
        "actionContextHash": derive_protocol_hash(
            "ActionContextHash",
            &json!({
                "action": "direct encrypted ballot randomness rejection test",
                "ballotIndex": ballot_index
            }),
        ).expect("action hash"),
        "recoveryEpoch": 0,
        "deviceEpoch": 0,
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

fn direct_ballot_test_hash(label: &str) -> String {
    hash512_hex(
        "sealed-lattice/direct-encrypted-ballot/setup-handoff-test-root-v1",
        &[DIRECT_BALLOT_TEST_SETUP_SEED.as_bytes(), label.as_bytes()],
    )
}

fn accepted_public_key_material_for_setup_public_material(setup_public_material: &Value) -> Value {
    let setup_inputs = setup_public_material
        .get("setupInputs")
        .expect("setup inputs");
    let passive_public_key = public_bgv_key_from_passive_setup_package(setup_public_material)
        .expect("passive public key");
    let (public_b, _public_a) = passive_public_key.public_key_components();
    let public_matrix_seed_hash = direct_ballot_test_hash("accepted public matrix seed hash");
    let public_derivations = derive_collective_bgv_setup_public_derivations_from_request(&json!({
        "publicMatrixSeedHash": public_matrix_seed_hash,
    }))
    .expect("public derivations");
    let public_key_share_material_set_root =
        direct_ballot_test_hash("public key share material set root");
    let public_key_share_succinct_proof_set_root =
        direct_ballot_test_hash("public key share succinct proof set root");
    let aggregate_limbs = public_b
        .iter()
        .enumerate()
        .map(|(rns_limb_index, coefficients)| {
            json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "component": "b",
                "coefficientByteLength": POLYNOMIAL_DEGREE * 8,
                "coefficientVectorHash512": coefficient_vector_hash512(
                    coefficients,
                    PUBLIC_KEY_SHARE_COEFFICIENT_VECTOR_HASH_DOMAIN,
                ),
                "coefficientsLeHex": coefficient_vector_le_hex(coefficients),
            })
        })
        .collect::<Vec<_>>();
    let mut collective_public_key = json!({
        "objectType": "CollectivePublicKey",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": "public-key-share",
        "proofVerificationStatus": "succinct-public-key-share-argument-verified-with-accepted-proof-accounting",
        "proofModelStatus": "succinct-public-key-share-argument-accounting-accepted",
        "aggregationStatus": "succinct-proof-aggregated-with-accepted-setup-proof-accounting",
        "materialEncoding": "embedded-full-collective-public-key-coefficients",
        "ceremonyId": required_string_field(setup_inputs, "ceremonyId").expect("ceremony id"),
        "manifestHash": required_string_field(setup_inputs, "manifestHash").expect("manifest hash"),
        "rosterHash": required_string_field(setup_inputs, "rosterHash").expect("roster hash"),
        "setupProfileHash": profile_hash().expect("profile hash"),
        "qShareHash": direct_ballot_test_hash("q share hash"),
        "carryAwareVssShareRelationProfileHash": direct_ballot_test_hash(
            "carry-aware VSS share relation profile hash",
        ),
        "commitmentProfileHash": direct_ballot_test_hash("commitment profile hash"),
        "setupEpoch": "direct-ballot-test-setup-epoch",
        "participantCount": 10,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": POLYNOMIAL_DEGREE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_derivations["crpRoots"]["publicKeyCrpRoot"],
        "publicAPolynomialRoot": public_derivations["bgvPublicA"]["publicPolynomialRoot"],
        "sameSecretConsistencyRoot": direct_ballot_test_hash("same secret consistency root"),
        "sameSecretProofSetRoot": direct_ballot_test_hash("same secret proof set root"),
        "sameSecretProofFamilyBindingRoot": direct_ballot_test_hash(
            "same secret proof family binding root",
        ),
        "publicKeyShareSetRoot": direct_ballot_test_hash("public key share set root"),
        "publicKeyShareProofSetRoot": direct_ballot_test_hash("public key share proof set root"),
        "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
        "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root,
        "sourceShareMaterialRoots": [],
        "aggregateCoefficientVectorsByLimb": aggregate_limbs,
    });
    collective_public_key["collectivePublicKeyRoot"] = json!(
        derive_protocol_hash("CollectivePublicKeyRoot", &collective_public_key)
            .expect("collective public key root")
    );

    let mut accepted_public_key_material = json!({
        "objectType": DIRECT_BALLOT_ACCEPTED_PUBLIC_KEY_MATERIAL_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": required_string_field(setup_inputs, "ceremonyId").expect("ceremony id"),
        "manifestHash": required_string_field(setup_inputs, "manifestHash").expect("manifest hash"),
        "rosterHash": required_string_field(setup_inputs, "rosterHash").expect("roster hash"),
        "thresholdProfileHash": required_string_field(setup_inputs, "thresholdProfileHash")
            .expect("threshold profile hash"),
        "setupProfileHash": profile_hash().expect("profile hash"),
        "qShareHash": direct_ballot_test_hash("q share hash"),
        "commitmentProfileHash": direct_ballot_test_hash("commitment profile hash"),
        "setupEpoch": "direct-ballot-test-setup-epoch",
        "setupPackageHash": required_string_field(setup_public_material, "setupPackageHash")
            .expect("setup package hash"),
        "bgvProfileHash": profile_hash().expect("profile hash"),
        "batchEncoderHash": batch_encoder_hash().expect("batch encoder hash"),
        "batchLayoutBindingHash": batch_layout_binding_hash()
            .expect("batch layout binding hash"),
        "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()
            .expect("ballot score encoding profile hash"),
        "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()
            .expect("encrypted ballot layout hash"),
        "directBallotReservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()
            .expect("direct ballot reserved slot rule hash"),
        "directBallotEncoderMatrixRoot": direct_ballot_encoder_matrix_root()
            .expect("direct ballot encoder matrix root"),
        "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()
            .expect("direct ballot arithmetic certificate hash"),
        "ballotValidityProofProfileHash": direct_ballot_relation_proof_profile_hash()
            .expect("direct ballot relation proof profile hash"),
        "collectivePublicKeyRoot": collective_public_key["collectivePublicKeyRoot"],
        "publicKeyShareMaterialSetRoot": public_key_share_material_set_root,
        "publicKeyShareSuccinctProofSetRoot": public_key_share_succinct_proof_set_root,
        "commonRandomness": {
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicDerivations": public_derivations,
        },
        "collectivePublicKey": collective_public_key,
    });
    accepted_public_key_material["bgvPublicKeyRoot"] = json!(
        accepted_direct_ballot_bgv_public_key_root(&accepted_public_key_material)
            .expect("BGV public key root")
    );

    accepted_public_key_material
}

fn accepted_setup_handoff_for_accepted_public_key_material(
    accepted_public_key_material: &Value,
) -> Value {
    let direct_ballot_creation_policy =
        direct_ballot_creation_policy_value().expect("direct ballot creation policy");
    let direct_ballot_creation_policy_hash =
        direct_ballot_creation_policy_hash().expect("direct ballot creation policy hash");

    let mut handoff = json!({
        "objectType": "CollectiveBgvAcceptedSetupHandoff",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": required_string_field(accepted_public_key_material, "ceremonyId")
            .expect("ceremony id"),
        "manifestHash": required_string_field(accepted_public_key_material, "manifestHash")
            .expect("manifest hash"),
        "rosterHash": required_string_field(accepted_public_key_material, "rosterHash")
            .expect("roster hash"),
        "thresholdProfileHash": required_string_field(
            accepted_public_key_material,
            "thresholdProfileHash",
        ).expect("threshold profile hash"),
        "setupProfileHash": required_string_field(
            accepted_public_key_material,
            "setupProfileHash",
        ).expect("setup profile hash"),
        "qShareHash": required_string_field(accepted_public_key_material, "qShareHash")
            .expect("Q share hash"),
        "commitmentProfileHash": required_string_field(
            accepted_public_key_material,
            "commitmentProfileHash",
        ).expect("commitment profile hash"),
        "setupEpoch": required_string_field(accepted_public_key_material, "setupEpoch")
            .expect("setup epoch"),
        "setupPackageHash": required_string_field(accepted_public_key_material, "setupPackageHash")
            .expect("setup package hash"),
        "directBallotEncryptionHandoff": {
            "status": "accepted-collective-public-key-root-bound-for-direct-ballot-encryption",
            "collectivePublicKeyRoot": required_string_field(
                accepted_public_key_material,
                "collectivePublicKeyRoot",
            ).expect("collective public key root"),
            "bgvPublicKeyRoot": required_string_field(
                accepted_public_key_material,
                "bgvPublicKeyRoot",
            ).expect("BGV public key root"),
            "bgvProfileHash": profile_hash().expect("profile hash"),
            "canonicalCiphertextConventionHash": canonical_ciphertext_convention_hash()
                .expect("canonical ciphertext convention hash"),
            "batchEncoderHash": batch_encoder_hash().expect("batch encoder hash"),
            "batchLayoutBindingHash": batch_layout_binding_hash()
                .expect("batch layout binding hash"),
            "ballotScoreEncodingProfileHash": ballot_score_encoding_profile_hash()
                .expect("ballot score encoding profile hash"),
            "encryptedBallotLayoutHash": encrypted_ballot_layout_hash()
                .expect("encrypted ballot layout hash"),
            "directBallotReservedSlotRuleHash": direct_ballot_reserved_slot_rule_hash()
                .expect("direct ballot reserved slot rule hash"),
            "directBallotEncoderMatrixRoot": direct_ballot_encoder_matrix_root()
                .expect("direct ballot encoder matrix root"),
            "witnessPartitionProfileHash": direct_ballot_witness_partition_profile_hash()
                .expect("direct ballot witness partition profile hash"),
            "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()
                .expect("direct ballot arithmetic certificate hash"),
            "ballotValidityProofProfileHash": direct_ballot_relation_proof_profile_hash()
                .expect("direct ballot relation proof profile hash"),
            "publicKeyShareMaterialSetRoot": required_string_field(
                accepted_public_key_material,
                "publicKeyShareMaterialSetRoot",
            ).expect("public key share material set root"),
            "publicKeyShareSuccinctProofSetRoot": required_string_field(
                accepted_public_key_material,
                "publicKeyShareSuccinctProofSetRoot",
            ).expect("public key share succinct proof set root"),
            "acceptedPublicKeyMaterial": {
                "materialSource": "accepted public-key share material with accepted public-key share proofs",
                "collectivePublicKeyRoot": required_string_field(
                    accepted_public_key_material,
                    "collectivePublicKeyRoot",
                ).expect("collective public key root"),
                "bgvPublicKeyRoot": required_string_field(
                    accepted_public_key_material,
                    "bgvPublicKeyRoot",
                ).expect("BGV public key root"),
                "publicKeyShareMaterialSetRoot": required_string_field(
                    accepted_public_key_material,
                    "publicKeyShareMaterialSetRoot",
                ).expect("public key share material set root"),
                "publicKeyShareSuccinctProofSetRoot": required_string_field(
                    accepted_public_key_material,
                    "publicKeyShareSuccinctProofSetRoot",
                ).expect("public key share succinct proof set root"),
            },
            "supportedBallotCreationPolicy": direct_ballot_creation_policy,
            "supportedBallotCreationPolicyHash": direct_ballot_creation_policy_hash,
        },
        "publicAggregationHandoff": {
            "status": "accepted-public-ciphertext-aggregation-bound-to-setup-context-and-collective-public-key-root",
            "thresholdShareCommitmentRoot": direct_ballot_test_hash("threshold share commitment root"),
        },
        "boundedEvaluatorReplayHandoff": {
            "status": "accepted-public-evaluation-keys-bound-to-frozen-evaluator-schedule",
            "evaluatorKeyScheduleRoot": direct_ballot_test_hash("evaluator key schedule root"),
            "relinearizationKeyShareRoundsRoot": direct_ballot_test_hash("relinearization key share rounds root"),
            "trusteeEvaluationKeyProofSetRoot": direct_ballot_test_hash("trustee evaluation key proof set root"),
            "evaluationKeySetHash": direct_ballot_test_hash("evaluation key set hash"),
        },
        "futureTargetDecryptionHandoff": {
            "status": "target decryption remains downstream",
            "targetDecryptionProfileId": crate::bgv::setup::TARGET_DECRYPTION_PROFILE_ID,
            "claimBoundary": "target decryption remains downstream and any target-decryption readiness claim is refused until Q_target, smudging, C1-C4, and decryption-share proof closure exist",
        },
        "certificateRoots": {
            "setupCommitmentSecurityCertificateHash": direct_ballot_test_hash("setup commitment security certificate hash"),
            "setupTransportCertificateHash": direct_ballot_test_hash("setup transport certificate hash"),
            "setupProofAccountingCertificateHash": direct_ballot_test_hash("setup proof accounting certificate hash"),
            "setupKeyCorrectnessCertificateHash": direct_ballot_test_hash("setup key correctness certificate hash"),
            "activeStaticSetupTheoremCertificateHash": direct_ballot_test_hash("active static setup theorem certificate hash"),
            "heSecurityCertificateHash": direct_ballot_test_hash("HE security certificate hash"),
        },
    });
    let accepted_setup_handoff_root =
        derive_protocol_hash("AcceptedSetupHandoffRoot", &handoff).expect("handoff root");
    handoff["acceptedSetupHandoffRoot"] = json!(accepted_setup_handoff_root);

    handoff
}

fn rebind_accepted_setup_handoff_root(accepted_setup_handoff: &mut Value) {
    accepted_setup_handoff
        .as_object_mut()
        .expect("accepted setup handoff is an object")
        .remove("acceptedSetupHandoffRoot");
    let accepted_setup_handoff_root =
        derive_protocol_hash("AcceptedSetupHandoffRoot", accepted_setup_handoff)
            .expect("handoff root");
    accepted_setup_handoff["acceptedSetupHandoffRoot"] = json!(accepted_setup_handoff_root);
}

fn valid_ballot_input() -> DirectBallotInput {
    DirectBallotInput {
        voter_identity: "voter-validation".to_string(),
        voter_roster_position: 0,
        action_context_hash: "a".repeat(128),
        recovery_epoch: 0,
        device_epoch: 0,
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

fn direct_ballot_relation_response_offset(_proof_bytes: &[u8]) -> usize {
    direct_ballot_relation_commitment_offset(_proof_bytes)
        + super::relation_proof::direct_ballot_relation_commitment_bytes()
}

fn direct_ballot_relation_commitment_offset(_proof_bytes: &[u8]) -> usize {
    8 + 64 + 24
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

fn direct_ballot_projected_bgv_no_wrap_response_offset(proof_bytes: &[u8]) -> usize {
    direct_ballot_score_response_offset(proof_bytes)
        + (DIRECT_BALLOT_OPTION_COUNT
            + DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT)
            * direct_ballot_response_coefficient_bytes()
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
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
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
