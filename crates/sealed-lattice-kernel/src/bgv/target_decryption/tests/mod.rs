use super::*;
use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    evaluator::records::target_layout_hash,
    evaluator::top_k::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, canonical_target_basis_hash, packed_score_slot,
    },
    modular_arithmetic::{add_mod, inverse_mod, sub_mod},
    setup::{
        accepted_setup_target_decryption_setup_parameters_hash,
        generate_passive_setup_package_from_request,
    },
};
use std::sync::OnceLock;

mod share_generation;

const TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT: u64 = 3;
const TARGET_DECRYPTION_FIXTURE_SETUP_SEED: &str = "target-decryption-setup-seed";
const TARGET_DECRYPTION_FIXTURE_CEREMONY_ID: &str = "target-decryption-ceremony";
const TARGET_DECRYPTION_FIXTURE_SETUP_EPOCH: &str = "setup-epoch-1";
const TARGET_DECRYPTION_FIXTURE_COMPACT_SETUP_EPOCH: &str = "target-decryption-test";

// The three fixture trustees, listed in roster order. Roster position is the
// array index; the Shamir abscissa is roster_position + 1, matching
// read_setup_binding. Both the passive crypto package (which supplies the
// collective secret and encrypts the target ciphertexts) and the accepted
// SetupPackage bind these identities in the same roster order, so the shares
// derived from the crypto key interpolate against the accepted-package roster.
const TARGET_DECRYPTION_FIXTURE_TRUSTEES: [&str; 3] = ["trustee-1", "trustee-2", "trustee-3"];

fn target_decryption_fixture_manifest_hash() -> String {
    derive_canonical_object_hash(
        &json!({ "objectType": "ElectionManifestHash", "manifest": "target-decryption-test" }),
    )
    .expect("manifest hash")
}

fn target_decryption_fixture_roster_hash() -> String {
    derive_canonical_object_hash(
        &json!({ "objectType": "RosterHash", "roster": "target-decryption-test" }),
    )
    .expect("roster hash")
}

fn target_decryption_fixture_public_matrix_seed_hash() -> String {
    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvCommonRandomnessPublicMatrixSeed",
        "seed": "target-decryption-test",
    }))
    .expect("public matrix seed hash")
}

fn target_decryption_fixture_signing_public_key_hash(trustee_identity: &str) -> String {
    derive_canonical_object_hash(&json!({
        "objectType": "MlDsaSigningPublicKey",
        "keyPurpose": "collective-bgv-setup-signing",
        "trusteeIdentity": trustee_identity,
    }))
    .expect("signing public key hash")
}

// The passive development package that supplies the collective secret / evaluator
// key and encrypts the target ciphertexts. It shares the fixture roster and setup
// seed with the accepted SetupPackage but is NEVER fed to the target-decryption
// trust boundary: read_setup_binding refuses it (objectType is not SetupPackage).
// It exists only to carry the secret material the accepted package cannot.
fn passive_crypto_package() -> Value {
    generate_passive_setup_package_from_request(&json!({
        "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
        "manifestHash": target_decryption_fixture_manifest_hash(),
        "rosterHash": target_decryption_fixture_roster_hash(),
        "thresholdParametersHash": derive_canonical_object_hash(
            &json!({ "objectType": "ThresholdParametersHash", "threshold": "target-decryption-test" }),
        ).expect("threshold hash"),
        "participants": TARGET_DECRYPTION_FIXTURE_TRUSTEES
            .iter()
            .enumerate()
            .map(|(roster_position, trustee_identity)| json!({
                "trusteeIdentity": trustee_identity,
                "rosterPosition": roster_position,
                "boardPosition": roster_position,
            }))
            .collect::<Vec<_>>(),
        "setupSeed": TARGET_DECRYPTION_FIXTURE_SETUP_SEED,
    }))
    .expect("passive crypto package")
}

fn target_decryption_evaluator_key() -> DevelopmentBgvKey {
    development_evaluator_key_from_passive_setup_package(
        &passive_crypto_package(),
        TARGET_DECRYPTION_FIXTURE_SETUP_SEED,
    )
    .expect("evaluator key")
}

// Minimal accepted SetupPackage (objectType "SetupPackage") consumed at the
// target-decryption trust boundary. It carries exactly what read_setup_binding
// reads: a five-field setupContext (with participantCount so the roster-derived
// setupParametersHash matches), a phaseTranscript whose setupIntent phase binds
// the fixture roster, commonRandomness.publicMatrixSeedHash, and the injected
// VSS aggregate-threshold commitment set plus share-linkage statement
// root. The commitments are built (see aggregate_threshold_...)
// from the SAME Shamir shares the local witness opens, so the C2 binding in
// share_generation is exercised, not bypassed.
fn accepted_setup_package() -> Value {
    static ACCEPTED_SETUP_PACKAGE_CACHE: OnceLock<Value> = OnceLock::new();
    ACCEPTED_SETUP_PACKAGE_CACHE
        .get_or_init(build_accepted_setup_package)
        .clone()
}

fn accepted_setup_package_base() -> Value {
    let manifest_hash = target_decryption_fixture_manifest_hash();
    let roster_hash = target_decryption_fixture_roster_hash();
    let setup_parameters_hash = accepted_setup_target_decryption_setup_parameters_hash(
        TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT,
    )
    .expect("roster-derived setup parameters hash");
    let setup_intent_participants = TARGET_DECRYPTION_FIXTURE_TRUSTEES
        .iter()
        .enumerate()
        .map(|(roster_position, trustee_identity)| json!({
            "objectType": "SetupPhaseParticipantObject",
            "objectVersion": 1,
            "phaseId": "setupIntent",
            "phaseNumber": 0,
            "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
            "rosterPosition": roster_position,
            "trusteeIdentity": trustee_identity,
            "signingPublicKeyHash": target_decryption_fixture_signing_public_key_hash(trustee_identity),
        }))
        .collect::<Vec<_>>();

    json!({
        "objectType": "SetupPackage",
        "objectVersion": 1,
        "setupContext": {
            "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": TARGET_DECRYPTION_FIXTURE_SETUP_EPOCH,
            "participantCount": TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT,
        },
        "commonRandomness": {
            "objectType": "CollectiveBgvCommonRandomness",
            "objectVersion": 1,
            "publicMatrixSeedHash": target_decryption_fixture_public_matrix_seed_hash(),
        },
        "phaseTranscript": [
            {
                "objectType": "SetupPhaseRecord",
                "phaseId": "setupIntent",
                "phaseNumber": 0,
                "participantPhaseObjects": setup_intent_participants,
            }
        ],
    })
}

fn build_accepted_setup_package() -> Value {
    let mut accepted_setup_package = accepted_setup_package_base();
    let target_share_profile = target_share_profile(&accepted_setup_package);
    let aggregate_threshold_commitment_set =
        aggregate_threshold_commitment_set(&accepted_setup_package, &target_share_profile);
    accepted_setup_package["vssPublicAggregateThresholdCommitmentSet"] =
        aggregate_threshold_commitment_set;
    accepted_setup_package["vssShareLinkageStatement"] = json!({
        "objectType": "VssShareLinkageStatement",
        "objectVersion": 1,
        "statementRoot": "4".repeat(128),
    });

    accepted_setup_package
}

// The target-share profile the reader re-derives (read_target_share_profile). Its
// hash preimage no longer carries a threshold-profile field: the target-decryption
// profile hashes are the kernel-canonical values (level 6, K_top = 20), recomputed
// from the bound BGV parameters, so the profile is independent of the setup
// package. The quorum values match the n = 3 roster-derived threshold (floor(n/3)
// + 1 = 2).
fn target_share_profile(_setup_package: &Value) -> Value {
    let (target_decryption_profile_hash, target_decryption_profile_binding_hash) =
        canonical_target_decryption_parameter_hashes().expect("target decryption profile hashes");
    let profile = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "targetDecryptionProfileHash": target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": target_decryption_profile_binding_hash,
        "decryptionThreshold": 2,
        "minimumSharesForInterpolation": 2,
        "decryptionShareQuorum": 2,
    });
    let mut with_hash = profile;
    with_hash["targetShareProfileHash"] =
        json!(derive_canonical_object_hash(&with_hash).expect("target share profile hash"));
    with_hash
}

fn level_zero_ciphertext(key: &DevelopmentBgvKey, slots: &[u64], seed: &str) -> Ciphertext {
    let coefficients = encode_slots_to_coefficients(slots).expect("encode slots");
    let full = key
        .encrypt_coefficients(&coefficients, seed)
        .expect("encrypt coefficients");
    Ciphertext {
        components: vec![
            vec![full.components[0][0].clone()],
            vec![full.components[1][0].clone()],
        ],
        level: 0,
        decrypt_scaling: 1,
    }
}

fn canonical_target_ciphertext(key: &DevelopmentBgvKey, slots: &[u64], seed: &str) -> Ciphertext {
    let coefficients = encode_slots_to_coefficients(slots).expect("encode slots");
    let full = key
        .encrypt_coefficients(&coefficients, seed)
        .expect("encrypt coefficients");
    Ciphertext {
        components: vec![
            full.components[0][..=CANONICAL_TARGET_CIPHERTEXT_LEVEL].to_vec(),
            full.components[1][..=CANONICAL_TARGET_CIPHERTEXT_LEVEL].to_vec(),
        ],
        level: CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        decrypt_scaling: 1,
    }
}

fn sparse_target_slots(ids: &[u64], orders: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let mut target_ids = vec![0_u64; POLYNOMIAL_DEGREE];
    let mut target_orders = vec![0_u64; POLYNOMIAL_DEGREE];
    for option in 0..MAXIMUM_OPTION_COUNT {
        target_ids[packed_score_slot(option)] = ids[option];
        target_orders[packed_score_slot(option)] = orders[option];
    }
    (target_ids, target_orders)
}

fn accepted_record(target_ciphertext_hash: &str, target_layout_hash: &str) -> Value {
    let (target_decryption_parameters_hash, _) =
        canonical_target_decryption_parameter_hashes().expect("target decryption parameters hash");
    let mut record = json!({
        "objectType": "TargetAcceptedRecord",
        "objectVersion": 1,
        "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
        "electionManifestHash": target_decryption_fixture_manifest_hash(),
        "targetProposalHash": derive_canonical_object_hash(
            &json!({ "objectType": "TargetProposalHash", "target": "accepted" }),
        ).expect("proposal hash"),
        "evaluatorReplayRecordHash": derive_canonical_object_hash(
            &json!({ "objectType": "EvaluatorReplayRecordHash", "replay": "accepted" }),
        ).expect("replay hash"),
        "targetContextHash": derive_canonical_object_hash(
            &json!({ "objectType": "TargetContextHash", "context": "accepted target" }),
        ).expect("context hash"),
        "targetFinalityRecordHash": derive_canonical_object_hash(
            &json!({ "objectType": "TargetFinalityRecordHash", "finality": "record" }),
        ).expect("record hash"),
        "targetFinalityCheckpointHash": derive_canonical_object_hash(
            &json!({ "objectType": "TargetFinalityCheckpointHash", "finality": "checkpoint" }),
        ).expect("checkpoint hash"),
        "targetPreimageHash": derive_canonical_object_hash(
            &json!({ "objectType": "TargetPreimageHash", "preimage": "accepted" }),
        ).expect("preimage hash"),
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "targetDecryptionParametersHash": target_decryption_parameters_hash,
        "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
        "boardSequence": 0,
        "boardPosition": 0,
        "organizerIdentity": "organizer",
    });
    record["targetAcceptedRecordHash"] =
        json!(derive_canonical_object_hash(&record).expect("target accepted record hash"));
    record
}

fn target_fixture() -> (Value, Value, Value, Value) {
    let setup_package = accepted_setup_package();
    let evaluator_key = target_decryption_evaluator_key();
    let mut ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
    let mut orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
    ids[0] = 1;
    ids[2] = 3;
    orders[0] = 1;
    orders[2] = 2;
    let (target_id_slots, target_order_slots) = sparse_target_slots(&ids, &orders);
    let target_id = canonical_target_ciphertext(&evaluator_key, &target_id_slots, "target-id");
    let target_order =
        canonical_target_ciphertext(&evaluator_key, &target_order_slots, "target-order");
    assert_eq!(target_id.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
    assert_eq!(target_order.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
    let target_id_root =
        crate::bgv::evaluator::engine::ciphertext_object_root(&target_id).expect("target id root");
    let target_order_root = crate::bgv::evaluator::engine::ciphertext_object_root(&target_order)
        .expect("target order root");
    let aggregate_ciphertext_root = "a".repeat(128);
    let target_layout_hash = target_layout_hash(MAXIMUM_OPTION_COUNT).expect("layout hash");
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        &aggregate_ciphertext_root,
        2,
        &target_layout_hash,
        &target_id_root,
        &target_order_root,
    )
    .expect("target ciphertext hash");
    let accepted_record = accepted_record(&target_ciphertext_hash, &target_layout_hash);
    let target_ciphertext_binding = json!({
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": 2,
        "targetLayoutHash": target_layout_hash,
    });
    let target_ciphertexts = json!({
        "targetIdCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_id)
            .expect("target id hex"),
        "targetOrderCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_order)
            .expect("target order hex"),
    });

    (
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
    )
}

fn aggregate_threshold_commitment_set(
    setup_package: &Value,
    target_share_profile: &Value,
) -> Value {
    let setup_binding = read_setup_binding(setup_package).expect("setup binding");
    let target_share_profile =
        read_target_share_profile(target_share_profile, &setup_binding).expect("share profile");
    let evaluator_key = target_decryption_evaluator_key();
    let rns_limb_count = CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1;
    let mut recipient_records =
        Vec::with_capacity(setup_binding.participants.len() * rns_limb_count);
    for participant in &setup_binding.participants {
        let share_by_limb = derive_threshold_secret_share_by_limb(
            &evaluator_key,
            &target_share_profile.hash,
            TARGET_DECRYPTION_FIXTURE_SETUP_SEED,
            participant.interpolation_point,
            target_share_profile.minimum_shares_for_interpolation,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .expect("target share limbs");
        for (rns_limb_index, share_values) in share_by_limb.iter().enumerate() {
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let aggregate_commitment_message_values =
                aggregate_opening_values(share_values, rns_prime);
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let message_coefficient_bound =
                aggregate_message_coefficient_bound(rns_prime, setup_binding.participants.len())
                    .expect("aggregate message coefficient bound");
            let computation = compute_aggregate_opening(AggregateOpeningRootsInput {
                setup_binding: &setup_binding,
                participant,
                setup_epoch: TARGET_DECRYPTION_FIXTURE_COMPACT_SETUP_EPOCH,
                public_matrix_seed_hash: &setup_binding.public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                aggregate_commitment_message_values: &aggregate_commitment_message_values,
                message_coefficient_bound,
                aggregate_randomness_by_column: &aggregate_randomness_by_column,
            })
            .expect("aggregate opening computation");
            let source_share_commitment_roots = (0..setup_binding.participants.len())
                .map(|_| json!("9".repeat(128)))
                .collect::<Vec<_>>();
            let source_share_opening_roots = (0..setup_binding.participants.len())
                .map(|_| json!("8".repeat(128)))
                .collect::<Vec<_>>();
            recipient_records.push(json!({
                "objectType": "VssPublicAggregateThresholdCommitment",
                "objectVersion": 1,
                "recipientIdentity": participant.trustee_identity.as_str(),
                "recipientRosterPosition": participant.roster_position,
                "recipientTrusteePoint": participant.interpolation_point,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "aggregateCommitmentRoot": computation.commitment_root,
                "aggregateOpeningRoot": computation.opening_root,
                "commitment": computation.commitment,
                "sourceShareCommitmentRoots": source_share_commitment_roots,
                "sourceShareOpeningRoots": source_share_opening_roots,
            }));
        }
    }

    let mut set = json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "objectVersion": 1,
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash.as_str(),
        "participantCount": setup_binding.participants.len(),
        "rnsLimbCount": rns_limb_count,
        "ringDegree": POLYNOMIAL_DEGREE,
        "recipientRecords": recipient_records,
    });
    set["aggregateThresholdCommitmentRoot"] =
        json!(derive_canonical_object_hash(&set).expect("aggregate threshold commitment set root"));
    set
}

fn aggregate_opening_values(share_values: &[u64], rns_prime: u64) -> Vec<u64> {
    let mut aggregate_commitment_message_values = share_values.to_vec();
    aggregate_commitment_message_values[0] += rns_prime;
    aggregate_commitment_message_values
}

fn generate_share_from_fresh_local_witness(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    let local_target_share_witness_value = local_target_share_witness(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        trustee_identity,
    );

    generate_local_share(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        &local_target_share_witness_value,
        trustee_identity,
    )
}

fn generate_local_share(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    local_target_share_witness_value: &Value,
    trustee_identity: &str,
) -> Value {
    generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": trustee_identity,
    }))
    .expect("local witness share")
}

struct TargetShareProofStatementInput<'a> {
    setup_package: &'a Value,
    accepted_record: &'a Value,
    target_ciphertext_binding: &'a Value,
    target_ciphertexts: &'a Value,
    target_share_profile: &'a Value,
    local_target_share_witness_value: &'a Value,
    target_decryption_share: &'a Value,
    trustee_identity: &'a str,
}

fn derive_share_proof_statement(
    input: TargetShareProofStatementInput<'_>,
) -> CanonicalResult<Value> {
    derive_bgv_target_decryption_share_proof_statement_from_request(&json!({
        "setupPackage": input.setup_package,
        "localTargetShareWitness": input.local_target_share_witness_value,
        "targetAcceptedRecord": input.accepted_record,
        "targetCiphertextBinding": input.target_ciphertext_binding,
        "targetCiphertexts": input.target_ciphertexts,
        "targetShareProfile": input.target_share_profile,
        "trusteeIdentity": input.trustee_identity,
        "targetDecryptionShare": input.target_decryption_share,
    }))
}

struct TargetShareProofStatementBindingInput<'a> {
    setup_package: &'a Value,
    accepted_record: &'a Value,
    target_ciphertext_binding: &'a Value,
    target_ciphertexts: &'a Value,
    target_share_profile: &'a Value,
    target_decryption_share: &'a Value,
    proof_statement: &'a Value,
}

fn verify_share_proof_statement_binding(
    input: TargetShareProofStatementBindingInput<'_>,
) -> CanonicalResult<Value> {
    verify_bgv_target_decryption_share_proof_statement_binding_from_request(&json!({
        "setupPackage": input.setup_package,
        "targetAcceptedRecord": input.accepted_record,
        "targetCiphertextBinding": input.target_ciphertext_binding,
        "targetCiphertexts": input.target_ciphertexts,
        "targetShareProfile": input.target_share_profile,
        "targetDecryptionShare": input.target_decryption_share,
        "proofStatement": input.proof_statement,
    }))
}

fn rebind_share_proof_statement_root(statement: &mut Value) {
    let statement_object = statement
        .as_object_mut()
        .expect("target share proof statement object");
    statement_object.remove("proofStatementRoot");
    statement["proofStatementRoot"] =
        json!(derive_canonical_object_hash(statement).expect("target share proof statement root"));
}

fn rebind_target_accepted_record_hash(accepted_record: &mut Value) {
    accepted_record
        .as_object_mut()
        .expect("target accepted record object")
        .remove("targetAcceptedRecordHash");
    accepted_record["targetAcceptedRecordHash"] =
        json!(derive_canonical_object_hash(accepted_record).expect("target accepted record hash"));
}

fn rebind_active_credential_binding_root(statement: &mut Value) {
    let active_credential_bindings =
        statement["aggregateOpeningBinding"]["activeCredentialBindings"].clone();
    statement["aggregateOpeningBinding"]["activeCredentialBindingRoot"] = json!(
        derive_canonical_object_hash(&json!({
            "objectType": "TargetDecryptionAggregateOpeningCredentialBindingSet",
            "objectVersion": 1,
            "activeCredentialBindings": active_credential_bindings,
        }))
        .expect("active credential binding root")
    );
}

fn rebind_target_decryption_share_hashes(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    target_decryption_share: &mut Value,
    trustee_identity: &str,
) {
    let setup_binding = read_setup_binding(setup_package).expect("setup binding");
    let target_share_profile =
        read_target_share_profile(target_share_profile, &setup_binding).expect("share profile");
    let target_accepted =
        read_target_accepted_binding(accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        target_ciphertexts,
        target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .expect("participant");
    let share_root =
        derive_canonical_object_hash(&target_decryption_share["sharePayload"]).expect("share root");
    target_decryption_share["shareRoot"] = json!(share_root);
    target_decryption_share["targetDecryptionShareHash"] = json!(
        derive_canonical_object_hash(&share_record_hash_input(
            &setup_binding,
            &target_accepted,
            &target_ciphertext_pair,
            &target_share_profile,
            participant,
            target_decryption_share["shareRoot"]
                .as_str()
                .expect("target share root"),
        ))
        .expect("target share hash")
    );
}

fn change_first_partial_decryption_coefficient(target_decryption_share: &mut Value) {
    let partial_record = &mut target_decryption_share["sharePayload"]["targetId"][0];
    let mut coefficients = coefficient_vector_from_le_hex(
        partial_record["partialDecryptionLeHex"]
            .as_str()
            .expect("partial decryption hex"),
        POLYNOMIAL_DEGREE,
        "target partial-decryption coefficient vector byte length does not match the selected BGV profile",
    )
    .expect("partial decryption coefficients");
    coefficients[0] = add_mod_fast(coefficients[0], 1, DATA_PRIMES[0]);
    partial_record["partialDecryptionLeHex"] = json!(coefficient_vector_le_hex(&coefficients));
    partial_record["partialDecryptionHash512"] = json!(coefficient_vector_hash512(
        &coefficients,
        TARGET_PARTIAL_DECRYPTION_LIMB_HASH_DOMAIN,
    ));
}

fn local_target_share_witness(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    let setup_binding = read_setup_binding(setup_package).expect("setup binding");
    let setup_context_hashes =
        collective_bgv_setup_context_hashes_from_package(setup_package).expect("context hashes");
    let target_share_profile =
        read_target_share_profile(target_share_profile, &setup_binding).expect("share profile");
    let target_accepted =
        read_target_accepted_binding(accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        target_ciphertexts,
        target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .expect("participant");
    let evaluator_key = target_decryption_evaluator_key();
    let share_by_limb = derive_threshold_secret_share_by_limb(
        &evaluator_key,
        &target_share_profile.hash,
        TARGET_DECRYPTION_FIXTURE_SETUP_SEED,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )
    .expect("target share limbs");
    let setup_epoch = TARGET_DECRYPTION_FIXTURE_COMPACT_SETUP_EPOCH;
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root = hash_at_path(
        setup_package,
        &["vssShareLinkageStatement", "statementRoot"],
    )
    .expect("share-linkage statement root");
    let aggregate_threshold_commitment_root = setup_package
        .get("vssPublicAggregateThresholdCommitmentSet")
        .and_then(|aggregate_set| aggregate_set.get("aggregateThresholdCommitmentRoot"))
        .and_then(Value::as_str)
        .expect("aggregate threshold commitment set root")
        .to_string();
    let aggregate_opening_credentials = share_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, share_values)| {
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let aggregate_commitment_message_values =
                aggregate_opening_values(share_values, rns_prime);
            let message_coefficient_bound = aggregate_message_coefficient_bound(
                rns_prime,
                setup_binding.participants.len(),
            )
            .expect("aggregate message coefficient bound");
            let (aggregate_commitment_root, aggregate_opening_root) =
                compute_aggregate_opening_roots(AggregateOpeningRootsInput {
                    setup_binding: &setup_binding,
                    participant,
                    setup_epoch,
                    public_matrix_seed_hash: &public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    aggregate_commitment_message_values: &aggregate_commitment_message_values,
                    message_coefficient_bound,
                    aggregate_randomness_by_column: &aggregate_randomness_by_column,
                })
                .expect("aggregate opening roots");
            json!({
                "objectType": "LocalTrusteeVssPublicAggregateOpeningCredential",
                "objectVersion": 1,
                "recipientIdentity": participant.trustee_identity.as_str(),
                "recipientRosterPosition": participant.roster_position,
                "recipientTrusteePoint": participant.interpolation_point,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "aggregateCommitmentRoot": aggregate_commitment_root,
                "aggregateOpeningRoot": aggregate_opening_root,
                "aggregateCommitmentMessageValuesLeHex": coefficient_vector_le_hex(&aggregate_commitment_message_values),
                "aggregateRandomnessByColumnSignedByteHex": aggregate_randomness_by_column
                    .iter()
                    .map(|column| signed_byte_vector_hex(column).expect("signed-byte randomness"))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "objectType": "LocalTrusteeTargetDecryptionProofWitnessMaterial",
        "objectVersion": 1,
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_context_hashes.roster_hash,
        "setupParametersHash": setup_context_hashes.setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": participant.trustee_identity.as_str(),
        "trusteeRosterPosition": participant.roster_position,
        "targetDecryptionSmudging": target_decryption_smudging_witness_value(
            &setup_binding,
            &target_accepted,
            &target_ciphertext_pair,
            &target_share_profile,
            participant,
        ).expect("target-decryption smudging witness"),
        "aggregateOpening": {
            "objectType": "LocalTrusteeVssPublicAggregateOpeningWitness",
            "objectVersion": 1,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
            "shareLinkageStatementRoot": share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
            "aggregateOpeningCredentials": aggregate_opening_credentials,
        },
    })
}

fn lagrange_weights_at_zero(
    interpolation_points: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    interpolation_points
        .iter()
        .enumerate()
        .map(|(participant_index, selected_point)| {
            let selected_point = *selected_point % modulus;
            let mut numerator = 1_u64;
            let mut denominator = 1_u64;
            for (other_participant_index, other_point) in interpolation_points.iter().enumerate() {
                if other_participant_index == participant_index {
                    continue;
                }
                let other_point = *other_point % modulus;
                numerator = mul_mod(numerator, sub_mod(0, other_point, modulus)?, modulus)?;
                denominator = mul_mod(
                    denominator,
                    sub_mod(selected_point, other_point, modulus)?,
                    modulus,
                )?;
            }
            mul_mod(numerator, inverse_mod(denominator, modulus)?, modulus)
        })
        .collect()
}

fn limbwise_difference(
    released_partials: &[Vec<u64>],
    unsmudged_partials: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if released_partials.len() != unsmudged_partials.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "released and unsmudged target partials must have the same active limb count",
        ));
    }
    released_partials
        .iter()
        .zip(unsmudged_partials.iter())
        .enumerate()
        .map(|(rns_limb_index, (released_limb, unsmudged_limb))| {
            if released_limb.len() != unsmudged_limb.len() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "released and unsmudged target partial limbs must have the same coefficient count",
                ));
            }
            let modulus = DATA_PRIMES[rns_limb_index];
            released_limb
                .iter()
                .zip(unsmudged_limb.iter())
                .map(|(released_coefficient, unsmudged_coefficient)| {
                    sub_mod(*released_coefficient, *unsmudged_coefficient, modulus)
                })
                .collect()
        })
        .collect()
}

fn assert_smudging_recombines_to_zero(
    role_name: &str,
    interpolation_points: &[u64],
    smudging_by_participant: &[Vec<Vec<u64>>],
) {
    assert_eq!(
        smudging_by_participant.len(),
        interpolation_points.len(),
        "{role_name} smudging input count must match the interpolation quorum"
    );
    assert!(
        smudging_by_participant
            .iter()
            .flat_map(|participant_limbs| participant_limbs.iter())
            .flat_map(|limb| limb.iter())
            .any(|coefficient| *coefficient != 0),
        "{role_name} smudging contribution should exercise a non-zero mask"
    );

    let active_limb_count = smudging_by_participant
        .first()
        .expect("at least one smudging share")
        .len();
    for (rns_limb_index, &modulus) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
        let lagrange_weights = lagrange_weights_at_zero(interpolation_points, modulus)
            .expect("Lagrange weights at zero");
        let mut reconstructed_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        for (participant_index, participant_limbs) in smudging_by_participant.iter().enumerate() {
            let participant_limb = participant_limbs
                .get(rns_limb_index)
                .expect("participant smudging limb");
            assert_eq!(
                participant_limb.len(),
                POLYNOMIAL_DEGREE,
                "{role_name} smudging limb must match the ring degree"
            );
            for (coefficient_index, coefficient) in participant_limb.iter().enumerate() {
                let weighted_coefficient =
                    mul_mod(*coefficient, lagrange_weights[participant_index], modulus)
                        .expect("weighted smudging coefficient");
                reconstructed_coefficients[coefficient_index] = add_mod(
                    reconstructed_coefficients[coefficient_index],
                    weighted_coefficient,
                    modulus,
                )
                .expect("reconstructed smudging coefficient");
            }
        }
        let first_nonzero_coefficient = reconstructed_coefficients
            .iter()
            .position(|coefficient| *coefficient != 0);
        assert_eq!(
            first_nonzero_coefficient, None,
            "{role_name} smudging limb {rns_limb_index} must interpolate to the zero plaintext mask"
        );
    }
}

fn staged_target_result_release(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile_value: &Value,
    target_share_proofs: Vec<Value>,
    release_verification_id: &str,
) -> CanonicalResult<Value> {
    let release_setup_context =
        derive_bgv_target_decryption_result_release_setup_context_from_request(&json!({
            "setupPackage": setup_package,
        }))?;
    begin_bgv_target_decryption_result_release_from_request(&json!({
        "releaseVerificationId": release_verification_id,
        "releaseSetupContext": release_setup_context,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile_value,
    }))?;
    for target_share_proof in target_share_proofs {
        absorb_bgv_target_decryption_result_release_share_from_request(&json!({
            "releaseVerificationId": release_verification_id,
            "targetShareProof": target_share_proof,
        }))?;
    }
    finish_bgv_target_decryption_result_release_from_request(&json!({
        "releaseVerificationId": release_verification_id,
    }))
}

#[test]
fn local_target_share_witness_generates_smudged_share() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );

    assert_eq!(
        local_share["sharePayload"]["smudgingInputReport"]["objectType"],
        json!("TargetDecryptionSmudgingInputReport")
    );
    assert_eq!(
        local_share["sharePayload"]["smudgingInputReport"]["roleReports"]
            .as_array()
            .expect("role reports")
            .len(),
        2
    );
    assert_eq!(
        local_share["sharePayload"]["smudgingInputReportHash"],
        json!(
            derive_canonical_object_hash(&local_share["sharePayload"]["smudgingInputReport"])
                .expect("smudging input report hash")
        )
    );
}

#[test]
fn target_decryption_smudging_zero_shares_cancel_for_interpolation_quorum() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let target_share_profile_binding =
        read_target_share_profile(&target_share_profile_value, &setup_binding)
            .expect("target share profile");
    let target_accepted =
        read_target_accepted_binding(&accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");
    let selected_participants = setup_binding
        .participants
        .iter()
        .take(target_share_profile_binding.minimum_shares_for_interpolation)
        .collect::<Vec<_>>();
    assert_eq!(
        selected_participants.len(),
        target_share_profile_binding.minimum_shares_for_interpolation,
        "fixture must include enough participants for interpolation"
    );

    let mut interpolation_points = Vec::with_capacity(selected_participants.len());
    let mut target_id_smudging_by_participant = Vec::with_capacity(selected_participants.len());
    let mut target_order_smudging_by_participant = Vec::with_capacity(selected_participants.len());
    for participant in selected_participants {
        interpolation_points.push(participant.interpolation_point);
        let local_target_share_witness_value = local_target_share_witness(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &participant.trustee_identity,
        );
        let local_witness = read_local_target_decryption_share_witness(
            &local_target_share_witness_value,
            &setup_binding,
            &target_accepted,
            &target_ciphertext_pair,
            &target_share_profile_binding,
            participant,
        )
        .expect("local target-share witness");
        let local_share = generate_local_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &local_target_share_witness_value,
            &participant.trustee_identity,
        );

        let released_target_id_partials = read_partial_limb_set(
            &local_share["sharePayload"],
            "targetId",
            target_ciphertext_pair.target_id.level,
        )
        .expect("released target-id partials");
        let released_target_order_partials = read_partial_limb_set(
            &local_share["sharePayload"],
            "targetOrder",
            target_ciphertext_pair.target_order.level,
        )
        .expect("released target-order partials");
        let unsmudged_target_id_partials = partial_decryption_by_limb(
            &target_ciphertext_pair.target_id,
            &local_witness.secret_share_by_limb,
        )
        .expect("unsmudged target-id partials");
        let unsmudged_target_order_partials = partial_decryption_by_limb(
            &target_ciphertext_pair.target_order,
            &local_witness.secret_share_by_limb,
        )
        .expect("unsmudged target-order partials");

        target_id_smudging_by_participant.push(
            limbwise_difference(&released_target_id_partials, &unsmudged_target_id_partials)
                .expect("target-id smudging difference"),
        );
        target_order_smudging_by_participant.push(
            limbwise_difference(
                &released_target_order_partials,
                &unsmudged_target_order_partials,
            )
            .expect("target-order smudging difference"),
        );
    }

    assert_smudging_recombines_to_zero(
        "target-id",
        &interpolation_points,
        &target_id_smudging_by_participant,
    );
    assert_smudging_recombines_to_zero(
        "target-order",
        &interpolation_points,
        &target_order_smudging_by_participant,
    );
}

#[test]
fn target_decryption_quorum_release_recovers_target_slots() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let setup_binding = read_setup_binding(&setup_package).expect("setup binding");
    let target_share_profile_binding =
        read_target_share_profile(&target_share_profile_value, &setup_binding)
            .expect("target share profile");
    let target_accepted =
        read_target_accepted_binding(&accepted_record, &setup_binding).expect("target accepted");
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &target_accepted,
    )
    .expect("target ciphertext pair");

    let trustees = ["trustee-1", "trustee-2"];
    let mut interpolation_points = Vec::with_capacity(trustees.len());
    let mut target_id_partials_by_share = Vec::with_capacity(trustees.len());
    let mut target_order_partials_by_share = Vec::with_capacity(trustees.len());
    for trustee_identity in trustees {
        let local_target_share_witness_value = local_target_share_witness(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            trustee_identity,
        );
        let local_share = generate_local_share(
            &setup_package,
            &accepted_record,
            &target_ciphertext_binding,
            &target_ciphertexts,
            &target_share_profile_value,
            &local_target_share_witness_value,
            trustee_identity,
        );
        interpolation_points.push(
            local_share["interpolationPoint"]
                .as_u64()
                .expect("interpolation point"),
        );
        target_id_partials_by_share.push(
            read_partial_limb_set(
                &local_share["sharePayload"],
                "targetId",
                target_ciphertext_pair.target_id.level,
            )
            .expect("target-id partials"),
        );
        target_order_partials_by_share.push(
            read_partial_limb_set(
                &local_share["sharePayload"],
                "targetOrder",
                target_ciphertext_pair.target_order.level,
            )
            .expect("target-order partials"),
        );
    }
    assert_eq!(
        target_id_partials_by_share.len(),
        target_share_profile_binding.minimum_shares_for_interpolation
    );

    let target_id_partial_refs = target_id_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let target_order_partial_refs = target_order_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let target_id_slots = release_target_role_slots(
        &target_ciphertext_pair.target_id,
        &interpolation_points,
        &target_id_partial_refs,
    )
    .expect("target-id release");
    let target_order_slots = release_target_role_slots(
        &target_ciphertext_pair.target_order,
        &interpolation_points,
        &target_order_partial_refs,
    )
    .expect("target-order release");

    let mut expected_target_ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
    let mut expected_target_orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
    expected_target_ids[0] = 1;
    expected_target_ids[2] = 3;
    expected_target_orders[0] = 1;
    expected_target_orders[2] = 2;
    assert_eq!(
        packed_target_option_values(&target_id_slots, target_ciphertext_pair.top_count)
            .expect("target-id options"),
        expected_target_ids
    );
    assert_eq!(
        packed_target_option_values(&target_order_slots, target_ciphertext_pair.top_count)
            .expect("target-order options"),
        expected_target_orders
    );

    let mut tampered_target_id_partials_by_share = target_id_partials_by_share;
    tampered_target_id_partials_by_share[0][0][0] = add_mod_fast(
        tampered_target_id_partials_by_share[0][0][0],
        1,
        DATA_PRIMES[0],
    );
    let tampered_target_id_partial_refs = tampered_target_id_partials_by_share
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let tampered_target_id_slots = release_target_role_slots(
        &target_ciphertext_pair.target_id,
        &interpolation_points,
        &tampered_target_id_partial_refs,
    )
    .expect("tampered target-id release");
    assert_ne!(
        packed_target_option_values(&tampered_target_id_slots, target_ciphertext_pair.top_count)
            .expect("tampered target-id options"),
        expected_target_ids
    );
}

#[test]
fn target_result_release_requires_proof_backed_quorum() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let error = staged_target_result_release(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        Vec::new(),
        "rust-target-release-empty",
    )
    .expect_err("target result release must require a quorum");

    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(error.message.contains("share quorum"));

    let raw_share = generate_share_from_fresh_local_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let error = staged_target_result_release(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        vec![
            json!({ "targetDecryptionShare": raw_share.clone() }),
            json!({ "targetDecryptionShare": raw_share }),
        ],
        "rust-target-release-proofless",
    )
    .expect_err("target result release must reject proofless shares");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofStatement"));
}

#[test]
fn target_share_proof_statement_binds_local_witness_and_share() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );

    let statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");

    assert_eq!(
        statement["objectType"],
        json!("BgvTargetDecryptionShareProofStatement")
    );
    assert_eq!(
        statement["targetDecryptionShareHash"],
        local_share["targetDecryptionShareHash"]
    );
    assert_eq!(statement["shareRoot"], local_share["shareRoot"]);
    assert_eq!(
        statement["aggregateOpeningBinding"]["publicMatrixSeedHash"],
        setup_package["commonRandomness"]["publicMatrixSeedHash"]
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["shareLinkageStatementRoot"],
        setup_package["vssShareLinkageStatement"]["statementRoot"]
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["aggregateThresholdCommitmentRoot"],
        setup_package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"]
    );
    let expected_active_credential_binding_root = derive_canonical_object_hash(&json!({
        "objectType": "TargetDecryptionAggregateOpeningCredentialBindingSet",
        "objectVersion": 1,
        "activeCredentialBindings": statement["aggregateOpeningBinding"]["activeCredentialBindings"],
    }))
    .expect("active credential binding root");
    assert_eq!(
        statement["aggregateOpeningBinding"]["activeCredentialBindingRoot"],
        json!(expected_active_credential_binding_root)
    );
    assert_eq!(
        statement["aggregateOpeningBinding"]["activeCredentialBindings"]
            .as_array()
            .expect("active credential bindings")
            .len(),
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1
    );

    let mut root_input = statement.clone();
    root_input
        .as_object_mut()
        .expect("statement object")
        .remove("proofStatementRoot");
    assert_eq!(
        statement["proofStatementRoot"],
        json!(derive_canonical_object_hash(&root_input).expect("statement root"))
    );
}

#[test]
fn target_share_proof_relation_rejects_rebound_wrong_partial_decryption() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let mut local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );
    change_first_partial_decryption_coefficient(&mut local_share);
    rebind_target_decryption_share_hashes(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &mut local_share,
        "trustee-1",
    );

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect_err("rebound wrong partial decryption must not satisfy the relation");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("restored local witness relation"));
}

#[test]
fn target_share_proof_statement_binding_accepts_bound_statement() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");

    let verification =
        verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
            setup_package: &setup_package,
            accepted_record: &accepted_record,
            target_ciphertext_binding: &target_ciphertext_binding,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile,
            target_decryption_share: &local_share,
            proof_statement: &statement,
        })
        .expect("target share proof statement binding");

    assert_eq!(verification["ok"], json!(false));
    assert_eq!(
        verification["operation"],
        json!("verifyBgvTargetDecryptionShareProofStatementBinding")
    );
    assert_eq!(
        verification["refusalReason"],
        json!("TargetDecryptionProofUnavailable")
    );
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_aggregate_commitment_body() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let mut statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let first_coordinate =
        statement["aggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]
            ["commitmentLimbs"][0]["coordinates"][0]
            .as_u64()
            .expect("first aggregate commitment coordinate");
    let first_modulus =
        statement["aggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]
            ["commitmentLimbs"][0]["modulus"]
            .as_u64()
            .expect("first aggregate commitment modulus");
    statement["aggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]["commitmentLimbs"]
        [0]["coordinates"][0] = json!((first_coordinate + 1) % first_modulus);
    rebind_active_credential_binding_root(&mut statement);
    rebind_share_proof_statement_root(&mut statement);

    let error = verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("wrong aggregate commitment body must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("commitment body"));
}

#[test]
fn target_result_release_rejects_wrong_target_context_before_proof_bytes() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let first_share_proof = statement_backed_target_share_with_malformed_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let second_share_proof = statement_backed_target_share_with_malformed_proof_material(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-2",
    );
    let mut wrong_target_record = accepted_record.clone();
    wrong_target_record["targetContextHash"] = json!("8".repeat(128));
    rebind_target_accepted_record_hash(&mut wrong_target_record);

    let error = staged_target_result_release(
        &setup_package,
        &wrong_target_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        vec![first_share_proof, second_share_proof],
        "rust-target-release-wrong-context",
    )
    .expect_err("target result release must reject shares bound to another target context");

    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(
        error.message.contains("proof statement"),
        "{}",
        error.message
    );
}

fn statement_backed_target_share_with_malformed_proof_material(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    let local_target_share_witness_value = local_target_share_witness(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        trustee_identity,
    );
    let target_decryption_share = generate_local_share(
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        &local_target_share_witness_value,
        trustee_identity,
    );
    let proof_statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
        target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &target_decryption_share,
        trustee_identity,
    })
    .expect("target share proof statement");

    json!({
        "targetDecryptionShare": target_decryption_share,
        "proofStatement": proof_statement,
        "proofMaterial": {
            "objectType": "BgvTargetDecryptionShareProofMaterial",
            "objectVersion": 8,
            "proofRecords": [
                {
                    "objectType": "BgvTargetDecryptionShareProofRecord",
                    "objectVersion": 7,
                    "proofBytesBase64": "AQIDBAU=",
                },
            ],
        },
    })
}

#[test]
fn target_decryption_share_generation_refuses_passive_setup_package() {
    // The passive development package carries the collective secret but is not the
    // accepted, verifier-gated SetupPackage. read_setup_binding must refuse it at
    // the trust boundary (objectType BgvPassiveSetupPackage, not SetupPackage) so
    // shares can never be certified against a package the accepted-setup verifier
    // never blessed. This fires before any witness material is read.
    let (_accepted_setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&_accepted_setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &_accepted_setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": passive_crypto_package(),
        "localTargetShareWitness": local_target_share_witness_value,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("target decryption must refuse the passive setup package");

    assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
}
