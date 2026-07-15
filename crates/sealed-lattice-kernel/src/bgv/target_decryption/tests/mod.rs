use super::*;
use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    evaluator::records::target_layout_hash,
    evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    modular_arithmetic::{add_mod, inverse_mod, sub_mod},
    setup::accepted_setup_target_decryption_setup_parameters_hash,
};
use crate::foundation::{
    derive_canonical_stream_descriptor, CanonicalStreamDomain, FOUNDATION_PROFILE,
};
use crate::protocol_signatures::{
    create_ml_dsa_public_key_hash_fixture, create_protocol_signature_fixture,
};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};

mod share_generation;

const TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT: u64 = 3;
const TARGET_DECRYPTION_FIXTURE_SETUP_SEED: &str = "target-decryption-setup-seed";
const TARGET_DECRYPTION_FIXTURE_CEREMONY_ID: &str = "target-decryption-ceremony";
const TARGET_DECRYPTION_FIXTURE_SETUP_EPOCH: &str = "setup-epoch-1";

struct AcceptedSetupFixture {
    setup_package: Value,
    local_aggregate_opening_handoffs: Vec<Value>,
    aggregate_opening_material_by_root: BTreeMap<String, Vec<u8>>,
}

struct AggregateThresholdCommitmentSetupOutput {
    public_commitment_set: Value,
    local_aggregate_opening_handoffs: Vec<Value>,
    aggregate_opening_material_by_root: BTreeMap<String, Vec<u8>>,
}

const TARGET_DECRYPTION_FIXTURE_TRUSTEES: [&str; 3] = ["trustee-1", "trustee-2", "trustee-3"];

fn target_decryption_fixture_manifest_hash() -> String {
    derive_canonical_object_hash(
        &json!({ "objectType": "ElectionManifestHash", "manifest": "target-decryption-test" }),
    )
    .expect("manifest hash")
}

fn target_decryption_fixture_roster_hash() -> String {
    let roster_entries = TARGET_DECRYPTION_FIXTURE_TRUSTEES
        .iter()
        .enumerate()
        .map(|(roster_position, trustee_identity)| {
            let signing_public_key_hash = create_ml_dsa_public_key_hash_fixture(
                &target_decryption_fixture_signature_seed_label(trustee_identity),
            )
            .expect("target-decryption setup signing public-key hash");
            json!({
                "objectType": "CollectiveBgvSetupRosterEntry",
                "rosterPosition": roster_position,
                "trusteeIdentity": trustee_identity,
                "signingPublicKeyHash": signing_public_key_hash,
            })
        })
        .collect::<Vec<_>>();
    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvSetupRoster",
        "rosterEntries": roster_entries,
    }))
    .expect("roster hash")
}

fn target_decryption_fixture_public_matrix_seed_hash() -> String {
    derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvCommonRandomnessPublicMatrixSeed",
        "seed": "target-decryption-test",
    }))
    .expect("public matrix seed hash")
}

fn target_decryption_fixture_signature_seed_label(trustee_identity: &str) -> String {
    format!("{trustee_identity}-target-decryption-setup-signing")
}

fn target_decryption_evaluator_key() -> DevelopmentBgvKey {
    DevelopmentBgvKey::generate(TARGET_DECRYPTION_FIXTURE_SETUP_SEED).expect("evaluator key")
}

fn accepted_setup_package() -> Value {
    accepted_setup_fixture().setup_package.clone()
}

fn accepted_setup_fixture() -> &'static AcceptedSetupFixture {
    static ACCEPTED_SETUP_FIXTURE_CACHE: OnceLock<AcceptedSetupFixture> = OnceLock::new();
    ACCEPTED_SETUP_FIXTURE_CACHE.get_or_init(build_accepted_setup_fixture)
}

fn accepted_setup_package_base() -> Value {
    let manifest_hash = target_decryption_fixture_manifest_hash();
    let roster_hash = target_decryption_fixture_roster_hash();
    let setup_parameters_hash = accepted_setup_target_decryption_setup_parameters_hash(
        TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT,
    )
    .expect("roster-derived setup parameters hash");
    let setup_context = json!({
        "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": TARGET_DECRYPTION_FIXTURE_SETUP_EPOCH,
        "participantCount": TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT,
    });
    let setup_context_hash = derive_canonical_object_hash(&json!({
        "objectType": "CollectiveBgvSetupContext",
        "ceremonyId": TARGET_DECRYPTION_FIXTURE_CEREMONY_ID,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": TARGET_DECRYPTION_FIXTURE_SETUP_EPOCH,
        "participantCount": TARGET_DECRYPTION_FIXTURE_PARTICIPANT_COUNT,
    }))
    .expect("setup context hash");
    let setup_intent_registrations = TARGET_DECRYPTION_FIXTURE_TRUSTEES
        .iter()
        .enumerate()
        .map(|(roster_position, trustee_identity)| {
            let signature_seed_label =
                target_decryption_fixture_signature_seed_label(trustee_identity);
            let signing_public_key_hash =
                create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                    .expect("target-decryption setup signing public-key hash");
            let private_vss_mailbox_public_key_hash = derive_canonical_object_hash(&json!({
                "objectType": "TargetDecryptionFixtureMailboxPublicKey",
                "rosterPosition": roster_position,
            }))
            .expect("target-decryption fixture mailbox public-key hash");
            let registration_payload = json!({
                "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                "setupContextHash": setup_context_hash,
                "rosterPosition": roster_position,
                "trusteeIdentity": trustee_identity,
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "signingPublicKeyHash": signing_public_key_hash,
                "privateVssMailboxPublicKeyHash": private_vss_mailbox_public_key_hash,
            });
            let registration_root = derive_canonical_object_hash(&registration_payload)
                .expect("target-decryption setup registration root");
            let signature_envelope = create_protocol_signature_fixture(
                &signature_seed_label,
                json!({
                    "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                    "objectRoot": registration_root,
                }),
            )
            .expect("target-decryption setup signature fixture")
            .envelope;
            json!({
                "objectType": "CollectiveBgvSetupIntentTrusteeRegistration",
                "trusteeIdentity": trustee_identity,
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "privateVssMailboxPublicKeyHash": private_vss_mailbox_public_key_hash,
                "signatureEnvelope": signature_envelope,
            })
        })
        .collect::<Vec<_>>();

    json!({
        "objectType": "SetupPackage",
        "setupContext": setup_context,
        "commonRandomness": {
            "objectType": "CollectiveBgvCommonRandomness",
            "publicMatrixSeedHash": target_decryption_fixture_public_matrix_seed_hash(),
        },
        "setupIntent": {
            "objectType": "CollectiveBgvSetupIntent",
            "trusteeRegistrations": setup_intent_registrations,
        },
    })
}

fn build_accepted_setup_fixture() -> AcceptedSetupFixture {
    let mut accepted_setup_package = accepted_setup_package_base();
    let aggregate_threshold_commitment_setup_output =
        aggregate_threshold_commitment_set(&accepted_setup_package);
    accepted_setup_package["vssPublicAggregateThresholdCommitmentSet"] =
        aggregate_threshold_commitment_setup_output.public_commitment_set;
    accepted_setup_package["vssShareLinkageStatement"] = json!({
        "objectType": "VssShareLinkageStatement",
        "qShareRnsLimbCount": CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1,
    });

    AcceptedSetupFixture {
        setup_package: accepted_setup_package,
        local_aggregate_opening_handoffs: aggregate_threshold_commitment_setup_output
            .local_aggregate_opening_handoffs,
        aggregate_opening_material_by_root: aggregate_threshold_commitment_setup_output
            .aggregate_opening_material_by_root,
    }
}

fn target_share_profile(_setup_package: &Value) -> Value {
    json!({
        "objectType": "TargetDecryptionShareProfile",
        "minimumSharesForInterpolation": 2,
        "decryptionShareQuorum": 2,
    })
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
    target_ids[..MAXIMUM_OPTION_COUNT].copy_from_slice(&ids[..MAXIMUM_OPTION_COUNT]);
    target_orders[..MAXIMUM_OPTION_COUNT].copy_from_slice(&orders[..MAXIMUM_OPTION_COUNT]);
    (target_ids, target_orders)
}

fn accepted_record(setup_package: &Value, target_ciphertext_hash: &str) -> Value {
    json!({
        "objectType": "TargetAcceptedRecord",
        "setupPackageHash": derive_collective_setup_package_hash(setup_package)
            .expect("setup package hash"),
        "targetCiphertextHash": target_ciphertext_hash,
    })
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
    let accepted_record = accepted_record(&setup_package, &target_ciphertext_hash);
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
) -> AggregateThresholdCommitmentSetupOutput {
    let setup_context_hashes =
        collective_bgv_setup_context_hashes_from_package(setup_package).expect("setup context");
    let public_matrix_seed_hash =
        hash_at_path(setup_package, &["commonRandomness", "publicMatrixSeedHash"])
            .expect("public matrix seed hash");
    let participants = accepted_setup_participant_roster_from_package(setup_package)
        .expect("setup participants")
        .into_iter()
        .map(|(roster_position, trustee_identity)| ParticipantBinding {
            trustee_identity,
            roster_position,
        })
        .collect::<Vec<_>>();
    let decryption_threshold = participants.len() / 3 + 1;
    let evaluator_key = target_decryption_evaluator_key();
    let rns_limb_count = CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1;
    let mut recipient_records = Vec::with_capacity(participants.len() * rns_limb_count);
    let mut local_aggregate_opening_handoffs = Vec::with_capacity(participants.len());
    let mut aggregate_opening_material_by_root = BTreeMap::new();
    for participant in &participants {
        let interpolation_point = participant
            .interpolation_point()
            .expect("participant interpolation point");
        let share_by_limb = derive_threshold_secret_share_by_limb(
            &evaluator_key,
            &setup_context_hashes.setup_parameters_hash,
            TARGET_DECRYPTION_FIXTURE_SETUP_SEED,
            interpolation_point,
            decryption_threshold,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .expect("target share limbs");
        let mut aggregate_opening_credentials = Vec::with_capacity(rns_limb_count);
        for (rns_limb_index, share_values) in share_by_limb.iter().enumerate() {
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let aggregate_commitment_message_values = aggregate_opening_values(share_values);
            let aggregate_material_seed_hex =
                fixture_aggregate_material_seed_hex(participant.roster_position, rns_limb_index);
            let computation = compute_aggregate_opening(AggregateOpeningRootsInput {
                setup_context_hash: &setup_context_hashes.setup_context_hash,
                participant,
                rns_limb_index,
                rns_prime,
                aggregate_commitment_message_values: &aggregate_commitment_message_values,
                message_coefficient_bound: rns_prime,
                aggregate_material_seed_hex: &aggregate_material_seed_hex,
            })
            .expect("aggregate opening computation");
            let aggregate_opening_bytes = aggregate_commitment_message_values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<_>>();
            assert!(
                aggregate_opening_material_by_root
                    .insert(computation.opening_root.clone(), aggregate_opening_bytes)
                    .is_none(),
                "aggregate opening roots must be unique"
            );
            aggregate_opening_credentials.push(json!({
                "objectType": "LocalTrusteeVssPublicAggregateOpeningCredential",
                "recipientIdentity": participant.trustee_identity.as_str(),
                "recipientRosterPosition": participant.roster_position,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "aggregateCommitmentRoot": computation.commitment_root.clone(),
                "aggregateOpeningRoot": computation.opening_root.clone(),
                "aggregateMaterialSeedHex": aggregate_material_seed_hex,
            }));
            recipient_records.push(json!({
                "objectType": "VssPublicAggregateThresholdCommitment",
                "recipientIdentity": participant.trustee_identity.as_str(),
                "aggregateCommitmentRoot": computation.commitment_root,
                "aggregateOpeningRoot": computation.opening_root,
                "commitment": computation.commitment,
            }));
        }
        local_aggregate_opening_handoffs.push(json!({
            "trusteeIdentity": participant.trustee_identity.as_str(),
            "trusteeRosterPosition": participant.roster_position,
            "aggregateOpeningCredentials": aggregate_opening_credentials,
        }));
    }

    let mut set = json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientRecords": recipient_records,
    });
    set["aggregateThresholdCommitmentRoot"] =
        json!(derive_canonical_object_hash(&set).expect("aggregate threshold commitment set root"));
    AggregateThresholdCommitmentSetupOutput {
        public_commitment_set: set,
        local_aggregate_opening_handoffs,
        aggregate_opening_material_by_root,
    }
}

fn with_staged_aggregate_opening_material<T>(
    local_target_share_witness: &Value,
    operation: impl FnOnce() -> T,
) -> T {
    with_staged_aggregate_opening_material_transform(
        local_target_share_witness,
        |_aggregate_opening_root, _material| {},
        operation,
    )
}

fn with_staged_aggregate_opening_material_transform<T>(
    local_target_share_witness: &Value,
    transform: impl Fn(&str, &mut Vec<u8>),
    operation: impl FnOnce() -> T,
) -> T {
    static MATERIAL_USE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _material_use_guard = MATERIAL_USE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("target-decryption aggregate opening test lock");
    let credentials = local_target_share_witness["aggregateOpening"]["aggregateOpeningCredentials"]
        .as_array()
        .expect("aggregate opening credentials");
    for credential in credentials {
        let aggregate_opening_root = credential["aggregateOpeningRoot"]
            .as_str()
            .expect("aggregate opening root");
        let mut material = accepted_setup_fixture()
            .aggregate_opening_material_by_root
            .get(aggregate_opening_root)
            .expect("fixture aggregate opening material")
            .clone();
        transform(aggregate_opening_root, &mut material);
        authenticate_aggregate_opening_material_stream(aggregate_opening_root, &material);
    }
    operation()
}

fn authenticate_aggregate_opening_material_stream(aggregate_opening_root: &str, material: &[u8]) {
    let descriptor = derive_canonical_stream_descriptor(
        CanonicalStreamDomain::RecipientAggregateThresholdShareProof,
        material,
    )
    .expect("derive aggregate opening stream descriptor");
    let descriptor_bytes = descriptor
        .encode()
        .expect("encode aggregate opening stream descriptor");
    let aggregate_opening_root_bytes = crate::transcript_core::decode_hex(aggregate_opening_root)
        .expect("decode aggregate opening root");
    let stream = crate::bgv::setup::begin_bgv_canonical_stream(
        crate::bgv::setup::BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING,
        &aggregate_opening_root_bytes,
        &descriptor_bytes,
    )
    .expect("begin aggregate opening material stream");
    for (chunk_index, chunk) in material
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        crate::bgv::setup::absorb_bgv_canonical_stream_chunk(
            stream.handle,
            u32::try_from(chunk_index).expect("aggregate opening chunk index fits u32"),
            chunk,
        )
        .expect("absorb aggregate opening material chunk");
    }
    crate::bgv::setup::finish_bgv_canonical_stream(stream.handle)
        .expect("finish aggregate opening material stream");
}

fn fixture_aggregate_material_seed_hex(roster_position: usize, rns_limb_index: usize) -> String {
    crate::hashing::hash512_hex(
        "sealed-lattice-bgv-rns/target-decryption-fixture-aggregate-material-seed",
        &[
            &(roster_position as u64).to_le_bytes(),
            &(rns_limb_index as u64).to_le_bytes(),
        ],
    )
}

fn aggregate_opening_values(share_values: &[u64]) -> Vec<u64> {
    share_values.to_vec()
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
    with_staged_aggregate_opening_material(local_target_share_witness_value, || {
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
    })
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
    with_staged_aggregate_opening_material(input.local_target_share_witness_value, || {
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
    })
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
}

fn local_target_share_witness(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    _target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    let setup_binding = read_setup_binding(setup_package).expect("setup binding");
    let target_accepted =
        read_target_accepted_binding(accepted_record, &setup_binding).expect("target accepted");
    read_target_ciphertext_pair(
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
    let aggregate_opening_handoff = accepted_setup_fixture()
        .local_aggregate_opening_handoffs
        .iter()
        .find(|handoff| handoff["trusteeIdentity"] == participant.trustee_identity)
        .expect("setup-produced local aggregate opening handoff");
    assert_eq!(
        aggregate_opening_handoff["trusteeRosterPosition"], participant.roster_position,
        "setup-produced aggregate opening handoff roster position",
    );
    let aggregate_opening_credentials =
        aggregate_opening_handoff["aggregateOpeningCredentials"].clone();
    let private_flooding_seed_hex = format!("{:02x}", participant.roster_position + 1).repeat(64);
    json!({
        "objectType": "LocalTrusteeTargetDecryptionProofWitnessMaterial",
        "privateFloodingSeedHex": private_flooding_seed_hex,
        "aggregateOpening": {
            "objectType": "LocalTrusteeVssPublicAggregateOpeningWitness",
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

fn assert_flooding_noise_is_independent(
    role_name: &str,
    interpolation_points: &[u64],
    noise_by_participant: &[Vec<Vec<u64>>],
) {
    assert_eq!(
        noise_by_participant.len(),
        interpolation_points.len(),
        "{role_name} flooding-noise input count must match the interpolation quorum"
    );
    assert!(
        noise_by_participant
            .iter()
            .flat_map(|participant_limbs| participant_limbs.iter())
            .flat_map(|limb| limb.iter())
            .any(|coefficient| *coefficient != 0),
        "{role_name} flooding noise should exercise a non-zero mask"
    );

    let active_limb_count = noise_by_participant
        .first()
        .expect("at least one flooding-noise share")
        .len();
    let mut reconstructed_noise_is_nonzero = false;
    for (rns_limb_index, &modulus) in DATA_PRIMES.iter().enumerate().take(active_limb_count) {
        let lagrange_weights = lagrange_weights_at_zero(interpolation_points, modulus)
            .expect("Lagrange weights at zero");
        let mut reconstructed_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        for (participant_index, participant_limbs) in noise_by_participant.iter().enumerate() {
            let participant_limb = participant_limbs
                .get(rns_limb_index)
                .expect("participant flooding-noise limb");
            assert_eq!(
                participant_limb.len(),
                POLYNOMIAL_DEGREE,
                "{role_name} flooding-noise limb must match the ring degree"
            );
            for coefficient in participant_limb {
                let centered_coefficient = if *coefficient <= modulus / 2 {
                    i128::from(*coefficient)
                } else {
                    i128::from(*coefficient) - i128::from(modulus)
                };
                assert_eq!(
                    centered_coefficient % i128::from(PLAINTEXT_MODULUS),
                    0,
                    "{role_name} flooding-noise contribution must be plaintext-scaled"
                );
            }
            for (coefficient_index, coefficient) in participant_limb.iter().enumerate() {
                let weighted_coefficient =
                    mul_mod(*coefficient, lagrange_weights[participant_index], modulus)
                        .expect("weighted flooding-noise coefficient");
                reconstructed_coefficients[coefficient_index] = add_mod(
                    reconstructed_coefficients[coefficient_index],
                    weighted_coefficient,
                    modulus,
                )
                .expect("reconstructed flooding-noise coefficient");
            }
        }
        reconstructed_noise_is_nonzero |= reconstructed_coefficients
            .iter()
            .any(|coefficient| *coefficient != 0);
    }
    assert!(
        reconstructed_noise_is_nonzero,
        "{role_name} trustee-private flooding noise must not be a correlated zero share"
    );
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
    begin_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": release_verification_id,
        "setupPackage": setup_package,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile_value,
    }))?;
    for target_share_proof in target_share_proofs {
        absorb_bgv_target_decryption_result_release_share_for_test(&json!({
            "releaseVerificationId": release_verification_id,
            "targetShareProof": target_share_proof,
        }))?;
    }
    finish_bgv_target_decryption_result_release_for_test(&json!({
        "releaseVerificationId": release_verification_id,
    }))
}

#[test]
fn target_setup_binding_uses_the_accepted_package_hash_boundary() {
    let setup_package = accepted_setup_package();
    let expected_setup_package_hash =
        derive_collective_setup_package_hash(&setup_package).expect("setup package hash");
    assert_eq!(
        read_setup_binding(&setup_package)
            .expect("setup binding")
            .setup_package_hash,
        expected_setup_package_hash,
    );
}

mod behavior_proof;
mod behavior_witness;
mod replay_release;
