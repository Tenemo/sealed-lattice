use super::*;
use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    evaluator::records::target_layout_hash,
    evaluator::top_k::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, canonical_target_basis_hash,
        canonicalize_target_ciphertext, packed_score_slot,
    },
    modular_arithmetic::{add_mod, inverse_mod, sub_mod},
    profile::direct_comparison_profile_hash,
    setup::generate_passive_setup_package_from_request,
};

mod share_generation;

fn setup_request() -> Value {
    json!({
        "ceremonyId": "target-decryption-ceremony",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &json!({ "manifest": "target-decryption-test" }),
        ).expect("manifest hash"),
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &json!({ "roster": "target-decryption-test" }),
        ).expect("roster hash"),
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
            &json!({ "threshold": "target-decryption-test" }),
        ).expect("threshold hash"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
        ],
        "setupSeed": "target-decryption-setup-seed",
    })
}

fn setup_package() -> Value {
    generate_passive_setup_package_from_request(&setup_request()).expect("setup package")
}

fn target_share_profile(setup_package: &Value) -> Value {
    let profile = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "thresholdProfileHash": setup_package["setupInputs"]["thresholdProfileHash"],
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": setup_package["targetDecryptionProfileBinding"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileBindingHash": setup_package["targetDecryptionProfileBinding"]["targetDecryptionProfileBindingHash"],
        "decryptionThreshold": 2,
        "minimumSharesForInterpolation": 2,
        "decryptionShareQuorum": 2,
    });
    let mut with_hash = profile;
    with_hash["targetShareProfileHash"] = json!(
        derive_protocol_hash("TargetDecryptionShareProfileHash", &with_hash)
            .expect("target share profile hash")
    );
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
    let ciphertext = key
        .encrypt_coefficients(&coefficients, seed)
        .expect("encrypt coefficients");
    canonicalize_target_ciphertext(&ciphertext).expect("canonical target ciphertext")
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

fn accepted_record(
    setup_package: &Value,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
) -> Value {
    let mut record = json!({
        "objectType": "TargetAcceptedRecord",
        "objectVersion": 1,
        "ceremonyId": setup_package["setupInputs"]["ceremonyId"],
        "electionManifestHash": setup_package["setupInputs"]["manifestHash"],
        "targetProposalHash": derive_protocol_hash(
            "TargetProposalHash",
            &json!({ "target": "accepted" }),
        ).expect("proposal hash"),
        "evaluatorReplayRecordHash": derive_protocol_hash(
            "EvaluatorReplayRecordHash",
            &json!({ "replay": "accepted" }),
        ).expect("replay hash"),
        "targetContextHash": derive_protocol_hash(
            "TargetContextHash",
            &json!({ "context": "accepted target" }),
        ).expect("context hash"),
        "targetFinalityRecordHash": derive_protocol_hash(
            "TargetFinalityRecordHash",
            &json!({ "finality": "record" }),
        ).expect("record hash"),
        "targetFinalityCheckpointHash": derive_protocol_hash(
            "TargetFinalityCheckpointHash",
            &json!({ "finality": "checkpoint" }),
        ).expect("checkpoint hash"),
        "evaluatorReplayProfileHash": direct_comparison_profile_hash()
            .expect("direct comparison profile hash"),
        "targetPreimageHash": derive_protocol_hash(
            "TargetPreimageHash",
            &json!({ "preimage": "accepted" }),
        ).expect("preimage hash"),
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "targetDecryptionProfileHash": setup_package["targetDecryptionProfileBinding"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
        "boardSequence": 0,
        "boardPosition": 0,
        "organizerIdentity": "organizer",
    });
    record["targetAcceptedRecordHash"] = json!(
        derive_protocol_hash("TargetAcceptedRecordHash", &record)
            .expect("target accepted record hash")
    );
    record
}

fn target_fixture() -> (Value, Value, Value, Value) {
    let mut setup_package = setup_package();
    let target_share_profile = target_share_profile(&setup_package);
    let compact_aggregate_threshold_commitment_set =
        compact_aggregate_threshold_commitment_set(&setup_package, &target_share_profile);
    setup_package["compactVssAggregateThresholdCommitmentSet"] =
        compact_aggregate_threshold_commitment_set;
    setup_package["compactVssShareLinkageStatement"] = json!({
        "objectType": "CompactVssShareLinkageStatement",
        "objectVersion": 1,
        "statementRoot": "4".repeat(128),
    });
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        "target-decryption-setup-seed",
    )
    .expect("evaluator key");
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
        &canonical_target_basis_hash().expect("target basis hash"),
        &target_id_root,
        &target_order_root,
    )
    .expect("target ciphertext hash");
    let accepted_record =
        accepted_record(&setup_package, &target_ciphertext_hash, &target_layout_hash);
    let target_ciphertext_binding = json!({
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": 2,
        "targetLayoutHash": target_layout_hash,
        "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
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

fn compact_aggregate_threshold_commitment_set(
    setup_package: &Value,
    target_share_profile: &Value,
) -> Value {
    let setup_binding = read_setup_binding(setup_package).expect("setup binding");
    let target_share_profile =
        read_target_share_profile(target_share_profile, &setup_binding).expect("share profile");
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        setup_package,
        "target-decryption-setup-seed",
    )
    .expect("evaluator key");
    let rns_limb_count = CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1;
    let mut recipient_records =
        Vec::with_capacity(setup_binding.participants.len() * rns_limb_count);
    for participant in &setup_binding.participants {
        let share_by_limb = derive_threshold_secret_share_by_limb(
            &evaluator_key,
            &setup_binding.setup_package_hash,
            &target_share_profile.hash,
            "target-decryption-setup-seed",
            participant.interpolation_point,
            target_share_profile.minimum_shares_for_interpolation,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        )
        .expect("target share limbs");
        for (rns_limb_index, share_values) in share_by_limb.iter().enumerate() {
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let aggregate_commitment_message_values =
                compact_aggregate_opening_values(share_values, rns_prime);
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let message_coefficient_bound = compact_aggregate_message_coefficient_bound(
                rns_prime,
                setup_binding.participants.len(),
            )
            .expect("compact aggregate message coefficient bound");
            let computation =
                compute_compact_aggregate_opening(CompactAggregateOpeningRootsInput {
                    setup_binding: &setup_binding,
                    participant,
                    setup_epoch: "target-decryption-test",
                    public_matrix_seed_hash: &setup_binding.public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    aggregate_commitment_message_values: &aggregate_commitment_message_values,
                    message_coefficient_bound,
                    aggregate_randomness_by_column: &aggregate_randomness_by_column,
                })
                .expect("compact aggregate opening computation");
            let source_share_commitment_roots = (0..setup_binding.participants.len())
                .map(|_| json!("9".repeat(128)))
                .collect::<Vec<_>>();
            let source_share_opening_roots = (0..setup_binding.participants.len())
                .map(|_| json!("8".repeat(128)))
                .collect::<Vec<_>>();
            recipient_records.push(json!({
                "objectType": "CompactVssAggregateThresholdCommitment",
                "objectVersion": 1,
                "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
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
        "objectType": "CompactVssAggregateThresholdCommitmentSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
        "publicMatrixSeedHash": setup_binding.public_matrix_seed_hash.as_str(),
        "participantCount": setup_binding.participants.len(),
        "rnsLimbCount": rns_limb_count,
        "ringDegree": POLYNOMIAL_DEGREE,
        "recipientRecords": recipient_records,
    });
    set["aggregateThresholdCommitmentRoot"] = json!(
        derive_protocol_hash("ThresholdShareCommitmentRoot", &set)
            .expect("aggregate threshold commitment set root")
    );
    set
}

fn compact_aggregate_opening_values(share_values: &[u64], rns_prime: u64) -> Vec<u64> {
    let mut aggregate_commitment_message_values = share_values.to_vec();
    aggregate_commitment_message_values[0] += rns_prime;
    aggregate_commitment_message_values
}

fn rebind_compact_aggregate_threshold_commitment_set_root(aggregate_set: &mut Value) {
    let aggregate_set_object = aggregate_set
        .as_object_mut()
        .expect("compact aggregate threshold commitment set object");
    aggregate_set_object.remove("aggregateThresholdCommitmentRoot");
    aggregate_set["aggregateThresholdCommitmentRoot"] = json!(
        derive_protocol_hash("ThresholdShareCommitmentRoot", aggregate_set)
            .expect("aggregate threshold commitment set root")
    );
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
    statement["proofStatementRoot"] = json!(
        derive_protocol_hash("BgvTargetDecryptionShareProofStatementRoot", statement)
            .expect("target share proof statement root")
    );
}

fn rebind_target_proof_material_root(proof_material: &mut Value) {
    proof_material
        .as_object_mut()
        .expect("proof material object")
        .remove("proofMaterialRoot");
    proof_material["proofMaterialRoot"] = json!(
        derive_protocol_hash("TargetDecryptionShareProofMaterialRoot", proof_material)
            .expect("target proof material root")
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
    let share_root = derive_protocol_hash(
        "BgvTargetDecryptionShareRoot",
        &target_decryption_share["sharePayload"],
    )
    .expect("target share root");
    target_decryption_share["shareRoot"] = json!(share_root);
    target_decryption_share["targetDecryptionShareHash"] = json!(
        derive_protocol_hash(
            "BgvTargetDecryptionShareHash",
            &share_record_hash_input(
                &setup_binding,
                &target_accepted,
                &target_ciphertext_pair,
                &target_share_profile,
                participant,
                target_decryption_share["shareRoot"]
                    .as_str()
                    .expect("target share root"),
            ),
        )
        .expect("target share hash")
    );
}

fn rebind_target_share_smudging_report_hash(target_decryption_share: &mut Value) {
    target_decryption_share["sharePayload"]["smudgingInputReportHash"] = json!(
        derive_protocol_hash(
            "TargetDecryptionSmudgingInputReportHash",
            &target_decryption_share["sharePayload"]["smudgingInputReport"],
        )
        .expect("smudging input report hash")
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

fn rebind_active_credential_binding_root(statement: &mut Value) {
    let active_credential_bindings =
        statement["compactAggregateOpeningBinding"]["activeCredentialBindings"].clone();
    statement["compactAggregateOpeningBinding"]["activeCredentialBindingRoot"] = json!(
        derive_protocol_hash(
            "TargetDecryptionCompactAggregateOpeningCredentialBindingRoot",
            &json!({
                "objectType": "TargetDecryptionCompactAggregateOpeningCredentialBindingSet",
                "objectVersion": 1,
                "activeCredentialBindings": active_credential_bindings,
            }),
        )
        .expect("active credential binding root")
    );
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
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        setup_package,
        "target-decryption-setup-seed",
    )
    .expect("evaluator key");
    let share_by_limb = derive_threshold_secret_share_by_limb(
        &evaluator_key,
        &setup_binding.setup_package_hash,
        &target_share_profile.hash,
        "target-decryption-setup-seed",
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )
    .expect("target share limbs");
    let setup_epoch = "target-decryption-test";
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root = hash_at_path(
        setup_package,
        &["compactVssShareLinkageStatement", "statementRoot"],
    )
    .expect("compact share-linkage statement root");
    let aggregate_threshold_commitment_root = setup_package
        .get("compactVssAggregateThresholdCommitmentSet")
        .and_then(|aggregate_set| aggregate_set.get("aggregateThresholdCommitmentRoot"))
        .and_then(Value::as_str)
        .expect("compact aggregate threshold commitment set root")
        .to_string();
    let compact_aggregate_opening_credentials = share_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, share_values)| {
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let aggregate_commitment_message_values =
                compact_aggregate_opening_values(share_values, rns_prime);
            let message_coefficient_bound = compact_aggregate_message_coefficient_bound(
                rns_prime,
                setup_binding.participants.len(),
            )
            .expect("compact aggregate message coefficient bound");
            let (aggregate_commitment_root, aggregate_opening_root) =
                compute_compact_aggregate_opening_roots(CompactAggregateOpeningRootsInput {
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
                .expect("compact aggregate opening roots");
            json!({
                "objectType": "LocalTrusteeCompactVssAggregateOpeningCredential",
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
        "setupProfileId": "CollectiveBgvSetup-v1",
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_context_hashes.roster_hash,
        "setupProfileHash": setup_context_hashes.setup_profile_hash,
        "qShareHash": setup_context_hashes.q_share_hash,
        "carryAwareVssShareRelationProfileHash": setup_context_hashes.carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": setup_context_hashes.commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": participant.trustee_identity.as_str(),
        "trusteeRosterPosition": participant.roster_position,
        "thresholdShareCommitmentRecipientRoot": "1".repeat(128),
        "aggregateThresholdShareRoot": "2".repeat(128),
        "sourcePrivateEnvelopeReferences": [],
        "targetDecryptionSmudging": target_decryption_smudging_witness_value(
            &setup_binding,
            &target_accepted,
            &target_ciphertext_pair,
            &target_share_profile,
            participant,
            "target-decryption-setup-seed",
        ),
        "compactAggregateOpening": {
            "objectType": "LocalTrusteeCompactVssAggregateOpeningWitness",
            "objectVersion": 1,
            "profileId": "sealed-lattice-compact-vss-sparse-linear-v1",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
            "shareLinkageStatementRoot": share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
            "compactAggregateOpeningCredentials": compact_aggregate_opening_credentials,
        },
    })
}

fn le_word_hex(bytes: [u8; 8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn replace_le_hex_word(value: &mut Value, word_index: usize, replacement_hex: &str) {
    let source = value.as_str().expect("hex field").to_string();
    let start = word_index * 16;
    let end = start + 16;
    assert!(
        source.len() >= end,
        "hex field must contain the replaced word"
    );
    let mut updated = source;
    updated.replace_range(start..end, replacement_hex);
    *value = json!(updated);
}

fn replace_u64_le_hex_word(value: &mut Value, word_index: usize, replacement: u64) {
    replace_le_hex_word(value, word_index, &le_word_hex(replacement.to_le_bytes()));
}

fn replace_signed_byte_hex(value: &mut Value, byte_index: usize, replacement: i8) {
    let source = value.as_str().expect("hex field").to_string();
    let start = byte_index * 2;
    let end = start + 2;
    assert!(
        source.len() >= end,
        "hex field must contain the replaced byte"
    );
    let mut updated = source;
    updated.replace_range(start..end, &format!("{:02x}", replacement as u8));
    *value = json!(updated);
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
        local_share["sharePayload"]["smudgingInputReport"]["smudgingProfileId"],
        json!(TARGET_DECRYPTION_SMUDGING_PROFILE_ID)
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
            derive_protocol_hash(
                "TargetDecryptionSmudgingInputReportHash",
                &local_share["sharePayload"]["smudgingInputReport"]
            )
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
fn target_share_proof_statement_binds_compact_local_witness_and_share() {
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
        statement["smudgingInputReportHash"],
        local_share["sharePayload"]["smudgingInputReportHash"]
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["publicMatrixSeedHash"],
        setup_package["commonRandomness"]["publicMatrixSeedHash"]
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["shareLinkageStatementRoot"],
        setup_package["compactVssShareLinkageStatement"]["statementRoot"]
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["aggregateThresholdCommitmentRoot"],
        setup_package["compactVssAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"]
    );
    let expected_active_credential_binding_root = derive_protocol_hash(
        "TargetDecryptionCompactAggregateOpeningCredentialBindingRoot",
        &json!({
            "objectType": "TargetDecryptionCompactAggregateOpeningCredentialBindingSet",
            "objectVersion": 1,
            "activeCredentialBindings": statement["compactAggregateOpeningBinding"]["activeCredentialBindings"],
        }),
    )
    .expect("active credential binding root");
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["activeCredentialBindingRoot"],
        json!(expected_active_credential_binding_root)
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["activeCredentialBindings"]
            .as_array()
            .expect("active credential bindings")
            .len(),
        CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1
    );
    let active_credential_bindings =
        statement["compactAggregateOpeningBinding"]["activeCredentialBindings"]
            .as_array()
            .expect("active credential bindings");
    let rns_limb_count = setup_package["compactVssAggregateThresholdCommitmentSet"]["rnsLimbCount"]
        .as_u64()
        .expect("aggregate rns limb count") as usize;
    let recipient_roster_position = statement["rosterPosition"]
        .as_u64()
        .expect("statement roster position") as usize;
    for (limb_index, active_binding) in active_credential_bindings.iter().enumerate() {
        let accepted_record_index = recipient_roster_position * rns_limb_count + limb_index;
        assert_eq!(
            active_binding["aggregateCommitment"],
            setup_package["compactVssAggregateThresholdCommitmentSet"]["recipientRecords"]
                [accepted_record_index]["commitment"]
        );
    }
    let smudging_commitment_binding = &statement["smudgingCommitmentBinding"];
    assert_eq!(
        smudging_commitment_binding["objectType"],
        json!("TargetDecryptionSmudgingCommitmentBinding")
    );
    let smudging_commitment_set = &smudging_commitment_binding["smudgingCommitmentSet"];
    assert_eq!(
        smudging_commitment_binding["smudgingCommitmentSetRoot"],
        smudging_commitment_set["smudgingCommitmentSetRoot"]
    );
    let mut smudging_commitment_set_without_root = smudging_commitment_set.clone();
    smudging_commitment_set_without_root
        .as_object_mut()
        .expect("smudging commitment set object")
        .remove("smudgingCommitmentSetRoot");
    assert_eq!(
        smudging_commitment_set["smudgingCommitmentSetRoot"],
        json!(
            derive_protocol_hash(
                "TargetDecryptionSmudgingCommitmentSetRoot",
                &smudging_commitment_set_without_root
            )
            .expect("smudging commitment set root")
        )
    );
    assert_eq!(
        smudging_commitment_set["publicMatrixSeedHash"],
        setup_package["commonRandomness"]["publicMatrixSeedHash"]
    );
    assert_eq!(
        smudging_commitment_set["targetDecryptionCiphertextHash"],
        accepted_record["targetCiphertextHash"]
    );
    assert_eq!(
        smudging_commitment_set["commitmentRole"],
        json!(TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE)
    );
    let active_limb_count = CANONICAL_TARGET_CIPHERTEXT_LEVEL + 1;
    let smudging_polynomial_degree = target_share_profile["minimumSharesForInterpolation"]
        .as_u64()
        .expect("minimum shares for interpolation") as usize
        - 1;
    let smudging_commitment_records = smudging_commitment_set["commitmentRecords"]
        .as_array()
        .expect("smudging commitment records");
    assert_eq!(
        smudging_commitment_records.len(),
        TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count * smudging_polynomial_degree
    );
    let first_smudging_commitment_record = &smudging_commitment_records[0];
    assert_eq!(first_smudging_commitment_record["role"], json!("targetId"));
    assert_eq!(first_smudging_commitment_record["rnsLimbIndex"], json!(0));
    assert_eq!(
        first_smudging_commitment_record["polynomialDegree"],
        json!(1)
    );
    assert_eq!(
        first_smudging_commitment_record["commitment"]["commitmentRole"],
        json!(TARGET_DECRYPTION_SMUDGING_COMMITMENT_ROLE)
    );

    let mut root_input = statement.clone();
    root_input
        .as_object_mut()
        .expect("statement object")
        .remove("proofStatementRoot");
    assert_eq!(
        statement["proofStatementRoot"],
        json!(
            derive_protocol_hash("BgvTargetDecryptionShareProofStatementRoot", &root_input)
                .expect("statement root")
        )
    );
}

#[test]
#[ignore = "heavy target-decryption proof material test"]
fn heavy_target_decryption_share_proof_material_verifies_complete_active_slices() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile_value = target_share_profile(&setup_package);
    let local_target_share_witness_value = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        "trustee-1",
    );
    let local_share = generate_local_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile_value,
        &local_target_share_witness_value,
        "trustee-1",
    );
    let statement = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile_value,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect("target share proof statement");
    let proof_material =
        generate_bgv_target_decryption_share_proof_material_from_local_witness_request(&json!({
            "setupPackage": &setup_package,
            "targetAcceptedRecord": &accepted_record,
            "targetCiphertextBinding": &target_ciphertext_binding,
            "targetCiphertexts": &target_ciphertexts,
            "targetShareProfile": &target_share_profile_value,
            "localTargetShareWitness": &local_target_share_witness_value,
            "targetDecryptionShare": &local_share,
            "proofStatement": &statement,
            "trusteeIdentity": "trustee-1",
            "proofRandomnessSeedHex": "21".repeat(64),
            "proofRandomnessNonceHex": "22".repeat(64),
        }))
        .expect("target proof material generation");

    assert_eq!(
        proof_material["objectType"],
        json!("BgvTargetDecryptionShareProofMaterial")
    );
    assert_eq!(
        proof_material["proofRecords"]
            .as_array()
            .expect("proof records")
            .len(),
        1
    );
    assert_eq!(
        proof_material["objectVersion"],
        json!(8),
        "all-active-limb target proof material uses the compacted record layout"
    );
    assert!(
        proof_material
            .get("targetShareProofStatementRoot")
            .is_none(),
        "target proof material should not duplicate the high-level statement root"
    );
    assert_eq!(
        proof_material["proofRecords"][0]["objectVersion"],
        json!(7),
        "target proof records use the verifier-derived coverage layout"
    );
    assert!(
        proof_material["proofRecords"][0]
            .get("proofRecordRoot")
            .is_none(),
        "target proof records should not duplicate a record root inside the material root"
    );
    assert!(
        proof_material["proofRecords"][0]
            .get("proofBytesBase64")
            .is_some(),
        "proof material should package proof bytes as base64"
    );
    let verified = verify_bgv_target_decryption_share_proof_material_from_request(&json!({
        "setupPackage": &setup_package,
        "targetAcceptedRecord": &accepted_record,
        "targetCiphertextBinding": &target_ciphertext_binding,
        "targetCiphertexts": &target_ciphertexts,
        "targetShareProfile": &target_share_profile_value,
        "targetDecryptionShare": &local_share,
        "proofStatement": &statement,
        "proofMaterial": &proof_material,
    }))
    .expect("verify target proof material");
    assert_eq!(verified["ok"], true);
    assert_eq!(
        verified["proofMaterialRoot"],
        proof_material["proofMaterialRoot"]
    );

    let mut missing_record_material = proof_material.clone();
    missing_record_material["proofRecords"]
        .as_array_mut()
        .expect("proof records")
        .pop();
    rebind_target_proof_material_root(&mut missing_record_material);
    let error = verify_bgv_target_decryption_share_proof_material_from_request(&json!({
        "setupPackage": &setup_package,
        "targetAcceptedRecord": &accepted_record,
        "targetCiphertextBinding": &target_ciphertext_binding,
        "targetCiphertexts": &target_ciphertexts,
        "targetShareProfile": &target_share_profile_value,
        "targetDecryptionShare": &local_share,
        "proofStatement": &statement,
        "proofMaterial": missing_record_material,
    }))
    .expect_err("missing proof material coverage must reject");
    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(
        error.message.contains("all-active-limb proof record"),
        "{}",
        error.message
    );

    let mut invalid_base64_material = proof_material.clone();
    invalid_base64_material["proofRecords"][0]["proofBytesBase64"] = json!("not canonical base64");
    rebind_target_proof_material_root(&mut invalid_base64_material);
    let error = verify_bgv_target_decryption_share_proof_material_from_request(&json!({
        "setupPackage": &setup_package,
        "targetAcceptedRecord": &accepted_record,
        "targetCiphertextBinding": &target_ciphertext_binding,
        "targetCiphertexts": &target_ciphertexts,
        "targetShareProfile": &target_share_profile_value,
        "targetDecryptionShare": &local_share,
        "proofStatement": &statement,
        "proofMaterial": invalid_base64_material,
    }))
    .expect_err("malformed base64 proof bytes must reject");
    assert!(
        error.message.contains("proofBytesBase64"),
        "{}",
        error.message
    );

    let mut tampered_proof_material = proof_material;
    let proof_bytes_base64 = tampered_proof_material["proofRecords"][0]["proofBytesBase64"]
        .as_str()
        .expect("proof bytes base64")
        .to_string();
    let mut proof_bytes =
        decode_standard_base64(&proof_bytes_base64, "target-decryption proofBytesBase64")
            .expect("target proof bytes");
    proof_bytes[0] ^= 1;
    tampered_proof_material["proofRecords"][0]["proofBytesBase64"] =
        json!(encode_standard_base64(&proof_bytes));
    rebind_target_proof_material_root(&mut tampered_proof_material);
    let error = verify_bgv_target_decryption_share_proof_material_from_request(&json!({
        "setupPackage": &setup_package,
        "targetAcceptedRecord": &accepted_record,
        "targetCiphertextBinding": &target_ciphertext_binding,
        "targetCiphertexts": &target_ciphertexts,
        "targetShareProfile": &target_share_profile_value,
        "targetDecryptionShare": &local_share,
        "proofStatement": &statement,
        "proofMaterial": tampered_proof_material,
    }))
    .expect_err("tampered proof bytes must reject");
    assert!(
        error.message.contains("proof") || error.message.contains("transcript"),
        "{}",
        error.message
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

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("restored local witness relation"));
}

#[test]
fn target_share_proof_relation_rejects_rebound_wrong_smudging_report() {
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
    let maximum_absolute_noise_share = local_share["sharePayload"]["smudgingInputReport"]
        ["roleReports"][0]["limbReports"][0]["maximumAbsoluteNoiseShare"]
        .as_u64()
        .expect("maximum absolute noise share");
    local_share["sharePayload"]["smudgingInputReport"]["roleReports"][0]["limbReports"][0]["maximumAbsoluteNoiseShare"] =
        json!(if maximum_absolute_noise_share == 0 {
            1
        } else {
            0
        });
    rebind_target_share_smudging_report_hash(&mut local_share);
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
    .expect_err("rebound wrong smudging report must not satisfy the relation");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("restored local witness relation"));
}

#[test]
fn target_share_proof_relation_rejects_wrong_smudging_opening_seed() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut local_target_share_witness_value = local_target_share_witness(
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
    let original_seed =
        local_target_share_witness_value["targetDecryptionSmudging"]["smudgingSeedHex"]
            .as_str()
            .expect("smudging seed")
            .to_string();
    local_target_share_witness_value["targetDecryptionSmudging"]["smudgingSeedHex"] =
        json!(if original_seed == "1".repeat(128) {
            "2".repeat(128)
        } else {
            "1".repeat(128)
        });

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
    .expect_err("wrong smudging opening seed must not satisfy the relation");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
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
fn target_share_proof_statement_binding_rejects_rebound_wrong_active_binding_root() {
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
    statement["compactAggregateOpeningBinding"]["activeCredentialBindingRoot"] =
        json!("0".repeat(128));
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
    .expect_err("wrong active credential binding root must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("active credential binding root"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_share_linkage_root() {
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
    statement["compactAggregateOpeningBinding"]["shareLinkageStatementRoot"] =
        json!("0".repeat(128));
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
    .expect_err("wrong compact share-linkage statement root must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("share-linkage statement root"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_accepted_compact_aggregate_record_mismatch()
{
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
    statement["compactAggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitmentRoot"] =
        json!("0".repeat(128));
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
    .expect_err("wrong accepted compact aggregate record root must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("accepted aggregate commitment record")
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
    let first_coordinate = statement["compactAggregateOpeningBinding"]["activeCredentialBindings"]
        [0]["aggregateCommitment"]["commitmentLimbs"][0]["coordinates"][0]
        .as_u64()
        .expect("first aggregate commitment coordinate");
    let first_modulus = statement["compactAggregateOpeningBinding"]["activeCredentialBindings"][0]
        ["aggregateCommitment"]["commitmentLimbs"][0]["modulus"]
        .as_u64()
        .expect("first aggregate commitment modulus");
    statement["compactAggregateOpeningBinding"]["activeCredentialBindings"][0]["aggregateCommitment"]
        ["commitmentLimbs"][0]["coordinates"][0] = json!((first_coordinate + 1) % first_modulus);
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
    .expect_err("wrong compact aggregate commitment body must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("commitment body"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_share_root() {
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
    statement["shareRoot"] = json!("0".repeat(128));
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
    .expect_err("wrong share root must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("proof statement"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_target_decryption_ciphertext_hash() {
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
    statement["targetDecryptionCiphertextHash"] = json!("0".repeat(128));
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
    .expect_err("wrong target-decryption ciphertext hash must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("proof statement"));
}

#[test]
fn target_share_proof_statement_binding_rejects_wrong_target_ciphertext_binding() {
    let (setup_package, accepted_record, mut target_ciphertext_binding, target_ciphertexts) =
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
    target_ciphertext_binding["aggregateCiphertextRoot"] = json!("b".repeat(128));

    let error = verify_share_proof_statement_binding(TargetShareProofStatementBindingInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("wrong target ciphertext binding must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("accepted target ciphertext hash"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_smudging_report_hash() {
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
    statement["smudgingInputReportHash"] = json!("0".repeat(128));
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
    .expect_err("wrong smudging report hash must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("proof statement"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_wrong_smudging_commitment_binding_root() {
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
    statement["smudgingCommitmentBinding"]["smudgingCommitmentSetRoot"] = json!("0".repeat(128));
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
    .expect_err("wrong smudging commitment binding root must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("smudging commitment binding root"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_malformed_smudging_commitment_coordinate() {
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
    let first_commitment_modulus = statement["smudgingCommitmentBinding"]["smudgingCommitmentSet"]
        ["commitmentRecords"][0]["commitment"]["commitmentLimbs"][0]["modulus"]
        .as_u64()
        .expect("first smudging commitment modulus");
    statement["smudgingCommitmentBinding"]["smudgingCommitmentSet"]["commitmentRecords"][0]["commitment"]
        ["commitmentLimbs"][0]["coordinates"][0] = json!(first_commitment_modulus);
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
    .expect_err("malformed smudging commitment coordinate must be refused");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("coordinate is outside"));
}

#[test]
fn target_share_proof_statement_binding_rejects_rebound_missing_active_binding() {
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
    statement["compactAggregateOpeningBinding"]["activeCredentialBindings"]
        .as_array_mut()
        .expect("active credential bindings")
        .remove(0);
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
    .expect_err("missing active compact opening binding must be refused");

    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(error.message.contains("one active credential binding"));
}

#[test]
fn target_share_proof_statement_rejects_share_not_restored_from_local_witness() {
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
    let other_trustee_share = generate_share_from_fresh_local_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-2",
    );

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &local_target_share_witness_value,
        target_decryption_share: &other_trustee_share,
        trustee_identity: "trustee-1",
    })
    .expect_err("share must match local witness");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("restored local witness relation"));
}

#[test]
fn target_share_proof_statement_rejects_wrong_witness_target_basis() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    witness["compactAggregateOpening"]["targetBasisHash"] = json!("0".repeat(128));
    let local_share = generate_share_from_fresh_local_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &witness,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect_err("wrong target basis must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("target basis"));
}

#[test]
fn target_share_proof_statement_rejects_missing_compact_opening_credential() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"]
        .as_array_mut()
        .expect("compact aggregate opening credentials")
        .remove(0);
    let local_share = generate_share_from_fresh_local_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let error = derive_share_proof_statement(TargetShareProofStatementInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        local_target_share_witness_value: &witness,
        target_decryption_share: &local_share,
        trustee_identity: "trustee-1",
    })
    .expect_err("missing compact opening credential must be refused");

    assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
    assert!(error.message.contains("missing active"));
}

#[test]
fn local_target_share_witness_rejects_wrong_target_basis() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    witness["compactAggregateOpening"]["targetBasisHash"] = json!("0".repeat(128));

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong target basis must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("target basis"));
}

#[test]
fn local_target_share_witness_rejects_wrong_public_matrix_seed_hash() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    witness["compactAggregateOpening"]["publicMatrixSeedHash"] = json!("0".repeat(128));

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong public matrix seed hash must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("public matrix seed"));
}

#[test]
fn local_target_share_witness_requires_accepted_compact_aggregate_set() {
    let (mut setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    setup_package
        .as_object_mut()
        .expect("setup package")
        .remove("compactVssAggregateThresholdCommitmentSet");

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("missing accepted compact aggregate set must be refused");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("accepted compact aggregate"));
}

#[test]
fn local_target_share_witness_rejects_accepted_compact_aggregate_record_mismatch() {
    let (mut setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    let aggregate_set = setup_package
        .get_mut("compactVssAggregateThresholdCommitmentSet")
        .expect("compact aggregate threshold commitment set");
    let replacement_record_index = aggregate_set["rnsLimbCount"]
        .as_u64()
        .expect("aggregate set RNS limb count") as usize;
    let replacement_record = aggregate_set["recipientRecords"][replacement_record_index].clone();
    aggregate_set["recipientRecords"][0]["aggregateCommitmentRoot"] =
        replacement_record["aggregateCommitmentRoot"].clone();
    aggregate_set["recipientRecords"][0]["commitment"] = replacement_record["commitment"].clone();
    rebind_compact_aggregate_threshold_commitment_set_root(aggregate_set);
    witness["compactAggregateOpening"]["aggregateThresholdCommitmentRoot"] =
        aggregate_set["aggregateThresholdCommitmentRoot"].clone();

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("mismatched accepted compact aggregate record must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("accepted aggregate commitment record")
    );
}

#[test]
fn local_target_share_witness_rejects_wrong_smudging_binding() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    witness["targetDecryptionSmudging"]["targetShareProfileHash"] = json!("0".repeat(128));

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong smudging binding must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("smudging witness"));
}

#[test]
fn local_target_share_witness_rejects_wrong_trustee() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-2",
    }))
    .expect_err("wrong trustee must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("trustee identity"));
}

#[test]
fn local_target_share_witness_rejects_wrong_compact_aggregate_message() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    replace_u64_le_hex_word(
        &mut witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"][0]["aggregateCommitmentMessageValuesLeHex"],
        0,
        DATA_PRIMES[0] - 1,
    );

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong compact aggregate message must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("opening root"), "{}", error.message);
}

#[test]
fn local_target_share_witness_rejects_wrong_compact_opening_randomness() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let mut witness = local_target_share_witness(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
    {
        let randomness_column = witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"]
            [0]["aggregateRandomnessByColumnSignedByteHex"][0]
            .as_str()
            .expect("randomness column")
            .to_string();
        let mut randomness_columns = witness["compactAggregateOpening"]
            ["compactAggregateOpeningCredentials"][0]["aggregateRandomnessByColumnSignedByteHex"]
            .as_array()
            .expect("randomness columns")
            .clone();
        let mut first_column = json!(randomness_column);
        replace_signed_byte_hex(&mut first_column, 0, 1);
        randomness_columns[0] = first_column;
        witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"][0]["aggregateRandomnessByColumnSignedByteHex"] =
            json!(randomness_columns);
    }

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong compact aggregate opening randomness must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("compact aggregate opening credential")
    );
}
