use super::*;
use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    evaluator::records::target_layout_hash,
    evaluator::top_k::{
        CANONICAL_TARGET_CIPHERTEXT_LEVEL, canonical_target_basis_hash,
        canonicalize_target_ciphertext,
    },
    profile::{direct_comparison_profile_hash, profile_hash},
    setup::generate_passive_setup_package_from_request,
};

mod recombination;

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
        "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileBindingHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileBindingHash"],
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
        "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
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
    let setup_package = setup_package();
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

fn generate_share(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    generate_bgv_target_decryption_share_from_request(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": "target-decryption-setup-seed",
        },
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": trustee_identity,
    }))
    .expect("generate share")
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

struct TargetShareProofStatementVerificationInput<'a> {
    setup_package: &'a Value,
    accepted_record: &'a Value,
    target_ciphertext_binding: &'a Value,
    target_ciphertexts: &'a Value,
    target_share_profile: &'a Value,
    target_decryption_share: &'a Value,
    proof_statement: &'a Value,
}

fn verify_share_proof_statement(
    input: TargetShareProofStatementVerificationInput<'_>,
) -> CanonicalResult<Value> {
    verify_bgv_target_decryption_share_proof_statement_from_request(&json!({
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
    let public_matrix_seed_hash = "3".repeat(128);
    let share_linkage_statement_root = "4".repeat(128);
    let aggregate_threshold_commitment_root = "5".repeat(128);
    let compact_aggregate_opening_credentials = share_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, share_values)| {
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let (aggregate_commitment_root, aggregate_opening_root) =
                compute_compact_aggregate_opening_roots(CompactAggregateOpeningRootsInput {
                    setup_binding: &setup_binding,
                    participant,
                    setup_epoch,
                    public_matrix_seed_hash: &public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime: DATA_PRIMES[rns_limb_index],
                    aggregate_share_values: share_values,
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
                "rnsPrime": DATA_PRIMES[rns_limb_index],
                "aggregateCommitmentRoot": aggregate_commitment_root,
                "aggregateOpeningRoot": aggregate_opening_root,
                "aggregateShareValues": share_values,
                "aggregateRandomnessByColumn": aggregate_randomness_by_column,
                "sourceShareOpeningRoots": [],
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
        "witnessOwnership": TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP,
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
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": canonical_target_basis_hash().expect("target basis hash"),
            "shareLinkageStatementRoot": share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
            "compactAggregateOpeningCredentials": compact_aggregate_opening_credentials,
        },
    })
}

#[test]
fn local_target_share_witness_generates_same_share_as_seed_path() {
    let (setup_package, accepted_record, target_ciphertext_binding, target_ciphertexts) =
        target_fixture();
    let target_share_profile = target_share_profile(&setup_package);
    let seed_share = generate_share(
        &setup_package,
        &accepted_record,
        &target_ciphertext_binding,
        &target_ciphertexts,
        &target_share_profile,
        "trustee-1",
    );
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

    assert_eq!(local_share, seed_share);
    assert_eq!(
        local_share["sharePayload"]["smudgingInputReport"]["objectType"],
        json!("TargetDecryptionSmudgingInputReport")
    );
    assert_eq!(
        local_share["sharePayload"]["smudgingInputReport"]["smudgingProfileId"],
        json!(TARGET_DECRYPTION_SMUDGING_PROFILE_ID)
    );
    assert_eq!(
        local_share["sharePayload"]["smudgingInputReport"]["zeroSharingRule"],
        json!(TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE)
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
        statement["oneShotTargetContextRule"],
        json!(TARGET_DECRYPTION_ONE_SHOT_CONTEXT_RULE)
    );
    assert_eq!(
        statement["restoredWitnessOwnershipRule"],
        json!(TARGET_DECRYPTION_RESTORED_WITNESS_RULE)
    );
    assert_eq!(
        statement["targetBasisRule"],
        json!(TARGET_DECRYPTION_TARGET_BASIS_RULE)
    );
    assert_eq!(
        statement["smudgingRequirement"],
        json!(TARGET_DECRYPTION_SMUDGING_REQUIREMENT)
    );
    assert_eq!(
        statement["recombinationRequirement"],
        json!(TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT)
    );
    assert_eq!(
        statement["proofBoundary"],
        json!(TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY)
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["witnessOwnership"],
        json!(TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP)
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["publicMatrixSeedHash"],
        json!("3".repeat(128))
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["shareLinkageStatementRoot"],
        json!("4".repeat(128))
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["aggregateThresholdCommitmentRoot"],
        json!("5".repeat(128))
    );
    assert_eq!(
        statement["compactAggregateOpeningBinding"]["activeCredentialBindings"]
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
        json!(
            derive_protocol_hash("BgvTargetDecryptionShareProofStatementRoot", &root_input)
                .expect("statement root")
        )
    );
}

#[test]
fn target_share_proof_statement_verifier_accepts_bound_statement() {
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

    let verification = verify_share_proof_statement(TargetShareProofStatementVerificationInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect("target share proof statement verification");

    assert_eq!(verification["ok"], json!(true));
    assert_eq!(
        verification["operation"],
        json!("verifyBgvTargetDecryptionShareProofStatement")
    );
    assert_eq!(
        verification["proofStatementRoot"],
        statement["proofStatementRoot"]
    );
    assert_eq!(
        verification["targetDecryptionShareHash"],
        local_share["targetDecryptionShareHash"]
    );
    assert_eq!(
        verification["smudgingInputReportHash"],
        local_share["sharePayload"]["smudgingInputReportHash"]
    );
    assert_eq!(
        verification["smudgingRequirement"],
        json!(TARGET_DECRYPTION_SMUDGING_REQUIREMENT)
    );
    assert_eq!(
        verification["recombinationRequirement"],
        json!(TARGET_DECRYPTION_RECOMBINATION_REQUIREMENT)
    );
    assert_eq!(
        verification["proofBoundary"],
        json!(TARGET_DECRYPTION_SHARE_PROOF_BOUNDARY)
    );
}

#[test]
fn target_share_proof_statement_verifier_rejects_rebound_wrong_share_root() {
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

    let error = verify_share_proof_statement(TargetShareProofStatementVerificationInput {
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
fn target_share_proof_statement_verifier_rejects_rebound_weakened_proof_boundary() {
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
    statement["proofBoundary"] = json!("statement binding only");
    rebind_share_proof_statement_root(&mut statement);

    let error = verify_share_proof_statement(TargetShareProofStatementVerificationInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("weakened proof boundary must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("proof statement"));
}

#[test]
fn target_share_proof_statement_verifier_rejects_rebound_obligation_change() {
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
    statement["smudgingRequirement"] = json!("released decryption shares require no smudging");
    rebind_share_proof_statement_root(&mut statement);

    let error = verify_share_proof_statement(TargetShareProofStatementVerificationInput {
        setup_package: &setup_package,
        accepted_record: &accepted_record,
        target_ciphertext_binding: &target_ciphertext_binding,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        target_decryption_share: &local_share,
        proof_statement: &statement,
    })
    .expect_err("changed target-decryption obligation must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("obligation"));
}

#[test]
fn target_share_proof_statement_verifier_rejects_rebound_missing_active_binding() {
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

    let error = verify_share_proof_statement(TargetShareProofStatementVerificationInput {
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
    let other_trustee_share = generate_share(
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
    assert!(error.message.contains("restored from local witness"));
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
    let local_share = generate_share(
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
    let local_share = generate_share(
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
fn local_target_share_witness_rejects_wrong_ownership_boundary() {
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
    witness["witnessOwnership"] = json!("source-owned-dealer-state");

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("wrong ownership boundary must be refused");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("witness ownership"));
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
fn local_target_share_witness_rejects_noncanonical_limb_value() {
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
    witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"][0]["aggregateShareValues"]
        [0] = json!(DATA_PRIMES[0]);

    let error = generate_bgv_target_decryption_share_from_local_share_request(&json!({
        "setupPackage": setup_package,
        "localTargetShareWitness": witness,
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": "trustee-1",
    }))
    .expect_err("non-canonical limb value must be refused");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("non-canonical residue"));
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
    witness["compactAggregateOpening"]["compactAggregateOpeningCredentials"][0]["aggregateRandomnessByColumn"]
        [0][0] = json!(1);

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
