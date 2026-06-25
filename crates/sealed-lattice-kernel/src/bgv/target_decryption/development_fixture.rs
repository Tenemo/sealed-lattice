use super::*;

use crate::bgv::{
    evaluator::{
        engine::{
            ciphertext_canonical_bytes_hex, ciphertext_object_root, encode_slots_to_coefficients,
        },
        records::{MAXIMUM_OPTION_COUNT, target_layout_hash},
        top_k::{
            CANONICAL_TARGET_CIPHERTEXT_LEVEL, canonical_target_basis_hash,
            canonicalize_target_ciphertext, packed_score_slot,
        },
    },
    profile::{DATA_PRIMES, POLYNOMIAL_DEGREE, direct_comparison_profile_hash},
    setup::generate_passive_setup_package_from_request,
};

const DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED: &str = "target-decryption-development-fixture-seed";
const DEVELOPMENT_TARGET_DECRYPTION_SETUP_EPOCH: &str = "target-decryption-development-fixture";
const DEVELOPMENT_TARGET_DECRYPTION_TRUSTEE_IDENTITY: &str = "trustee-1";

pub(crate) fn generate_bgv_target_decryption_fixture_from_request(
    _request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = development_setup_package()?;
    let setup_binding = read_setup_binding(&setup_package)?;
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED,
    )?;
    let target_share_profile_record = development_target_share_profile(&setup_binding)?;
    let target_share_profile =
        read_target_share_profile(&target_share_profile_record, &setup_binding)?;
    let (target_accepted_record, target_ciphertext_binding, target_ciphertexts) =
        development_target_records(&setup_package, &evaluator_key)?;
    let target_accepted = read_target_accepted_binding(&target_accepted_record, &setup_binding)?;
    let target_ciphertext_pair = read_target_ciphertext_pair(
        &target_ciphertexts,
        &target_ciphertext_binding,
        &target_accepted,
    )?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| {
            candidate.trustee_identity == DEVELOPMENT_TARGET_DECRYPTION_TRUSTEE_IDENTITY
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "development target-decryption fixture trustee is missing from setup",
            )
        })?;
    let local_target_share_witness = development_local_target_share_witness(
        &setup_binding,
        &target_accepted,
        &target_ciphertext_pair,
        &target_share_profile,
        participant,
        &evaluator_key,
    )?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionDevelopmentFixture",
        "objectVersion": 1,
        "fixtureScope": "development-target-decryption-command-parity",
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED,
        },
        "targetAcceptedRecord": target_accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile_record,
        "trusteeIdentity": DEVELOPMENT_TARGET_DECRYPTION_TRUSTEE_IDENTITY,
        "localTargetShareWitness": local_target_share_witness,
    }))
}

fn development_setup_package() -> CanonicalResult<Value> {
    generate_passive_setup_package_from_request(&json!({
        "ceremonyId": "target-decryption-development-fixture",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &json!({ "manifest": "target decryption development fixture" }),
        )?,
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &json!({ "roster": "target decryption development fixture" }),
        )?,
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
            &json!({ "threshold": "target decryption development fixture" }),
        )?,
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
        ],
        "setupSeed": DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED,
    }))
}

fn development_target_share_profile(setup_binding: &SetupBinding) -> CanonicalResult<Value> {
    let profile_without_hash = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "thresholdProfileHash": setup_binding.threshold_profile_hash,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": setup_binding.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "decryptionThreshold": 2,
        "minimumSharesForInterpolation": 2,
        "decryptionShareQuorum": 2,
    });
    let mut profile = profile_without_hash;
    profile["targetShareProfileHash"] = json!(derive_protocol_hash(
        "TargetDecryptionShareProfileHash",
        &profile
    )?);

    Ok(profile)
}

fn development_target_records(
    setup_package: &Value,
    evaluator_key: &DevelopmentBgvKey,
) -> CanonicalResult<(Value, Value, Value)> {
    let mut target_ids = vec![0_u64; POLYNOMIAL_DEGREE];
    let mut target_orders = vec![0_u64; POLYNOMIAL_DEGREE];
    target_ids[packed_score_slot(0)] = 1;
    target_ids[packed_score_slot(2)] = 3;
    target_orders[packed_score_slot(0)] = 1;
    target_orders[packed_score_slot(2)] = 2;

    let target_id = development_canonical_target_ciphertext(
        evaluator_key,
        &target_ids,
        "target-decryption-development-fixture-id",
    )?;
    let target_order = development_canonical_target_ciphertext(
        evaluator_key,
        &target_orders,
        "target-decryption-development-fixture-order",
    )?;
    let target_id_root = ciphertext_object_root(&target_id)?;
    let target_order_root = ciphertext_object_root(&target_order)?;
    let aggregate_ciphertext_root = "a".repeat(128);
    let top_count = 2;
    let target_layout_hash = target_layout_hash(MAXIMUM_OPTION_COUNT)?;
    let target_basis_hash = canonical_target_basis_hash()?;
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        &aggregate_ciphertext_root,
        top_count,
        &target_layout_hash,
        &target_basis_hash,
        &target_id_root,
        &target_order_root,
    )?;
    let target_accepted_record = development_target_accepted_record(
        setup_package,
        &target_ciphertext_hash,
        &target_layout_hash,
        &target_basis_hash,
    )?;

    Ok((
        target_accepted_record,
        json!({
            "aggregateCiphertextRoot": aggregate_ciphertext_root,
            "topCount": top_count,
            "targetLayoutHash": target_layout_hash,
            "targetBasisHash": target_basis_hash,
        }),
        json!({
            "targetIdCanonicalBytesHex": ciphertext_canonical_bytes_hex(&target_id)?,
            "targetOrderCanonicalBytesHex": ciphertext_canonical_bytes_hex(&target_order)?,
        }),
    ))
}

fn development_canonical_target_ciphertext(
    evaluator_key: &DevelopmentBgvKey,
    slots: &[u64],
    seed: &str,
) -> CanonicalResult<Ciphertext> {
    let coefficients = encode_slots_to_coefficients(slots)?;
    let (ciphertext, _) = evaluator_key.encrypt_coefficients_with_witness(&coefficients, seed)?;
    let target_ciphertext = canonicalize_target_ciphertext(&ciphertext)?;
    if target_ciphertext.level != CANONICAL_TARGET_CIPHERTEXT_LEVEL {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "development target ciphertext did not reach the canonical target level",
        ));
    }

    Ok(target_ciphertext)
}

fn development_target_accepted_record(
    setup_package: &Value,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
    target_basis_hash: &str,
) -> CanonicalResult<Value> {
    let mut record = json!({
        "objectType": "TargetAcceptedRecord",
        "objectVersion": 1,
        "ceremonyId": setup_package["setupInputs"]["ceremonyId"],
        "electionManifestHash": setup_package["setupInputs"]["manifestHash"],
        "targetProposalHash": derive_protocol_hash(
            "TargetProposalHash",
            &json!({ "target": "development accepted target" }),
        )?,
        "evaluatorReplayRecordHash": derive_protocol_hash(
            "EvaluatorReplayRecordHash",
            &json!({ "replay": "development accepted target" }),
        )?,
        "targetContextHash": derive_protocol_hash(
            "TargetContextHash",
            &json!({ "context": "development accepted target" }),
        )?,
        "targetFinalityRecordHash": derive_protocol_hash(
            "TargetFinalityRecordHash",
            &json!({ "finality": "development record" }),
        )?,
        "targetFinalityCheckpointHash": derive_protocol_hash(
            "TargetFinalityCheckpointHash",
            &json!({ "finality": "development checkpoint" }),
        )?,
        "evaluatorReplayProfileHash": direct_comparison_profile_hash()?,
        "targetPreimageHash": derive_protocol_hash(
            "TargetPreimageHash",
            &json!({ "preimage": "development accepted target" }),
        )?,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetBasisHash": target_basis_hash,
        "boardSequence": 0,
        "boardPosition": 0,
        "organizerIdentity": "organizer",
    });
    record["targetAcceptedRecordHash"] =
        json!(derive_protocol_hash("TargetAcceptedRecordHash", &record)?);

    Ok(record)
}

fn development_local_target_share_witness(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    evaluator_key: &DevelopmentBgvKey,
) -> CanonicalResult<Value> {
    let share_by_limb = derive_threshold_secret_share_by_limb(
        evaluator_key,
        &setup_binding.setup_package_hash,
        &target_share_profile.hash,
        DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        CANONICAL_TARGET_CIPHERTEXT_LEVEL,
    )?;
    let public_matrix_seed_hash = setup_binding.public_matrix_seed_hash.clone();
    let share_linkage_statement_root = "4".repeat(128);
    let aggregate_threshold_commitment_root = "5".repeat(128);
    let compact_aggregate_opening_credentials = share_by_limb
        .iter()
        .enumerate()
        .map(|(rns_limb_index, share_values)| {
            let aggregate_randomness_by_column = vec![vec![0_i64; POLYNOMIAL_DEGREE]; 2];
            let rns_prime = DATA_PRIMES[rns_limb_index];
            let mut aggregate_commitment_message_values = share_values.clone();
            let mut aggregate_share_carry_values = vec![0_u64; POLYNOMIAL_DEGREE];
            aggregate_commitment_message_values[0] += rns_prime;
            aggregate_share_carry_values[0] = 1;
            let message_coefficient_bound = compact_aggregate_message_coefficient_bound(
                rns_prime,
                setup_binding.participants.len(),
            )?;
            let (aggregate_commitment_root, aggregate_opening_root) =
                compute_compact_aggregate_opening_roots(CompactAggregateOpeningRootsInput {
                    setup_binding,
                    participant,
                    setup_epoch: DEVELOPMENT_TARGET_DECRYPTION_SETUP_EPOCH,
                    public_matrix_seed_hash: &public_matrix_seed_hash,
                    rns_limb_index,
                    rns_prime,
                    aggregate_commitment_message_values: &aggregate_commitment_message_values,
                    message_coefficient_bound,
                    aggregate_randomness_by_column: &aggregate_randomness_by_column,
                })?;

            Ok(json!({
                "objectType": "LocalTrusteeCompactVssAggregateOpeningCredential",
                "objectVersion": 1,
                "recipientIdentity": participant.trustee_identity.as_str(),
                "recipientRosterPosition": participant.roster_position,
                "recipientTrusteePoint": participant.interpolation_point,
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "aggregateCommitmentRoot": aggregate_commitment_root,
                "aggregateOpeningRoot": aggregate_opening_root,
                "aggregateShareValues": share_values,
                "aggregateCommitmentMessageValues": aggregate_commitment_message_values,
                "aggregateShareCarryValues": aggregate_share_carry_values,
                "aggregateRandomnessByColumn": aggregate_randomness_by_column,
                "sourceShareOpeningRoots": [],
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(json!({
        "objectType": "LocalTrusteeTargetDecryptionProofWitnessMaterial",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_binding.roster_hash.as_str(),
        "setupProfileHash": setup_binding.setup_profile_hash.as_str(),
        "qShareHash": setup_binding.q_share_hash.as_str(),
        "carryAwareVssShareRelationProfileHash": setup_binding
            .carry_aware_vss_share_relation_profile_hash
            .as_str(),
        "commitmentProfileHash": setup_binding.commitment_profile_hash.as_str(),
        "setupEpoch": DEVELOPMENT_TARGET_DECRYPTION_SETUP_EPOCH,
        "trusteeIdentity": participant.trustee_identity.as_str(),
        "trusteeRosterPosition": participant.roster_position,
        "thresholdShareCommitmentRecipientRoot": "1".repeat(128),
        "aggregateThresholdShareRoot": "2".repeat(128),
        "sourcePrivateEnvelopeReferences": [],
        "witnessOwnership": TARGET_DECRYPTION_RESTORED_WITNESS_OWNERSHIP,
        "targetDecryptionSmudging": target_decryption_smudging_witness_value(
            setup_binding,
            target_accepted,
            target_ciphertexts,
            target_share_profile,
            participant,
            DEVELOPMENT_TARGET_DECRYPTION_SETUP_SEED,
        ),
        "compactAggregateOpening": {
            "objectType": "LocalTrusteeCompactVssAggregateOpeningWitness",
            "objectVersion": 1,
            "profileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "targetBasisHash": canonical_target_basis_hash()?,
            "shareLinkageStatementRoot": share_linkage_statement_root,
            "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
            "compactAggregateOpeningCredentials": compact_aggregate_opening_credentials,
        },
    }))
}
