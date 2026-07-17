use super::share_linkage::*;
use super::*;

pub(in super::super::super) fn vss_public_coefficient_commitment_set_object(
    package: &serde_json::Value,
    ring_degree: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let threshold_degree = decryption_threshold_for_participant_count(participant_count);
    let source_trustee_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_source_coefficient_record(
                setup_context,
                ring_degree,
                threshold_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    })
}

pub(super) fn vss_public_source_coefficient_record(
    setup_context: &serde_json::Value,
    ring_degree: usize,
    threshold_degree: u64,
    source_trustee_roster_position: u64,
) -> serde_json::Value {
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let coefficient_commitments = DATA_PRIMES
        .iter()
        .copied()
        .enumerate()
        .flat_map(|(rns_limb_index, rns_prime)| {
            let source_trustee_identity = source_trustee_identity.clone();
            (0..threshold_degree).map(move |shamir_coefficient_index| {
                vss_public_coefficient_commitment_record(
                    setup_context,
                    ring_degree,
                    &source_trustee_identity,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                )
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "coefficientCommitments": coefficient_commitments,
    })
}

pub(in super::super::super) fn vss_public_coefficient_commitment_record(
    setup_context: &serde_json::Value,
    ring_degree: usize,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    shamir_coefficient_index: u64,
) -> serde_json::Value {
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    let coefficient_message = accepted_vss_coefficient_message_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        rns_prime,
        ring_degree,
    );
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentContext",
        "setupContextHash": setup_context_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": shamir_coefficient_index,
    });
    let context_hash = accepted_committed_material_context_hash("coefficient", &commitment_context);
    let material_seed_hex = accepted_vss_material_seed(&context_hash);
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: "coefficient",
            commitment_context: &commitment_context,
            rns_limb_index,
            message_coefficients: &coefficient_message,
            material_seed_hex: &material_seed_hex,
        },
    )
    .expect("VSS coefficient committed-material commitment");

    computation.commitment
}

pub(in super::super::super) fn vss_public_recipient_share_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let source_trustee_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_source_recipient_share_record(
                package,
                ring_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    })
}

pub(super) fn vss_public_source_recipient_share_record(
    package: &serde_json::Value,
    ring_degree: usize,
    source_trustee_roster_position: u64,
) -> serde_json::Value {
    let participant_count = participant_count_from_package(package);
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let recipient_share_commitments = (0..participant_count)
        .flat_map(|recipient_roster_position| {
            let source_trustee_identity = source_trustee_identity.clone();
            (0..DATA_PRIMES.len()).map(move |rns_limb_index| {
                vss_public_recipient_share_commitment_record(
                    package,
                    ring_degree,
                    &source_trustee_identity,
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "recipientShareCommitments": recipient_share_commitments,
    })
}

pub(super) fn vss_public_recipient_share_commitment_record(
    package: &serde_json::Value,
    ring_degree: usize,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    let rns_prime = DATA_PRIMES[rns_limb_index];
    let threshold_degree = vss_fixture_threshold_degree(package);
    let (share_coefficients, _carry_witnesses) = vss_public_recipient_share_values_and_carries(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        threshold_degree,
        rns_prime,
        ring_degree,
    );
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitmentContext",
        "setupContextHash": setup_context_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    });
    let context_hash =
        accepted_committed_material_context_hash("recipient-share", &commitment_context);
    let material_seed_hex = accepted_vss_material_seed(&context_hash);
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: "recipient-share",
            commitment_context: &commitment_context,
            rns_limb_index,
            message_coefficients: &share_coefficients,
            material_seed_hex: &material_seed_hex,
        },
    )
    .expect("VSS recipient-share committed-material commitment");

    computation.commitment
}

pub(in super::super::super) fn vss_public_aggregate_threshold_commitment_set_object(
    package: &serde_json::Value,
) -> VssProofMaterialSetFixture {
    let participant_count = participant_count_from_package(package);
    let recipient_coordinates = (0..participant_count)
        .flat_map(|recipient_roster_position| {
            (0..DATA_PRIMES.len())
                .map(move |rns_limb_index| (recipient_roster_position, rns_limb_index))
        })
        .collect::<Vec<_>>();
    let mut aggregate_set =
        vss_public_aggregate_threshold_commitment_set_without_proofs_for_coordinates(
            package,
            &recipient_coordinates,
        );
    let aggregate_threshold_proofs = super::aggregate_threshold::vss_aggregate_threshold_proofs(
        package,
        &aggregate_set,
        &recipient_coordinates,
    );
    aggregate_set["aggregateThresholdProofBytesHashes"] =
        serde_json::json!(aggregate_threshold_proofs.proof_bytes_hashes);

    VssProofMaterialSetFixture {
        value: aggregate_set,
        proof_binding_leases: aggregate_threshold_proofs.proof_binding_leases,
    }
}

pub(super) fn vss_public_aggregate_threshold_commitment_set_without_proofs_for_coordinates(
    package: &serde_json::Value,
    recipient_coordinates: &[(u64, usize)],
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let recipient_records = recipient_coordinates
        .iter()
        .map(|&(recipient_roster_position, rns_limb_index)| {
            vss_public_aggregate_threshold_commitment_record(
                package,
                ring_degree,
                recipient_roster_position,
                rns_limb_index,
            )
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientRecords": recipient_records,
    })
}

pub(super) fn vss_public_aggregate_threshold_commitment_record(
    package: &serde_json::Value,
    ring_degree: usize,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let participant_count = participant_count_from_package(package);
    let threshold_degree = vss_fixture_threshold_degree(package);
    let rns_prime = DATA_PRIMES[rns_limb_index];
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    // The threshold share is the modular sum of every source's recipient share
    // for this recipient and limb. The committed-material bodies carry no public
    // coordinates, so recompute the summands from the same deterministic fixture
    // the recipient-share records commit, then reduce modulo the limb prime.
    // The "T = sum" binding is proved by the threshold-aggregate proof, not by
    // this record.
    let mut aggregate_message = vec![0_u64; ring_degree];
    for source_trustee_roster_position in 0..participant_count {
        let (share_values, _carries) = vss_public_recipient_share_values_and_carries(
            source_trustee_roster_position,
            recipient_roster_position,
            rns_limb_index,
            threshold_degree,
            rns_prime,
            ring_degree,
        );
        for (accumulator, value) in aggregate_message.iter_mut().zip(share_values.iter()) {
            *accumulator =
                ((u128::from(*accumulator) + u128::from(*value)) % u128::from(rns_prime)) as u64;
        }
    }
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitmentContext",
        "setupContextHash": crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
            .expect("setup context hash"),
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    });
    let context_hash =
        accepted_committed_material_context_hash("aggregate-threshold-share", &commitment_context);
    let material_seed_hex = accepted_vss_material_seed(&context_hash);
    let computation = crate::bgv::setup::compute_vss_committed_material_commitment(
        crate::bgv::setup::VssCommittedMaterialCommitmentInput {
            commitment_role: "aggregate-threshold-share",
            commitment_context: &commitment_context,
            rns_limb_index,
            message_coefficients: &aggregate_message,
            material_seed_hex: &material_seed_hex,
        },
    )
    .expect("VSS aggregate committed-material commitment");

    serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "aggregateOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    })
}
