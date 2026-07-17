use super::*;

// Keep the specified four-limb structural grouping so fixture coverage remains
// explicit and deterministic. These records carry invalid proof bytes hashes;
// they do not claim that the grouped relation has passed common-proof
// verification.
const VSS_SHARE_LINKAGE_RNS_LIMBS_PER_PROOF_RECORD: usize = 4;

pub(in super::super::super) fn vss_share_linkage_statement_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let ring_degree = vss_commitment_ring_degree_from_fixture_package(package);
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
        .expect("setup context hash");
    serde_json::json!({
        "objectType": "VssShareLinkageStatement",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
    })
}

pub(in super::super::super) fn vss_share_linkage_proof_material_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let participant_count = participant_count_from_package(package);
    let proof_record_fixtures = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            vss_share_linkage_proof_records(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "VssShareLinkageProofMaterialSet",
        "proofRecords": proof_record_fixtures,
    })
}

pub(super) fn vss_share_linkage_proof_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let item_records = vss_share_linkage_item_records(package, source_trustee_roster_position);
    let participant_count: usize = participant_count_from_package(package)
        .try_into()
        .expect("participant count fits usize");
    let proof_items_per_record = participant_count
        .checked_mul(VSS_SHARE_LINKAGE_RNS_LIMBS_PER_PROOF_RECORD)
        .expect("VSS share-linkage proof item count");
    item_records
        .chunks(proof_items_per_record)
        .enumerate()
        .map(|(proof_record_index, item_records)| {
            vss_share_linkage_proof_record(
                package,
                source_trustee_roster_position,
                proof_record_index,
                item_records,
            )
        })
        .collect()
}

pub(super) fn vss_share_linkage_proof_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let verification_input = serde_json::json!({
        "statement": package["vssShareLinkageStatement"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
        "coverage": item_records,
    });
    let proof_bytes_hash = invalid_common_proof_fixture_hash(
        VSS_SHARE_LINKAGE_PROOF_FAMILY,
        VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
        &verification_input,
    );
    serde_json::json!({
        "objectType": "VssShareLinkageProofRecord",
        "coverage": item_records,
        "proofBytesHash": proof_bytes_hash,
    })
}

pub(super) fn vss_share_linkage_item_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let participant_count = participant_count_from_package(package);
    (0..DATA_PRIMES.len())
        .flat_map(|rns_limb_index| {
            (0..participant_count).map(move |recipient_roster_position| {
                vss_share_linkage_item_record(
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect()
}

pub(super) fn vss_share_linkage_item_record(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    serde_json::json!({
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
    })
}

pub(super) fn vss_public_recipient_share_values(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    threshold_degree: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    let recipient_trustee_point = crate::bgv::setup::sharing::canonical_trustee_point(
        recipient_roster_position as usize,
        rns_prime,
    )
    .expect("recipient trustee point");
    let coefficient_messages = (0..threshold_degree)
        .map(|shamir_coefficient_index| {
            accepted_vss_coefficient_message_fixture(
                source_trustee_roster_position,
                rns_limb_index,
                shamir_coefficient_index,
                rns_prime,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let mut trustee_point_powers = Vec::with_capacity(threshold_degree as usize);
    let mut trustee_point_power = 1_u128;
    for _ in 0..threshold_degree {
        trustee_point_powers.push(trustee_point_power);
        trustee_point_power = trustee_point_power
            .checked_mul(u128::from(recipient_trustee_point))
            .expect("recipient trustee point power");
    }
    let mut share_coefficients = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let lifted_share = coefficient_messages
            .iter()
            .zip(trustee_point_powers.iter())
            .fold(0_u128, |sum, (messages, point_power)| {
                sum + u128::from(messages[coefficient_position]) * *point_power
            });
        share_coefficients.push((lifted_share % u128::from(rns_prime)) as u64);
    }

    share_coefficients
}
