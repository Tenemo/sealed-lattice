use super::*;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_coefficient_commitment_components(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    participant_count: u64,
) -> VssMaterialPackageComponents {
    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&serde_json::json!({
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": participant_count,
        }))
        .expect("setup context hash");
    let decryption_threshold = decryption_threshold_for_participant_count(participant_count);
    let mut source_trustee_records = Vec::new();
    let mut public_source_trustee_records = Vec::new();
    let mut coefficient_commitment_material = Vec::new();

    for source_trustee_roster_position in 0..participant_count {
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitment_roots = Vec::new();
        let mut public_coefficient_commitments = Vec::new();
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..decryption_threshold {
                let coefficient_message = accepted_vss_coefficient_message_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    rns_prime,
                    ring_degree,
                );
                let coefficient_message_wide = coefficient_message
                    .iter()
                    .map(|coefficient| u128::from(*coefficient))
                    .collect::<Vec<_>>();
                let randomness_by_column = accepted_vss_randomness_fixture(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    ring_degree,
                );
                let commitment = compute_setup_commitment_for_tests(
                    public_matrix_seed_hash,
                    rns_limb_index,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("setup commitment");
                let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
                let full_commitment = setup_commitment_full_value(&commitment);
                coefficient_commitment_roots.push(commitment_root);
                coefficient_commitment_material.push(full_commitment.clone());
                public_coefficient_commitments.push(full_commitment);
            }
        }

        let source_trustee_record = serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "sourceTrusteeIdentity": source_trustee_identity,
            "coefficientCommitmentRoots": coefficient_commitment_roots,
        });
        source_trustee_records.push(source_trustee_record);
        public_source_trustee_records.push(serde_json::json!({
            "objectType": "VssPublicSourceCoefficientCommitments",
            "coefficientCommitments": public_coefficient_commitments,
        }));
    }

    let commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    });
    let material_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "thresholdDegree": decryption_threshold,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "coefficientCommitments": coefficient_commitment_material,
    });
    let public_commitment_set = serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": public_source_trustee_records,
    });
    VssMaterialPackageComponents {
        vss_coefficient_commitments: commitment_set,
        vss_coefficient_commitment_material: material_set,
        vss_public_coefficient_commitments: public_commitment_set,
    }
}

pub(in super::super) fn accepted_vss_coefficient_message_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> Vec<u64> {
    if shamir_coefficient_index == 0 {
        return (0..ring_degree)
            .map(|coefficient_position| {
                match accepted_vss_secret_coefficient_fixture(
                    source_trustee_roster_position,
                    coefficient_position,
                ) {
                    -1 => rns_prime - 1,
                    0 => 0,
                    1 => 1,
                    _ => unreachable!("secret fixture is centered ternary"),
                }
            })
            .collect();
    }

    (0..ring_degree)
        .map(|coefficient_position| {
            let value = ((source_trustee_roster_position + 1) * 17)
                + ((rns_limb_index as u64 + 1) * 5)
                + ((shamir_coefficient_index + 1) * 3)
                + (coefficient_position as u64 % 11);
            value % rns_prime
        })
        .collect()
}

pub(in super::super) fn accepted_vss_secret_coefficient_fixture(
    source_trustee_roster_position: u64,
    coefficient_position: usize,
) -> i64 {
    match (source_trustee_roster_position as usize + coefficient_position) % 3 {
        0 => -1,
        1 => 0,
        _ => 1,
    }
}

pub(in super::super) fn accepted_vss_randomness_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<Vec<i128>>> {
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .enumerate()
        .map(|(commitment_limb_position, _)| {
            (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                .map(|randomness_column_index| {
                    (0..ring_degree)
                        .map(|coefficient_position| {
                            let support_position = source_trustee_roster_position as usize
                                + rns_limb_index
                                + shamir_coefficient_index as usize
                                + commitment_limb_position
                                + randomness_column_index
                                + coefficient_position;
                            match support_position % 3 {
                                0 => -1,
                                1 => 0,
                                _ => 1,
                            }
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}
