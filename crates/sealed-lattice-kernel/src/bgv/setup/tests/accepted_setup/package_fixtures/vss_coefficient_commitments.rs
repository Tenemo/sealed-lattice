use super::*;

use crate::hashing::derive_canonical_object_hash;

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_coefficient_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    participant_count: u64,
) -> (serde_json::Value, serde_json::Value) {
    let decryption_threshold = participant_count / 3 + 1;
    let mut source_trustee_records = Vec::new();
    let mut coefficient_commitment_material = Vec::new();

    for source_trustee_roster_position in 0..participant_count {
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitments = Vec::new();
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
                    rns_prime,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("setup commitment");
                let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
                coefficient_commitments.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitment",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupParametersHash": setup_parameters_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                }));
                coefficient_commitment_material.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitmentMaterial",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupParametersHash": setup_parameters_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                    "commitment": setup_commitment_full_value(&commitment),
                }));
            }
        }

        let mut source_trustee_record = serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coefficientCommitments": coefficient_commitments,
        });
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_canonical_object_hash(&source_trustee_record)
                .expect("source trustee commitment root")
        );
        source_trustee_records.push(source_trustee_record);
    }

    let mut commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    });
    commitment_set["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&commitment_set).expect("VSS commitment set root")
    );

    let mut material_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": commitment_set["vssCoefficientCommitmentRoot"].clone(),
        "materialEncoding": "full-public-setup-commitment-values",
        "participantCount": participant_count,
        "thresholdDegree": decryption_threshold,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "materialRecordCount": coefficient_commitment_material.len(),
        "coefficientCommitments": coefficient_commitment_material,
    });
    material_set["vssCoefficientCommitmentMaterialRoot"] = serde_json::json!(
        derive_canonical_object_hash(&material_set)
            .expect("VSS coefficient commitment material root")
    );

    (commitment_set, material_set)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn streamed_vss_coefficient_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    derivation_id: &str,
    participant_count: u64,
) -> VssMaterialPackageComponents {
    let decryption_threshold = participant_count / 3 + 1;
    let total_byte_length =
        vss_material_binary_total_byte_length(ring_degree, participant_count, decryption_threshold);
    let chunk_count = total_byte_length.div_ceil(SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS);
    let transported_material_template = serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES_FOR_TESTS,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
    });
    let setup_context = collective_setup_context_fixture(
        ceremony_id,
        manifest_hash,
        roster_hash,
        setup_parameters_hash,
        setup_epoch,
        participant_count,
    );
    begin_threshold_share_commitment_transport_derivation_stream_request(&serde_json::json!({
        "derivationId": derivation_id,
        "setupContext": setup_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "transportedVssCoefficientCommitmentMaterial": transported_material_template,
    }))
    .expect("begin streamed full-ring VSS material");
    let mut writer =
        StreamingVssMaterialFixtureWriter::new(derivation_id.to_string(), total_byte_length);
    let mut header = Vec::new();
    append_vss_material_binary_header(
        &mut header,
        ring_degree,
        participant_count,
        decryption_threshold,
    );
    writer
        .write_bytes(&header)
        .expect("write streamed VSS material header");

    let mut source_trustee_records = Vec::new();
    for source_trustee_roster_position in 0..participant_count {
        terminal_phase(&format!(
            "streaming VSS source trustee {source_trustee_roster_position}"
        ));
        let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
        let mut coefficient_commitments = Vec::new();
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
                    rns_prime,
                    shamir_coefficient_index,
                    &coefficient_message_wide,
                    &randomness_by_column,
                    ring_degree,
                )
                .expect("setup commitment");
                let commitment_root = setup_commitment_root(&commitment).expect("commitment root");
                coefficient_commitments.push(serde_json::json!({
                    "objectType": "VssCoefficientCommitment",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupParametersHash": setup_parameters_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": shamir_coefficient_index,
                    "commitmentRoot": commitment_root,
                }));
                let mut record_bytes = Vec::new();
                append_vss_material_binary_record(
                    &mut record_bytes,
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                    &commitment,
                );
                writer
                    .write_bytes(&record_bytes)
                    .expect("write streamed VSS material record");
            }
        }

        let mut source_trustee_record = serde_json::json!({
            "objectType": "VssSourceTrusteeCoefficientCommitments",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity,
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "coefficientCommitments": coefficient_commitments,
        });
        source_trustee_record["sourceTrusteeCommitmentRoot"] = serde_json::json!(
            derive_canonical_object_hash(&source_trustee_record)
                .expect("source trustee commitment root")
        );
        source_trustee_records.push(source_trustee_record);
    }

    let mut commitment_set = serde_json::json!({
        "objectType": "VssCoefficientCommitmentSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "sourceTrusteeRecords": source_trustee_records,
    });
    commitment_set["vssCoefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&commitment_set).expect("VSS commitment set root")
    );
    let stream_derivation = writer
        .finish(
            &commitment_set["vssCoefficientCommitmentRoot"],
            &commitment_set["sourceTrusteeRecords"],
        )
        .expect("finish streamed full-ring VSS material");
    let transport = stream_derivation["transport"].clone();
    let transported_vss_coefficient_commitment_material = serde_json::json!({
        "objectType": "SetupTransportedVssCoefficientCommitmentMaterial",
        "objectVersion": 1,
        "binaryFormat": "sealed-lattice-vss-coefficient-commitment-material-binary-v1",
        "chunkSizeBytes": transport["chunkSizeBytes"].clone(),
        "chunkCount": transport["chunkCount"].clone(),
        "totalByteLength": transport["totalByteLength"].clone(),
        "fullObjectHash": transport["fullObjectHash"].clone(),
        "chunkRoot": transport["chunkRoot"].clone(),
        "chunkHashes": transport["chunkHashes"].clone(),
    });

    VssMaterialPackageComponents {
        vss_coefficient_commitments: commitment_set,
        vss_coefficient_commitment_material: stream_derivation["vssCoefficientCommitmentMaterial"]
            .clone(),
        threshold_share_commitments: stream_derivation["thresholdShareCommitments"].clone(),
        transported_vss_coefficient_commitment_material: Some(
            transported_vss_coefficient_commitment_material,
        ),
        verified_vss_coefficient_commitment_material: Some(
            stream_derivation["verifiedVssCoefficientCommitmentMaterial"].clone(),
        ),
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
) -> Vec<Vec<i128>> {
    (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
        .map(|randomness_column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    match (source_trustee_roster_position as usize
                        + rns_limb_index
                        + shamir_coefficient_index as usize
                        + randomness_column_index
                        + coefficient_position)
                        % 3
                    {
                        0 => -1,
                        1 => 0,
                        _ => 1,
                    }
                })
                .collect()
        })
        .collect()
}
