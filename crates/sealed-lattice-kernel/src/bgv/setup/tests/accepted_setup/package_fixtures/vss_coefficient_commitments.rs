use super::*;
use crate::bgv::setup::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;

pub(super) fn vss_coefficient_commitment_components(
    setup_context: &serde_json::Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    participant_count: u64,
) -> VssMaterialPackageComponents {
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(setup_context)
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
                let public_commitment =
                    super::super::proof_record_fixtures::vss_public_coefficient_commitment_record(
                        setup_context,
                        ring_degree,
                        &source_trustee_identity,
                        source_trustee_roster_position,
                        rns_limb_index,
                        rns_prime,
                        shamir_coefficient_index,
                    );
                coefficient_commitment_roots.push(commitment_root);
                coefficient_commitment_material.push(full_commitment);
                public_coefficient_commitments.push(public_commitment);
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

#[test]
fn pre_finalized_coefficient_commitments_pass_full_context_bound_verification() {
    let participant_count = MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT;
    let manifest_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssCoefficientCommitmentFixtureManifest",
    }))
    .expect("fixture manifest hash");
    let roster_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssCoefficientCommitmentFixtureRoster",
        "participantCount": participant_count,
    }))
    .expect("fixture roster hash");
    let setup_parameters_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssCoefficientCommitmentFixtureParameters",
        "participantCount": participant_count,
    }))
    .expect("fixture setup parameters hash");
    let setup_context = collective_setup_context_fixture(
        "coefficient-commitment-fixture",
        &manifest_hash,
        &roster_hash,
        &setup_parameters_hash,
        "setup-epoch-1",
        participant_count,
    );
    let setup_context_hash = crate::bgv::setup::accepted_setup::setup_context_hash(&setup_context)
        .expect("setup context hash");
    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssCoefficientCommitmentFixturePublicMatrixSeed",
    }))
    .expect("fixture public matrix seed hash");
    let components = vss_coefficient_commitment_components(
        &setup_context,
        &public_matrix_seed_hash,
        DEVELOPMENT_RING_DEGREE,
        participant_count,
    );
    let trustee_identities = (0..participant_count)
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let coefficient_set = &components.vss_public_coefficient_commitments;
    let threshold_degree = decryption_threshold_for_participant_count(participant_count);
    let participant_count =
        usize::try_from(participant_count).expect("fixture participant count fits usize");
    let threshold_degree =
        usize::try_from(threshold_degree).expect("fixture threshold degree fits usize");
    let verification_context =
        crate::bgv::setup::vss_commitment::VssPublicCoefficientCommitmentSetContext {
            setup_context_hash: &setup_context_hash,
            public_matrix_seed_hash: &public_matrix_seed_hash,
            participant_count,
            trustee_identities: &trustee_identities,
            rns_limb_count: DATA_PRIMES.len(),
            threshold_degree,
        };

    let verified_root =
        crate::bgv::setup::vss_commitment::verify_vss_public_coefficient_commitment_set(
            coefficient_set,
            &verification_context,
        )
        .expect("pre-finalized coefficient commitments must pass full verification");
    let canonical_root =
        crate::bgv::setup::vss_commitment::vss_public_coefficient_commitment_set_root(
            coefficient_set,
            &trustee_identities,
        )
        .expect("pre-finalized coefficient commitment set root");
    assert_eq!(verified_root, canonical_root);

    let mut wrong_last_coordinate_set = coefficient_set.clone();
    let last_source_commitments = wrong_last_coordinate_set["sourceTrusteeRecords"]
        .as_array_mut()
        .and_then(|source_records| source_records.last_mut())
        .and_then(|source_record| source_record["coefficientCommitments"].as_array_mut())
        .expect("last source trustee coefficient commitments");
    let first_commitment = last_source_commitments
        .first()
        .expect("first coefficient commitment")
        .clone();
    *last_source_commitments
        .last_mut()
        .expect("last coefficient commitment") = first_commitment;
    let coordinate_error =
        crate::bgv::setup::vss_commitment::verify_vss_public_coefficient_commitment_set(
            &wrong_last_coordinate_set,
            &verification_context,
        )
        .expect_err("the final coefficient must bind its exact coordinate");
    assert_eq!(coordinate_error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(coordinate_error.message.contains("commitmentContextHash"));

    let different_setup_context_hash = "0".repeat(128);
    assert_ne!(different_setup_context_hash, setup_context_hash);
    let different_context =
        crate::bgv::setup::vss_commitment::VssPublicCoefficientCommitmentSetContext {
            setup_context_hash: &different_setup_context_hash,
            ..verification_context
        };
    let error = crate::bgv::setup::vss_commitment::verify_vss_public_coefficient_commitment_set(
        coefficient_set,
        &different_context,
    )
    .expect_err("coefficient commitments must reject a different setup context");
    assert_eq!(error.code, CanonicalErrorCode::ComponentMismatch);
    assert!(error.message.contains("commitmentContextHash"));
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
