use super::same_secret_bridge::*;
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
    let threshold_degree = participant_count / 3 + 1;
    let source_trustee_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_source_coefficient_record(
                setup_context,
                public_matrix_seed_hash,
                ring_degree,
                threshold_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut set = serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    set["coefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&set).expect("VSS coefficient commitment root")
    );

    set
}

pub(super) fn vss_public_source_coefficient_record(
    setup_context: &serde_json::Value,
    public_matrix_seed_hash: &str,
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
                    public_matrix_seed_hash,
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
    let mut source_record = serde_json::json!({
        "objectType": "VssPublicSourceCoefficientCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": coefficient_commitments,
    });
    source_record["sourceCoefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_record)
            .expect("VSS source coefficient commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_public_coefficient_commitment_record(
    setup_context: &serde_json::Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    shamir_coefficient_index: u64,
) -> serde_json::Value {
    let coefficient_message = accepted_vss_coefficient_message_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        rns_prime,
        ring_degree,
    );
    let message_digit_columns =
        crate::bgv::setup::vss_commitment::vss_public_canonical_message_digit_columns(
            &coefficient_message,
            ring_degree,
        )
        .expect("VSS coefficient message digits");
    let randomness_by_column = vss_public_coefficient_randomness_i64_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
    );
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentContext",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": shamir_coefficient_index,
    });
    let computation =
        crate::bgv::setup::vss_commitment::compute_vss_public_commitment_from_opening(
            crate::bgv::setup::vss_commitment::VssPublicCommitmentOpeningInput {
                commitment_role: "coefficient",
                commitment_context: &commitment_context,
                public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                ring_degree,
                message_coefficients: &coefficient_message,
                message_digit_columns: &message_digit_columns,
                message_coefficient_bound: rns_prime,
                randomness_by_column: &randomness_by_column,
            },
        )
        .expect("VSS coefficient commitment");

    serde_json::json!({
        "objectType": "VssPublicCoefficientCommitment",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": shamir_coefficient_index,
        "coefficientCommitmentRoot": computation.commitment_root,
        "coefficientOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    })
}

pub(in super::super::super) fn vss_public_recipient_share_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("coefficient ring degree") as usize;
    let source_trustee_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_source_recipient_share_record(
                package,
                public_matrix_seed_hash,
                ring_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut recipient_set = serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    recipient_set["recipientShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&recipient_set).expect("VSS recipient-share commitment root")
    );

    recipient_set
}

pub(super) fn vss_public_source_recipient_share_record(
    package: &serde_json::Value,
    public_matrix_seed_hash: &str,
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
                    public_matrix_seed_hash,
                    ring_degree,
                    &source_trustee_identity,
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut source_record = serde_json::json!({
        "objectType": "VssPublicSourceRecipientShareCommitments",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientShareCommitments": recipient_share_commitments,
    });
    source_record["sourceRecipientShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_record)
            .expect("VSS source recipient-share commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_public_recipient_share_commitment_record(
    package: &serde_json::Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let rns_prime = DATA_PRIMES[rns_limb_index];
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("coefficient threshold degree");
    let (share_coefficients, _carry_witnesses) = vss_public_recipient_share_values_and_carries(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        threshold_degree,
        rns_prime,
        ring_degree,
    );
    let message_digit_columns =
        crate::bgv::setup::vss_commitment::vss_public_canonical_message_digit_columns(
            &share_coefficients,
            ring_degree,
        )
        .expect("VSS recipient-share message digits");
    let randomness_by_column = vss_public_recipient_share_randomness_i64_fixture(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        ring_degree,
    );
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitmentContext",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    });
    let computation =
        crate::bgv::setup::vss_commitment::compute_vss_public_commitment_from_opening(
            crate::bgv::setup::vss_commitment::VssPublicCommitmentOpeningInput {
                commitment_role: "recipient-share",
                commitment_context: &commitment_context,
                public_matrix_seed_hash,
                rns_limb_index,
                rns_prime,
                ring_degree,
                message_coefficients: &share_coefficients,
                message_digit_columns: &message_digit_columns,
                message_coefficient_bound: rns_prime,
                randomness_by_column: &randomness_by_column,
            },
        )
        .expect("VSS recipient-share commitment");

    serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shareCommitmentRoot": computation.commitment_root,
        "shareOpeningRoot": computation.opening_root,
        "commitment": computation.commitment,
    })
}

pub(in super::super::super) fn vss_public_aggregate_threshold_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["vssPublicRecipientShareCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("recipient-share ring degree") as usize;
    let recipient_records = (0..participant_count)
        .flat_map(|recipient_roster_position| {
            (0..DATA_PRIMES.len()).map(move |rns_limb_index| {
                vss_public_aggregate_threshold_commitment_record(
                    package,
                    public_matrix_seed_hash,
                    ring_degree,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect::<Vec<_>>();
    let mut aggregate_set = serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "recipientRecords": recipient_records,
    });
    aggregate_set["aggregateThresholdCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&aggregate_set).expect("aggregate threshold commitment root")
    );

    aggregate_set
}

pub(super) fn vss_public_aggregate_threshold_commitment_record(
    package: &serde_json::Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let participant_count = participant_count_from_package(package);
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let source_share_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_public_recipient_share_commitment_record_from_package(
                package,
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
            )
        })
        .collect::<Vec<_>>();
    let source_share_commitment_roots = source_share_records
        .iter()
        .map(|record| record["shareCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let source_share_opening_roots = source_share_records
        .iter()
        .map(|record| record["shareOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitmentContext",
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": DATA_PRIMES[rns_limb_index],
        "sourceShareCommitmentRoots": source_share_commitment_roots,
        "sourceShareOpeningRoots": source_share_opening_roots,
    });
    let commitment = vss_public_sum_commitment_body(
        "aggregate-threshold-share",
        &commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        DATA_PRIMES[rns_limb_index],
        ring_degree,
        &source_share_records,
    );
    let aggregate_commitment_root =
        derive_canonical_object_hash(&commitment).expect("aggregate threshold commitment root");
    let aggregate_opening_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicAggregateThresholdOpening",
        "commitmentRole": "aggregate-threshold-share",
        "commitmentContext": commitment_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": DATA_PRIMES[rns_limb_index],
        "ringDegree": ring_degree,
        "sourceShareOpeningRoots": source_share_opening_roots,
    }))
    .expect("aggregate threshold opening root");

    serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": DATA_PRIMES[rns_limb_index],
        "aggregateCommitmentRoot": aggregate_commitment_root,
        "aggregateOpeningRoot": aggregate_opening_root,
        "commitment": commitment,
        "sourceShareCommitmentRoots": source_share_commitment_roots,
        "sourceShareOpeningRoots": source_share_opening_roots,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_public_sum_commitment_body(
    commitment_role: &str,
    commitment_context: &serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    source_share_records: &[serde_json::Value],
) -> serde_json::Value {
    let commitment_context_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicCommitmentContext",
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
    }))
    .expect("VSS commitment context hash");
    let first_commitment =
        &source_share_records.first().expect("source share record")["commitment"];
    let commitment_limbs = first_commitment["commitmentLimbs"]
        .as_array()
        .expect("source commitment limbs")
        .iter()
        .enumerate()
        .map(|(limb_position, limb)| {
            let commitment_modulus_index = limb["commitmentModulusIndex"]
                .as_u64()
                .expect("commitment modulus index");
            let modulus = limb["modulus"].as_u64().expect("commitment modulus");
            let coordinate_count = limb["coordinates"]
                .as_array()
                .expect("commitment coordinates")
                .len();
            let coordinates = (0..coordinate_count)
                .map(|coordinate_index| {
                    source_share_records.iter().fold(0_u128, |sum, record| {
                        let source_limb = &record["commitment"]["commitmentLimbs"][limb_position];
                        let coordinate = source_limb["coordinates"][coordinate_index]
                            .as_u64()
                            .expect("source commitment coordinate");
                        (sum + u128::from(coordinate)) % u128::from(modulus)
                    }) as u64
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": modulus,
                "coordinates": coordinates,
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "objectType": "VssPublicCommitment",
        "commitmentRole": commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "outputCoordinateCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    })
}
