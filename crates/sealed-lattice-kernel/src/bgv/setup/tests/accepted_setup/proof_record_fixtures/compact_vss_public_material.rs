use super::*;

const COMPACT_VSS_COMMITMENT_PROFILE_ID: &str =
    "sealed-lattice-compact-vss-development-covered-linear-v1";
const COMPACT_VSS_COMMITMENT_BINARY_FORMAT: &str =
    "sealed-lattice-compact-vss-commitment-binary-v1";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "compact-vss-share-linkage";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/compact-vss-share-linkage/proof-bytes-v1";
const COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION: &str = "recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments";
const COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE: &str = "public share-linkage proof records are grouped by source trustee and split into bounded recipient-limb batches whose packed proof ring fits the supported evaluation domain";
const COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE: &str = "recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point";
const COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE: &str = "aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb";
const COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE: &str = "coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "compact-same-secret-bridge";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1";
const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const COMPACT_SAME_SECRET_BRIDGE_RELATION: &str = "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const COMPACT_SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const COMPACT_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const COMPACT_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
pub(in super::super) const COMPACT_SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "compact-same-secret-bridge-proof-material";
pub(in super::super) const COMPACT_VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "compact-vss-share-linkage-proof-material";

pub(in super::super) fn compact_vss_coefficient_commitment_set_object(
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
            compact_vss_source_coefficient_record(
                setup_context,
                public_matrix_seed_hash,
                ring_degree,
                threshold_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut set = serde_json::json!({
        "objectType": "CompactVssCoefficientCommitmentSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    set["coefficientCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &set)
            .expect("compact VSS coefficient commitment root")
    );

    set
}

fn compact_vss_source_coefficient_record(
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
                compact_vss_coefficient_commitment_record(
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
        "objectType": "CompactVssSourceCoefficientCommitments",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": coefficient_commitments,
    });
    source_record["sourceCoefficientCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("VssCoefficientCommitmentRoot", &source_record)
            .expect("compact VSS source coefficient commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
fn compact_vss_coefficient_commitment_record(
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
        crate::bgv::setup::compact_vss_commitment::compact_vss_canonical_message_digit_columns(
            &coefficient_message,
            ring_degree,
        )
        .expect("compact VSS coefficient message digits");
    let randomness_by_column = compact_vss_coefficient_randomness_i64_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
    );
    let commitment_context = serde_json::json!({
        "objectType": "CompactVssCoefficientCommitmentContext",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "shamirCoefficientIndex": shamir_coefficient_index,
    });
    let computation =
        crate::bgv::setup::compact_vss_commitment::compute_compact_vss_commitment_from_opening(
            crate::bgv::setup::compact_vss_commitment::CompactVssCommitmentOpeningInput {
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
        .expect("compact VSS coefficient commitment");

    serde_json::json!({
        "objectType": "CompactVssCoefficientCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
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

pub(in super::super) fn compact_vss_recipient_share_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["compactVssCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact coefficient ring degree") as usize;
    let source_trustee_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            compact_vss_source_recipient_share_record(
                package,
                public_matrix_seed_hash,
                ring_degree,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut recipient_set = serde_json::json!({
        "objectType": "CompactVssRecipientShareCommitmentSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    recipient_set["recipientShareCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("ThresholdShareCommitmentRoot", &recipient_set)
            .expect("compact VSS recipient-share commitment root")
    );

    recipient_set
}

fn compact_vss_source_recipient_share_record(
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
                compact_vss_recipient_share_commitment_record(
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
        "objectType": "CompactVssSourceRecipientShareCommitments",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientShareCommitments": recipient_share_commitments,
    });
    source_record["sourceRecipientShareCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("ThresholdShareCommitmentRoot", &source_record)
            .expect("compact VSS source recipient-share commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
fn compact_vss_recipient_share_commitment_record(
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
    let threshold_degree = package["compactVssCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("compact coefficient threshold degree");
    let (share_coefficients, _carry_witnesses) = compact_vss_recipient_share_values_and_carries(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        threshold_degree,
        rns_prime,
        ring_degree,
    );
    let message_digit_columns =
        crate::bgv::setup::compact_vss_commitment::compact_vss_canonical_message_digit_columns(
            &share_coefficients,
            ring_degree,
        )
        .expect("compact VSS recipient-share message digits");
    let randomness_by_column = compact_vss_recipient_share_randomness_i64_fixture(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        ring_degree,
    );
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let commitment_context = serde_json::json!({
        "objectType": "CompactVssRecipientShareCommitmentContext",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
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
        crate::bgv::setup::compact_vss_commitment::compute_compact_vss_commitment_from_opening(
            crate::bgv::setup::compact_vss_commitment::CompactVssCommitmentOpeningInput {
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
        .expect("compact VSS recipient-share commitment");

    serde_json::json!({
        "objectType": "CompactVssRecipientShareCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
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

pub(in super::super) fn compact_vss_aggregate_threshold_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["compactVssRecipientShareCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact recipient-share ring degree") as usize;
    let recipient_records = (0..participant_count)
        .flat_map(|recipient_roster_position| {
            (0..DATA_PRIMES.len()).map(move |rns_limb_index| {
                compact_vss_aggregate_threshold_commitment_record(
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
        "objectType": "CompactVssAggregateThresholdCommitmentSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "recipientRecords": recipient_records,
    });
    aggregate_set["aggregateThresholdCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash("ThresholdShareCommitmentRoot", &aggregate_set)
            .expect("compact aggregate threshold commitment root")
    );

    aggregate_set
}

fn compact_vss_aggregate_threshold_commitment_record(
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
            compact_vss_recipient_share_commitment_record_from_package(
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
        "objectType": "CompactVssAggregateThresholdCommitmentContext",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "recipientTrusteePoint": recipient_roster_position + 1,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": DATA_PRIMES[rns_limb_index],
        "sourceShareCommitmentRoots": source_share_commitment_roots,
        "sourceShareOpeningRoots": source_share_opening_roots,
    });
    let commitment = compact_vss_public_sum_commitment_body(
        "aggregate-threshold-share",
        &commitment_context,
        public_matrix_seed_hash,
        rns_limb_index,
        DATA_PRIMES[rns_limb_index],
        ring_degree,
        &source_share_records,
    );
    let aggregate_commitment_root = derive_protocol_hash("SetupCommitmentRoot", &commitment)
        .expect("compact aggregate threshold commitment root");
    let aggregate_opening_root = derive_protocol_hash(
        "SetupCommitmentRoot",
        &serde_json::json!({
            "objectType": "CompactVssAggregateThresholdOpening",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "commitmentRole": "aggregate-threshold-share",
            "commitmentContext": commitment_context,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": DATA_PRIMES[rns_limb_index],
            "ringDegree": ring_degree,
            "sourceShareOpeningRoots": source_share_opening_roots,
        }),
    )
    .expect("compact aggregate threshold opening root");

    serde_json::json!({
        "objectType": "CompactVssAggregateThresholdCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
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
fn compact_vss_public_sum_commitment_body(
    commitment_role: &str,
    commitment_context: &serde_json::Value,
    public_matrix_seed_hash: &str,
    rns_limb_index: usize,
    rns_prime: u64,
    ring_degree: usize,
    source_share_records: &[serde_json::Value],
) -> serde_json::Value {
    let commitment_context_hash = derive_protocol_hash(
        "SetupCommitmentRoot",
        &serde_json::json!({
            "objectType": "CompactVssCommitmentContext",
            "objectVersion": 1,
            "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "commitmentRole": commitment_role,
            "commitmentContext": commitment_context,
        }),
    )
    .expect("compact VSS commitment context hash");
    let first_commitment =
        &source_share_records.first().expect("source share record")["commitment"];
    let commitment_limbs = first_commitment["commitmentLimbs"]
        .as_array()
        .expect("compact source commitment limbs")
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
        "objectType": "CompactVssCommitment",
        "objectVersion": 1,
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "commitmentRole": commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
        "ringDegree": ring_degree,
        "outputCoordinateCount": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    })
}

pub(in super::super) fn compact_vss_share_linkage_statement_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let threshold_degree = package["compactVssCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("compact threshold degree");
    let ring_degree = package["compactVssCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact ring degree");
    let source_statement_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            compact_vss_share_linkage_source_statement_record(
                package,
                &target_basis_hash,
                public_matrix_seed_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement = serde_json::json!({
        "objectType": "CompactVssShareLinkageStatement",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": package["compactVssCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": package["compactVssRecipientShareCommitmentSet"]["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": package["compactVssAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "relation": COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "proofBatchingRule": COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "shamirEvaluationRule": COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "aggregateThresholdRule": COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "commonKeyRule": COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
        "sourceStatementRecords": source_statement_records,
    });
    statement["statementRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &statement)
            .expect("compact VSS share-linkage statement root")
    );

    statement
}

fn compact_vss_share_linkage_source_statement_record(
    package: &serde_json::Value,
    target_basis_hash: &str,
    public_matrix_seed_hash: &str,
    source_trustee_roster_position: u64,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let coefficient_source_record =
        compact_vss_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        compact_vss_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_opening_roots = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("compact coefficient commitments")
        .iter()
        .take(
            DATA_PRIMES.len()
                * package["compactVssCoefficientCommitmentSet"]["thresholdDegree"]
                    .as_u64()
                    .expect("threshold degree") as usize,
        )
        .map(|record| record["coefficientOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let recipient_share_opening_roots = recipient_source_record["recipientShareCommitments"]
        .as_array()
        .expect("compact recipient-share commitments")
        .iter()
        .map(|record| record["shareOpeningRoot"].clone())
        .collect::<Vec<_>>();
    let mut source_statement = serde_json::json!({
        "objectType": "CompactVssShareLinkageSourceStatement",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "ringDegree": package["compactVssCoefficientCommitmentSet"]["ringDegree"],
        "participantCount": package["compactVssCoefficientCommitmentSet"]["participantCount"],
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": package["compactVssCoefficientCommitmentSet"]["thresholdDegree"],
        "coefficientCommitmentRoot": package["compactVssCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"],
        "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"],
        "coefficientOpeningRoots": coefficient_opening_roots,
        "recipientShareOpeningRoots": recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": package["compactVssAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "relation": COMPACT_VSS_SHARE_LINKAGE_STATEMENT_RELATION,
        "proofBatchingRule": COMPACT_VSS_SHARE_LINKAGE_PROOF_BATCHING_RULE,
        "shamirEvaluationRule": COMPACT_VSS_SHARE_LINKAGE_SHAMIR_EVALUATION_RULE,
        "aggregateThresholdRule": COMPACT_VSS_SHARE_LINKAGE_AGGREGATE_THRESHOLD_RULE,
        "commonKeyRule": COMPACT_VSS_SHARE_LINKAGE_COMMON_KEY_RULE,
    });
    source_statement["sourceStatementRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &source_statement)
            .expect("compact VSS share-linkage source statement root")
    );

    source_statement
}

pub(in super::super) fn compact_vss_share_linkage_proof_material_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let statement = &package["compactVssShareLinkageStatement"];
    let participant_count = participant_count_from_package(package);
    let proof_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            compact_vss_share_linkage_proof_records(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "CompactVssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "profileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": statement["ceremonyId"],
        "manifestHash": statement["manifestHash"],
        "rosterHash": statement["rosterHash"],
        "setupProfileHash": statement["setupProfileHash"],
        "qShareHash": statement["qShareHash"],
        "carryAwareVssShareRelationProfileHash": statement["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": statement["commitmentProfileHash"],
        "setupEpoch": statement["setupEpoch"],
        "publicMatrixSeedHash": statement["publicMatrixSeedHash"],
        "targetBasisHash": statement["targetBasisHash"],
        "ringDegree": statement["ringDegree"],
        "participantCount": statement["participantCount"],
        "targetRnsLimbCount": statement["targetRnsLimbCount"],
        "thresholdDegree": statement["thresholdDegree"],
        "coefficientCommitmentRoot": statement["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": statement["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": statement["aggregateThresholdCommitmentRoot"],
        "statementRoot": statement["statementRoot"],
        "proofRecords": proof_records,
    });
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &proof_material_set)
            .expect("compact VSS share-linkage proof material set root")
    );

    proof_material_set
}

fn compact_vss_share_linkage_proof_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let item_records =
        compact_vss_share_linkage_item_records(package, source_trustee_roster_position);
    let proof_items_per_record = participant_count_from_package(package)
        .try_into()
        .expect("participant count fits usize");
    item_records
        .chunks(proof_items_per_record)
        .enumerate()
        .map(|(proof_record_index, item_records)| {
            compact_vss_share_linkage_proof_record(
                package,
                source_trustee_roster_position,
                proof_record_index,
                item_records,
            )
        })
        .collect()
}

fn compact_vss_share_linkage_proof_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let compact_vss_share_linkage =
        compact_vss_share_linkage_proof_statement(package, item_records);
    let linkage_items = compact_vss_share_linkage_coverage_items_from_records(item_records);
    let proof_bytes_hex = compact_vss_share_linkage_proof_bytes_hex(
        package,
        &compact_vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("compact VSS share-linkage proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "CompactVssShareLinkageProofRecord",
        "objectVersion": 1,
        "proofFamily": COMPACT_VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "linkageItems": linkage_items,
        "compactVssShareLinkage": compact_vss_share_linkage,
        "proofBytesHash": hash512_hex(
            COMPACT_VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &proof_record)
            .expect("compact VSS share-linkage proof record root")
    );

    proof_record
}

fn compact_vss_share_linkage_proof_statement(
    package: &serde_json::Value,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let mut primary_item = item_records
        .first()
        .expect("compact VSS primary share-linkage item")
        .clone();
    primary_item["publicMatrixSeedHash"] =
        package["compactVssShareLinkageStatement"]["publicMatrixSeedHash"].clone();
    primary_item["shareLinkageStatementRoot"] =
        package["compactVssShareLinkageStatement"]["statementRoot"].clone();
    primary_item["additionalLinkageItems"] =
        serde_json::json!(item_records.iter().skip(1).cloned().collect::<Vec<_>>());

    primary_item
}

fn compact_vss_share_linkage_item_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let participant_count = participant_count_from_package(package);
    (0..DATA_PRIMES.len())
        .flat_map(|rns_limb_index| {
            (0..participant_count).map(move |recipient_roster_position| {
                compact_vss_share_linkage_item_record(
                    package,
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect()
}

fn compact_vss_share_linkage_item_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let threshold_degree = package["compactVssCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
    let coefficient_source_record =
        compact_vss_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        compact_vss_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_records = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitment records");
    let coefficient_record_offset = rns_limb_index
        .checked_mul(threshold_degree)
        .expect("coefficient record offset");
    let selected_coefficient_records = &coefficient_records
        [coefficient_record_offset..coefficient_record_offset + threshold_degree];
    let recipient_record = compact_vss_recipient_share_commitment_record_from_package(
        package,
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
    );

    serde_json::json!({
        "sourceTrusteeIdentity": coefficient_source_record["sourceTrusteeIdentity"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"],
        "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"],
        "recipientIdentity": recipient_record["recipientIdentity"],
        "recipientRosterPosition": recipient_roster_position,
        "sourceRnsLimbIndex": rns_limb_index,
        "sourceMessageModulus": DATA_PRIMES[rns_limb_index],
        "coefficientCommitmentRoots": selected_coefficient_records
            .iter()
            .map(|record| record["coefficientCommitmentRoot"].clone())
            .collect::<Vec<_>>(),
        "coefficientOpeningRoots": selected_coefficient_records
            .iter()
            .map(|record| record["coefficientOpeningRoot"].clone())
            .collect::<Vec<_>>(),
        "coefficientCommitments": selected_coefficient_records
            .iter()
            .map(|record| record["commitment"].clone())
            .collect::<Vec<_>>(),
        "recipientShareCommitmentRoot": recipient_record["shareCommitmentRoot"],
        "recipientShareOpeningRoot": recipient_record["shareOpeningRoot"],
        "recipientShareCommitment": recipient_record["commitment"],
    })
}

fn compact_vss_share_linkage_coverage_items_from_records(
    item_records: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    item_records
        .iter()
        .enumerate()
        .map(|(item_index, item_record)| {
            serde_json::json!({
                "sourceTrusteeRosterPosition": item_record["sourceTrusteeRosterPosition"],
                "recipientRosterPosition": item_record["recipientRosterPosition"],
                "sourceRnsLimbIndex": item_record["sourceRnsLimbIndex"],
                "itemIndex": item_index,
            })
        })
        .collect()
}

fn compact_vss_share_linkage_proof_bytes_hex(
    package: &serde_json::Value,
    compact_vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> String {
    let request = compact_vss_share_linkage_proof_generation_request(
        package,
        compact_vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let checkpoint_key = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &serde_json::json!({
            "statementRoot": package["compactVssShareLinkageStatement"]["statementRoot"],
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "proofRecordIndex": proof_record_index,
            "compactVssShareLinkage": compact_vss_share_linkage,
        }),
    )
    .expect("compact VSS share-linkage proof checkpoint key");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        COMPACT_VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY,
        &checkpoint_key,
        || {
            let generated = generate_compact_vss_share_linkage_proof_from_request(&request)
                .expect("compact VSS share-linkage proof");
            crate::transcript_core::decode_hex(
                generated["proofBytesHex"]
                    .as_str()
                    .expect("compact VSS share-linkage proof bytes hex"),
            )
            .expect("compact VSS share-linkage proof bytes")
        },
    );

    to_hex(&proof_bytes)
}

fn compact_vss_share_linkage_statement_items(
    compact_vss_share_linkage: &serde_json::Value,
) -> Vec<&serde_json::Value> {
    let mut items = vec![compact_vss_share_linkage];
    items.extend(
        compact_vss_share_linkage["additionalLinkageItems"]
            .as_array()
            .expect("compact VSS additional linkage items")
            .iter(),
    );

    items
}

fn compact_vss_share_linkage_coefficient_slots(
    linkage_items: &[&serde_json::Value],
    threshold_degree: u64,
) -> Vec<(usize, u64)> {
    let mut coefficient_slots = Vec::new();
    for item in linkage_items {
        let rns_limb_index = item["sourceRnsLimbIndex"]
            .as_u64()
            .expect("compact linkage item limb") as usize;
        for shamir_coefficient_index in 0..threshold_degree {
            let coefficient_slot = (rns_limb_index, shamir_coefficient_index);
            if !coefficient_slots.contains(&coefficient_slot) {
                coefficient_slots.push(coefficient_slot);
            }
        }
    }

    coefficient_slots
}

fn compact_vss_share_linkage_proof_generation_request(
    package: &serde_json::Value,
    compact_vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> serde_json::Value {
    let statement = &package["compactVssShareLinkageStatement"];
    let ring_degree = statement["ringDegree"]
        .as_u64()
        .expect("compact share-linkage ring degree") as usize;
    let threshold_degree = statement["thresholdDegree"]
        .as_u64()
        .expect("compact share-linkage threshold degree");
    let linkage_items = compact_vss_share_linkage_statement_items(compact_vss_share_linkage);
    let coefficient_slots =
        compact_vss_share_linkage_coefficient_slots(&linkage_items, threshold_degree);
    let coefficient_messages_by_shamir_index = coefficient_slots
        .iter()
        .map(|(rns_limb_index, shamir_coefficient_index)| {
            accepted_vss_coefficient_message_fixture(
                source_trustee_roster_position,
                *rns_limb_index,
                *shamir_coefficient_index,
                DATA_PRIMES[*rns_limb_index],
                ring_degree,
            )
            .into_iter()
            .map(|value| i64::try_from(value).expect("compact coefficient message fits i64"))
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let coefficient_opening_randomness_by_shamir_index = coefficient_slots
        .iter()
        .map(|(rns_limb_index, shamir_coefficient_index)| {
            compact_vss_coefficient_randomness_i64_fixture(
                source_trustee_roster_position,
                *rns_limb_index,
                *shamir_coefficient_index,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let mut recipient_share_messages_by_item = Vec::new();
    let mut recipient_share_opening_randomness_by_item = Vec::new();
    let mut carry_witnesses_by_item = Vec::new();
    for item in &linkage_items {
        let item_source_trustee_roster_position = item["sourceTrusteeRosterPosition"]
            .as_u64()
            .expect("compact linkage item source trustee");
        assert_eq!(
            item_source_trustee_roster_position, source_trustee_roster_position,
            "compact linkage proof batch must contain one source trustee"
        );
        let recipient_roster_position = item["recipientRosterPosition"]
            .as_u64()
            .expect("compact linkage item recipient");
        let rns_limb_index = item["sourceRnsLimbIndex"]
            .as_u64()
            .expect("compact linkage item limb") as usize;
        let (share_coefficients, carry_witnesses) = compact_vss_recipient_share_values_and_carries(
            source_trustee_roster_position,
            recipient_roster_position,
            rns_limb_index,
            threshold_degree,
            DATA_PRIMES[rns_limb_index],
            ring_degree,
        );
        recipient_share_messages_by_item.push(
            share_coefficients
                .into_iter()
                .map(|value| i64::try_from(value).expect("compact recipient share fits i64"))
                .collect::<Vec<_>>(),
        );
        recipient_share_opening_randomness_by_item.push(
            compact_vss_recipient_share_randomness_i64_fixture(
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
                ring_degree,
            ),
        );
        carry_witnesses_by_item.push(carry_witnesses);
    }
    let proof_randomness_seed_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "compact-vss-share-linkage-proof-randomness",
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "proofRecordIndex": proof_record_index,
        }),
    )
    .expect("compact VSS share-linkage proof randomness seed");
    let proof_randomness_nonce_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "compact-vss-share-linkage-proof-randomness-nonce",
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "proofRecordIndex": proof_record_index,
        }),
    )
    .expect("compact VSS share-linkage proof randomness nonce");

    serde_json::json!({
        "context": {
            "ceremonyId": statement["ceremonyId"],
            "manifestHash": statement["manifestHash"],
            "rosterHash": statement["rosterHash"],
            "trusteeIdentity": "compact-vss-share-linkage",
            "trusteeRosterPosition": 0,
            "setupEpoch": statement["setupEpoch"],
            "shareLinkageStatementRoot": statement["statementRoot"],
        },
        "ringDegree": ring_degree,
        "compactVssShareLinkage": compact_vss_share_linkage,
        "coefficientMessagesByShamirIndex": coefficient_messages_by_shamir_index,
        "recipientShareMessages": recipient_share_messages_by_item
            .first()
            .expect("primary compact recipient share messages"),
        "coefficientOpeningRandomnessByShamirIndex": coefficient_opening_randomness_by_shamir_index,
        "recipientShareOpeningRandomness": recipient_share_opening_randomness_by_item
            .first()
            .expect("primary compact recipient share opening randomness"),
        "carryWitnesses": carry_witnesses_by_item
            .first()
            .expect("primary compact carry witnesses"),
        "recipientShareMessagesByItem": recipient_share_messages_by_item,
        "recipientShareOpeningRandomnessByItem": recipient_share_opening_randomness_by_item,
        "carryWitnessesByItem": carry_witnesses_by_item,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    })
}

fn compact_vss_coefficient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["compactVssCoefficientCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

fn compact_vss_recipient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["compactVssRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

fn compact_vss_recipient_share_commitment_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let rns_limb_count = package["compactVssRecipientShareCommitmentSet"]["rnsLimbCount"]
        .as_u64()
        .expect("compact recipient-share limb count") as usize;
    let record_index = (recipient_roster_position as usize)
        .checked_mul(rns_limb_count)
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .expect("compact recipient-share record index");
    package["compactVssRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]["recipientShareCommitments"][record_index]
        .clone()
}

fn compact_vss_recipient_share_values_and_carries(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    threshold_degree: u64,
    rns_prime: u64,
    ring_degree: usize,
) -> (Vec<u64>, Vec<i64>) {
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
    let mut carry_witnesses = Vec::with_capacity(ring_degree);
    for coefficient_position in 0..ring_degree {
        let lifted_share = coefficient_messages
            .iter()
            .zip(trustee_point_powers.iter())
            .fold(0_u128, |sum, (messages, point_power)| {
                sum + u128::from(messages[coefficient_position]) * *point_power
            });
        share_coefficients.push((lifted_share % u128::from(rns_prime)) as u64);
        carry_witnesses.push(
            i64::try_from(lifted_share / u128::from(rns_prime))
                .expect("compact recipient share carry fits i64"),
        );
    }

    (share_coefficients, carry_witnesses)
}

fn compact_vss_recipient_share_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    let seed_offset = 10_000
        + source_trustee_roster_position as i64 * 503
        + recipient_roster_position as i64 * 37
        + rns_limb_index as i64 * 11;
    (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
        .map(|column_index| {
            (0..ring_degree)
                .map(|coefficient_position| {
                    ((seed_offset + column_index as i64 * 5 + coefficient_position as i64 * 7)
                        .rem_euclid(3))
                        - 1
                })
                .collect()
        })
        .collect()
}

pub(in super::super) fn compact_same_secret_bridge_statement_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let compact_coefficient_set = &package["compactVssCoefficientCommitmentSet"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = compact_coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("compact source coefficient records")
        .iter()
        .enumerate()
        .map(|(source_trustee_roster_position, source_record)| {
            compact_same_secret_bridge_statement_record(
                package,
                source_record,
                &target_basis_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement_set = serde_json::json!({
        "objectType": "CompactVssSameSecretBridgeStatementSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": compact_coefficient_set["ringDegree"],
        "participantCount": compact_coefficient_set["participantCount"],
        "targetRnsLimbCount": compact_coefficient_set["rnsLimbCount"],
        "thresholdDegree": compact_coefficient_set["thresholdDegree"],
        "compactCoefficientCommitmentRoot": compact_coefficient_set["coefficientCommitmentRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "integerSupport": COMPACT_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": COMPACT_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": COMPACT_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "statementRecords": statement_records,
    });
    statement_set["compactSameSecretBridgeStatementSetRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &statement_set)
            .expect("compact same-secret bridge statement set root")
    );

    statement_set
}

fn compact_same_secret_bridge_statement_record(
    package: &serde_json::Value,
    compact_source_record: &serde_json::Value,
    target_basis_hash: &str,
    source_trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = compact_source_record["sourceTrusteeIdentity"]
        .as_str()
        .expect("source trustee identity");
    let same_secret_statement =
        &package["sameSecretConsistency"]["statementRecords"][source_trustee_roster_position];
    let same_secret_proof =
        &package["sameSecretProofs"]["proofRecords"][source_trustee_roster_position];
    let coefficient_commitments = compact_source_record["coefficientCommitments"]
        .as_array()
        .expect("compact coefficient commitments");
    let threshold_degree = package["compactVssCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
    let target_constant_records = (0..DATA_PRIMES.len())
        .map(|rns_limb_index| {
            let coefficient_record_index = rns_limb_index
                .checked_mul(threshold_degree)
                .expect("compact coefficient record index");
            let coefficient_record = &coefficient_commitments[coefficient_record_index];
            (
                serde_json::json!({
                    "rnsLimbIndex": coefficient_record["rnsLimbIndex"],
                    "rnsPrime": coefficient_record["rnsPrime"],
                    "shamirCoefficientIndex": coefficient_record["shamirCoefficientIndex"],
                    "coefficientCommitmentRoot": coefficient_record["coefficientCommitmentRoot"],
                }),
                serde_json::json!({
                    "rnsLimbIndex": coefficient_record["rnsLimbIndex"],
                    "rnsPrime": coefficient_record["rnsPrime"],
                    "shamirCoefficientIndex": coefficient_record["shamirCoefficientIndex"],
                    "commitment": coefficient_record["commitment"],
                }),
            )
        })
        .collect::<Vec<_>>();
    let (target_constant_roots, target_constant_commitments): (Vec<_>, Vec<_>) =
        target_constant_records.into_iter().unzip();
    let mut statement_record = serde_json::json!({
        "objectType": "CompactVssSameSecretBridgeStatement",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupProfileHash": setup_context["setupProfileHash"],
        "qShareHash": setup_context["qShareHash"],
        "carryAwareVssShareRelationProfileHash": setup_context["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": setup_context["commitmentProfileHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "ringDegree": package["compactVssCoefficientCommitmentSet"]["ringDegree"],
        "trusteeIdentity": source_trustee_identity,
        "trusteeRosterPosition": source_trustee_roster_position,
        "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
        "sameSecretProofRoot": same_secret_proof["sameSecretProofRoot"],
        "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": COMPACT_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": COMPACT_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": COMPACT_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": target_constant_roots,
        "targetConstantCoefficientCommitments": target_constant_commitments,
        "relation": COMPACT_SAME_SECRET_BRIDGE_RELATION,
    });
    statement_record["compactSameSecretBridgeStatementRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &statement_record)
            .expect("compact same-secret bridge statement root")
    );

    statement_record
}

pub(in super::super) fn compact_same_secret_bridge_proof_material_set_object(
    package: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
) -> serde_json::Value {
    let statement_set = &package["compactSameSecretBridgeStatementSet"];
    let proof_records = statement_set["statementRecords"]
        .as_array()
        .expect("compact same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            compact_same_secret_bridge_proof_record(
                package,
                statement_record,
                transported_same_secret_proof_material,
                trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "CompactVssSameSecretBridgeProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "setupProofProfileId": "SealedLattice-SetupProof-v1",
        "proofFamily": COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": statement_set["ceremonyId"],
        "manifestHash": statement_set["manifestHash"],
        "rosterHash": statement_set["rosterHash"],
        "setupProfileHash": statement_set["setupProfileHash"],
        "qShareHash": statement_set["qShareHash"],
        "carryAwareVssShareRelationProfileHash": statement_set["carryAwareVssShareRelationProfileHash"],
        "commitmentProfileHash": statement_set["commitmentProfileHash"],
        "setupEpoch": statement_set["setupEpoch"],
        "targetBasisHash": statement_set["targetBasisHash"],
        "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
        "ringDegree": statement_set["ringDegree"],
        "participantCount": statement_set["participantCount"],
        "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
        "thresholdDegree": statement_set["thresholdDegree"],
        "compactCoefficientCommitmentRoot": statement_set["compactCoefficientCommitmentRoot"],
        "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
        "compactSameSecretBridgeStatementSetRoot": statement_set["compactSameSecretBridgeStatementSetRoot"],
        "proofRecords": proof_records,
    });
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &proof_material_set)
            .expect("compact same-secret bridge proof material set root")
    );

    proof_material_set
}

fn compact_same_secret_bridge_proof_record(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let proof_bytes_hex = compact_same_secret_bridge_proof_bytes_hex(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("compact same-secret bridge proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "CompactVssSameSecretBridgeProofRecord",
        "objectVersion": 1,
        "proofFamily": COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "compactSameSecretBridgeStatementRoot": statement_record["compactSameSecretBridgeStatementRoot"],
        "proofBytesHash": hash512_hex(
            COMPACT_SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_protocol_hash("SetupProofRecordBindingHash", &proof_record)
            .expect("compact same-secret bridge proof record root")
    );

    proof_record
}

fn compact_same_secret_bridge_proof_bytes_hex(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> String {
    let request = compact_same_secret_bridge_proof_generation_request(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let checkpoint_key = statement_record["compactSameSecretBridgeStatementRoot"]
        .as_str()
        .expect("compact same-secret bridge statement root");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        COMPACT_SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY,
        checkpoint_key,
        || {
            let generated = generate_compact_same_secret_bridge_proof_from_request(&request)
                .expect("compact same-secret bridge proof");
            crate::transcript_core::decode_hex(
                generated["proofBytesHex"]
                    .as_str()
                    .expect("compact same-secret bridge proof bytes hex"),
            )
            .expect("compact same-secret bridge proof bytes")
        },
    );

    to_hex(&proof_bytes)
}

fn compact_same_secret_bridge_proof_generation_request(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_roots = statement_record["targetConstantCoefficientCommitmentRoots"]
        .as_array()
        .expect("compact bridge target roots");
    let target_commitments = statement_record["targetConstantCoefficientCommitments"]
        .as_array()
        .expect("compact bridge target commitments");
    let target_rns_primes = target_roots
        .iter()
        .map(|root_record| root_record["rnsPrime"].clone())
        .collect::<Vec<_>>();
    let target_constant_commitment_roots = target_roots
        .iter()
        .map(|root_record| root_record["coefficientCommitmentRoot"].clone())
        .collect::<Vec<_>>();
    let target_constant_commitments = target_commitments
        .iter()
        .map(|commitment_record| commitment_record["commitment"].clone())
        .collect::<Vec<_>>();
    let ring_degree = statement_record["ringDegree"]
        .as_u64()
        .expect("compact bridge ring degree") as usize;
    let opening_randomness_by_limb = (0..target_roots.len())
        .map(|rns_limb_index| {
            compact_vss_coefficient_randomness_i64_fixture(
                trustee_roster_position as u64,
                rns_limb_index,
                0,
                ring_degree,
            )
        })
        .collect::<Vec<_>>();
    let secret_coefficients = (0..ring_degree)
        .map(|coefficient_position| {
            accepted_vss_secret_coefficient_fixture(
                trustee_roster_position as u64,
                coefficient_position,
            )
        })
        .collect::<Vec<_>>();
    let negative_indicator_coefficients = secret_coefficients
        .iter()
        .map(|coefficient| i64::from(*coefficient < 0))
        .collect::<Vec<_>>();
    let proof_randomness_seed_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "compact-same-secret-bridge-proof-randomness",
            "trusteeRosterPosition": trustee_roster_position,
        }),
    )
    .expect("compact same-secret bridge proof randomness seed");
    let proof_randomness_nonce_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "compact-same-secret-bridge-proof-randomness-nonce",
            "trusteeRosterPosition": trustee_roster_position,
        }),
    )
    .expect("compact same-secret bridge proof randomness nonce");
    let mut request = serde_json::json!({
        "context": {
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "trusteeIdentity": statement_record["trusteeIdentity"],
            "trusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "setupEpoch": setup_context["setupEpoch"],
            "compactSameSecretBridgeStatementRoot": statement_record["compactSameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "sameSecretProofRoot": statement_record["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
        },
        "ringDegree": ring_degree,
        "compactSameSecretBridge": {
            "compactSameSecretBridgeStatementRoot": statement_record["compactSameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "sameSecretProofRoot": statement_record["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
            "publicMatrixSeedHash": statement_record["publicMatrixSeedHash"],
            "sourceTrusteeIdentity": statement_record["trusteeIdentity"],
            "sourceTrusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "targetBasisHash": statement_record["targetBasisHash"],
            "targetRnsPrimes": target_rns_primes,
            "targetConstantCommitmentRoots": target_constant_commitment_roots,
            "targetConstantCommitments": target_constant_commitments,
        },
        "secretCoefficients": secret_coefficients,
        "negativeIndicatorCoefficients": negative_indicator_coefficients,
        "openingRandomnessByLimb": opening_randomness_by_limb,
        "proofRandomnessSeedHex": proof_randomness_seed_hex,
        "proofRandomnessNonceHex": proof_randomness_nonce_hex,
    });
    if let Some(transported_material) = transported_same_secret_proof_material {
        request["transportedSameSecretProofMaterial"] = transported_material.clone();
    }

    request
}

pub(in super::super) fn compact_same_secret_bridge_request_for_fixture(
    transported_same_secret_proof_material: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut request = serde_json::json!({});
    if let Some(transported_material) = transported_same_secret_proof_material {
        request["transportedSameSecretProofMaterial"] = transported_material.clone();
    }

    request
}

pub(in super::super) fn accepted_vss_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    accepted_vss_randomness_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
    )
    .into_iter()
    .map(|column| {
        column
            .into_iter()
            .map(|value| i64::try_from(value).expect("ternary randomness fits i64"))
            .collect()
    })
    .collect()
}

pub(in super::super) fn compact_vss_coefficient_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::compact_vss_commitment::COMPACT_VSS_RANDOMNESS_COLUMN_COUNT)
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

#[test]
fn compact_vss_public_material_fixture_verifies_generated_fields() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["compactVssCoefficientCommitmentSet"] =
        compact_vss_coefficient_commitment_set_object(&package, 128);
    package["compactVssRecipientShareCommitmentSet"] =
        compact_vss_recipient_share_commitment_set_object(&package);
    package["compactVssAggregateThresholdCommitmentSet"] =
        compact_vss_aggregate_threshold_commitment_set_object(&package);
    package["compactVssShareLinkageStatement"] =
        compact_vss_share_linkage_statement_object(&package);
    package["compactVssShareLinkageProofMaterialSet"] =
        compact_vss_share_linkage_proof_material_set_object(&package);

    let verification =
        crate::bgv::setup::verify_compact_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["compactVssShareLinkageStatement"],
                "coefficientCommitmentSet": package["compactVssCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["compactVssRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["compactVssAggregateThresholdCommitmentSet"],
                "proofMaterialSet": package["compactVssShareLinkageProofMaterialSet"],
            }),
        )
        .expect("generated compact VSS public material verifies");

    assert_eq!(verification["ok"], serde_json::json!(true));
    assert_eq!(
        verification["proofRecordCount"],
        serde_json::json!(3 * DATA_PRIMES.len())
    );
    assert_eq!(
        verification["coveredLinkageItemCount"],
        serde_json::json!(3 * 3 * DATA_PRIMES.len())
    );
    assert!(
        verification["proofMaterialSetRoot"].is_string(),
        "generated compact VSS proof material set must bind a root"
    );
}
