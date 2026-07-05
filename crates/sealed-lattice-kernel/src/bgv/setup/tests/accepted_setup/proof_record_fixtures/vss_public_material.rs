use super::*;

use crate::bgv::setup::setup_proof::SetupProofMaterialTransportHashes;
use crate::bgv::setup::trustee_evaluation_key_proof::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
};
use crate::hashing::derive_canonical_object_hash;

const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str = "sealed-lattice-vss-public-commitment-binary-v1";
const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes-v1";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes-v1";
const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const SAME_SECRET_BRIDGE_RELATION: &str = "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
pub(in super::super) const SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "same-secret-bridge-proof-material";
pub(in super::super) const VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY: &str =
    "vss-share-linkage-proof-material";

pub(in super::super) fn vss_public_coefficient_commitment_set_object(
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
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    set["coefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&set).expect("compact VSS coefficient commitment root")
    );

    set
}

fn vss_public_source_coefficient_record(
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
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "coefficientCommitments": coefficient_commitments,
    });
    source_record["sourceCoefficientCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_record)
            .expect("compact VSS source coefficient commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
fn vss_public_coefficient_commitment_record(
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
        .expect("compact VSS coefficient message digits");
    let randomness_by_column = vss_public_coefficient_randomness_i64_fixture(
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
    );
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicCoefficientCommitmentContext",
        "objectVersion": 1,
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
        .expect("compact VSS coefficient commitment");

    serde_json::json!({
        "objectType": "VssPublicCoefficientCommitment",
        "objectVersion": 1,
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

pub(in super::super) fn vss_public_recipient_share_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact coefficient ring degree") as usize;
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
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": source_trustee_records,
    });
    recipient_set["recipientShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&recipient_set)
            .expect("compact VSS recipient-share commitment root")
    );

    recipient_set
}

fn vss_public_source_recipient_share_record(
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
        "objectVersion": 1,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientShareCommitments": recipient_share_commitments,
    });
    source_record["sourceRecipientShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_record)
            .expect("compact VSS source recipient-share commitment root")
    );

    source_record
}

#[allow(clippy::too_many_arguments)]
fn vss_public_recipient_share_commitment_record(
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
        .expect("compact coefficient threshold degree");
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
        .expect("compact VSS recipient-share message digits");
    let randomness_by_column = vss_public_recipient_share_randomness_i64_fixture(
        source_trustee_roster_position,
        recipient_roster_position,
        rns_limb_index,
        ring_degree,
    );
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let commitment_context = serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitmentContext",
        "objectVersion": 1,
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
        .expect("compact VSS recipient-share commitment");

    serde_json::json!({
        "objectType": "VssPublicRecipientShareCommitment",
        "objectVersion": 1,
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

pub(in super::super) fn vss_public_aggregate_threshold_commitment_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let ring_degree = package["vssPublicRecipientShareCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact recipient-share ring degree") as usize;
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
        "objectVersion": 1,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "recipientRecords": recipient_records,
    });
    aggregate_set["aggregateThresholdCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&aggregate_set)
            .expect("compact aggregate threshold commitment root")
    );

    aggregate_set
}

fn vss_public_aggregate_threshold_commitment_record(
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
        "objectVersion": 1,
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
    let aggregate_commitment_root = derive_canonical_object_hash(&commitment)
        .expect("compact aggregate threshold commitment root");
    let aggregate_opening_root = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicAggregateThresholdOpening",
        "objectVersion": 1,
        "commitmentRole": "aggregate-threshold-share",
        "commitmentContext": commitment_context,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": DATA_PRIMES[rns_limb_index],
        "ringDegree": ring_degree,
        "sourceShareOpeningRoots": source_share_opening_roots,
    }))
    .expect("compact aggregate threshold opening root");

    serde_json::json!({
        "objectType": "VssPublicAggregateThresholdCommitment",
        "objectVersion": 1,
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
fn vss_public_sum_commitment_body(
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
        "objectVersion": 1,
        "commitmentRole": commitment_role,
        "commitmentContext": commitment_context,
    }))
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
        "objectType": "VssPublicCommitment",
        "objectVersion": 1,
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

pub(in super::super) fn vss_share_linkage_statement_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let participant_count = participant_count_from_package(package);
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("compact threshold degree");
    let ring_degree = package["vssPublicCoefficientCommitmentSet"]["ringDegree"]
        .as_u64()
        .expect("compact ring degree");
    let source_statement_records = (0..participant_count)
        .map(|source_trustee_roster_position| {
            vss_share_linkage_source_statement_record(
                package,
                &target_basis_hash,
                public_matrix_seed_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement = serde_json::json!({
        "objectType": "VssShareLinkageStatement",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": package["vssPublicCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "recipientShareCommitmentRoot": package["vssPublicRecipientShareCommitmentSet"]["recipientShareCommitmentRoot"],
        "aggregateThresholdCommitmentRoot": package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "sourceStatementRecords": source_statement_records,
    });
    statement["statementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement).expect("compact VSS share-linkage statement root")
    );

    statement
}

fn vss_share_linkage_source_statement_record(
    package: &serde_json::Value,
    target_basis_hash: &str,
    public_matrix_seed_hash: &str,
    source_trustee_roster_position: u64,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let coefficient_source_record =
        vss_public_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        vss_public_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_opening_roots = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("compact coefficient commitments")
        .iter()
        .take(
            DATA_PRIMES.len()
                * package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
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
        "objectType": "VssShareLinkageSourceStatement",
        "objectVersion": 1,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "targetBasisHash": target_basis_hash,
        "sourceTrusteeIdentity": source_trustee_identity,
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "ringDegree": package["vssPublicCoefficientCommitmentSet"]["ringDegree"],
        "participantCount": package["vssPublicCoefficientCommitmentSet"]["participantCount"],
        "targetRnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"],
        "coefficientCommitmentRoot": package["vssPublicCoefficientCommitmentSet"]["coefficientCommitmentRoot"],
        "sourceCoefficientCommitmentRoot": coefficient_source_record["sourceCoefficientCommitmentRoot"],
        "sourceRecipientShareCommitmentRoot": recipient_source_record["sourceRecipientShareCommitmentRoot"],
        "coefficientOpeningRoots": coefficient_opening_roots,
        "recipientShareOpeningRoots": recipient_share_opening_roots,
        "aggregateThresholdCommitmentRoot": package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
    });
    source_statement["sourceStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&source_statement)
            .expect("compact VSS share-linkage source statement root")
    );

    source_statement
}

pub(in super::super) fn vss_share_linkage_proof_material_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let statement = &package["vssShareLinkageStatement"];
    let participant_count = participant_count_from_package(package);
    let proof_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            vss_share_linkage_proof_records(package, source_trustee_roster_position)
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "VssShareLinkageProofMaterialSet",
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "ceremonyId": statement["ceremonyId"],
        "manifestHash": statement["manifestHash"],
        "rosterHash": statement["rosterHash"],
        "setupParametersHash": statement["setupParametersHash"],
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
        derive_canonical_object_hash(&proof_material_set)
            .expect("compact VSS share-linkage proof material set root")
    );

    proof_material_set
}

fn vss_share_linkage_proof_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let item_records = vss_share_linkage_item_records(package, source_trustee_roster_position);
    let proof_items_per_record = participant_count_from_package(package)
        .try_into()
        .expect("participant count fits usize");
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

fn vss_share_linkage_proof_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let vss_share_linkage = vss_share_linkage_proof_statement(package, item_records);
    let linkage_items = vss_share_linkage_coverage_items_from_records(item_records);
    let proof_bytes_hex = vss_share_linkage_proof_bytes_hex(
        package,
        &vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("compact VSS share-linkage proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "VssShareLinkageProofRecord",
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "linkageItems": linkage_items,
        "vssShareLinkage": vss_share_linkage,
        "proofBytesHash": hash512_hex(
            VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record)
            .expect("compact VSS share-linkage proof record root")
    );

    proof_record
}

fn vss_share_linkage_proof_statement(
    package: &serde_json::Value,
    item_records: &[serde_json::Value],
) -> serde_json::Value {
    let mut primary_item = item_records
        .first()
        .expect("compact VSS primary share-linkage item")
        .clone();
    primary_item["publicMatrixSeedHash"] =
        package["vssShareLinkageStatement"]["publicMatrixSeedHash"].clone();
    primary_item["shareLinkageStatementRoot"] =
        package["vssShareLinkageStatement"]["statementRoot"].clone();
    primary_item["additionalLinkageItems"] =
        serde_json::json!(item_records.iter().skip(1).cloned().collect::<Vec<_>>());

    primary_item
}

fn vss_share_linkage_item_records(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> Vec<serde_json::Value> {
    let participant_count = participant_count_from_package(package);
    (0..DATA_PRIMES.len())
        .flat_map(|rns_limb_index| {
            (0..participant_count).map(move |recipient_roster_position| {
                vss_share_linkage_item_record(
                    package,
                    source_trustee_roster_position,
                    recipient_roster_position,
                    rns_limb_index,
                )
            })
        })
        .collect()
}

fn vss_share_linkage_item_record(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
        .as_u64()
        .expect("threshold degree") as usize;
    let coefficient_source_record =
        vss_public_coefficient_source_record_from_package(package, source_trustee_roster_position);
    let recipient_source_record =
        vss_public_recipient_source_record_from_package(package, source_trustee_roster_position);
    let coefficient_records = coefficient_source_record["coefficientCommitments"]
        .as_array()
        .expect("coefficient commitment records");
    let coefficient_record_offset = rns_limb_index
        .checked_mul(threshold_degree)
        .expect("coefficient record offset");
    let selected_coefficient_records = &coefficient_records
        [coefficient_record_offset..coefficient_record_offset + threshold_degree];
    let recipient_record = vss_public_recipient_share_commitment_record_from_package(
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

fn vss_share_linkage_coverage_items_from_records(
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

fn vss_share_linkage_proof_bytes_hex(
    package: &serde_json::Value,
    vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> String {
    let request = vss_share_linkage_proof_generation_request(
        package,
        vss_share_linkage,
        source_trustee_roster_position,
        proof_record_index,
    );
    let checkpoint_key = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssShareLinkageProofCheckpointKey",
        "statementRoot": package["vssShareLinkageStatement"]["statementRoot"],
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
        "vssShareLinkage": vss_share_linkage,
    }))
    .expect("compact VSS share-linkage proof checkpoint key");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        VSS_SHARE_LINKAGE_PROOF_CHECKPOINT_DIRECTORY,
        &checkpoint_key,
        || {
            let generated = generate_vss_share_linkage_proof_from_request(&request)
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

fn vss_share_linkage_statement_items(
    vss_share_linkage: &serde_json::Value,
) -> Vec<&serde_json::Value> {
    let mut items = vec![vss_share_linkage];
    items.extend(
        vss_share_linkage["additionalLinkageItems"]
            .as_array()
            .expect("compact VSS additional linkage items")
            .iter(),
    );

    items
}

fn vss_share_linkage_coefficient_slots(
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

fn vss_share_linkage_proof_generation_request(
    package: &serde_json::Value,
    vss_share_linkage: &serde_json::Value,
    source_trustee_roster_position: u64,
    proof_record_index: usize,
) -> serde_json::Value {
    let statement = &package["vssShareLinkageStatement"];
    let ring_degree = statement["ringDegree"]
        .as_u64()
        .expect("compact share-linkage ring degree") as usize;
    let threshold_degree = statement["thresholdDegree"]
        .as_u64()
        .expect("compact share-linkage threshold degree");
    let linkage_items = vss_share_linkage_statement_items(vss_share_linkage);
    let coefficient_slots = vss_share_linkage_coefficient_slots(&linkage_items, threshold_degree);
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
            vss_public_coefficient_randomness_i64_fixture(
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
        let (share_coefficients, carry_witnesses) = vss_public_recipient_share_values_and_carries(
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
            vss_public_recipient_share_randomness_i64_fixture(
                source_trustee_roster_position,
                recipient_roster_position,
                rns_limb_index,
                ring_degree,
            ),
        );
        carry_witnesses_by_item.push(carry_witnesses);
    }
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "vss-share-linkage-proof-randomness",
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
    }))
    .expect("compact VSS share-linkage proof randomness seed");
    let proof_randomness_nonce_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "vss-share-linkage-proof-randomness-nonce",
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "proofRecordIndex": proof_record_index,
    }))
    .expect("compact VSS share-linkage proof randomness nonce");

    serde_json::json!({
        "context": {
            "ceremonyId": statement["ceremonyId"],
            "manifestHash": statement["manifestHash"],
            "rosterHash": statement["rosterHash"],
            "trusteeIdentity": "vss-share-linkage",
            "trusteeRosterPosition": 0,
            "setupEpoch": statement["setupEpoch"],
            "shareLinkageStatementRoot": statement["statementRoot"],
        },
        "ringDegree": ring_degree,
        "vssShareLinkage": vss_share_linkage,
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

fn vss_public_coefficient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["vssPublicCoefficientCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

fn vss_public_recipient_source_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
) -> &serde_json::Value {
    &package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]
}

fn vss_public_recipient_share_commitment_record_from_package(
    package: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
) -> serde_json::Value {
    let rns_limb_count = package["vssPublicRecipientShareCommitmentSet"]["rnsLimbCount"]
        .as_u64()
        .expect("compact recipient-share limb count") as usize;
    let record_index = (recipient_roster_position as usize)
        .checked_mul(rns_limb_count)
        .and_then(|offset| offset.checked_add(rns_limb_index))
        .expect("compact recipient-share record index");
    package["vssPublicRecipientShareCommitmentSet"]["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]["recipientShareCommitments"][record_index]
        .clone()
}

fn vss_public_recipient_share_values_and_carries(
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

fn vss_public_recipient_share_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
    rns_limb_index: usize,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    let seed_offset = 10_000
        + source_trustee_roster_position as i64 * 503
        + recipient_roster_position as i64 * 37
        + rns_limb_index as i64 * 11;
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
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

pub(in super::super) fn same_secret_bridge_statement_set_object(
    package: &serde_json::Value,
) -> serde_json::Value {
    let setup_context = &package["setupContext"];
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let target_basis_hash =
        crate::bgv::evaluator::top_k::canonical_target_basis_hash().expect("target basis hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let statement_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("compact source coefficient records")
        .iter()
        .enumerate()
        .map(|(source_trustee_roster_position, source_record)| {
            same_secret_bridge_statement_record(
                package,
                source_record,
                &target_basis_hash,
                source_trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut statement_set = serde_json::json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": coefficient_set["ringDegree"],
        "participantCount": coefficient_set["participantCount"],
        "targetRnsLimbCount": coefficient_set["rnsLimbCount"],
        "thresholdDegree": coefficient_set["thresholdDegree"],
        "coefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "sameSecretConsistencyRoot": package["sameSecretConsistency"]["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": package["sameSecretProofs"]["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": package["sameSecretConsistency"]["sameSecretProofFamilyBindingRoot"],
        "integerSupport": SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "statementRecords": statement_records,
    });
    statement_set["sameSecretBridgeStatementSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_set)
            .expect("compact same-secret bridge statement set root")
    );

    statement_set
}

fn same_secret_bridge_statement_record(
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
    let threshold_degree = package["vssPublicCoefficientCommitmentSet"]["thresholdDegree"]
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
        "objectType": "VssSameSecretBridgeStatement",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": setup_context["ceremonyId"],
        "manifestHash": setup_context["manifestHash"],
        "rosterHash": setup_context["rosterHash"],
        "setupParametersHash": setup_context["setupParametersHash"],
        "setupEpoch": setup_context["setupEpoch"],
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
        "ringDegree": package["vssPublicCoefficientCommitmentSet"]["ringDegree"],
        "trusteeIdentity": source_trustee_identity,
        "trusteeRosterPosition": source_trustee_roster_position,
        "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
        "sameSecretProofRoot": same_secret_proof["sameSecretProofRoot"],
        "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": target_constant_roots,
        "targetConstantCoefficientCommitments": target_constant_commitments,
        "relation": SAME_SECRET_BRIDGE_RELATION,
    });
    statement_record["sameSecretBridgeStatementRoot"] = serde_json::json!(
        derive_canonical_object_hash(&statement_record)
            .expect("compact same-secret bridge statement root")
    );

    statement_record
}

pub(in super::super) fn same_secret_bridge_proof_material_set_object(
    package: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
) -> serde_json::Value {
    let statement_set = &package["sameSecretBridgeStatementSet"];
    let proof_records = statement_set["statementRecords"]
        .as_array()
        .expect("compact same-secret bridge statement records")
        .iter()
        .enumerate()
        .map(|(trustee_roster_position, statement_record)| {
            same_secret_bridge_proof_record(
                package,
                statement_record,
                transported_same_secret_proof_material,
                trustee_roster_position,
            )
        })
        .collect::<Vec<_>>();
    let mut proof_material_set = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofMaterialSet",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": statement_set["ceremonyId"],
        "manifestHash": statement_set["manifestHash"],
        "rosterHash": statement_set["rosterHash"],
        "setupParametersHash": statement_set["setupParametersHash"],
        "setupEpoch": statement_set["setupEpoch"],
        "targetBasisHash": statement_set["targetBasisHash"],
        "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
        "ringDegree": statement_set["ringDegree"],
        "participantCount": statement_set["participantCount"],
        "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
        "thresholdDegree": statement_set["thresholdDegree"],
        "coefficientCommitmentRoot": statement_set["coefficientCommitmentRoot"],
        "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
        "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
        "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
        "sameSecretBridgeStatementSetRoot": statement_set["sameSecretBridgeStatementSetRoot"],
        "proofRecords": proof_records,
    });
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_material_set)
            .expect("compact same-secret bridge proof material set root")
    );

    proof_material_set
}

fn same_secret_bridge_proof_record(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> serde_json::Value {
    let proof_bytes_hex = same_secret_bridge_proof_bytes_hex(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let proof_bytes = crate::transcript_core::decode_hex(&proof_bytes_hex)
        .expect("compact same-secret bridge proof bytes");
    let mut proof_record = serde_json::json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
        "proofBytesHash": hash512_hex(
            SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
    });
    proof_record["proofRecordRoot"] = serde_json::json!(
        derive_canonical_object_hash(&proof_record)
            .expect("compact same-secret bridge proof record root")
    );

    proof_record
}

fn same_secret_bridge_proof_bytes_hex(
    package: &serde_json::Value,
    statement_record: &serde_json::Value,
    transported_same_secret_proof_material: Option<&serde_json::Value>,
    trustee_roster_position: usize,
) -> String {
    let request = same_secret_bridge_proof_generation_request(
        package,
        statement_record,
        transported_same_secret_proof_material,
        trustee_roster_position,
    );
    let checkpoint_key = statement_record["sameSecretBridgeStatementRoot"]
        .as_str()
        .expect("compact same-secret bridge statement root");
    let proof_bytes = checkpointed_anchor_proof_bytes(
        SAME_SECRET_BRIDGE_PROOF_CHECKPOINT_DIRECTORY,
        checkpoint_key,
        || {
            let generated = generate_same_secret_bridge_proof_from_request(&request)
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

fn same_secret_bridge_proof_generation_request(
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
            vss_public_coefficient_randomness_i64_fixture(
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
    let proof_randomness_seed_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "same-secret-bridge-proof-randomness",
        "trusteeRosterPosition": trustee_roster_position,
    }))
    .expect("compact same-secret bridge proof randomness seed");
    let proof_randomness_nonce_hex = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "VssPublicMaterialFixtureRandomness",
        "fixture": "same-secret-bridge-proof-randomness-nonce",
        "trusteeRosterPosition": trustee_roster_position,
    }))
    .expect("compact same-secret bridge proof randomness nonce");
    let mut request = serde_json::json!({
        "context": {
            "ceremonyId": setup_context["ceremonyId"],
            "manifestHash": setup_context["manifestHash"],
            "rosterHash": setup_context["rosterHash"],
            "trusteeIdentity": statement_record["trusteeIdentity"],
            "trusteeRosterPosition": statement_record["trusteeRosterPosition"],
            "setupEpoch": setup_context["setupEpoch"],
            "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
            "sameSecretStatementRoot": statement_record["sameSecretStatementRoot"],
            "sameSecretProofRoot": statement_record["sameSecretProofRoot"],
            "sameSecretProofFamilyBindingRoot": statement_record["sameSecretProofFamilyBindingRoot"],
        },
        "ringDegree": ring_degree,
        "sameSecretBridge": {
            "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
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

pub(in super::super) fn vss_public_coefficient_randomness_i64_fixture(
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    (0..crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT)
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
fn vss_public_material_fixture_verifies_generated_fields() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    package["vssShareLinkageProofMaterialSet"] =
        vss_share_linkage_proof_material_set_object(&package);

    let verification = crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
        &serde_json::json!({
            "statement": package["vssShareLinkageStatement"],
            "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
            "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
            "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
            "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
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

    // The compact same-secret bridge links the generated compact coefficient
    // commitments to the accepted same-secret proof over the target key-switch
    // basis. Generate it and verify both the statement set and the bridge proof
    // material set through the kernel commands, so the generator's bridge objects
    // are exercised against the same verifier the accepted-setup path uses. The
    // minimal package carries the same-secret consistency statements but not the
    // proof set the bridge references, so add the same-secret proofs first.
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] =
        same_secret_bridge_proof_material_set_object(&package, None);
    let bridge_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "sameSecretConsistency": package["sameSecretConsistency"],
        "sameSecretProofs": package["sameSecretProofs"],
        "proofMaterialSet": package["sameSecretBridgeProofMaterialSet"],
    });
    let bridge_statement_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_statement_set_request(&bridge_request)
            .expect("generated compact same-secret bridge statement set verifies");
    assert_eq!(bridge_statement_verification["ok"], serde_json::json!(true));
    let bridge_proof_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &bridge_request,
        )
        .expect("generated compact same-secret bridge proof material set verifies");
    assert_eq!(bridge_proof_verification["ok"], serde_json::json!(true));
}

// Move every compact share-linkage proof record's proof bytes out of the
// embedded base64 field and onto the shared setup proof-material transport,
// returning the rewritten proof material set alongside the transported material
// object that carries the streamed chunks. Each record binds its proof record
// root to the transport reference fields instead of the base64 bytes, exactly
// as the kernel verifier rebuilds it, so a transported set verifies identically
// to the embedded set it replaces.
pub(in super::super) fn move_vss_share_linkage_proof_bytes_to_transport(
    proof_material_set: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("compact share-linkage proof records");
    let mut transported_proof_materials = Vec::new();
    for proof_record in proof_records.iter_mut() {
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_record["proofBytesBase64"]
                .as_str()
                .expect("embedded compact share-linkage proof bytes"),
            "compact share-linkage proofBytesBase64",
        )
        .expect("decode compact share-linkage proof bytes");
        let chunks = transport_chunks(&proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("compact share-linkage transport hashes");
        let proof_material_root = transport_proof_material_root(
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            proof_record["proofBytesHash"]
                .as_str()
                .expect("proofBytesHash"),
            &transport_hashes,
        );

        let record_object = proof_record
            .as_object_mut()
            .expect("compact share-linkage proof record object");
        record_object.remove("proofBytesBase64");
        record_object.remove("proofRecordRoot");
        record_object.insert(
            "proofBytesEncoding".to_string(),
            serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING),
        );
        insert_transport_reference(record_object, &proof_material_root, &transport_hashes);
        proof_record["proofRecordRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record)
                .expect("compact share-linkage transported proof record root")
        );

        transported_proof_materials.push(transport_material_object(
            VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE,
            VSS_SHARE_LINKAGE_PROOF_FAMILY,
            &proof_material_root,
            &chunks,
            &transport_hashes,
        ));
    }

    rebind_proof_material_set_root(proof_material_set);

    serde_json::json!({
        "objectType": VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": VSS_SHARE_LINKAGE_PROOF_FAMILY,
        "proofMaterials": transported_proof_materials,
    })
}

// Move every compact same-secret bridge proof record's proof bytes onto the
// shared setup proof-material transport, mirroring the share-linkage helper.
pub(in super::super) fn move_same_secret_bridge_proof_bytes_to_transport(
    proof_material_set: &mut serde_json::Value,
) -> serde_json::Value {
    let proof_records = proof_material_set["proofRecords"]
        .as_array_mut()
        .expect("compact same-secret bridge proof records");
    let mut transported_proof_materials = Vec::new();
    for proof_record in proof_records.iter_mut() {
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_record["proofBytesBase64"]
                .as_str()
                .expect("embedded compact same-secret bridge proof bytes"),
            "compact same-secret bridge proofBytesBase64",
        )
        .expect("decode compact same-secret bridge proof bytes");
        let chunks = transport_chunks(&proof_bytes);
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &chunks,
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )
        .expect("compact same-secret bridge transport hashes");
        let proof_material_root = transport_proof_material_root(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            proof_record["proofBytesHash"]
                .as_str()
                .expect("proofBytesHash"),
            &transport_hashes,
        );

        let record_object = proof_record
            .as_object_mut()
            .expect("compact same-secret bridge proof record object");
        record_object.remove("proofBytesBase64");
        record_object.remove("proofRecordRoot");
        record_object.insert(
            "proofBytesEncoding".to_string(),
            serde_json::json!(SETUP_PROOF_MATERIAL_ENCODING),
        );
        insert_transport_reference(record_object, &proof_material_root, &transport_hashes);
        proof_record["proofRecordRoot"] = serde_json::json!(
            derive_canonical_object_hash(proof_record)
                .expect("compact same-secret bridge transported proof record root")
        );

        transported_proof_materials.push(transport_material_object(
            SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE,
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            &proof_material_root,
            &chunks,
            &transport_hashes,
        ));
    }

    rebind_proof_material_set_root(proof_material_set);

    serde_json::json!({
        "objectType": SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "proofMaterials": transported_proof_materials,
    })
}

const VSS_SHARE_LINKAGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterialSet";
const VSS_SHARE_LINKAGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedVssShareLinkageProofMaterial";
const SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterialSet";
const SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterial";

// Recompute a compact proof material set root over the canonical body. The
// verifier hashes the set with its proofMaterialSetRoot field absent, so the
// stale root must be removed before rehashing rather than left in place.
fn rebind_proof_material_set_root(proof_material_set: &mut serde_json::Value) {
    proof_material_set
        .as_object_mut()
        .expect("compact proof material set object")
        .remove("proofMaterialSetRoot");
    proof_material_set["proofMaterialSetRoot"] = serde_json::json!(
        derive_canonical_object_hash(proof_material_set)
            .expect("compact transported proof material set root")
    );
}

// Split proof bytes into the uniform transport chunk size the kernel enforces.
// The compact development proofs are far smaller than one chunk, so this yields
// a single chunk, but the split is written for the general case.
fn transport_chunks(proof_bytes: &[u8]) -> Vec<Vec<u8>> {
    let chunk_size =
        usize::try_from(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES).expect("chunk size fits usize");
    if proof_bytes.is_empty() {
        return vec![Vec::new()];
    }
    proof_bytes.chunks(chunk_size).map(<[u8]>::to_vec).collect()
}

fn transport_proof_material_root(
    proof_family: &str,
    proof_bytes_hash: &str,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> String {
    derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": proof_family,
        "proofBytesHash": proof_bytes_hash,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
    .expect("compact transport proof material root")
}

fn insert_transport_reference(
    record_object: &mut serde_json::Map<String, serde_json::Value>,
    proof_material_root: &str,
    transport_hashes: &SetupProofMaterialTransportHashes,
) {
    record_object.insert(
        "proofMaterialRoot".to_string(),
        serde_json::json!(proof_material_root),
    );
    record_object.insert(
        "proofChunkSizeBytes".to_string(),
        serde_json::json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES),
    );
    record_object.insert(
        "proofChunkCount".to_string(),
        serde_json::json!(transport_hashes.chunk_hashes.len()),
    );
    record_object.insert(
        "proofTotalByteLength".to_string(),
        serde_json::json!(transport_hashes.total_byte_length),
    );
    record_object.insert(
        "proofFullObjectHash".to_string(),
        serde_json::json!(transport_hashes.full_object_hash),
    );
    record_object.insert(
        "proofChunkRoot".to_string(),
        serde_json::json!(transport_hashes.chunk_root),
    );
    record_object.insert(
        "proofChunkHashes".to_string(),
        serde_json::json!(transport_hashes.chunk_hashes),
    );
}

fn transport_material_object(
    object_type: &str,
    proof_family: &str,
    proof_material_root: &str,
    chunks: &[Vec<u8>],
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> serde_json::Value {
    let chunk_entries = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            serde_json::json!({
                "chunkIndex": chunk_index,
                "bytesBase64": crate::transcript_core::encode_standard_base64(chunk),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "objectType": object_type,
        "objectVersion": 1,
        "proofFamily": proof_family,
        "proofMaterialRoot": proof_material_root,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
        "chunks": chunk_entries,
    })
}

// Assert two compact proof-material-set verification responses accept and agree
// on every verified field except the proof material set root, which binds the
// per-record proof-bytes encoding and so legitimately differs between the
// embedded and transported forms.
fn assert_semantically_identical_compact_verification(
    embedded: &serde_json::Value,
    transported: &serde_json::Value,
) {
    assert_eq!(
        embedded["ok"],
        serde_json::json!(true),
        "embedded compact verification must accept"
    );
    assert_eq!(
        transported["ok"],
        serde_json::json!(true),
        "transported compact verification must accept"
    );
    let mut embedded_without_root = embedded.clone();
    let mut transported_without_root = transported.clone();
    for response in [&mut embedded_without_root, &mut transported_without_root] {
        response
            .as_object_mut()
            .expect("compact verification response object")
            .remove("proofMaterialSetRoot");
    }
    assert_eq!(
        embedded_without_root, transported_without_root,
        "embedded and transported compact verifications must agree on every field except the proof material set root"
    );
}

#[test]
fn vss_share_linkage_transported_proof_material_matches_embedded() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    let embedded_proof_material_set = vss_share_linkage_proof_material_set_object(&package);

    let embedded_verification =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": embedded_proof_material_set,
            }),
        )
        .expect("embedded compact share-linkage proof material set verifies");

    let mut transported_proof_material_set = embedded_proof_material_set.clone();
    let transported_material =
        move_vss_share_linkage_proof_bytes_to_transport(&mut transported_proof_material_set);

    let transported_verification =
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedVssShareLinkageProofMaterial": transported_material,
            }),
        )
        .expect("transported compact share-linkage proof material set verifies");

    // The transported and embedded forms both accept and agree on every verified
    // semantic field. The proof material set root legitimately differs because it
    // canonically binds the record encoding: an embedded record carries base64
    // proof bytes while a transported record carries the transport reference, and
    // the verifier recomputes the root from the encoding it was given. So the
    // transported verification's root binds the transported set it was given, not
    // the embedded set's root.
    assert_semantically_identical_compact_verification(
        &embedded_verification,
        &transported_verification,
    );
    assert_eq!(
        transported_verification["proofMaterialSetRoot"],
        transported_proof_material_set["proofMaterialSetRoot"],
        "transported verification must recompute the transported proof material set root"
    );
    assert_ne!(
        transported_verification["proofMaterialSetRoot"],
        embedded_verification["proofMaterialSetRoot"],
        "the transported record encoding must give a distinct proof material set root"
    );

    // A transported record with no supplied transport material must be refused.
    assert!(
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
            }),
        )
        .is_err(),
        "transported compact share-linkage records must require transported proof material"
    );

    // Tampering with a transported chunk hash must be rejected.
    let mut tampered_material =
        move_vss_share_linkage_proof_bytes_to_transport(&mut embedded_proof_material_set.clone());
    tampered_material["proofMaterials"][0]["chunkHashes"][0] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_share_linkage_proof_material_set_from_request(
            &serde_json::json!({
                "statement": package["vssShareLinkageStatement"],
                "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
                "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
                "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedVssShareLinkageProofMaterial": tampered_material,
            }),
        )
        .is_err(),
        "tampered transported compact share-linkage chunk hash must be rejected"
    );
}

#[test]
fn same_secret_bridge_transported_proof_material_matches_embedded() {
    let mut package = minimal_collective_setup_package_for_participant_count(3);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    let embedded_proof_material_set = same_secret_bridge_proof_material_set_object(&package, None);

    let embedded_request = serde_json::json!({
        "statementSet": package["sameSecretBridgeStatementSet"],
        "sameSecretConsistency": package["sameSecretConsistency"],
        "sameSecretProofs": package["sameSecretProofs"],
        "proofMaterialSet": embedded_proof_material_set,
    });
    let embedded_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &embedded_request,
        )
        .expect("embedded compact same-secret bridge proof material set verifies");

    let mut transported_proof_material_set = embedded_proof_material_set.clone();
    let transported_material =
        move_same_secret_bridge_proof_bytes_to_transport(&mut transported_proof_material_set);

    let transported_verification =
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedSameSecretBridgeProofMaterial": transported_material,
            }),
        )
        .expect("transported compact same-secret bridge proof material set verifies");

    // As with share-linkage, both forms accept and agree on every verified
    // semantic field; only the proof material set root legitimately differs
    // because it canonically binds the per-record proof-bytes encoding.
    assert_semantically_identical_compact_verification(
        &embedded_verification,
        &transported_verification,
    );
    assert_eq!(
        transported_verification["proofMaterialSetRoot"],
        transported_proof_material_set["proofMaterialSetRoot"],
        "transported verification must recompute the transported proof material set root"
    );
    assert_ne!(
        transported_verification["proofMaterialSetRoot"],
        embedded_verification["proofMaterialSetRoot"],
        "the transported record encoding must give a distinct proof material set root"
    );

    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
            }),
        )
        .is_err(),
        "transported compact same-secret bridge records must require transported proof material"
    );

    let mut tampered_material =
        move_same_secret_bridge_proof_bytes_to_transport(&mut embedded_proof_material_set.clone());
    tampered_material["proofMaterials"][0]["chunkHashes"][0] = serde_json::json!("0".repeat(128));
    assert!(
        crate::bgv::setup::verify_vss_same_secret_bridge_proof_material_set_request(
            &serde_json::json!({
                "statementSet": package["sameSecretBridgeStatementSet"],
                "sameSecretConsistency": package["sameSecretConsistency"],
                "sameSecretProofs": package["sameSecretProofs"],
                "proofMaterialSet": transported_proof_material_set,
                "transportedSameSecretBridgeProofMaterial": tampered_material,
            }),
        )
        .is_err(),
        "tampered transported compact same-secret bridge chunk hash must be rejected"
    );
}

// Rebind a setup package to the compact coefficient commitment sets, the compact
// same-secret bridge, and a ThresholdShareCommitmentBinding so the package
// is accepted through the compact path of the collective setup verifier. The
// participant count is read from the package, so this drives any supported
// roster size.
pub(in super::super) fn compactify_collective_setup_package(
    mut package: serde_json::Value,
) -> serde_json::Value {
    let participant_count = participant_count_from_package(&package);
    package["vssPublicCoefficientCommitmentSet"] =
        vss_public_coefficient_commitment_set_object(&package, 128);
    package["vssPublicRecipientShareCommitmentSet"] =
        vss_public_recipient_share_commitment_set_object(&package);
    package["vssPublicAggregateThresholdCommitmentSet"] =
        vss_public_aggregate_threshold_commitment_set_object(&package);
    package["vssShareLinkageStatement"] = vss_share_linkage_statement_object(&package);
    package["vssShareLinkageProofMaterialSet"] =
        vss_share_linkage_proof_material_set_object(&package);
    // Rebuild the same-secret consistency statements to bind the compact constant
    // coefficient commitments. The statement builder reads the full-VSS field
    // names (sourceTrusteeCommitmentRoot, per-commitment commitmentRoot), so pass
    // a compact coefficient view that aliases those to the compact roots the
    // accepted-setup verifier recomputes. The same-secret proofs and bridge below
    // then reference these compact-bound statements.
    let coefficient_set = package["vssPublicCoefficientCommitmentSet"].clone();
    let compact_consistency_source_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("compact source trustee records")
        .iter()
        .map(|source_record| {
            let commitments = source_record["coefficientCommitments"]
                .as_array()
                .expect("compact coefficient commitments")
                .iter()
                .map(|commitment| {
                    let mut commitment = commitment.clone();
                    commitment["commitmentRoot"] = commitment["coefficientCommitmentRoot"].clone();
                    commitment
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "sourceTrusteeRosterPosition": source_record["sourceTrusteeRosterPosition"],
                "sourceTrusteeIdentity": source_record["sourceTrusteeIdentity"],
                "sourceTrusteeCommitmentRoot": source_record["sourceCoefficientCommitmentRoot"],
                "coefficientCommitments": commitments,
            })
        })
        .collect::<Vec<_>>();
    let compact_consistency_view = serde_json::json!({
        "vssCoefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "sourceTrusteeRecords": compact_consistency_source_records,
    });
    package["sameSecretConsistency"] =
        super::super::package_fixtures::same_secret_consistency_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &compact_consistency_view,
            participant_count,
        );
    // The public key shares and their proofs bind the same-secret statement roots,
    // which the compact rebuild changed, so rebuild them against the compact
    // statements.
    let rebuilt_public_key_shares = super::super::package_fixtures::public_key_shares_object(
        package["setupContext"]["ceremonyId"]
            .as_str()
            .expect("ceremony id"),
        package["setupContext"]["manifestHash"]
            .as_str()
            .expect("manifest hash"),
        package["setupContext"]["rosterHash"]
            .as_str()
            .expect("roster hash"),
        package["setupContext"]["setupParametersHash"]
            .as_str()
            .expect("setup parameters hash"),
        package["setupContext"]["setupEpoch"]
            .as_str()
            .expect("setup epoch"),
        &package["commonRandomness"],
        &package["sameSecretConsistency"],
        participant_count,
    );
    package["publicKeyShares"] = rebuilt_public_key_shares;
    let rebuilt_public_key_share_proofs =
        super::super::package_fixtures::public_key_share_proofs_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &package["commonRandomness"],
            &package["sameSecretConsistency"],
            &package["publicKeyShares"],
            participant_count,
        );
    package["publicKeyShareProofs"] = rebuilt_public_key_share_proofs;
    // The evaluator key schedule also binds the same-secret statement root and the
    // rebuilt public key share material.
    let setup_parameters =
        crate::bgv::setup::accepted_setup::describe_collective_bgv_setup_parameters()
            .expect("setup parameters");
    let rebuilt_evaluator_key_schedule =
        super::super::package_fixtures::evaluator_key_schedule_object(
            package["setupContext"]["ceremonyId"]
                .as_str()
                .expect("ceremony id"),
            package["setupContext"]["manifestHash"]
                .as_str()
                .expect("manifest hash"),
            package["setupContext"]["rosterHash"]
                .as_str()
                .expect("roster hash"),
            package["setupContext"]["setupParametersHash"]
                .as_str()
                .expect("setup parameters hash"),
            package["setupContext"]["setupEpoch"]
                .as_str()
                .expect("setup epoch"),
            &setup_parameters,
            &package["commonRandomness"],
            &package["sameSecretConsistency"],
            &package["publicKeyShares"],
            &package["publicKeyShareProofs"],
            participant_count,
        );
    package["evaluatorKeySchedule"] = rebuilt_evaluator_key_schedule;
    package["sameSecretProofs"] = same_secret_proofs_object(&package);
    package["sameSecretBridgeStatementSet"] = same_secret_bridge_statement_set_object(&package);
    package["sameSecretBridgeProofMaterialSet"] =
        same_secret_bridge_proof_material_set_object(&package, None);

    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let statement = &package["vssShareLinkageStatement"];
    let mut threshold_binding = serde_json::json!({
        "objectType": "ThresholdShareCommitmentBinding",
        "objectVersion": 1,
        "publicMatrixSeedHash": coefficient_set["publicMatrixSeedHash"],
        "participantCount": coefficient_set["participantCount"],
        "thresholdDegree": coefficient_set["thresholdDegree"],
        "targetRnsLimbCount": statement["targetRnsLimbCount"],
        "ringDegree": coefficient_set["ringDegree"],
        "aggregateThresholdCommitmentRoot":
            package["vssPublicAggregateThresholdCommitmentSet"]["aggregateThresholdCommitmentRoot"],
        "shareLinkageStatementRoot": statement["statementRoot"],
        "shareLinkageProofMaterialSetRoot":
            package["vssShareLinkageProofMaterialSet"]["proofMaterialSetRoot"],
    });
    threshold_binding["thresholdShareCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&threshold_binding)
            .expect("compact threshold-share commitment binding root")
    );
    package["thresholdShareCommitments"] = threshold_binding;

    // The public VSS coefficient material is replaced by the compact sets.
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("vssCoefficientCommitments");
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("vssCoefficientCommitmentMaterial");

    // The private VSS envelopes bind (as AAD) to the accepted coefficient
    // commitment root and each source trustee's per-trustee coefficient root,
    // which on the compact path are the compact set root and each compact source
    // record's sourceCoefficientCommitmentRoot, so rebuild the envelopes against
    // a compact-rooted coefficient view.
    let ceremony_id = package["setupContext"]["ceremonyId"]
        .as_str()
        .expect("ceremony id")
        .to_string();
    let manifest_hash = package["setupContext"]["manifestHash"]
        .as_str()
        .expect("manifest hash")
        .to_string();
    let roster_hash = package["setupContext"]["rosterHash"]
        .as_str()
        .expect("roster hash")
        .to_string();
    let setup_parameters_hash = package["setupContext"]["setupParametersHash"]
        .as_str()
        .expect("setup parameters hash")
        .to_string();
    let setup_epoch = package["setupContext"]["setupEpoch"]
        .as_str()
        .expect("setup epoch")
        .to_string();
    let common_randomness = package["commonRandomness"].clone();
    let coefficient_set = &package["vssPublicCoefficientCommitmentSet"];
    let compact_source_records = coefficient_set["sourceTrusteeRecords"]
        .as_array()
        .expect("compact source trustee records")
        .iter()
        .map(|source_record| {
            serde_json::json!({
                "sourceTrusteeRosterPosition": source_record["sourceTrusteeRosterPosition"],
                "sourceTrusteeCommitmentRoot": source_record["sourceCoefficientCommitmentRoot"],
            })
        })
        .collect::<Vec<_>>();
    let coefficient_view = serde_json::json!({
        "vssCoefficientCommitmentRoot": coefficient_set["coefficientCommitmentRoot"],
        "sourceTrusteeRecords": compact_source_records,
    });
    let rebuilt_envelopes = super::super::package_fixtures::private_vss_envelope_commitments_object(
        &ceremony_id,
        &manifest_hash,
        &roster_hash,
        &setup_parameters_hash,
        &setup_epoch,
        &common_randomness,
        &coefficient_view,
        participant_count,
    );
    // The VSS share acceptances reference the rebuilt envelopes and the same
    // compact-rooted coefficient view, so rebuild them to match.
    let rebuilt_acceptances = super::super::package_fixtures::vss_share_acceptances_object(
        &ceremony_id,
        &manifest_hash,
        &roster_hash,
        &setup_parameters_hash,
        &setup_epoch,
        &rebuilt_envelopes,
        &coefficient_view,
        participant_count,
    );
    package["privateVssEnvelopeCommitmentRoot"] =
        rebuilt_envelopes["privateVssEnvelopeCommitmentRoot"].clone();
    package["privateVssEnvelopeCommitments"] = rebuilt_envelopes;
    package["vssShareAcceptances"] = rebuilt_acceptances;

    // The compact commitment sets are embedded and proof-verified in-package, so
    // there is no large public VSS material to stream: the transport certificate
    // carries no transported objects on the compact path.
    let mut transport_certificate = package["setupTransportCertificate"].clone();
    {
        let certificate_object = transport_certificate
            .as_object_mut()
            .expect("transport certificate object");
        certificate_object.insert("transportedObjects".to_string(), serde_json::json!([]));
        certificate_object.insert("totalByteLength".to_string(), serde_json::json!(0));
        certificate_object.insert("chunkCount".to_string(), serde_json::json!(0));
        certificate_object.remove("setupTransportCertificateHash");
    }
    let transport_certificate_hash =
        derive_canonical_object_hash(&transport_certificate).expect("transport certificate hash");
    transport_certificate["setupTransportCertificateHash"] =
        serde_json::json!(transport_certificate_hash);
    package["setupTransportCertificateHash"] = serde_json::json!(transport_certificate_hash);
    package["setupTransportCertificate"] = transport_certificate;

    rebind_collective_setup_package_hash(&mut package);
    package
}

// The reference compact package: the reduced-ring three-trustee base package run
// through the compact transform. The accepted-setup compact path is exercised
// against it.
pub(in super::super) fn minimal_compact_collective_setup_package() -> serde_json::Value {
    compactify_collective_setup_package(minimal_collective_setup_package_for_participant_count(3))
}

// The compact setup package flows through every accepted-setup phase on the
// compact path: the public coefficient commitment material is replaced by the
// compact commitment sets and same-secret bridge, and every downstream phase
// (private VSS envelopes, share acceptances, same-secret consistency, public key
// shares and proofs, evaluator schedule, transport certificate, final objects)
// binds those compact roots. Like the full-VSS minimal package this reduced-ring
// package is pre-terminal (no collective public key runtime material), so it is
// not fully valid; the check is that it passes every compact-specific phase and
// object requirement, leaving only the terminal runtime objects missing.
#[test]
fn minimal_compact_collective_setup_package_passes_compact_acceptance() {
    let package = minimal_compact_collective_setup_package();
    let result = crate::bgv::setup::accepted_setup::verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({}),
    )
    .expect("compact collective setup package verification result");
    let context = || serde_json::to_string_pretty(&result).unwrap();
    // No phase refuses the compact material.
    assert!(
        result["refusedObjects"]
            .as_array()
            .is_none_or(|refused| refused.is_empty()),
        "compact package must not be refused at any phase: {}",
        context()
    );
    // Every compact-specific phase passed, so the flow reached the final phase.
    assert_eq!(
        result["currentPhase"],
        "setupPackageVerification",
        "{}",
        context()
    );
    // The compact commitment sets satisfy the coefficient-commitment requirement;
    // only the terminal runtime objects a pre-terminal setup package lacks may
    // remain.
    let missing_objects = result["missingObjects"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        missing_objects.iter().all(|missing_object| matches!(
            missing_object.as_str(),
            Some("publicKeyShareMaterial")
                | Some("publicKeyShareSuccinctProofs")
                | Some("collectivePublicKey")
                | Some("collectivePublicKeyRoot")
        )),
        "only terminal runtime objects may remain missing for the pre-terminal compact package: {}",
        context()
    );
}
