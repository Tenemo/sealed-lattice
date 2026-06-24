use super::*;

use crate::bgv::setup::{
    CompactVssCommitmentOpeningInput, compute_compact_vss_commitment_from_opening,
    read_compact_vss_randomness_by_column,
};

const COMPACT_VSS_AGGREGATE_COMMITMENT_ROLE: &str = "aggregate-threshold-share";

pub(super) struct CompactAggregateOpeningCheckInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) credential: &'a Value,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_share_values: &'a [u64],
}

pub(super) struct CompactAggregateOpeningRootsInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_share_values: &'a [u64],
    pub(super) aggregate_randomness_by_column: &'a [Vec<i64>],
}

pub(super) fn verify_compact_aggregate_opening_credential(
    input: CompactAggregateOpeningCheckInput<'_>,
) -> CanonicalResult<(String, String)> {
    let aggregate_randomness_by_column = read_compact_vss_randomness_by_column(
        input.credential,
        "aggregateRandomnessByColumn",
        POLYNOMIAL_DEGREE,
        Some(input.rns_prime),
    )?;
    let (commitment_root, opening_root) =
        compute_compact_aggregate_opening_roots(CompactAggregateOpeningRootsInput {
            setup_binding: input.setup_binding,
            participant: input.participant,
            setup_epoch: input.setup_epoch,
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            rns_prime: input.rns_prime,
            aggregate_share_values: input.aggregate_share_values,
            aggregate_randomness_by_column: &aggregate_randomness_by_column,
        })?;
    compare_hash_field(
        input.credential,
        "aggregateCommitmentRoot",
        &commitment_root,
        "compact aggregate opening credential commitment root",
    )?;
    compare_hash_field(
        input.credential,
        "aggregateOpeningRoot",
        &opening_root,
        "compact aggregate opening credential opening root",
    )?;

    Ok((commitment_root, opening_root))
}

pub(super) fn compute_compact_aggregate_opening_roots(
    input: CompactAggregateOpeningRootsInput<'_>,
) -> CanonicalResult<(String, String)> {
    let commitment_context = compact_aggregate_commitment_context(
        input.setup_binding,
        input.participant,
        input.setup_epoch,
        input.rns_limb_index,
        input.rns_prime,
    );
    let computation =
        compute_compact_vss_commitment_from_opening(CompactVssCommitmentOpeningInput {
            commitment_role: COMPACT_VSS_AGGREGATE_COMMITMENT_ROLE,
            commitment_context: &commitment_context,
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            rns_prime: input.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: input.aggregate_share_values,
            randomness_by_column: input.aggregate_randomness_by_column,
        })?;

    Ok((computation.commitment_root, computation.opening_root))
}

fn compact_aggregate_commitment_context(
    setup_binding: &SetupBinding,
    participant: &ParticipantBinding,
    setup_epoch: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> Value {
    json!({
        "objectType": "CompactVssAggregateThresholdShareCommitmentContext",
        "objectVersion": 1,
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_binding.roster_hash.as_str(),
        "setupProfileHash": setup_binding.setup_profile_hash.as_str(),
        "qShareHash": setup_binding.q_share_hash.as_str(),
        "carryAwareVssShareRelationProfileHash": setup_binding.carry_aware_vss_share_relation_profile_hash.as_str(),
        "commitmentProfileHash": setup_binding.commitment_profile_hash.as_str(),
        "setupEpoch": setup_epoch,
        "recipientIdentity": participant.trustee_identity.as_str(),
        "recipientRosterPosition": participant.roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    })
}
