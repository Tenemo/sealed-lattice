use super::*;

use crate::bgv::setup::{
    VssCommittedMaterialCommitmentInput, compute_vss_committed_material_commitment,
};

const VSS_PUBLIC_AGGREGATE_COMMITMENT_ROLE: &str = "aggregate-threshold-share";

pub(super) struct AggregateOpeningCheckInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) credential: &'a Value,
}

pub(super) struct AggregateOpeningRootsInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_commitment_message_values: &'a [u64],
    pub(super) message_coefficient_bound: u64,
    // The trustee's private deterministic material seed for the aggregate
    // committed-material trees; the same seed regenerates byte-identical trees
    // at proof time.
    pub(super) aggregate_material_seed_hex: &'a str,
}

pub(super) struct AggregateOpeningComputation {
    #[cfg(test)]
    pub(super) commitment: Value,
    pub(super) commitment_root: String,
    pub(super) commitment_context_hash: String,
    pub(super) opening_root: String,
}

pub(super) struct VerifiedAggregateOpeningCredential {
    pub(super) commitment_root: String,
    pub(super) commitment_context_hash: String,
    pub(super) opening_root: String,
    pub(super) aggregate_share_values: Vec<u64>,
    pub(super) aggregate_commitment_message_values: Vec<u64>,
    pub(super) aggregate_material_seed_hex: String,
}

pub(super) fn verify_aggregate_opening_credential(
    input: AggregateOpeningCheckInput<'_>,
) -> CanonicalResult<VerifiedAggregateOpeningCredential> {
    let aggregate_material_seed_hex =
        string_at_path(input.credential, &["aggregateMaterialSeedHex"])?.to_string();
    let aggregate_commitment_message_values = read_aggregate_u64_vector_le_hex(
        input.credential,
        "aggregateCommitmentMessageValuesLeHex",
        "aggregate opening credential message byte length must match ringDegree",
    )?;
    let aggregate_share_values =
        derive_aggregate_share_values(&aggregate_commitment_message_values, input.rns_prime)?;
    let message_coefficient_bound = aggregate_message_coefficient_bound(
        input.rns_prime,
        input.setup_binding.participants.len(),
    )?;
    let computation = compute_aggregate_opening(AggregateOpeningRootsInput {
        setup_binding: input.setup_binding,
        participant: input.participant,
        setup_epoch: input.setup_epoch,
        rns_limb_index: input.rns_limb_index,
        rns_prime: input.rns_prime,
        aggregate_commitment_message_values: &aggregate_commitment_message_values,
        message_coefficient_bound,
        aggregate_material_seed_hex: &aggregate_material_seed_hex,
    })?;
    compare_hash_field(
        input.credential,
        "aggregateCommitmentRoot",
        &computation.commitment_root,
        "aggregate opening credential commitment root",
    )?;
    compare_hash_field(
        input.credential,
        "aggregateOpeningRoot",
        &computation.opening_root,
        "aggregate opening credential opening root",
    )?;

    Ok(VerifiedAggregateOpeningCredential {
        commitment_root: computation.commitment_root,
        commitment_context_hash: computation.commitment_context_hash,
        opening_root: computation.opening_root,
        aggregate_share_values,
        aggregate_commitment_message_values,
        aggregate_material_seed_hex,
    })
}

#[cfg(test)]
pub(super) fn compute_aggregate_opening_roots(
    input: AggregateOpeningRootsInput<'_>,
) -> CanonicalResult<(String, String)> {
    let computation = compute_aggregate_opening(input)?;

    Ok((computation.commitment_root, computation.opening_root))
}

pub(super) fn compute_aggregate_opening(
    input: AggregateOpeningRootsInput<'_>,
) -> CanonicalResult<AggregateOpeningComputation> {
    let commitment_context = aggregate_commitment_context(
        input.setup_binding,
        input.participant,
        input.setup_epoch,
        input.rns_limb_index,
        input.rns_prime,
    );
    let computation =
        compute_vss_committed_material_commitment(VssCommittedMaterialCommitmentInput {
            commitment_role: VSS_PUBLIC_AGGREGATE_COMMITMENT_ROLE,
            commitment_context: &commitment_context,
            rns_limb_index: input.rns_limb_index,
            rns_prime: input.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: input.aggregate_commitment_message_values,
            message_coefficient_bound: input.message_coefficient_bound,
            material_seed_hex: input.aggregate_material_seed_hex,
        })?;

    Ok(AggregateOpeningComputation {
        #[cfg(test)]
        commitment: computation.commitment,
        commitment_root: computation.commitment_root,
        commitment_context_hash: computation.commitment_context_hash,
        opening_root: computation.opening_root,
    })
}

pub(super) fn read_aggregate_u64_vector_le_hex(
    credential: &Value,
    field_name: &str,
    length_error_message: &'static str,
) -> CanonicalResult<Vec<u64>> {
    coefficient_vector_from_le_hex(
        string_at_path(credential, &[field_name])?,
        POLYNOMIAL_DEGREE,
        length_error_message,
    )
}

fn derive_aggregate_share_values(
    aggregate_commitment_message_values: &[u64],
    rns_prime: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut aggregate_share_values = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let aggregate_commitment_message_value = aggregate_commitment_message_values
            .get(coefficient_index)
            .copied()
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "aggregate opening message length must match ringDegree",
                )
            })?;
        aggregate_share_values.push(aggregate_commitment_message_value % rns_prime);
    }

    Ok(aggregate_share_values)
}

fn aggregate_commitment_context(
    setup_binding: &SetupBinding,
    participant: &ParticipantBinding,
    setup_epoch: &str,
    rns_limb_index: usize,
    rns_prime: u64,
) -> Value {
    json!({
        "objectType": "VssPublicAggregateThresholdShareCommitmentContext",
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_binding.roster_hash.as_str(),
        "setupParametersHash": setup_binding.setup_parameters_hash.as_str(),
        "setupEpoch": setup_epoch,
        "recipientIdentity": participant.trustee_identity.as_str(),
        "recipientRosterPosition": participant.roster_position,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    })
}
