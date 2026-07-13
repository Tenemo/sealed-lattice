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
    let aggregate_opening_root = string_at_path(input.credential, &["aggregateOpeningRoot"])?;
    let aggregate_commitment_message_values =
        take_aggregate_opening_message_values(aggregate_opening_root)?;
    let aggregate_share_values =
        derive_aggregate_share_values(&aggregate_commitment_message_values, input.rns_prime)?;
    let computation = compute_aggregate_opening(AggregateOpeningRootsInput {
        setup_binding: input.setup_binding,
        participant: input.participant,
        setup_epoch: input.setup_epoch,
        rns_limb_index: input.rns_limb_index,
        rns_prime: input.rns_prime,
        aggregate_commitment_message_values: &aggregate_commitment_message_values,
        message_coefficient_bound: input.rns_prime,
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

fn take_aggregate_opening_message_values(
    aggregate_opening_root: &str,
) -> CanonicalResult<Vec<u64>> {
    let material = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        crate::bgv::setup::TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY,
        aggregate_opening_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "aggregate opening credential is missing canonical stream-authenticated message material",
        )
    })?;
    let expected_byte_length = POLYNOMIAL_DEGREE
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate opening message byte length overflowed usize",
            )
        })?;
    if material.len() != expected_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate opening message byte length must match ringDegree",
        ));
    }

    let mut values = Vec::new();
    values.try_reserve_exact(POLYNOMIAL_DEGREE).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregate opening message allocation failed within the fixed ring bound",
        )
    })?;
    let mut encoded_value = [0_u8; std::mem::size_of::<u64>()];
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let byte_offset = coefficient_index * encoded_value.len();
        if !material.copy_range(byte_offset, &mut encoded_value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "aggregate opening message ended before ringDegree values",
            ));
        }
        values.push(u64::from_le_bytes(encoded_value));
    }
    Ok(values)
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
        "objectType": "VssPublicAggregateThresholdCommitmentContext",
        "ceremonyId": setup_binding.ceremony_id.as_str(),
        "manifestHash": setup_binding.election_manifest_hash.as_str(),
        "rosterHash": setup_binding.roster_hash.as_str(),
        "setupParametersHash": setup_binding.setup_parameters_hash.as_str(),
        "setupEpoch": setup_epoch,
        "recipientIdentity": participant.trustee_identity.as_str(),
        "recipientRosterPosition": participant.roster_position,
        "recipientTrusteePoint": participant.interpolation_point,
        "rnsLimbIndex": rns_limb_index,
        "rnsPrime": rns_prime,
    })
}
