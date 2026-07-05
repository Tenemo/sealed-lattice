use super::*;

use crate::bgv::setup::{
    VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT, VssPublicCommitmentOpeningInput,
    compute_vss_public_commitment_from_opening, vss_public_canonical_message_digit_columns,
};

const VSS_PUBLIC_AGGREGATE_COMMITMENT_ROLE: &str = "aggregate-threshold-share";

pub(super) struct AggregateOpeningCheckInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) credential: &'a Value,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
}

pub(super) struct AggregateOpeningRootsInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) setup_epoch: &'a str,
    pub(super) public_matrix_seed_hash: &'a str,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_commitment_message_values: &'a [u64],
    pub(super) message_coefficient_bound: u64,
    pub(super) aggregate_randomness_by_column: &'a [Vec<i64>],
}

pub(super) struct AggregateOpeningComputation {
    pub(super) commitment: Value,
    pub(super) commitment_root: String,
    pub(super) opening_root: String,
}

pub(super) struct VerifiedAggregateOpeningCredential {
    pub(super) commitment_root: String,
    pub(super) opening_root: String,
    pub(super) aggregate_share_values: Vec<u64>,
    pub(super) aggregate_commitment_message_values: Vec<u64>,
    pub(super) aggregate_randomness_by_column: Vec<Vec<i64>>,
}

pub(super) fn verify_aggregate_opening_credential(
    input: AggregateOpeningCheckInput<'_>,
) -> CanonicalResult<VerifiedAggregateOpeningCredential> {
    let aggregate_randomness_by_column = read_aggregate_randomness_by_column_signed_byte_hex(
        input.credential,
        input.setup_binding.participants.len(),
    )?;
    let aggregate_commitment_message_values = read_aggregate_u64_vector_le_hex(
        input.credential,
        "aggregateCommitmentMessageValuesLeHex",
        "compact aggregate opening credential message byte length must match ringDegree",
    )?;
    let aggregate_share_values =
        derive_aggregate_share_values(&aggregate_commitment_message_values, input.rns_prime)?;
    let message_coefficient_bound = aggregate_message_coefficient_bound(
        input.rns_prime,
        input.setup_binding.participants.len(),
    )?;
    let (commitment_root, opening_root) =
        compute_aggregate_opening_roots(AggregateOpeningRootsInput {
            setup_binding: input.setup_binding,
            participant: input.participant,
            setup_epoch: input.setup_epoch,
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            rns_prime: input.rns_prime,
            aggregate_commitment_message_values: &aggregate_commitment_message_values,
            message_coefficient_bound,
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

    Ok(VerifiedAggregateOpeningCredential {
        commitment_root,
        opening_root,
        aggregate_share_values,
        aggregate_commitment_message_values,
        aggregate_randomness_by_column,
    })
}

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
    let message_digit_columns = vss_public_canonical_message_digit_columns(
        input.aggregate_commitment_message_values,
        POLYNOMIAL_DEGREE,
    )?;
    let computation =
        compute_vss_public_commitment_from_opening(VssPublicCommitmentOpeningInput {
            commitment_role: VSS_PUBLIC_AGGREGATE_COMMITMENT_ROLE,
            commitment_context: &commitment_context,
            public_matrix_seed_hash: input.public_matrix_seed_hash,
            rns_limb_index: input.rns_limb_index,
            rns_prime: input.rns_prime,
            ring_degree: POLYNOMIAL_DEGREE,
            message_coefficients: input.aggregate_commitment_message_values,
            message_digit_columns: &message_digit_columns,
            message_coefficient_bound: input.message_coefficient_bound,
            randomness_by_column: input.aggregate_randomness_by_column,
        })?;

    Ok(AggregateOpeningComputation {
        commitment: computation.commitment,
        commitment_root: computation.commitment_root,
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

fn read_aggregate_randomness_by_column_signed_byte_hex(
    credential: &Value,
    participant_count: usize,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let columns = array_at_path(credential, &["aggregateRandomnessByColumnSignedByteHex"])?;
    if columns.len() != VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "aggregateRandomnessByColumnSignedByteHex must carry the compact randomness column count",
        ));
    }
    let maximum_abs = i64::try_from(participant_count).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact aggregate opening participant count does not fit signed randomness bound",
        )
    })?;

    let randomness_by_column = columns
        .iter()
        .enumerate()
        .map(|(column_index, column)| {
            let coefficients = signed_byte_vector_from_hex(
                column.as_str().ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!(
                            "aggregateRandomnessByColumnSignedByteHex.{column_index} must be lowercase hex bytes"
                        ),
                    )
                })?,
                POLYNOMIAL_DEGREE,
                "compact aggregate opening credential signed-byte randomness length must match ringDegree",
            )?;
            if coefficients
                .iter()
                .any(|coefficient| coefficient.unsigned_abs() > maximum_abs.unsigned_abs())
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "compact VSS opening randomness coefficient exceeds the participant-count bound",
                ));
            }

            Ok(coefficients)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(randomness_by_column)
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
                    "compact aggregate opening message length must match ringDegree",
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
        "objectVersion": 1,
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
