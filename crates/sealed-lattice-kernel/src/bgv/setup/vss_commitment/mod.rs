use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_u64_at_path,
    read_positive_usize_at_path,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub(super) const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str =
    "sealed-lattice-vss-public-commitment-binary-v1";
pub(crate) const VSS_PUBLIC_OUTPUT_COORDINATE_COUNT: usize = 16;
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_COUNT: usize = 2;
#[cfg(test)]
pub(crate) const VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT: usize = 17;
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_BASE: u64 = 129_140_163;
// The decoder splits each digit into base-three trits; the digit base above is
// this trit base raised to the base-digit trit count (3^17 = 129_140_163). A
// single trit therefore ranges over {0, 1, 2}, which is the witness bound the
// trit-granular share-linkage consistency claims publish.
pub(crate) const VSS_PUBLIC_MESSAGE_TRIT_BASE: u64 = 3;
pub(crate) const VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT: usize = 2;
pub(in crate::bgv::setup) const VSS_PUBLIC_RANDOMNESS_PROJECTION_WEIGHT: usize = 32;
pub(in crate::bgv::setup) const VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] = [0, 1, 2];
const VSS_PUBLIC_SAMPLER_DOMAIN: &str = "sealed-lattice-vss-public-commitment/sampler-v1";
const VSS_PUBLIC_MATRIX_RESIDUE_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/matrix-residue-v1";
const VSS_PUBLIC_PROJECTION_INDEX_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/projection-index-v1";
const VSS_PUBLIC_OPENING_PAYLOAD_HASH_DOMAIN: &str =
    "sealed-lattice-vss-public-commitment/opening-payload-v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::bgv::setup) struct VssPublicMessageEncodingLayout {
    low_digit_trit_count: usize,
    high_digit_trit_count: usize,
}

impl VssPublicMessageEncodingLayout {
    pub(in crate::bgv::setup) fn digit_trit_count(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        match digit_index {
            0 => Ok(self.low_digit_trit_count),
            1 => Ok(self.high_digit_trit_count),
            _ => Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS message digit index is outside the selected profile",
            )),
        }
    }

    pub(in crate::bgv::setup) fn total_trit_count(self) -> usize {
        self.low_digit_trit_count + self.high_digit_trit_count
    }

    pub(in crate::bgv::setup) fn encoding_column_count(self) -> usize {
        VSS_PUBLIC_MESSAGE_DIGIT_COUNT + self.total_trit_count()
    }

    pub(in crate::bgv::setup) fn digit_encoding_column(
        self,
        digit_index: usize,
    ) -> CanonicalResult<usize> {
        if digit_index < VSS_PUBLIC_MESSAGE_DIGIT_COUNT {
            Ok(digit_index)
        } else {
            Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS message digit index is outside the selected profile",
            ))
        }
    }

    pub(in crate::bgv::setup) fn trit_encoding_column(
        self,
        digit_index: usize,
        trit_index: usize,
    ) -> CanonicalResult<usize> {
        let trit_count = self.digit_trit_count(digit_index)?;
        if trit_index >= trit_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS message trit index is outside the statement-bound layout",
            ));
        }

        let previous_trit_count =
            (0..digit_index).try_fold(0_usize, |sum, previous_digit_index| {
                sum.checked_add(self.digit_trit_count(previous_digit_index)?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "VSS message trit column offset overflowed",
                        )
                    })
            })?;

        Ok(VSS_PUBLIC_MESSAGE_DIGIT_COUNT + previous_trit_count + trit_index)
    }
}

pub(crate) struct VssPublicCommitmentOpeningInput<'a> {
    pub(crate) commitment_role: &'a str,
    pub(crate) commitment_context: &'a Value,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) rns_limb_index: usize,
    pub(crate) rns_prime: u64,
    pub(crate) ring_degree: usize,
    pub(crate) message_coefficients: &'a [u64],
    pub(crate) message_digit_columns: &'a [Vec<u64>],
    pub(crate) message_coefficient_bound: u64,
    pub(crate) randomness_by_column: &'a [Vec<i64>],
}

pub(crate) struct VssPublicCommitmentComputation {
    pub(crate) commitment: Value,
    pub(crate) commitment_root: String,
    pub(crate) commitment_context_hash: String,
    pub(crate) opening_root: String,
}

pub(crate) fn compute_vss_public_commitment_from_opening(
    input: VssPublicCommitmentOpeningInput<'_>,
) -> CanonicalResult<VssPublicCommitmentComputation> {
    validate_hash_string(input.public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_vss_public_commitment_role(input.commitment_role)?;
    if input.rns_prime == 0 {
        return Err(invalid_vss_public_input("rnsPrime must be positive"));
    }
    if input.ring_degree == 0 {
        return Err(invalid_vss_public_input("ringDegree must be positive"));
    }
    if input.message_coefficient_bound == 0 {
        return Err(invalid_vss_public_input(
            "messageCoefficientBound must be positive",
        ));
    }
    if input.message_coefficients.len() != input.ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS message coefficient count must match ringDegree",
        ));
    }
    for (coefficient_index, coefficient) in input.message_coefficients.iter().enumerate() {
        if *coefficient >= input.message_coefficient_bound {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "VSS message coefficient {coefficient_index} must be below messageCoefficientBound"
                ),
            ));
        }
    }
    let message_digit_columns = vss_public_message_digit_columns_for_opening(
        input.message_coefficients,
        input.message_digit_columns,
        input.message_coefficient_bound,
        input.ring_degree,
    )?;
    validate_vss_public_randomness_columns(
        input.randomness_by_column,
        input.ring_degree,
        None,
        "randomnessByColumn",
    )?;

    let commitment_context_hash = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCommitmentContext",
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
    }))?;
    let commitment_limbs = VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let modulus = DATA_PRIMES[*commitment_modulus_index];
            let coordinates = (0..VSS_PUBLIC_OUTPUT_COORDINATE_COUNT)
                .map(|output_coordinate_index| {
                    commitment_coordinate(CommitmentCoordinateInput {
                        public_matrix_seed_hash: input.public_matrix_seed_hash,
                        rns_limb_index: input.rns_limb_index,
                        commitment_modulus_index: *commitment_modulus_index,
                        output_coordinate_index,
                        modulus,
                        message_digit_columns: &message_digit_columns,
                        randomness_by_column: input.randomness_by_column,
                    })
                })
                .collect::<CanonicalResult<Vec<_>>>()?;

            Ok(json!({
                "commitmentModulusIndex": commitment_modulus_index,
                "modulus": modulus,
                "coordinates": coordinates,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let commitment = json!({
        "objectType": "VssPublicCommitment",
        "commitmentRole": input.commitment_role,
        "commitmentContextHash": commitment_context_hash,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "outputCoordinateCount": VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
        "randomnessColumnCount": VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
        "commitmentLimbs": commitment_limbs,
    });
    let commitment_root = derive_canonical_object_hash(&commitment)?;
    let opening_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCommitmentOpening",
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
        "publicMatrixSeedHash": input.public_matrix_seed_hash,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "openingPayloadHash512": vss_public_opening_payload_hash(
            input.message_coefficients,
            &message_digit_columns,
            input.randomness_by_column,
        )?,
    }))?;

    Ok(VssPublicCommitmentComputation {
        commitment,
        commitment_root,
        commitment_context_hash,
        opening_root,
    })
}

pub(crate) fn compute_vss_public_commitment_from_opening_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let computation = compute_vss_public_commitment_from_opening_value(request)?;

    Ok(vss_public_commitment_computation_response(&computation))
}

pub(crate) fn verify_vss_public_coefficient_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let coefficient_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    compare_required_string(
        string_at_path(coefficient_set, &["objectType"])?,
        "VssPublicCoefficientCommitmentSet",
        "VSS coefficient commitment set objectType",
    )?;
    let public_matrix_seed_hash = hash_at_path(coefficient_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        coefficient_set,
        &["participantCount"],
        "VSS coefficient commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        coefficient_set,
        &["rnsLimbCount"],
        "VSS coefficient commitment set rnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        coefficient_set,
        &["thresholdDegree"],
        "VSS coefficient commitment set thresholdDegree",
    )?;
    let ring_degree = read_positive_usize_at_path(
        coefficient_set,
        &["ringDegree"],
        "VSS coefficient commitment set ringDegree",
    )?;
    let source_trustee_records = array_at_path(coefficient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitment set must contain one source record per participant",
        ));
    }
    let expected_coefficient_count =
        rns_limb_count
            .checked_mul(threshold_degree)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS coefficient commitment coordinate count overflowed",
                )
            })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (expected_roster_position, source_record) in source_trustee_records.iter().enumerate() {
        verified_source_trustee_records.push(verify_vss_public_source_coefficient_record(
            VssPublicSourceCoefficientRecordInput {
                source_record,
                expected_roster_position,
                expected_coefficient_count,
                threshold_degree,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    let coefficient_commitment_root =
        hash_at_path(coefficient_set, &["coefficientCommitmentRoot"])?;
    if expected_set_root != coefficient_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS coefficient commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicCoefficientCommitmentSet",
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "thresholdDegree": threshold_degree,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_vss_public_recipient_share_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let recipient_set = value_at_path(request, &["recipientShareCommitmentSet"])?;
    compare_required_string(
        string_at_path(recipient_set, &["objectType"])?,
        "VssPublicRecipientShareCommitmentSet",
        "VSS recipient-share commitment set objectType",
    )?;
    let public_matrix_seed_hash = hash_at_path(recipient_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        recipient_set,
        &["participantCount"],
        "VSS recipient-share commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        recipient_set,
        &["rnsLimbCount"],
        "VSS recipient-share commitment set rnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        recipient_set,
        &["ringDegree"],
        "VSS recipient-share commitment set ringDegree",
    )?;
    let source_trustee_records = array_at_path(recipient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS recipient-share commitment set must contain one source record per participant",
        ));
    }
    let expected_recipient_share_count =
        participant_count
            .checked_mul(rns_limb_count)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "VSS recipient-share commitment coordinate count overflowed",
                )
            })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (expected_roster_position, source_record) in source_trustee_records.iter().enumerate() {
        verified_source_trustee_records.push(verify_vss_public_source_recipient_share_record(
            VssPublicSourceRecipientShareRecordInput {
                source_record,
                expected_source_roster_position: expected_roster_position,
                expected_recipient_share_count,
                rns_limb_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    let recipient_share_commitment_root =
        hash_at_path(recipient_set, &["recipientShareCommitmentRoot"])?;
    if expected_set_root != recipient_share_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS recipient-share commitment set root does not match its source records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicRecipientShareCommitmentSet",
        "recipientShareCommitmentRoot": recipient_share_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

pub(crate) fn verify_vss_public_aggregate_threshold_commitment_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let aggregate_set = value_at_path(request, &["aggregateThresholdCommitmentSet"])?;
    compare_required_string(
        string_at_path(aggregate_set, &["objectType"])?,
        "VssPublicAggregateThresholdCommitmentSet",
        "VSS aggregate threshold commitment set objectType",
    )?;
    let public_matrix_seed_hash = hash_at_path(aggregate_set, &["publicMatrixSeedHash"])?;
    let participant_count = read_positive_usize_at_path(
        aggregate_set,
        &["participantCount"],
        "VSS aggregate threshold commitment set participantCount",
    )?;
    let rns_limb_count = read_positive_usize_at_path(
        aggregate_set,
        &["rnsLimbCount"],
        "VSS aggregate threshold commitment set rnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        aggregate_set,
        &["ringDegree"],
        "VSS aggregate threshold commitment set ringDegree",
    )?;
    let recipient_records = array_at_path(aggregate_set, &["recipientRecords"])?;
    let expected_recipient_record_count = participant_count
        .checked_mul(rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold commitment coordinate count overflowed",
            )
        })?;
    if recipient_records.len() != expected_recipient_record_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS aggregate threshold commitment set must cover every recipient and RNS limb",
        ));
    }

    let mut verified_recipient_records = Vec::with_capacity(recipient_records.len());
    for (recipient_record_index, recipient_record) in recipient_records.iter().enumerate() {
        verified_recipient_records.push(verify_vss_public_aggregate_threshold_record(
            VssPublicAggregateThresholdRecordInput {
                recipient_record,
                expected_recipient_roster_position: recipient_record_index / rns_limb_count,
                expected_rns_limb_index: recipient_record_index % rns_limb_count,
                participant_count,
                public_matrix_seed_hash,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
        "recipientRecords": verified_recipient_records,
    }))?;
    let aggregate_threshold_commitment_root =
        hash_at_path(aggregate_set, &["aggregateThresholdCommitmentRoot"])?;
    if expected_set_root != aggregate_threshold_commitment_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS aggregate threshold commitment set root does not match its recipient records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssPublicAggregateThresholdCommitmentSet",
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

fn vss_public_encoded_commitment_byte_length() -> usize {
    VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len() * VSS_PUBLIC_OUTPUT_COORDINATE_COUNT * 8
}

fn invalid_vss_public_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

mod message_encoding;
mod readers;
mod record_verification;
mod sampler;
mod share_linkage;

use readers::*;
use record_verification::*;
use sampler::*;

pub(crate) use message_encoding::vss_public_canonical_message_digit_columns;
pub(in crate::bgv::setup) use message_encoding::{
    vss_public_message_digit_bound, vss_public_message_digit_column_label,
    vss_public_message_digit_only_encoding_layout, vss_public_message_digit_trits_for_count,
    vss_public_message_digit_weight, vss_public_message_digits, vss_public_message_encoding_layout,
};
// Consumed by the key-switch atom family backend same-secret linkage.
pub(in crate::bgv::setup) use message_encoding::{
    vss_public_message_coverage_terms_per_coordinate, vss_public_randomness_column_label,
};
pub(crate) use record_verification::validate_standalone_vss_public_commitment_body;
pub(in crate::bgv::setup) use sampler::{ProjectionTermsInput, projection_terms};
pub(crate) use share_linkage::verify_vss_share_linkage_statement_request;

#[cfg(test)]
pub(in crate::bgv::setup) mod tests;
