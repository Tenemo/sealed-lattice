use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_u64_at_path,
    read_positive_usize_at_path,
};

pub(super) const VSS_PUBLIC_COMMITMENT_BINARY_FORMAT: &str =
    "sealed-lattice-vss-public-commitment-binary";
pub(in crate::bgv::setup) const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes";
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_COUNT: usize = 2;
#[cfg(test)]
pub(crate) const VSS_PUBLIC_MESSAGE_BASE_DIGIT_TRIT_COUNT: usize = 17;
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_BASE: u64 = 129_140_163;
// The decoder splits each digit into base-three trits; the digit base above is
// this trit base raised to the base-digit trit count (3^17 = 129_140_163). A
// single trit therefore ranges over {0, 1, 2}, which is the witness bound the
// trit-granular share-linkage consistency claims publish.
pub(crate) const VSS_PUBLIC_MESSAGE_TRIT_BASE: u64 = 3;
// Single home: the VSS public commitment binds over exactly the BDLOP setup
// commitment modulus limbs, so alias that constant instead of restating it and
// letting the two drift.
pub(in crate::bgv::setup) const VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES: [usize; 3] =
    super::commitment::SETUP_COMMITMENT_MODULUS_LIMB_INDICES;

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
        "aggregateThresholdCommitmentRoot": aggregate_threshold_commitment_root,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "rnsLimbCount": rns_limb_count,
        "ringDegree": ring_degree,
    }))
}

fn invalid_vss_public_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

mod committed_material;
mod message_encoding;
mod readers;
mod record_verification;
mod share_linkage;

use readers::*;
use record_verification::*;

pub(crate) use committed_material::compute_vss_committed_material_commitment_request;
pub(crate) use committed_material::{
    VssCommittedMaterialCommitmentInput, compute_vss_committed_material_commitment,
};

pub(crate) use message_encoding::vss_public_canonical_message_digit_columns;
pub(in crate::bgv::setup) use message_encoding::{
    vss_public_cross_limb_message_encoding_layout, vss_public_message_digit_bound,
    vss_public_message_digit_trits_for_count, vss_public_message_digit_weight,
    vss_public_message_digits, vss_public_message_encoding_layout,
    vss_public_share_linkage_packed_message_encoding_layout,
    vss_public_share_linkage_source_message_encoding_layout,
};
pub(crate) use record_verification::validate_standalone_vss_committed_material_commitment;
pub(crate) use share_linkage::verify_vss_share_linkage_bindings_request;
pub(crate) use share_linkage::{
    VssAggregateThresholdProofContext, verify_vss_public_aggregate_threshold_proofs,
};

#[cfg(test)]
pub(in crate::bgv::setup) mod tests;
