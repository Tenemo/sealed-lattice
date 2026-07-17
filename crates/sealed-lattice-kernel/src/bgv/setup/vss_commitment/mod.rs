use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, is_lowercase_protocol_hash, read_positive_usize_at_path,
};

#[cfg(test)]
pub(in crate::bgv::setup) const VSS_SHARE_LINKAGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/vss-share-linkage/proof-bytes";
#[cfg(test)]
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_COUNT: usize = 2;
#[cfg(test)]
pub(crate) const VSS_PUBLIC_MESSAGE_DIGIT_BASE: u64 = 129_140_163;

pub(crate) struct VssPublicCoefficientCommitmentSetContext<'a> {
    pub(crate) setup_context_hash: &'a str,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) participant_count: usize,
    pub(crate) trustee_identities: &'a [String],
    pub(crate) rns_limb_count: usize,
    pub(crate) threshold_degree: usize,
}

pub(crate) struct VssPublicRecipientShareCommitmentSetContext<'a> {
    pub(crate) setup_context_hash: &'a str,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) participant_count: usize,
    pub(crate) trustee_identities: &'a [String],
    pub(crate) rns_limb_count: usize,
}

pub(crate) struct VssPublicAggregateThresholdCommitmentSetContext<'a> {
    pub(crate) setup_context_hash: &'a str,
    pub(crate) public_matrix_seed_hash: &'a str,
    pub(crate) participant_count: usize,
    pub(crate) trustee_identities: &'a [String],
    pub(crate) rns_limb_count: usize,
}

pub(crate) fn verify_vss_public_coefficient_commitment_set(
    coefficient_set: &Value,
    context: &VssPublicCoefficientCommitmentSetContext<'_>,
) -> CanonicalResult<String> {
    compare_required_string(
        string_at_path(coefficient_set, &["objectType"])?,
        "VssPublicCoefficientCommitmentSet",
        "VSS coefficient commitment set objectType",
    )?;
    compare_required_string(
        hash_at_path(coefficient_set, &["publicMatrixSeedHash"])?,
        context.public_matrix_seed_hash,
        "VSS coefficient commitment set publicMatrixSeedHash",
    )?;
    let source_trustee_records = array_at_path(coefficient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != context.participant_count
        || context.trustee_identities.len() != context.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitment set must contain one source record per participant",
        ));
    }
    let expected_coefficient_count = context
        .rns_limb_count
        .checked_mul(context.threshold_degree)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS coefficient commitment coordinate count overflowed",
            )
        })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (source_trustee_roster_position, source_record) in source_trustee_records.iter().enumerate()
    {
        verified_source_trustee_records.push(verify_vss_public_source_coefficient_record(
            VssPublicSourceCoefficientRecordInput {
                source_record,
                setup_context_hash: context.setup_context_hash,
                source_trustee_identity: &context.trustee_identities
                    [source_trustee_roster_position],
                source_trustee_roster_position,
                expected_coefficient_count,
                threshold_degree: context.threshold_degree,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicCoefficientCommitmentSet",
        "publicMatrixSeedHash": context.public_matrix_seed_hash,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    Ok(expected_set_root)
}

pub(crate) fn verify_vss_public_recipient_share_commitment_set(
    recipient_set: &Value,
    context: &VssPublicRecipientShareCommitmentSetContext<'_>,
) -> CanonicalResult<String> {
    compare_required_string(
        string_at_path(recipient_set, &["objectType"])?,
        "VssPublicRecipientShareCommitmentSet",
        "VSS recipient-share commitment set objectType",
    )?;
    compare_required_string(
        hash_at_path(recipient_set, &["publicMatrixSeedHash"])?,
        context.public_matrix_seed_hash,
        "VSS recipient-share commitment set publicMatrixSeedHash",
    )?;
    let source_trustee_records = array_at_path(recipient_set, &["sourceTrusteeRecords"])?;
    if source_trustee_records.len() != context.participant_count
        || context.trustee_identities.len() != context.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS recipient-share commitment set must contain one source record per participant",
        ));
    }
    let expected_recipient_share_count = context
        .participant_count
        .checked_mul(context.rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS recipient-share commitment coordinate count overflowed",
            )
        })?;

    let mut verified_source_trustee_records = Vec::with_capacity(source_trustee_records.len());
    for (source_trustee_roster_position, source_record) in source_trustee_records.iter().enumerate()
    {
        verified_source_trustee_records.push(verify_vss_public_source_recipient_share_record(
            VssPublicSourceRecipientShareRecordInput {
                source_record,
                setup_context_hash: context.setup_context_hash,
                source_trustee_identity: &context.trustee_identities
                    [source_trustee_roster_position],
                trustee_identities: context.trustee_identities,
                source_trustee_roster_position,
                expected_recipient_share_count,
                rns_limb_count: context.rns_limb_count,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicRecipientShareCommitmentSet",
        "publicMatrixSeedHash": context.public_matrix_seed_hash,
        "sourceTrusteeRecords": verified_source_trustee_records,
    }))?;
    Ok(expected_set_root)
}

pub(crate) fn verify_vss_public_aggregate_threshold_commitment_set(
    aggregate_set: &Value,
    context: &VssPublicAggregateThresholdCommitmentSetContext<'_>,
) -> CanonicalResult<String> {
    compare_required_string(
        string_at_path(aggregate_set, &["objectType"])?,
        "VssPublicAggregateThresholdCommitmentSet",
        "VSS aggregate threshold commitment set objectType",
    )?;
    compare_required_string(
        hash_at_path(aggregate_set, &["publicMatrixSeedHash"])?,
        context.public_matrix_seed_hash,
        "VSS aggregate threshold commitment set publicMatrixSeedHash",
    )?;
    let recipient_records = array_at_path(aggregate_set, &["recipientRecords"])?;
    let expected_recipient_record_count = context
        .participant_count
        .checked_mul(context.rns_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS aggregate threshold commitment coordinate count overflowed",
            )
        })?;
    if recipient_records.len() != expected_recipient_record_count
        || context.trustee_identities.len() != context.participant_count
    {
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
                setup_context_hash: context.setup_context_hash,
                expected_recipient_roster_position: recipient_record_index / context.rns_limb_count,
                recipient_identity: &context.trustee_identities
                    [recipient_record_index / context.rns_limb_count],
                expected_rns_limb_index: recipient_record_index % context.rns_limb_count,
            },
        )?);
    }

    let expected_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssPublicAggregateThresholdCommitmentSet",
        "publicMatrixSeedHash": context.public_matrix_seed_hash,
        "recipientRecords": verified_recipient_records,
    }))?;
    Ok(expected_set_root)
}

#[cfg(test)]
fn invalid_vss_public_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod committed_material;
#[cfg(test)]
mod message_encoding;
#[cfg(test)]
mod readers;
mod record_verification;
mod share_linkage;

#[cfg(test)]
use readers::*;
pub(crate) use record_verification::*;

#[cfg(test)]
pub(crate) use committed_material::{
    VssCommittedMaterialCommitmentInput, compute_vss_committed_material_commitment,
};

#[cfg(test)]
pub(crate) use message_encoding::vss_public_canonical_message_digit_columns;
#[cfg(test)]
pub(crate) use record_verification::validate_standalone_vss_committed_material_commitment;
pub(crate) use share_linkage::verify_vss_share_linkage_bindings_request;
#[cfg(test)]
pub(crate) use share_linkage::{
    VssAggregateThresholdProofContext, verify_vss_public_aggregate_threshold_proofs,
};
#[cfg(test)]
pub(in crate::bgv::setup) use share_linkage::{
    VssAggregateThresholdStatementInput, vss_aggregate_threshold_statement_from_commitment_records,
};

#[cfg(test)]
pub(in crate::bgv::setup) mod tests;
