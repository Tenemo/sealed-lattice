use super::setup_proof::SetupProofMaterialBytes;
use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_usize_at_path,
};
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
pub(in crate::bgv::setup) const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";

pub(crate) struct VerifiedSameSecretBridgeStatementSet {
    pub(in crate::bgv::setup) participant_count: usize,
    pub(in crate::bgv::setup) q_share_rns_limb_count: usize,
    pub(in crate::bgv::setup) threshold_degree: usize,
}

fn same_secret_bridge_profile(
    statement_set: &Value,
    coefficient_commitment_set: &Value,
) -> CanonicalResult<(usize, usize, usize)> {
    let statement_records = array_at_path(statement_set, &["statementRecords"])?;
    if statement_records.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statement set must contain at least one statement",
        ));
    }
    let participant_count = statement_records.len();
    let q_share_rns_limb_count = DATA_PRIMES.len();
    let coefficient_source_records =
        array_at_path(coefficient_commitment_set, &["sourceTrusteeRecords"])?;
    if coefficient_source_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statements and coefficient sources must cover the same roster",
        ));
    }
    let first_source_record = coefficient_source_records.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitment set must contain a source record",
        )
    })?;
    let coefficient_count = array_at_path(first_source_record, &["coefficientCommitments"])?.len();
    if coefficient_count == 0 || !coefficient_count.is_multiple_of(q_share_rns_limb_count) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitments must cover a complete non-empty Q_share basis for every threshold coefficient",
        ));
    }
    Ok((
        participant_count,
        q_share_rns_limb_count,
        coefficient_count / q_share_rns_limb_count,
    ))
}

pub(crate) fn verify_vss_same_secret_bridge_statement_set_request(
    request: &Value,
) -> CanonicalResult<VerifiedSameSecretBridgeStatementSet> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let vss_coefficient_commitments = value_at_path(request, &["vssCoefficientCommitments"])?;
    compare_required_string(
        string_at_path(statement_set, &["objectType"])?,
        "VssSameSecretBridgeStatementSet",
        "VSS same-secret bridge statement set objectType",
    )?;
    let setup_context_hash = hash_at_path(statement_set, &["setupContextHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement_set,
        &["ringDegree"],
        "VSS same-secret bridge statement set ringDegree",
    )?;
    let (participant_count, q_share_rns_limb_count, threshold_degree) =
        same_secret_bridge_profile(statement_set, coefficient_commitment_set)?;
    let trustee_identities = array_at_path(vss_coefficient_commitments, &["sourceTrusteeRecords"])?
        .iter()
        .map(|record| Ok(string_at_path(record, &["sourceTrusteeIdentity"])?.to_string()))
        .collect::<CanonicalResult<Vec<_>>>()?;
    if trustee_identities.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS coefficient commitments must cover the canonical trustee roster",
        ));
    }
    super::vss_commitment::verify_vss_public_coefficient_commitment_set(
        coefficient_commitment_set,
        &super::vss_commitment::VssPublicCoefficientCommitmentSetContext {
            setup_context_hash,
            public_matrix_seed_hash,
            participant_count,
            trustee_identities: &trustee_identities,
            rns_limb_count: q_share_rns_limb_count,
            threshold_degree,
            ring_degree,
        },
    )?;
    let statement_records = array_at_path(statement_set, &["statementRecords"])?;
    if statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statement set must contain one statement per participant",
        ));
    }

    for (expected_position, statement_record) in statement_records.iter().enumerate() {
        verify_statement_record(StatementRecordVerificationInput {
            statement_record,
            coefficient_commitment_set,
            vss_coefficient_commitments,
            expected_position,
            q_share_rns_limb_count,
            threshold_degree,
            ring_degree,
            statement_set: StatementSetBinding {
                setup_context_hash,
                public_matrix_seed_hash,
            },
            trustee_identity: &trustee_identities[expected_position],
        })?;
    }

    Ok(VerifiedSameSecretBridgeStatementSet {
        participant_count,
        q_share_rns_limb_count,
        threshold_degree,
    })
}

pub(crate) fn verify_vss_same_secret_bridge_proof_material_set_request(
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<()> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    let verified_statement_set = verify_vss_same_secret_bridge_statement_set_request(request)?;
    let participant_count = verified_statement_set.participant_count;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "VssSameSecretBridgeProofMaterialSet",
        "same-secret bridge proof material set objectType",
    )?;

    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let vss_coefficient_commitments = value_at_path(request, &["vssCoefficientCommitments"])?;

    let bridge_statement_records = array_at_path(statement_set, &["statementRecords"])?;
    let proof_bytes_hashes = array_at_path(proof_material_set, &["proofBytesHashes"])?;
    if proof_bytes_hashes.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge proof material set must contain one proof hash per bridge statement",
        ));
    }
    for (expected_position, proof_bytes_hash) in proof_bytes_hashes.iter().enumerate() {
        let bridge_statement =
            bridge_statement_records
                .get(expected_position)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "same-secret bridge proof material set has no matching bridge statement",
                    )
                })?;
        let validated_proof_reference = validate_same_secret_bridge_proof_reference(
            proof_bytes_hash.as_str().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "same-secret bridge proof hash must be a string",
                )
            })?,
        )?;
        let proof_verification_request =
            same_secret_bridge_proof_verification_request_from_public_records(
                statement_set,
                bridge_statement,
                coefficient_commitment_set,
                vss_coefficient_commitments,
                expected_position,
            )?;
        let verification_binding_hash = same_secret_bridge_proof_verification_binding_hash(
            &validated_proof_reference.proof_bytes_hash,
            &proof_verification_request,
        )?;
        let proof_binding_was_consumed = match proof_binding_session {
            Some(proof_binding_session) => crate::bgv::setup::consume_accepted_setup_proof_binding(
                proof_binding_session.session_handle,
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                &validated_proof_reference.proof_bytes_hash,
                &verification_binding_hash,
            )?,
            None => false,
        };
        if !proof_binding_was_consumed {
            let proof_bytes = resolve_same_secret_bridge_proof_bytes(
                validated_proof_reference,
                proof_binding_session,
            )?;
            verify_reconstructed_same_secret_bridge_proof(
                &proof_verification_request,
                &proof_bytes,
            )?;
        }
    }

    Ok(())
}

mod bridge_transport;
mod reconstructed;
mod statement_record;

use bridge_transport::*;
#[cfg(test)]
pub(in crate::bgv::setup) use reconstructed::verify_and_retain_same_secret_bridge_proof_binding;
use reconstructed::{
    StatementRecordVerificationInput, StatementSetBinding,
    verify_reconstructed_same_secret_bridge_proof,
};
pub(in crate::bgv::setup) use reconstructed::{
    authoritative_same_secret_bridge_targets, same_secret_bridge_proof_verification_binding_hash,
    same_secret_bridge_proof_verification_request_from_public_records,
};
use statement_record::*;
