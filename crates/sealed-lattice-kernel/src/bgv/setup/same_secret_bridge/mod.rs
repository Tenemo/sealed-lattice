use super::setup_proof::SetupProofMaterialBytes;
use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_usize_at_path,
};
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
pub(in crate::bgv::setup) const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";
pub(crate) fn verify_vss_same_secret_bridge_statement_set_request(
    request: &Value,
) -> CanonicalResult<()> {
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
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    hash_at_path(statement_set, &["vssCoefficientCommitmentRoot"])?;
    let participant_count = read_positive_usize_at_path(
        statement_set,
        &["participantCount"],
        "VSS same-secret bridge statement set participantCount",
    )?;
    let q_share_rns_limb_count = read_positive_usize_at_path(
        statement_set,
        &["qShareRnsLimbCount"],
        "VSS same-secret bridge statement set qShareRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement_set,
        &["thresholdDegree"],
        "VSS same-secret bridge statement set thresholdDegree",
    )?;
    let verified_coefficient_commitment_root =
        super::vss_commitment::verify_vss_public_coefficient_commitment_set(
            coefficient_commitment_set,
            &super::vss_commitment::VssPublicCoefficientCommitmentSetContext {
                public_matrix_seed_hash,
                participant_count,
                rns_limb_count: q_share_rns_limb_count,
                threshold_degree,
                ring_degree,
            },
        )?;
    compare_required_string(
        &verified_coefficient_commitment_root,
        coefficient_commitment_root,
        "VSS same-secret bridge authoritative coefficientCommitmentRoot",
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
        })?;
    }

    Ok(())
}

pub(crate) fn verify_vss_same_secret_bridge_proof_material_set_request(
    request: &Value,
    proof_binding_session: Option<&crate::bgv::setup::AcceptedSetupProofBindingSession>,
) -> CanonicalResult<()> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    verify_vss_same_secret_bridge_statement_set_request(request)?;
    let participant_count = read_positive_usize_at_path(
        statement_set,
        &["participantCount"],
        "same-secret bridge proof material statement participantCount",
    )?;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "VssSameSecretBridgeProofMaterialSet",
        "same-secret bridge proof material set objectType",
    )?;

    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let vss_coefficient_commitments = value_at_path(request, &["vssCoefficientCommitments"])?;

    let bridge_statement_records = array_at_path(statement_set, &["statementRecords"])?;
    let proof_records = array_at_path(proof_material_set, &["proofRecords"])?;
    if proof_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge proof material set must contain one proof record per bridge statement",
        ));
    }
    for (expected_position, proof_record) in proof_records.iter().enumerate() {
        let bridge_statement =
            bridge_statement_records
                .get(expected_position)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "same-secret bridge proof material set has no matching bridge statement",
                    )
                })?;
        compare_required_string(
            string_at_path(proof_record, &["objectType"])?,
            "VssSameSecretBridgeProofRecord",
            "same-secret bridge proof record objectType",
        )?;
        let bridge_statement_root =
            hash_at_path(bridge_statement, &["sameSecretBridgeStatementRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretBridgeStatementRoot"])?,
            bridge_statement_root,
            "same-secret bridge proof record statement root",
        )?;
        let validated_proof_reference =
            validate_same_secret_bridge_proof_reference(proof_record, bridge_statement_root)?;
        let proof_verification_request =
            same_secret_bridge_proof_verification_request_from_public_records(
                statement_set,
                bridge_statement,
                coefficient_commitment_set,
                vss_coefficient_commitments,
                expected_position,
            )?;
        let verification_binding_hash = same_secret_bridge_proof_verification_binding_hash(
            &validated_proof_reference.proof_material_root,
            &proof_verification_request,
        )?;
        let proof_binding_was_consumed = match proof_binding_session {
            Some(proof_binding_session) => crate::bgv::setup::consume_accepted_setup_proof_binding(
                proof_binding_session.session_handle,
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                &validated_proof_reference.proof_material_root,
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
