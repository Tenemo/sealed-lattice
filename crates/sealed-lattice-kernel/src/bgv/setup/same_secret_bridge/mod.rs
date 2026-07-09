use super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES, SetupProofMaterialBytes,
    SetupProofMaterialTransportHashes, setup_proof_material_transport_hashes,
    verified_setup_proof_material_bytes_from_request,
};
use super::vss_commitment::VSS_PUBLIC_COMMITMENT_BINARY_FORMAT;
use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_u64_at_path,
    read_positive_usize_at_path,
};
use std::sync::Arc;

const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes";
const SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretProofMaterialSet";
const SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE: &str = "SetupTransportedSameSecretProofMaterial";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const VSS_SAME_SECRET_BRIDGE_RELATION: &str = "target-basis constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";
const SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterialSet";
const SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterial";
const VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
const SETUP_CONTEXT_FIELD_NAMES: [&str; 5] = [
    "ceremonyId",
    "manifestHash",
    "rosterHash",
    "setupParametersHash",
    "setupEpoch",
];

pub(crate) fn verify_vss_same_secret_bridge_statement_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    compare_required_string(
        string_at_path(statement_set, &["objectType"])?,
        "VssSameSecretBridgeStatementSet",
        "VSS same-secret bridge statement set objectType",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "VSS same-secret bridge statement set proofFamily",
    )?;

    let ceremony_id = read_non_empty_string(statement_set, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement_set, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement_set, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement_set, &["rosterHash"])?;
    let setup_parameters_hash = hash_at_path(statement_set, &["setupParametersHash"])?;
    let target_basis_hash = hash_at_path(statement_set, &["targetBasisHash"])?;
    compare_required_string(
        target_basis_hash,
        &crate::bgv::evaluator::top_k::canonical_target_basis_hash()?,
        "VSS same-secret bridge statement set targetBasisHash",
    )?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement_set,
        &["ringDegree"],
        "VSS same-secret bridge statement set ringDegree",
    )?;
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    let same_secret_consistency_root = hash_at_path(statement_set, &["sameSecretConsistencyRoot"])?;
    let same_secret_proof_set_root = hash_at_path(statement_set, &["sameSecretProofSetRoot"])?;
    let same_secret_proof_family_binding_root =
        hash_at_path(statement_set, &["sameSecretProofFamilyBindingRoot"])?;
    let participant_count = read_positive_usize_at_path(
        statement_set,
        &["participantCount"],
        "VSS same-secret bridge statement set participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        statement_set,
        &["targetRnsLimbCount"],
        "VSS same-secret bridge statement set targetRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement_set,
        &["thresholdDegree"],
        "VSS same-secret bridge statement set thresholdDegree",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["integerSupport"])?,
        VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "VSS same-secret bridge statement set integerSupport",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["signedRepresentativeConvention"])?,
        VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "VSS same-secret bridge statement set signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["vssPublicCommitmentEncoding"])?,
        VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "VSS same-secret bridge statement set vssPublicCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["targetBasisLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "VSS same-secret bridge statement set targetBasisLimbOrder",
    )?;

    let statement_records = array_at_path(statement_set, &["statementRecords"])?;
    if statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS same-secret bridge statement set must contain one statement per participant",
        ));
    }

    let mut verified_statement_records = Vec::with_capacity(statement_records.len());
    for (expected_position, statement_record) in statement_records.iter().enumerate() {
        verified_statement_records.push(verify_statement_record(
            StatementRecordVerificationInput {
                statement_record,
                expected_position,
                target_rns_limb_count,
                ring_degree,
                statement_set: StatementSetBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    target_basis_hash,
                    public_matrix_seed_hash,
                    same_secret_proof_family_binding_root,
                },
            },
        )?);
    }

    let expected_statement_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "sameSecretConsistencyRoot": same_secret_consistency_root,
        "sameSecretProofSetRoot": same_secret_proof_set_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "statementRecords": verified_statement_records,
    }))?;
    let statement_set_root = hash_at_path(statement_set, &["sameSecretBridgeStatementSetRoot"])?;
    if expected_statement_set_root != statement_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS same-secret bridge statement set root does not match its bound statements",
        ));
    }
    verify_same_secret_evidence_sets(EvidenceSetVerificationInput {
        request,
        statement_set: StatementSetBinding {
            ceremony_id,
            manifest_hash,
            roster_hash,
            setup_parameters_hash,
            setup_epoch,
            target_basis_hash,
            public_matrix_seed_hash,
            same_secret_proof_family_binding_root,
        },
        participant_count,
        same_secret_consistency_root,
        same_secret_proof_set_root,
        same_secret_proof_family_binding_root,
        bridge_statement_records: &verified_statement_records,
    })?;

    Ok(json!({
        "ok": true,
        "operation": "verifyVssSameSecretBridgeStatementSet",
        "sameSecretBridgeStatementSetRoot": statement_set_root,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "sameSecretConsistencyRoot": same_secret_consistency_root,
        "sameSecretProofSetRoot": same_secret_proof_set_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
    }))
}

pub(crate) fn verify_vss_same_secret_bridge_proof_material_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    let statement_verification = verify_vss_same_secret_bridge_statement_set_request(request)?;
    let statement_set_root = hash_at_path(
        &statement_verification,
        &["sameSecretBridgeStatementSetRoot"],
    )?;
    let participant_count = read_positive_usize_at_path(
        &statement_verification,
        &["participantCount"],
        "same-secret bridge proof material statement participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        &statement_verification,
        &["targetRnsLimbCount"],
        "same-secret bridge proof material statement targetRnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        &statement_verification,
        &["ringDegree"],
        "same-secret bridge proof material statement ringDegree",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        &statement_verification,
        &["thresholdDegree"],
        "same-secret bridge proof material statement thresholdDegree",
    )?;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "VssSameSecretBridgeProofMaterialSet",
        "same-secret bridge proof material set objectType",
    )?;

    let ceremony_id = read_non_empty_string(statement_set, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement_set, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement_set, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement_set, &["rosterHash"])?;
    let setup_parameters_hash = hash_at_path(statement_set, &["setupParametersHash"])?;
    let target_basis_hash = hash_at_path(statement_set, &["targetBasisHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    let same_secret_consistency_root = hash_at_path(statement_set, &["sameSecretConsistencyRoot"])?;
    let same_secret_proof_set_root = hash_at_path(statement_set, &["sameSecretProofSetRoot"])?;
    let same_secret_proof_family_binding_root =
        hash_at_path(statement_set, &["sameSecretProofFamilyBindingRoot"])?;

    for (field_name, expected_value) in [
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
        ("ceremonyId", ceremony_id),
        ("setupEpoch", setup_epoch),
    ] {
        compare_required_string(
            string_at_path(proof_material_set, &[field_name])?,
            expected_value,
            &format!("same-secret bridge proof material set {field_name}"),
        )?;
    }
    for (field_name, expected_value) in [
        ("manifestHash", manifest_hash),
        ("rosterHash", roster_hash),
        ("setupParametersHash", setup_parameters_hash),
        ("targetBasisHash", target_basis_hash),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
        ("coefficientCommitmentRoot", coefficient_commitment_root),
        ("sameSecretConsistencyRoot", same_secret_consistency_root),
        ("sameSecretProofSetRoot", same_secret_proof_set_root),
        (
            "sameSecretProofFamilyBindingRoot",
            same_secret_proof_family_binding_root,
        ),
        ("sameSecretBridgeStatementSetRoot", statement_set_root),
    ] {
        compare_required_string(
            hash_at_path(proof_material_set, &[field_name])?,
            expected_value,
            &format!("same-secret bridge proof material set {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["participantCount"])?,
        participant_count as u64,
        "same-secret bridge proof material set participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["targetRnsLimbCount"])?,
        target_rns_limb_count as u64,
        "same-secret bridge proof material set targetRnsLimbCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["ringDegree"])?,
        ring_degree as u64,
        "same-secret bridge proof material set ringDegree",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["thresholdDegree"])?,
        threshold_degree as u64,
        "same-secret bridge proof material set thresholdDegree",
    )?;

    let bridge_statement_records = array_at_path(statement_set, &["statementRecords"])?;
    let proof_records = array_at_path(proof_material_set, &["proofRecords"])?;
    if proof_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret bridge proof material set must contain one proof record per bridge statement",
        ));
    }

    let mut total_proof_byte_length = 0usize;
    let mut verified_proof_count = 0usize;
    let mut verified_proof_records = Vec::with_capacity(proof_records.len());
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
        compare_required_string(
            string_at_path(proof_record, &["proofFamily"])?,
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "same-secret bridge proof record proofFamily",
        )?;
        let bridge_statement_root =
            hash_at_path(bridge_statement, &["sameSecretBridgeStatementRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretBridgeStatementRoot"])?,
            bridge_statement_root,
            "same-secret bridge proof record statement root",
        )?;
        let resolved_proof_bytes =
            resolve_same_secret_bridge_proof_bytes(proof_record, request, bridge_statement_root)?;
        let proof_bytes = resolved_proof_bytes.proof_bytes;
        let proof_byte_length = proof_bytes.len();
        total_proof_byte_length = total_proof_byte_length
            .checked_add(proof_byte_length)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "same-secret bridge proof byte length overflowed",
                )
            })?;
        let proof_record_without_root = resolved_proof_bytes.proof_record_without_root;
        let proof_record_root = resolved_proof_bytes.proof_record_root;

        verify_reconstructed_same_secret_bridge_proof(
            ReconstructedSameSecretBridgeProofVerification {
                bridge_statement,
                statement_set: StatementSetBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    target_basis_hash,
                    public_matrix_seed_hash,
                    same_secret_proof_family_binding_root,
                },
                expected_position,
                proof_byte_length,
                proof_bytes: &proof_bytes[..],
            },
        )?;
        verified_proof_count += 1;

        let mut verified_proof_record = proof_record_without_root;
        verified_proof_record["proofRecordRoot"] = json!(proof_record_root);
        verified_proof_records.push(verified_proof_record);
    }
    let proof_material_set_without_root = json!({
        "objectType": "VssSameSecretBridgeProofMaterialSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "sameSecretConsistencyRoot": same_secret_consistency_root,
        "sameSecretProofSetRoot": same_secret_proof_set_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "sameSecretBridgeStatementSetRoot": statement_set_root,
        "proofRecords": verified_proof_records,
    });
    let proof_material_set_root = hash_at_path(proof_material_set, &["proofMaterialSetRoot"])?;
    let expected_proof_material_set_root =
        derive_canonical_object_hash(&proof_material_set_without_root)?;
    if expected_proof_material_set_root != proof_material_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret bridge proof material set root does not match its bound proof records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyVssSameSecretBridgeProofMaterialSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementSetRoot": statement_set_root,
        "proofMaterialSetRoot": proof_material_set_root,
        "participantCount": participant_count,
        "proofRecordCount": proof_records.len(),
        "totalProofByteLength": total_proof_byte_length,
        "proofVerificationCount": verified_proof_count,
    }))
}

mod anchor_evidence;
mod anchor_transport;
mod bridge_transport;
mod reconstructed;
mod statement_record;
mod transport_common;

use anchor_evidence::*;
#[cfg(test)]
use anchor_transport::*;
use bridge_transport::*;
use reconstructed::*;
use statement_record::*;

#[cfg(test)]
mod tests;
