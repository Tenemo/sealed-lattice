use super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SetupProofMaterialBytes,
    verified_setup_proof_material_bytes_from_request,
};
use super::vss_commitment::VSS_PUBLIC_COMMITMENT_BINARY_FORMAT;
use super::*;
use crate::bgv::setup_helpers::{
    compare_required_string, compare_required_u64, read_positive_u64_at_path,
    read_positive_usize_at_path,
};
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const VSS_SAME_SECRET_BRIDGE_RELATION: &str = "public constant coefficient commitments bind to the same signed ternary trustee secret as the source VSS constant commitments across Q_share";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes";
const SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterialSet";
const SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretBridgeProofMaterial";
const VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound source and public commitment over Q_share";
const VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each Q_share RNS prime";
const VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER: &str = "target constant roots are ordered by contiguous Q_share rnsLimbIndex values starting at zero and bind the listed Q_share prime";
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
    let coefficient_commitment_set = value_at_path(request, &["coefficientCommitmentSet"])?;
    let vss_coefficient_commitments = value_at_path(request, &["vssCoefficientCommitments"])?;
    compare_required_string(
        string_at_path(statement_set, &["objectType"])?,
        "VssSameSecretBridgeStatementSet",
        "VSS same-secret bridge statement set objectType",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["proofFamily"])?,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "VSS same-secret bridge statement set proofFamily",
    )?;

    let ceremony_id = read_non_empty_string(statement_set, "ceremonyId")?;
    let setup_epoch = read_non_empty_string(statement_set, "setupEpoch")?;
    let manifest_hash = hash_at_path(statement_set, &["manifestHash"])?;
    let roster_hash = hash_at_path(statement_set, &["rosterHash"])?;
    let setup_parameters_hash = hash_at_path(statement_set, &["setupParametersHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement_set,
        &["ringDegree"],
        "VSS same-secret bridge statement set ringDegree",
    )?;
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    let vss_coefficient_commitment_root =
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
    let coefficient_commitment_verification =
        super::vss_commitment::verify_vss_public_coefficient_commitment_set_request(&json!({
            "coefficientCommitmentSet": coefficient_commitment_set,
        }))?;
    compare_required_string(
        hash_at_path(
            &coefficient_commitment_verification,
            &["coefficientCommitmentRoot"],
        )?,
        coefficient_commitment_root,
        "VSS same-secret bridge authoritative coefficientCommitmentRoot",
    )?;
    compare_required_string(
        hash_at_path(
            &coefficient_commitment_verification,
            &["publicMatrixSeedHash"],
        )?,
        public_matrix_seed_hash,
        "VSS same-secret bridge authoritative publicMatrixSeedHash",
    )?;
    for (field_name, expected_value) in [
        ("participantCount", participant_count),
        ("rnsLimbCount", q_share_rns_limb_count),
        ("thresholdDegree", threshold_degree),
        ("ringDegree", ring_degree),
    ] {
        compare_required_u64(
            unsigned_at_path(&coefficient_commitment_verification, &[field_name])?,
            expected_value as u64,
            &format!("VSS same-secret bridge authoritative {field_name}"),
        )?;
    }
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
        string_at_path(statement_set, &["qShareLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
        "VSS same-secret bridge statement set qShareLimbOrder",
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
                coefficient_commitment_set,
                vss_coefficient_commitments,
                expected_position,
                q_share_rns_limb_count,
                threshold_degree,
                ring_degree,
                statement_set: StatementSetBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                },
            },
        )?);
    }

    let expected_statement_set_root = derive_canonical_object_hash(&json!({
        "objectType": "VssSameSecretBridgeStatementSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "qShareLimbOrder": VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
        "statementRecords": verified_statement_records,
    }))?;
    let statement_set_root = hash_at_path(statement_set, &["sameSecretBridgeStatementSetRoot"])?;
    if expected_statement_set_root != statement_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "VSS same-secret bridge statement set root does not match its bound statements",
        ));
    }
    Ok(json!({
        "operation": "verifyVssSameSecretBridgeStatementSet",
        "sameSecretBridgeStatementSetRoot": statement_set_root,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "qShareLimbOrder": VSS_SAME_SECRET_BRIDGE_Q_SHARE_LIMB_ORDER,
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
    let q_share_rns_limb_count = read_positive_usize_at_path(
        &statement_verification,
        &["qShareRnsLimbCount"],
        "same-secret bridge proof material statement qShareRnsLimbCount",
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
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    let vss_coefficient_commitment_root =
        hash_at_path(statement_set, &["vssCoefficientCommitmentRoot"])?;
    let vss_coefficient_commitments = value_at_path(request, &["vssCoefficientCommitments"])?;

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
        ("publicMatrixSeedHash", public_matrix_seed_hash),
        ("coefficientCommitmentRoot", coefficient_commitment_root),
        (
            "vssCoefficientCommitmentRoot",
            vss_coefficient_commitment_root,
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
        unsigned_at_path(proof_material_set, &["qShareRnsLimbCount"])?,
        q_share_rns_limb_count as u64,
        "same-secret bridge proof material set qShareRnsLimbCount",
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
        let proof_record_without_root = resolved_proof_bytes.proof_record_without_root;
        let proof_record_root = resolved_proof_bytes.proof_record_root;
        let trustee_identity = string_at_path(bridge_statement, &["trusteeIdentity"])?;
        let source_constant_commitments =
            super::source_constant_commitments::canonical_source_constant_commitments_from_bridge_statement(
                vss_coefficient_commitments,
                bridge_statement,
                trustee_identity,
                expected_position as u64,
                public_matrix_seed_hash,
                ring_degree,
            )?;

        verify_reconstructed_same_secret_bridge_proof(
            ReconstructedSameSecretBridgeProofVerification {
                bridge_statement,
                statement_set: StatementSetBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_parameters_hash,
                    setup_epoch,
                    public_matrix_seed_hash,
                },
                expected_position,
                proof_bytes: &proof_bytes,
                source_constant_commitment_values: &source_constant_commitments.commitment_values,
            },
        )?;
        let mut verified_proof_record = proof_record_without_root;
        verified_proof_record["sameSecretBridgeProofRecordRoot"] = json!(proof_record_root);
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
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "ringDegree": ring_degree,
        "participantCount": participant_count,
        "qShareRnsLimbCount": q_share_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "coefficientCommitmentRoot": coefficient_commitment_root,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
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
        "operation": "verifyVssSameSecretBridgeProofMaterialSet",
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementSetRoot": statement_set_root,
        "proofMaterialSetRoot": proof_material_set_root,
        "participantCount": participant_count,
    }))
}

mod bridge_transport;
mod reconstructed;
mod statement_record;
mod transport_common;

use bridge_transport::*;
use reconstructed::*;
use statement_record::*;
