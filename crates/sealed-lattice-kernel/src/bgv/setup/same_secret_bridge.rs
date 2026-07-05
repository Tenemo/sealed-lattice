use super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialTransportHashes, setup_proof_material_transport_hashes,
    verified_setup_proof_material_chunks_from_request,
};
use super::vss_commitment::VSS_PUBLIC_COMMITMENT_BINARY_FORMAT;
use super::*;
use crate::bgv::setup_helpers::compare_required_string;
use std::sync::Arc;

const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1";
const SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretProofMaterialSet";
const SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE: &str = "SetupTransportedSameSecretProofMaterial";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const VSS_SAME_SECRET_BRIDGE_RELATION: &str = "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
const SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-bridge/proof-bytes-v1";
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
        "compact VSS same-secret bridge statement set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(statement_set, &["objectVersion"])?,
        1,
        "compact VSS same-secret bridge statement set objectVersion",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "compact VSS same-secret bridge statement set proofFamily",
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
        "compact VSS same-secret bridge statement set targetBasisHash",
    )?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let ring_degree = read_positive_usize_at_path(
        statement_set,
        &["ringDegree"],
        "compact VSS same-secret bridge statement set ringDegree",
    )?;
    let coefficient_commitment_root = hash_at_path(statement_set, &["coefficientCommitmentRoot"])?;
    let same_secret_consistency_root = hash_at_path(statement_set, &["sameSecretConsistencyRoot"])?;
    let same_secret_proof_set_root = hash_at_path(statement_set, &["sameSecretProofSetRoot"])?;
    let same_secret_proof_family_binding_root =
        hash_at_path(statement_set, &["sameSecretProofFamilyBindingRoot"])?;
    let participant_count = read_positive_usize_at_path(
        statement_set,
        &["participantCount"],
        "compact VSS same-secret bridge statement set participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        statement_set,
        &["targetRnsLimbCount"],
        "compact VSS same-secret bridge statement set targetRnsLimbCount",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        statement_set,
        &["thresholdDegree"],
        "compact VSS same-secret bridge statement set thresholdDegree",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["integerSupport"])?,
        VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "compact VSS same-secret bridge statement set integerSupport",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["signedRepresentativeConvention"])?,
        VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compact VSS same-secret bridge statement set signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["vssPublicCommitmentEncoding"])?,
        VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "compact VSS same-secret bridge statement set vssPublicCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["targetBasisLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "compact VSS same-secret bridge statement set targetBasisLimbOrder",
    )?;

    let statement_records = array_at_path(statement_set, &["statementRecords"])?;
    if statement_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS same-secret bridge statement set must contain one statement per participant",
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
        "objectVersion": 1,
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
            "compact VSS same-secret bridge statement set root does not match its bound statements",
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
        "compact same-secret bridge proof material statement participantCount",
    )?;
    let target_rns_limb_count = read_positive_usize_at_path(
        &statement_verification,
        &["targetRnsLimbCount"],
        "compact same-secret bridge proof material statement targetRnsLimbCount",
    )?;
    let ring_degree = read_positive_usize_at_path(
        &statement_verification,
        &["ringDegree"],
        "compact same-secret bridge proof material statement ringDegree",
    )?;
    let threshold_degree = read_positive_usize_at_path(
        &statement_verification,
        &["thresholdDegree"],
        "compact same-secret bridge proof material statement thresholdDegree",
    )?;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "VssSameSecretBridgeProofMaterialSet",
        "compact same-secret bridge proof material set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["objectVersion"])?,
        1,
        "compact same-secret bridge proof material set objectVersion",
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
            &format!("compact same-secret bridge proof material set {field_name}"),
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
            &format!("compact same-secret bridge proof material set {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["participantCount"])?,
        participant_count as u64,
        "compact same-secret bridge proof material set participantCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["targetRnsLimbCount"])?,
        target_rns_limb_count as u64,
        "compact same-secret bridge proof material set targetRnsLimbCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["ringDegree"])?,
        ring_degree as u64,
        "compact same-secret bridge proof material set ringDegree",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_material_set, &["thresholdDegree"])?,
        threshold_degree as u64,
        "compact same-secret bridge proof material set thresholdDegree",
    )?;

    let bridge_statement_records = array_at_path(statement_set, &["statementRecords"])?;
    let proof_records = array_at_path(proof_material_set, &["proofRecords"])?;
    if proof_records.len() != participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact same-secret bridge proof material set must contain one proof record per bridge statement",
        ));
    }

    let mut total_proof_byte_length = 0usize;
    let mut verified_proof_count = 0usize;
    let mut verified_proof_records = Vec::with_capacity(proof_records.len());
    for (expected_position, proof_record) in proof_records.iter().enumerate() {
        let bridge_statement = bridge_statement_records
            .get(expected_position)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact same-secret bridge proof material set has no matching bridge statement",
                )
            })?;
        compare_required_string(
            string_at_path(proof_record, &["objectType"])?,
            "VssSameSecretBridgeProofRecord",
            "compact same-secret bridge proof record objectType",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_record, &["objectVersion"])?,
            1,
            "compact same-secret bridge proof record objectVersion",
        )?;
        compare_required_string(
            string_at_path(proof_record, &["proofFamily"])?,
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "compact same-secret bridge proof record proofFamily",
        )?;
        let bridge_statement_root =
            hash_at_path(bridge_statement, &["sameSecretBridgeStatementRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretBridgeStatementRoot"])?,
            bridge_statement_root,
            "compact same-secret bridge proof record statement root",
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
                    "compact same-secret bridge proof byte length overflowed",
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
                proof_bytes: &proof_bytes,
            },
        )?;
        verified_proof_count += 1;

        let mut verified_proof_record = proof_record_without_root;
        verified_proof_record["proofRecordRoot"] = json!(proof_record_root);
        verified_proof_records.push(verified_proof_record);
    }
    let proof_material_set_without_root = json!({
        "objectType": "VssSameSecretBridgeProofMaterialSet",
        "objectVersion": 1,
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
            "compact same-secret bridge proof material set root does not match its bound proof records",
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

#[derive(Clone, Copy)]
struct StatementSetBinding<'a> {
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_parameters_hash: &'a str,
    setup_epoch: &'a str,
    target_basis_hash: &'a str,
    public_matrix_seed_hash: &'a str,
    same_secret_proof_family_binding_root: &'a str,
}

struct StatementRecordVerificationInput<'a> {
    statement_record: &'a Value,
    expected_position: usize,
    target_rns_limb_count: usize,
    ring_degree: usize,
    statement_set: StatementSetBinding<'a>,
}

struct ReconstructedSameSecretBridgeProofVerification<'a> {
    bridge_statement: &'a Value,
    statement_set: StatementSetBinding<'a>,
    expected_position: usize,
    proof_byte_length: usize,
    proof_bytes: &'a [u8],
}

struct EvidenceSetVerificationInput<'a> {
    request: &'a Value,
    statement_set: StatementSetBinding<'a>,
    participant_count: usize,
    same_secret_consistency_root: &'a str,
    same_secret_proof_set_root: &'a str,
    same_secret_proof_family_binding_root: &'a str,
    bridge_statement_records: &'a [Value],
}

fn verify_reconstructed_same_secret_bridge_proof(
    input: ReconstructedSameSecretBridgeProofVerification<'_>,
) -> CanonicalResult<()> {
    let trustee_identity = string_at_path(input.bridge_statement, &["trusteeIdentity"])?;
    compare_required_u64(
        unsigned_at_path(input.bridge_statement, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "compact same-secret bridge statement trusteeRosterPosition",
    )?;

    let bridge_target_constant_roots = array_at_path(
        input.bridge_statement,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    let bridge_target_constant_commitments = array_at_path(
        input.bridge_statement,
        &["targetConstantCoefficientCommitments"],
    )?;
    if bridge_target_constant_commitments.len() != bridge_target_constant_roots.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact same-secret bridge proof target commitments must match the bridge statement target roots",
        ));
    }
    let mut target_rns_primes = Vec::with_capacity(bridge_target_constant_roots.len());
    let mut target_constant_commitment_roots =
        Vec::with_capacity(bridge_target_constant_roots.len());
    let mut target_constant_commitments = Vec::with_capacity(bridge_target_constant_roots.len());
    for (target_rns_limb_index, bridge_target_root) in
        bridge_target_constant_roots.iter().enumerate()
    {
        let bridge_target_commitment = bridge_target_constant_commitments
            .get(target_rns_limb_index)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact same-secret bridge proof target commitment is missing",
                )
            })?;
        compare_required_u64(
            unsigned_at_path(bridge_target_root, &["rnsLimbIndex"])?,
            target_rns_limb_index as u64,
            "compact same-secret bridge target root rnsLimbIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_commitment, &["rnsLimbIndex"])?,
            target_rns_limb_index as u64,
            "compact same-secret bridge target commitment rnsLimbIndex",
        )?;
        let target_rns_prime = unsigned_at_path(bridge_target_root, &["rnsPrime"])?;
        compare_required_u64(
            target_rns_prime,
            unsigned_at_path(bridge_target_commitment, &["rnsPrime"])?,
            "compact same-secret bridge target commitment rnsPrime",
        )?;
        compare_required_u64(
            target_rns_prime,
            DATA_PRIMES[target_rns_limb_index],
            "compact same-secret bridge proof canonical target prime",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_root, &["shamirCoefficientIndex"])?,
            0,
            "compact same-secret bridge target root shamirCoefficientIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_target_commitment, &["shamirCoefficientIndex"])?,
            0,
            "compact same-secret bridge target commitment shamirCoefficientIndex",
        )?;
        let coefficient_commitment_root =
            hash_at_path(bridge_target_root, &["coefficientCommitmentRoot"])?;
        let target_commitment_body = value_at_path(bridge_target_commitment, &["commitment"])?;
        compare_required_string(
            &derive_canonical_object_hash(target_commitment_body)?,
            coefficient_commitment_root,
            "compact same-secret bridge target commitment body root",
        )?;
        target_rns_primes.push(target_rns_prime);
        target_constant_commitment_roots.push(coefficient_commitment_root.to_string());
        target_constant_commitments.push(target_commitment_body.clone());
    }

    let same_secret_bridge_statement_root =
        hash_at_path(input.bridge_statement, &["sameSecretBridgeStatementRoot"])?;
    let same_secret_statement_root =
        hash_at_path(input.bridge_statement, &["sameSecretStatementRoot"])?;
    let same_secret_proof_root = hash_at_path(input.bridge_statement, &["sameSecretProofRoot"])?;
    let same_secret_proof_family_binding_root = hash_at_path(
        input.bridge_statement,
        &["sameSecretProofFamilyBindingRoot"],
    )?;
    let proof_verification_request = json!({
        "context": {
            "ceremonyId": input.statement_set.ceremony_id,
            "manifestHash": input.statement_set.manifest_hash,
            "rosterHash": input.statement_set.roster_hash,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": input.expected_position,
            "setupEpoch": input.statement_set.setup_epoch,
            "sameSecretBridgeStatementRoot": same_secret_bridge_statement_root,
            "sameSecretStatementRoot": same_secret_statement_root,
            "sameSecretProofRoot": same_secret_proof_root,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        },
        "ringDegree": unsigned_at_path(input.bridge_statement, &["ringDegree"])?,
        "sameSecretBridge": {
            "sameSecretBridgeStatementRoot": same_secret_bridge_statement_root,
            "sameSecretStatementRoot": same_secret_statement_root,
            "sameSecretProofRoot": same_secret_proof_root,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
            "sourceTrusteeIdentity": trustee_identity,
            "sourceTrusteeRosterPosition": input.expected_position,
            "targetBasisHash": input.statement_set.target_basis_hash,
            "targetRnsPrimes": target_rns_primes,
            "targetConstantCommitmentRoots": target_constant_commitment_roots,
            "targetConstantCommitments": target_constant_commitments,
        },
        "proofBytesHex": crate::transcript_core::encode_hex(input.proof_bytes),
    });
    let proof_verification =
        super::trustee_evaluation_key_proof::verify_same_secret_bridge_proof_from_request(
            &proof_verification_request,
        )?;
    compare_required_string(
        string_at_path(&proof_verification, &["proofFamily"])?,
        SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "reconstructed compact same-secret bridge proof verification proofFamily",
    )?;
    hash_at_path(&proof_verification, &["statementHash"])?;
    compare_required_u64(
        unsigned_at_path(&proof_verification, &["proofByteLength"])?,
        input.proof_byte_length as u64,
        "reconstructed compact same-secret bridge proof verification proofByteLength",
    )?;

    Ok(())
}

// Resolved compact same-secret bridge proof bytes plus the canonical proof
// record whose root binds them. The embedded form carries the proof bytes as
// base64 inside the record; the transported form streams the bytes through the
// shared setup proof-material transport and binds the transport reference into
// the record root instead of the base64 bytes.
struct ResolvedSameSecretBridgeProofBytes {
    proof_bytes: Vec<u8>,
    proof_record_without_root: Value,
    proof_record_root: String,
}

fn resolve_same_secret_bridge_proof_bytes(
    proof_record: &Value,
    request: &Value,
    bridge_statement_root: &str,
) -> CanonicalResult<ResolvedSameSecretBridgeProofBytes> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    let proof_record_root = hash_at_path(proof_record, &["proofRecordRoot"])?.to_string();
    if proof_record.get("proofBytesBase64").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_bridge_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "compact same-secret bridge proof record must not mix embedded proofBytesBase64 with transported proof material",
            ));
        }
        let proof_bytes_base64 = string_at_path(proof_record, &["proofBytesBase64"])?;
        let proof_bytes = crate::transcript_core::decode_standard_base64(
            proof_bytes_base64,
            "compact same-secret bridge proofBytesBase64",
        )?;
        let expected_proof_bytes_hash =
            hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "compact same-secret bridge proof record proofBytesHash",
        )?;
        let proof_record_without_root = json!({
            "objectType": "VssSameSecretBridgeProofRecord",
            "objectVersion": 1,
            "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "sameSecretBridgeStatementRoot": bridge_statement_root,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesBase64": proof_bytes_base64,
        });
        let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
        if expected_proof_record_root != proof_record_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "compact same-secret bridge proof record root does not match its bound proof bytes",
            ));
        }

        return Ok(ResolvedSameSecretBridgeProofBytes {
            proof_bytes,
            proof_record_without_root,
            proof_record_root,
        });
    }

    compare_required_string(
        string_at_path(proof_record, &["proofBytesEncoding"])?,
        SETUP_PROOF_MATERIAL_ENCODING,
        "compact same-secret bridge proof record proofBytesEncoding",
    )?;
    let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
    let transported_binding =
        transported_same_secret_bridge_proof_material_binding(request, proof_material_root)?;
    verify_same_secret_bridge_proof_transport_reference(
        proof_record,
        &transported_binding.transport_hashes,
    )?;
    compare_required_string(
        proof_bytes_hash,
        &transported_binding.proof_bytes_hash,
        "compact same-secret bridge proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": "VssSameSecretBridgeProofRecord",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "sameSecretBridgeStatementRoot": bridge_statement_root,
        "proofBytesHash": proof_bytes_hash,
        "proofBytesEncoding": SETUP_PROOF_MATERIAL_ENCODING,
        "proofMaterialRoot": proof_material_root,
        "proofChunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "proofChunkCount": transported_binding.transport_hashes.chunk_hashes.len(),
        "proofTotalByteLength": transported_binding.transport_hashes.total_byte_length,
        "proofFullObjectHash": transported_binding.transport_hashes.full_object_hash,
        "proofChunkRoot": transported_binding.transport_hashes.chunk_root,
        "proofChunkHashes": transported_binding.transport_hashes.chunk_hashes,
    });
    let expected_proof_record_root = derive_canonical_object_hash(&proof_record_without_root)?;
    if expected_proof_record_root != proof_record_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "compact same-secret bridge proof record root does not match its transported proof material",
        ));
    }

    Ok(ResolvedSameSecretBridgeProofBytes {
        proof_bytes: transported_binding.proof_bytes,
        proof_record_without_root,
        proof_record_root,
    })
}

struct SameSecretBridgeProofTransportBinding {
    transport_hashes: SetupProofMaterialTransportHashes,
    proof_bytes: Vec<u8>,
    proof_bytes_hash: String,
}

fn transported_same_secret_bridge_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretBridgeProofTransportBinding> {
    let material_set = value_at_path(request, &["transportedSameSecretBridgeProofMaterial"])
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretBridgeProofMaterial is required by transported compact same-secret bridge proof records",
            )
        })?;
    verify_transported_same_secret_bridge_proof_material_set_header(material_set)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_same_secret_bridge_proof_material_header(proof_material)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretBridgeProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_same_secret_bridge_proof_chunks(
                proof_material,
                proof_material_index,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                SAME_SECRET_BRIDGE_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedSameSecretBridgeProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_BRIDGE_PROOF_FAMILY,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_bridge_proof_material_hashes(
            proof_material,
            &transport_hashes,
        )?;
        let proof_bytes = chunks.iter().flatten().copied().collect::<Vec<u8>>();
        let proof_bytes_hash =
            hash512_hex(SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        matching_binding = Some(SameSecretBridgeProofTransportBinding {
            transport_hashes,
            proof_bytes,
            proof_bytes_hash,
        });
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretBridgeProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_bridge_proof_material_set_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_BRIDGE_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transportedSameSecretBridgeProofMaterial.{field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transportedSameSecretBridgeProofMaterial.objectVersion",
    )
}

fn verify_transported_same_secret_bridge_proof_material_header(
    value: &Value,
) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_BRIDGE_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_BRIDGE_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transported compact same-secret bridge proof material {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transported compact same-secret bridge proof material objectVersion",
    )?;
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

fn transported_same_secret_bridge_proof_chunks(
    value: &Value,
    proof_material_index: usize,
) -> CanonicalResult<Vec<Vec<u8>>> {
    compare_required_u64(
        unsigned_at_path(value, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "transported compact same-secret bridge proof material chunkSizeBytes",
    )?;
    let chunk_count = read_positive_usize_at_path(
        value,
        &["chunkCount"],
        "transported compact same-secret bridge proof material chunkCount",
    )?;
    let chunk_values = array_at_path(value, &["chunks"])?;
    if chunk_values.len() != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported compact same-secret bridge proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_required_u64(
            unsigned_at_path(chunk_value, &["chunkIndex"])?,
            expected_chunk_index as u64,
            &format!(
                "transportedSameSecretBridgeProofMaterial.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex"
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            "transported compact same-secret bridge proof material bytesBase64",
        )?);
    }

    Ok(chunks)
}

fn verify_transported_same_secret_bridge_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(value, &["totalByteLength"])?,
        transport_hashes.total_byte_length,
        "transported compact same-secret bridge proof material totalByteLength",
    )?;
    compare_required_string(
        hash_at_path(value, &["fullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "transported compact same-secret bridge proof material fullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(value, &["chunkRoot"])?,
        &transport_hashes.chunk_root,
        "transported compact same-secret bridge proof material chunkRoot",
    )?;
    let chunk_hash_values = array_at_path(value, &["chunkHashes"])?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported compact same-secret bridge proof material chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(chunk_hash_value, &[])?,
            expected_chunk_hash,
            &format!(
                "transported compact same-secret bridge proof material chunkHashes.{chunk_index}"
            ),
        )?;
    }

    Ok(())
}

fn verify_same_secret_bridge_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "compact same-secret bridge proof record proofChunkSizeBytes",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkCount"])?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact same-secret bridge proof chunk count does not fit u64",
            )
        })?,
        "compact same-secret bridge proof record proofChunkCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofTotalByteLength"])?,
        transport_hashes.total_byte_length,
        "compact same-secret bridge proof record proofTotalByteLength",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofFullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "compact same-secret bridge proof record proofFullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofChunkRoot"])?,
        &transport_hashes.chunk_root,
        "compact same-secret bridge proof record proofChunkRoot",
    )?;
    let proof_chunk_hashes = array_at_path(proof_record, &["proofChunkHashes"])?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact same-secret bridge proof record proofChunkHashes length must match transported chunks",
        ));
    }
    for (chunk_index, (proof_chunk_hash, expected_chunk_hash)) in proof_chunk_hashes
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(proof_chunk_hash, &[])?,
            expected_chunk_hash,
            &format!("compact same-secret bridge proof record proofChunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

fn same_secret_bridge_proof_has_transport_reference(proof_record: &Value) -> bool {
    [
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some())
}

fn verify_same_secret_evidence_sets(
    input: EvidenceSetVerificationInput<'_>,
) -> CanonicalResult<()> {
    let (Some(same_secret_consistency), Some(same_secret_proofs)) = (
        input.request.get("sameSecretConsistency"),
        input.request.get("sameSecretProofs"),
    ) else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS same-secret bridge evidence verification requires both sameSecretConsistency and sameSecretProofs",
        ));
    };
    let same_secret_statement_records =
        verify_same_secret_consistency_evidence(same_secret_consistency, &input)?;
    verify_same_secret_proof_evidence(same_secret_proofs, &input, &same_secret_statement_records)
}

fn verify_same_secret_consistency_evidence(
    same_secret_consistency: &Value,
    input: &EvidenceSetVerificationInput<'_>,
) -> CanonicalResult<Vec<Value>> {
    compare_required_string(
        string_at_path(same_secret_consistency, &["objectType"])?,
        "SameSecretConsistencyStatementSet",
        "same-secret consistency objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_consistency, &["objectVersion"])?,
        1,
        "same-secret consistency objectVersion",
    )?;
    compare_required_string(
        string_at_path(same_secret_consistency, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "same-secret consistency proofFamily",
    )?;
    compare_evidence_context(
        same_secret_consistency,
        input.statement_set,
        "same-secret consistency",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_consistency, &["participantCount"])?,
        input.participant_count as u64,
        "same-secret consistency participantCount",
    )?;
    compare_required_string(
        hash_at_path(same_secret_consistency, &["sameSecretConsistencyRoot"])?,
        input.same_secret_consistency_root,
        "same-secret consistency root",
    )?;
    compare_required_string(
        hash_at_path(
            same_secret_consistency,
            &["sameSecretProofFamilyBindingRoot"],
        )?,
        input.same_secret_proof_family_binding_root,
        "same-secret consistency proof-family binding root",
    )?;
    let expected_consistency_root = derive_canonical_object_hash(&value_without_root_field(
        same_secret_consistency,
        "sameSecretConsistencyRoot",
        "same-secret consistency statement set",
    )?)?;
    if expected_consistency_root != input.same_secret_consistency_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret consistency root does not match its bound statement set",
        ));
    }

    let statement_records = array_at_path(same_secret_consistency, &["statementRecords"])?;
    if statement_records.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret consistency statement records must cover every participant",
        ));
    }
    let mut verified_statement_records = Vec::with_capacity(statement_records.len());
    for (expected_position, (statement_record, bridge_statement)) in statement_records
        .iter()
        .zip(input.bridge_statement_records.iter())
        .enumerate()
        .take(input.participant_count)
    {
        compare_required_string(
            string_at_path(statement_record, &["objectType"])?,
            "SameSecretConsistencyStatement",
            "same-secret consistency statement objectType",
        )?;
        compare_required_u64(
            unsigned_at_path(statement_record, &["objectVersion"])?,
            1,
            "same-secret consistency statement objectVersion",
        )?;
        compare_evidence_context(
            statement_record,
            input.statement_set,
            "same-secret consistency statement",
        )?;
        let trustee_identity = read_non_empty_string(statement_record, "trusteeIdentity")?;
        compare_required_u64(
            unsigned_at_path(statement_record, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret consistency statement trusteeRosterPosition",
        )?;
        compare_required_string(
            string_at_path(bridge_statement, &["trusteeIdentity"])?,
            trustee_identity,
            "compact same-secret bridge evidence trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(bridge_statement, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "compact same-secret bridge evidence trusteeRosterPosition",
        )?;
        let same_secret_statement_root =
            hash_at_path(statement_record, &["sameSecretStatementRoot"])?;
        let trustee_secret_commitment_root =
            hash_at_path(statement_record, &["trusteeSecretCommitmentRoot"])?;
        let same_secret_proof_family_binding_root =
            hash_at_path(statement_record, &["sameSecretProofFamilyBindingRoot"])?;
        compare_required_string(
            same_secret_proof_family_binding_root,
            input.same_secret_proof_family_binding_root,
            "same-secret consistency statement proof-family binding root",
        )?;
        compare_required_string(
            string_at_path(statement_record, &["sameSecretRelation"])?,
            SAME_SECRET_RELATION,
            "same-secret consistency statement relation",
        )?;
        let expected_statement_root = derive_canonical_object_hash(&value_without_root_field(
            statement_record,
            "sameSecretStatementRoot",
            "same-secret consistency statement",
        )?)?;
        if expected_statement_root != same_secret_statement_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret consistency statement root does not match its bound statement",
            ));
        }
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretStatementRoot"])?,
            same_secret_statement_root,
            "compact same-secret bridge evidence sameSecretStatementRoot",
        )?;
        compare_required_string(
            hash_at_path(bridge_statement, &["trusteeSecretCommitmentRoot"])?,
            trustee_secret_commitment_root,
            "compact same-secret bridge evidence trusteeSecretCommitmentRoot",
        )?;
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretProofFamilyBindingRoot"])?,
            same_secret_proof_family_binding_root,
            "compact same-secret bridge evidence sameSecretProofFamilyBindingRoot",
        )?;
        verified_statement_records.push(statement_record.clone());
    }

    Ok(verified_statement_records)
}

fn verify_same_secret_proof_evidence(
    same_secret_proofs: &Value,
    input: &EvidenceSetVerificationInput<'_>,
    same_secret_statement_records: &[Value],
) -> CanonicalResult<()> {
    compare_required_string(
        string_at_path(same_secret_proofs, &["objectType"])?,
        "SameSecretProofSet",
        "same-secret proof set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_proofs, &["objectVersion"])?,
        1,
        "same-secret proof set objectVersion",
    )?;
    compare_required_string(
        string_at_path(same_secret_proofs, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "same-secret proof set proofFamily",
    )?;
    compare_evidence_context(
        same_secret_proofs,
        input.statement_set,
        "same-secret proof set",
    )?;
    compare_required_u64(
        unsigned_at_path(same_secret_proofs, &["participantCount"])?,
        input.participant_count as u64,
        "same-secret proof set participantCount",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretConsistencyRoot"])?,
        input.same_secret_consistency_root,
        "same-secret proof set consistency root",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretProofSetRoot"])?,
        input.same_secret_proof_set_root,
        "same-secret proof set root",
    )?;
    compare_required_string(
        hash_at_path(same_secret_proofs, &["sameSecretProofFamilyBindingRoot"])?,
        input.same_secret_proof_family_binding_root,
        "same-secret proof set proof-family binding root",
    )?;
    let expected_proof_set_root = derive_canonical_object_hash(&value_without_root_field(
        same_secret_proofs,
        "sameSecretProofSetRoot",
        "same-secret proof set",
    )?)?;
    if expected_proof_set_root != input.same_secret_proof_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "same-secret proof set root does not match its bound proof records",
        ));
    }

    let proof_records = array_at_path(same_secret_proofs, &["proofRecords"])?;
    if proof_records.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof records must cover every participant",
        ));
    }

    for (expected_position, ((proof_record, statement_record), bridge_statement)) in proof_records
        .iter()
        .zip(same_secret_statement_records.iter())
        .zip(input.bridge_statement_records.iter())
        .enumerate()
        .take(input.participant_count)
    {
        compare_required_string(
            string_at_path(proof_record, &["objectType"])?,
            "SameSecretProof",
            "same-secret proof record objectType",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_record, &["objectVersion"])?,
            1,
            "same-secret proof record objectVersion",
        )?;
        compare_evidence_context(
            proof_record,
            input.statement_set,
            "same-secret proof record",
        )?;
        let trustee_identity = string_at_path(statement_record, &["trusteeIdentity"])?;
        compare_required_string(
            string_at_path(proof_record, &["trusteeIdentity"])?,
            trustee_identity,
            "same-secret proof record trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_record, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret proof record trusteeRosterPosition",
        )?;
        let same_secret_statement_root =
            hash_at_path(statement_record, &["sameSecretStatementRoot"])?;
        let trustee_secret_commitment_root =
            hash_at_path(statement_record, &["trusteeSecretCommitmentRoot"])?;
        let same_secret_proof_family_binding_root =
            hash_at_path(statement_record, &["sameSecretProofFamilyBindingRoot"])?;
        let same_secret_proof_root = hash_at_path(proof_record, &["sameSecretProofRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretStatementRoot"])?,
            same_secret_statement_root,
            "same-secret proof record statement root",
        )?;
        compare_required_string(
            hash_at_path(proof_record, &["trusteeSecretCommitmentRoot"])?,
            trustee_secret_commitment_root,
            "same-secret proof record trustee secret root",
        )?;
        compare_required_string(
            hash_at_path(proof_record, &["sameSecretProofFamilyBindingRoot"])?,
            same_secret_proof_family_binding_root,
            "same-secret proof record proof-family binding root",
        )?;
        verify_same_secret_proof_byte_binding(proof_record, input.request)?;
        let expected_proof_root = derive_canonical_object_hash(&value_without_root_field(
            proof_record,
            "sameSecretProofRoot",
            "same-secret proof",
        )?)?;
        if expected_proof_root != same_secret_proof_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret proof root does not match its bound proof record",
            ));
        }
        compare_required_string(
            hash_at_path(bridge_statement, &["sameSecretProofRoot"])?,
            same_secret_proof_root,
            "compact same-secret bridge evidence sameSecretProofRoot",
        )?;
    }

    Ok(())
}

fn verify_same_secret_proof_byte_binding(
    proof_record: &Value,
    request: &Value,
) -> CanonicalResult<()> {
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    if proof_record.get("proofBytesHex").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "same-secret proof record must not mix embedded proofBytesHex with transported proof material",
            ));
        }
        let proof_bytes_hex = string_at_path(proof_record, &["proofBytesHex"])?;
        let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
        let expected_proof_bytes_hash =
            hash512_hex(SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN, &[&proof_bytes]);
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "same-secret proof record proofBytesHash",
        )?;
    } else {
        compare_required_string(
            string_at_path(proof_record, &["proofBytesEncoding"])?,
            SETUP_PROOF_MATERIAL_ENCODING,
            "same-secret proof record proofBytesEncoding",
        )?;
        let proof_material_root = hash_at_path(proof_record, &["proofMaterialRoot"])?;
        let transported_binding =
            transported_same_secret_proof_material_binding(request, proof_material_root)?;
        verify_same_secret_proof_transport_reference(
            proof_record,
            &transported_binding.transport_hashes,
        )?;
        compare_required_string(
            proof_bytes_hash,
            &transported_binding.proof_bytes_hash,
            "same-secret proof record proofBytesHash",
        )?;
        let expected_proof_material_root = same_secret_anchor_proof_material_root(
            proof_record,
            &transported_binding.transport_hashes,
        )?;
        compare_required_string(
            proof_material_root,
            &expected_proof_material_root,
            "same-secret proof record proofMaterialRoot",
        )?;
    }

    Ok(())
}

struct SameSecretProofTransportBinding {
    transport_hashes: SetupProofMaterialTransportHashes,
    proof_bytes_hash: String,
}

fn transported_same_secret_proof_material_binding(
    request: &Value,
    expected_proof_material_root: &str,
) -> CanonicalResult<SameSecretProofTransportBinding> {
    let material_set = value_at_path(request, &["transportedSameSecretProofMaterial"]).map_err(
        |_| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretProofMaterial is required by transported same-secret proof records",
            )
        },
    )?;
    verify_transported_same_secret_proof_material_set_header(material_set)?;
    let proof_materials = array_at_path(material_set, &["proofMaterials"])?;
    let mut matching_binding = None;
    for (proof_material_index, proof_material) in proof_materials.iter().enumerate() {
        verify_transported_same_secret_proof_material_header(proof_material)?;
        let proof_material_root = hash_at_path(proof_material, &["proofMaterialRoot"])?;
        if proof_material_root != expected_proof_material_root {
            continue;
        }
        if matching_binding.is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            Arc::new(transported_same_secret_proof_chunks(
                proof_material,
                proof_material_index,
            )?)
        } else {
            verified_setup_proof_material_chunks_from_request(
                request,
                SAME_SECRET_PROOF_FAMILY,
                expected_proof_material_root,
                proof_material,
                "transportedSameSecretProofMaterial.proofMaterials",
            )?
        };
        let transport_hashes = setup_proof_material_transport_hashes(
            SAME_SECRET_PROOF_FAMILY,
            chunks.as_ref(),
            SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        )?;
        verify_transported_same_secret_proof_material_hashes(proof_material, &transport_hashes)?;
        let chunk_slices = chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        matching_binding = Some(SameSecretProofTransportBinding {
            transport_hashes,
            proof_bytes_hash: hash512_hex(
                SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN,
                &chunk_slices,
            ),
        });
    }

    matching_binding.ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transportedSameSecretProofMaterial.{field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transportedSameSecretProofMaterial.objectVersion",
    )
}

fn verify_transported_same_secret_proof_material_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE),
        ("proofFamily", SAME_SECRET_PROOF_FAMILY),
    ] {
        compare_required_string(
            string_at_path(value, &[field_name])?,
            expected_value,
            &format!("transported same-secret proof material {field_name}"),
        )?;
    }
    compare_required_u64(
        unsigned_at_path(value, &["objectVersion"])?,
        1,
        "transported same-secret proof material objectVersion",
    )?;
    hash_at_path(value, &["proofMaterialRoot"])?;

    Ok(())
}

fn transported_same_secret_proof_chunks(
    value: &Value,
    proof_material_index: usize,
) -> CanonicalResult<Vec<Vec<u8>>> {
    compare_required_u64(
        unsigned_at_path(value, &["chunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "transported same-secret proof material chunkSizeBytes",
    )?;
    let chunk_count = read_positive_usize_at_path(
        value,
        &["chunkCount"],
        "transported same-secret proof material chunkCount",
    )?;
    let chunk_values = array_at_path(value, &["chunks"])?;
    if chunk_values.len() != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        compare_required_u64(
            unsigned_at_path(chunk_value, &["chunkIndex"])?,
            expected_chunk_index as u64,
            &format!(
                "transportedSameSecretProofMaterial.proofMaterials.{proof_material_index}.chunks.{expected_chunk_index}.chunkIndex"
            ),
        )?;
        chunks.push(crate::transcript_core::decode_standard_base64(
            string_at_path(chunk_value, &["bytesBase64"])?,
            "transported same-secret proof material bytesBase64",
        )?);
    }

    Ok(chunks)
}

fn verify_transported_same_secret_proof_material_hashes(
    value: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(value, &["totalByteLength"])?,
        transport_hashes.total_byte_length,
        "transported same-secret proof material totalByteLength",
    )?;
    compare_required_string(
        hash_at_path(value, &["fullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "transported same-secret proof material fullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(value, &["chunkRoot"])?,
        &transport_hashes.chunk_root,
        "transported same-secret proof material chunkRoot",
    )?;
    let chunk_hash_values = array_at_path(value, &["chunkHashes"])?;
    if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported same-secret proof material chunkHashes length must match supplied chunks",
        ));
    }
    for (chunk_index, (chunk_hash_value, expected_chunk_hash)) in chunk_hash_values
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(chunk_hash_value, &[])?,
            expected_chunk_hash,
            &format!("transported same-secret proof material chunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

fn verify_same_secret_proof_transport_reference(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkSizeBytes"])?,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "same-secret proof record proofChunkSizeBytes",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofChunkCount"])?,
        u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret proof chunk count does not fit u64",
            )
        })?,
        "same-secret proof record proofChunkCount",
    )?;
    compare_required_u64(
        unsigned_at_path(proof_record, &["proofTotalByteLength"])?,
        transport_hashes.total_byte_length,
        "same-secret proof record proofTotalByteLength",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofFullObjectHash"])?,
        &transport_hashes.full_object_hash,
        "same-secret proof record proofFullObjectHash",
    )?;
    compare_required_string(
        hash_at_path(proof_record, &["proofChunkRoot"])?,
        &transport_hashes.chunk_root,
        "same-secret proof record proofChunkRoot",
    )?;
    let proof_chunk_hashes = array_at_path(proof_record, &["proofChunkHashes"])?;
    if proof_chunk_hashes.len() != transport_hashes.chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof record proofChunkHashes length must match transported chunks",
        ));
    }
    for (chunk_index, (proof_chunk_hash, expected_chunk_hash)) in proof_chunk_hashes
        .iter()
        .zip(transport_hashes.chunk_hashes.iter())
        .enumerate()
    {
        compare_required_string(
            hash_at_path(proof_chunk_hash, &[])?,
            expected_chunk_hash,
            &format!("same-secret proof record proofChunkHashes.{chunk_index}"),
        )?;
    }

    Ok(())
}

fn same_secret_anchor_proof_material_root(
    proof_record: &Value,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "SameSecretLinkageAnchorProofMaterialReference",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "trusteeIdentity": string_at_path(proof_record, &["trusteeIdentity"])?,
        "trusteeRosterPosition": unsigned_at_path(proof_record, &["trusteeRosterPosition"])?,
        "statementHash": hash_at_path(proof_record, &["statementHash"])?,
        "proofSizeBytes": unsigned_at_path(proof_record, &["proofSizeBytes"])?,
        "proofBytesHash": hash_at_path(proof_record, &["proofBytesHash"])?,
        "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "chunkCount": transport_hashes.chunk_hashes.len(),
        "totalByteLength": transport_hashes.total_byte_length,
        "fullObjectHash": transport_hashes.full_object_hash,
        "chunkRoot": transport_hashes.chunk_root,
        "chunkHashes": transport_hashes.chunk_hashes,
    }))
}

fn same_secret_proof_has_transport_reference(proof_record: &Value) -> bool {
    [
        "proofMaterialRoot",
        "proofChunkSizeBytes",
        "proofChunkCount",
        "proofTotalByteLength",
        "proofFullObjectHash",
        "proofChunkRoot",
        "proofChunkHashes",
    ]
    .iter()
    .any(|field_name| proof_record.get(*field_name).is_some())
}

fn verify_statement_record(input: StatementRecordVerificationInput<'_>) -> CanonicalResult<Value> {
    compare_required_string(
        string_at_path(input.statement_record, &["objectType"])?,
        "VssSameSecretBridgeStatement",
        "compact VSS same-secret bridge statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["objectVersion"])?,
        1,
        "compact VSS same-secret bridge statement objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["proofFamily"])?,
        SAME_SECRET_PROOF_FAMILY,
        "compact VSS same-secret bridge statement proofFamily",
    )?;
    compare_setup_context(input.statement_record, input.statement_set)?;
    compare_required_string(
        hash_at_path(input.statement_record, &["targetBasisHash"])?,
        input.statement_set.target_basis_hash,
        "compact VSS same-secret bridge statement targetBasisHash",
    )?;
    compare_required_string(
        hash_at_path(input.statement_record, &["publicMatrixSeedHash"])?,
        input.statement_set.public_matrix_seed_hash,
        "compact VSS same-secret bridge statement publicMatrixSeedHash",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["ringDegree"])?,
        input.ring_degree as u64,
        "compact VSS same-secret bridge statement ringDegree",
    )?;

    let trustee_identity = read_non_empty_string(input.statement_record, "trusteeIdentity")?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "compact VSS same-secret bridge statement trusteeRosterPosition",
    )?;
    let same_secret_statement_root =
        hash_at_path(input.statement_record, &["sameSecretStatementRoot"])?;
    let same_secret_proof_root = hash_at_path(input.statement_record, &["sameSecretProofRoot"])?;
    let trustee_secret_commitment_root =
        hash_at_path(input.statement_record, &["trusteeSecretCommitmentRoot"])?;
    let same_secret_proof_family_binding_root = hash_at_path(
        input.statement_record,
        &["sameSecretProofFamilyBindingRoot"],
    )?;
    compare_required_string(
        same_secret_proof_family_binding_root,
        input.statement_set.same_secret_proof_family_binding_root,
        "compact VSS same-secret bridge statement sameSecretProofFamilyBindingRoot",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["dataBasisRelation"])?,
        SAME_SECRET_RELATION,
        "compact VSS same-secret bridge statement dataBasisRelation",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["integerSupport"])?,
        VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "compact VSS same-secret bridge statement integerSupport",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["signedRepresentativeConvention"])?,
        VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compact VSS same-secret bridge statement signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["vssPublicCommitmentEncoding"])?,
        VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "compact VSS same-secret bridge statement vssPublicCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["targetBasisLimbOrder"])?,
        VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "compact VSS same-secret bridge statement targetBasisLimbOrder",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["relation"])?,
        VSS_SAME_SECRET_BRIDGE_RELATION,
        "compact VSS same-secret bridge statement relation",
    )?;

    let target_constant_roots = array_at_path(
        input.statement_record,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    let target_constant_commitments = array_at_path(
        input.statement_record,
        &["targetConstantCoefficientCommitments"],
    )?;
    if target_constant_roots.len() != input.target_rns_limb_count
        || target_constant_commitments.len() != input.target_rns_limb_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS same-secret bridge statement must bind one target constant root and commitment per target RNS limb",
        ));
    }
    let mut verified_target_constant_commitments = Vec::with_capacity(input.target_rns_limb_count);
    let verified_target_constant_roots = target_constant_roots
        .iter()
        .enumerate()
        .map(|(expected_rns_limb_index, root_record)| {
            let commitment_record = target_constant_commitments
                .get(expected_rns_limb_index)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "compact VSS same-secret bridge target constant commitment is missing",
                    )
                })?;
            let rns_limb_index = unsigned_at_path(root_record, &["rnsLimbIndex"])?;
            compare_required_u64(
                rns_limb_index,
                expected_rns_limb_index as u64,
                "compact VSS same-secret bridge target constant rnsLimbIndex",
            )?;
            let rns_prime = read_positive_u64_at_path(
                root_record,
                &["rnsPrime"],
                "compact VSS same-secret bridge target constant rnsPrime",
            )?;
            compare_required_u64(
                rns_prime,
                DATA_PRIMES[expected_rns_limb_index],
                "compact VSS same-secret bridge target constant rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(root_record, &["shamirCoefficientIndex"])?,
                0,
                "compact VSS same-secret bridge target constant shamirCoefficientIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["rnsLimbIndex"])?,
                expected_rns_limb_index as u64,
                "compact VSS same-secret bridge target constant commitment rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["rnsPrime"])?,
                rns_prime,
                "compact VSS same-secret bridge target constant commitment rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_record, &["shamirCoefficientIndex"])?,
                0,
                "compact VSS same-secret bridge target constant commitment shamirCoefficientIndex",
            )?;
            let coefficient_commitment_root =
                hash_at_path(root_record, &["coefficientCommitmentRoot"])?;
            let commitment_body = value_at_path(commitment_record, &["commitment"])?;
            compare_required_string(
                string_at_path(commitment_body, &["objectType"])?,
                "VssPublicCommitment",
                "compact VSS same-secret bridge target constant commitment objectType",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["objectVersion"])?,
                1,
                "compact VSS same-secret bridge target constant commitment objectVersion",
            )?;
            compare_required_string(
                string_at_path(commitment_body, &["commitmentRole"])?,
                "coefficient",
                "compact VSS same-secret bridge target constant commitment role",
            )?;
            compare_required_string(
                hash_at_path(commitment_body, &["publicMatrixSeedHash"])?,
                input.statement_set.public_matrix_seed_hash,
                "compact VSS same-secret bridge target constant commitment publicMatrixSeedHash",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsLimbIndex"])?,
                expected_rns_limb_index as u64,
                "compact VSS same-secret bridge target constant commitment body rnsLimbIndex",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["rnsPrime"])?,
                rns_prime,
                "compact VSS same-secret bridge target constant commitment body rnsPrime",
            )?;
            compare_required_u64(
                unsigned_at_path(commitment_body, &["ringDegree"])?,
                input.ring_degree as u64,
                "compact VSS same-secret bridge target constant commitment ringDegree",
            )?;
            compare_required_string(
                &derive_canonical_object_hash(commitment_body)?,
                coefficient_commitment_root,
                "compact VSS same-secret bridge target constant commitment body root",
            )?;
            verified_target_constant_commitments.push(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": 0,
                "commitment": commitment_body,
            }));

            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": 0,
                "coefficientCommitmentRoot": coefficient_commitment_root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_statement_root = derive_canonical_object_hash(&json!({
        "objectType": "VssSameSecretBridgeStatement",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "targetBasisHash": input.statement_set.target_basis_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sameSecretStatementRoot": same_secret_statement_root,
        "sameSecretProofRoot": same_secret_proof_root,
        "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
        "targetConstantCoefficientCommitments": verified_target_constant_commitments,
        "relation": VSS_SAME_SECRET_BRIDGE_RELATION,
    }))?;
    let statement_root = hash_at_path(input.statement_record, &["sameSecretBridgeStatementRoot"])?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!(
                "compact VSS same-secret bridge statement root does not match its bound roots: expected {expected_statement_root}, got {statement_root}",
            ),
        ));
    }

    Ok(json!({
        "objectType": "VssSameSecretBridgeStatement",
        "objectVersion": 1,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupParametersHash": input.statement_set.setup_parameters_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "targetBasisHash": input.statement_set.target_basis_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "ringDegree": input.ring_degree,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sameSecretStatementRoot": same_secret_statement_root,
        "sameSecretProofRoot": same_secret_proof_root,
        "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "vssPublicCommitmentEncoding": VSS_PUBLIC_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
        "targetConstantCoefficientCommitments": verified_target_constant_commitments,
        "relation": VSS_SAME_SECRET_BRIDGE_RELATION,
        "sameSecretBridgeStatementRoot": statement_root,
    }))
}

fn compare_setup_context(
    statement_record: &Value,
    statement_set: StatementSetBinding<'_>,
) -> CanonicalResult<()> {
    for field_name in SETUP_CONTEXT_FIELD_NAMES {
        let expected = match field_name {
            "ceremonyId" => statement_set.ceremony_id,
            "manifestHash" => statement_set.manifest_hash,
            "rosterHash" => statement_set.roster_hash,
            "setupParametersHash" => statement_set.setup_parameters_hash,
            "setupEpoch" => statement_set.setup_epoch,
            _ => unreachable!("unknown compact same-secret setup context field"),
        };
        let actual = if field_name == "ceremonyId" || field_name == "setupEpoch" {
            string_at_path(statement_record, &[field_name])?
        } else {
            hash_at_path(statement_record, &[field_name])?
        };
        compare_required_string(
            actual,
            expected,
            "compact VSS same-secret bridge statement setup context",
        )?;
    }

    Ok(())
}

fn compare_evidence_context(
    evidence_set: &Value,
    statement_set: StatementSetBinding<'_>,
    description: &str,
) -> CanonicalResult<()> {
    for field_name in SETUP_CONTEXT_FIELD_NAMES {
        let expected = match field_name {
            "ceremonyId" => statement_set.ceremony_id,
            "manifestHash" => statement_set.manifest_hash,
            "rosterHash" => statement_set.roster_hash,
            "setupParametersHash" => statement_set.setup_parameters_hash,
            "setupEpoch" => statement_set.setup_epoch,
            _ => unreachable!("unknown compact same-secret setup context field"),
        };
        let actual = if field_name == "ceremonyId" || field_name == "setupEpoch" {
            string_at_path(evidence_set, &[field_name])?
        } else {
            hash_at_path(evidence_set, &[field_name])?
        };
        compare_required_string(actual, expected, &format!("{description} setup context"))?;
    }

    Ok(())
}

fn value_without_root_field(
    value: &Value,
    root_field_name: &str,
    description: &str,
) -> CanonicalResult<Value> {
    let object = value.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be a JSON object"),
        )
    })?;
    if !object.contains_key(root_field_name) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must include {root_field_name}"),
        ));
    }
    let mut object_without_root = object.clone();
    object_without_root.remove(root_field_name);

    Ok(Value::Object(object_without_root))
}

fn read_positive_usize_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<usize> {
    let field = usize_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

fn read_positive_u64_at_path(
    value: &Value,
    path: &[&str],
    description: &str,
) -> CanonicalResult<u64> {
    let field = unsigned_at_path(value, path)?;
    if field == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{description} must be positive"),
        ));
    }

    Ok(field)
}

fn compare_required_u64(actual: u64, expected: u64, description: &str) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("passive BGV setup package {description} does not match its canonical binding"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        same_secret_anchor_proof_material_root, setup_proof_material_transport_hashes,
        value_without_root_field, verify_vss_same_secret_bridge_proof_material_set_request,
        verify_vss_same_secret_bridge_statement_set_request,
    };
    use crate::{
        bgv::parameters::DATA_PRIMES, encoding::CanonicalResult,
        hashing::derive_canonical_object_hash,
    };

    #[test]
    fn same_secret_bridge_statement_set_verifies_bound_roots() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set,
            "sameSecretConsistency": same_secret_consistency,
            "sameSecretProofs": same_secret_proofs,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyVssSameSecretBridgeStatementSet"
        );
        assert_eq!(
            verification["sameSecretBridgeStatementSetRoot"],
            statement_set["sameSecretBridgeStatementSetRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["targetRnsLimbCount"], json!(2_u64));
        assert_eq!(
            verification["vssPublicCommitmentEncoding"],
            "sealed-lattice-vss-public-commitment-binary-v1"
        );

        let (mut wrong_target_basis_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        wrong_target_basis_statement_set["targetBasisHash"] = json!("7".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": wrong_target_basis_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "compact same-secret bridge statement sets must bind the canonical target basis hash"
        );

        let (mut tampered_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        tampered_statement_set["statementRecords"][1]["targetConstantCoefficientCommitmentRoots"]
            [0]["coefficientCommitmentRoot"] = json!("c".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": tampered_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "tampered compact same-secret bridge target constant root must reject"
        );

        let (mut unsupported_convention_statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        unsupported_convention_statement_set["signedRepresentativeConvention"] =
            json!("unsupported compact bridge signed representative convention");
        unsupported_convention_statement_set["sameSecretBridgeStatementSetRoot"] = json!(
            derive_canonical_object_hash(&unsupported_convention_statement_set,)?
        );
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": unsupported_convention_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "unsupported signed-representative convention must reject"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_evidence_sets_bind_same_secret_roots() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        let mut forged_statement_set = statement_set;
        forged_statement_set["statementRecords"][0]["sameSecretProofRoot"] = json!("0".repeat(128));
        rebind_bridge_statement_root(&mut forged_statement_set["statementRecords"][0])?;
        rebind_bridge_statement_set_root(&mut forged_statement_set)?;
        let missing_evidence_error = verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": forged_statement_set.clone(),
        }))
        .expect_err("compact same-secret bridge statement verification must require evidence");
        assert!(
            missing_evidence_error
                .to_string()
                .contains("requires both sameSecretConsistency and sameSecretProofs"),
            "missing same-secret bridge evidence should report the required evidence sets: {missing_evidence_error}"
        );
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": forged_statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
            }))
            .is_err(),
            "evidence-backed verification must reject a bridge proof root that is absent from the proof set"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_checks_transported_same_secret_proof_material() -> CanonicalResult<()> {
        let (mut statement_set, same_secret_consistency, mut same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let transported_same_secret_proof_material =
            move_same_secret_proof_bytes_to_transport(&mut same_secret_proofs)?;
        rebind_bridge_statement_set_to_same_secret_proofs(&mut statement_set, &same_secret_proofs)?;

        let verification = verify_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
            "transportedSameSecretProofMaterial": transported_same_secret_proof_material.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
            }))
            .is_err(),
            "transported same-secret proof records must require transported proof material"
        );

        let mut tampered_material = transported_same_secret_proof_material;
        tampered_material["proofMaterials"][0]["chunks"][0]["bytesBase64"] = json!("/w==");
        assert!(
            verify_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeStatementSet",
                "statementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
                "transportedSameSecretProofMaterial": tampered_material,
            }))
            .is_err(),
            "transported same-secret proof material must bind supplied chunks"
        );

        Ok(())
    }

    #[test]
    fn same_secret_bridge_proof_material_set_rejects_unbound_material() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            same_secret_bridge_statement_set_with_evidence()?;
        let proof_material_set =
            same_secret_bridge_proof_material_set(&statement_set, ["aa", "bb"])?;

        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
                "proofMaterialSet": proof_material_set.clone(),
            }))
            .is_err(),
            "proof material must reject proof bytes that do not verify against reconstructed statements"
        );

        let mut tampered_proof_material_set = proof_material_set.clone();
        tampered_proof_material_set["proofRecords"][0]["proofBytesHash"] = json!("0".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
                "proofMaterialSet": tampered_proof_material_set,
            }))
            .is_err(),
            "proof material must reject a proofBytesHash that no longer matches proofBytesBase64"
        );

        let mut wrong_statement_root_material_set = proof_material_set;
        wrong_statement_root_material_set["proofRecords"][1]["sameSecretBridgeStatementRoot"] =
            json!("0".repeat(128));
        assert!(
            verify_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set,
                "sameSecretConsistency": same_secret_consistency,
                "sameSecretProofs": same_secret_proofs,
                "proofMaterialSet": wrong_statement_root_material_set,
            }))
            .is_err(),
            "proof material must bind each proof record to its bridge statement root"
        );

        Ok(())
    }

    fn same_secret_bridge_proof_material_set(
        statement_set: &Value,
        proof_bytes_hex_values: [&str; 2],
    ) -> CanonicalResult<Value> {
        let statement_records = statement_set["statementRecords"]
            .as_array()
            .expect("compact bridge statement records");
        let proof_records = statement_records
            .iter()
            .zip(proof_bytes_hex_values)
            .map(
                |(statement_record, proof_bytes_hex)| {
                    let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
                    let proof_record_without_root = json!({
                        "objectType": "VssSameSecretBridgeProofRecord",
                        "objectVersion": 1,
                        "proofFamily": super::SAME_SECRET_BRIDGE_PROOF_FAMILY,
                        "sameSecretBridgeStatementRoot": statement_record["sameSecretBridgeStatementRoot"],
                        "proofBytesHash": crate::hashing::hash512_hex(
                            super::SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
                            &[&proof_bytes],
                        ),
                        "proofBytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
                    });
                    let mut proof_record = proof_record_without_root;
                    proof_record["proofRecordRoot"] = json!(derive_canonical_object_hash(&proof_record,
                    )?);
                    Ok(proof_record)
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        let proof_material_set_without_root = json!({
            "objectType": "VssSameSecretBridgeProofMaterialSet",
            "objectVersion": 1,
            "proofFamily": super::SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "ceremonyId": statement_set["ceremonyId"],
            "manifestHash": statement_set["manifestHash"],
            "rosterHash": statement_set["rosterHash"],
            "setupParametersHash": statement_set["setupParametersHash"],
            "setupEpoch": statement_set["setupEpoch"],
            "targetBasisHash": statement_set["targetBasisHash"],
            "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
            "ringDegree": statement_set["ringDegree"],
            "participantCount": statement_set["participantCount"],
            "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
            "thresholdDegree": statement_set["thresholdDegree"],
            "coefficientCommitmentRoot": statement_set["coefficientCommitmentRoot"],
            "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
            "sameSecretBridgeStatementSetRoot": statement_set["sameSecretBridgeStatementSetRoot"],
            "proofRecords": proof_records,
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] =
            json!(derive_canonical_object_hash(&proof_material_set,)?);

        Ok(proof_material_set)
    }

    fn same_secret_bridge_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let target_basis_hash = crate::bgv::evaluator::top_k::canonical_target_basis_hash()?;
        let target_constant_records = (0..2_usize)
            .map(|rns_limb_index| {
                let rns_prime = DATA_PRIMES[rns_limb_index];
                let commitment_body = same_secret_bridge_target_commitment_body(
                    trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                )?;
                let coefficient_commitment_root = derive_canonical_object_hash(&commitment_body)?;
                Ok((
                    json!({
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": rns_prime,
                        "shamirCoefficientIndex": 0,
                        "coefficientCommitmentRoot": coefficient_commitment_root,
                    }),
                    json!({
                        "rnsLimbIndex": rns_limb_index,
                        "rnsPrime": rns_prime,
                        "shamirCoefficientIndex": 0,
                        "commitment": commitment_body,
                    }),
                ))
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let target_constant_coefficient_commitment_roots = target_constant_records
            .iter()
            .map(|(root, _commitment)| root.clone())
            .collect::<Vec<_>>();
        let target_constant_coefficient_commitments = target_constant_records
            .iter()
            .map(|(_root, commitment)| commitment.clone())
            .collect::<Vec<_>>();
        let statement_without_root = json!({
            "objectType": "VssSameSecretBridgeStatement",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": "8".repeat(128),
            "ringDegree": 8,
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "sameSecretStatementRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "sameSecretProofRoot": if trustee_roster_position == 0 {
                "c".repeat(128)
            } else {
                "d".repeat(128)
            },
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "dataBasisRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "vssPublicCommitmentEncoding": "sealed-lattice-vss-public-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "targetConstantCoefficientCommitmentRoots": target_constant_coefficient_commitment_roots,
            "targetConstantCoefficientCommitments": target_constant_coefficient_commitments,
            "relation": "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof",
        });
        let mut statement = statement_without_root;
        statement["sameSecretBridgeStatementRoot"] =
            json!(derive_canonical_object_hash(&statement,)?);

        Ok(statement)
    }

    fn same_secret_bridge_target_commitment_body(
        trustee_roster_position: usize,
        rns_limb_index: usize,
        rns_prime: u64,
    ) -> CanonicalResult<Value> {
        let coordinate_count =
            crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT;
        let commitment_limbs = (0..3_usize)
            .map(|commitment_modulus_index| {
                let modulus = DATA_PRIMES[commitment_modulus_index];
                let coordinates = (0..coordinate_count)
                    .map(|coordinate_index| {
                        ((trustee_roster_position as u64 + 1) * 17
                            + (rns_limb_index as u64 + 1) * 19
                            + (commitment_modulus_index as u64 + 1) * 23
                            + coordinate_index as u64)
                            % modulus
                    })
                    .collect::<Vec<_>>();
                json!({
                    "commitmentModulusIndex": commitment_modulus_index,
                    "modulus": modulus,
                    "coordinates": coordinates,
                })
            })
            .collect::<Vec<_>>();

        Ok(json!({
            "objectType": "VssPublicCommitment",
            "objectVersion": 1,
            "commitmentRole": "coefficient",
            "commitmentContextHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "rnsLimbIndex": rns_limb_index,
            "rnsPrime": rns_prime,
            "ringDegree": 8,
            "outputCoordinateCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_OUTPUT_COORDINATE_COUNT,
            "randomnessColumnCount": crate::bgv::setup::vss_commitment::VSS_PUBLIC_RANDOMNESS_COLUMN_COUNT,
            "commitmentLimbs": commitment_limbs,
        }))
    }

    fn same_secret_bridge_statement_set_with_evidence() -> CanonicalResult<(Value, Value, Value)> {
        let target_basis_hash = crate::bgv::evaluator::top_k::canonical_target_basis_hash()?;
        let same_secret_consistency = same_secret_consistency_statement_set()?;
        let same_secret_proofs = same_secret_proof_set(&same_secret_consistency)?;
        let mut statement_records = Vec::new();
        for trustee_roster_position in 0..2_usize {
            statement_records.push(same_secret_bridge_statement_record_from_evidence(
                trustee_roster_position,
                &same_secret_consistency["statementRecords"][trustee_roster_position],
                &same_secret_proofs["proofRecords"][trustee_roster_position],
            )?);
        }
        let statement_set_without_root = json!({
            "objectType": "VssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": "8".repeat(128),
            "ringDegree": 8,
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 4,
            "coefficientCommitmentRoot": "9".repeat(128),
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": same_secret_proofs["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "vssPublicCommitmentEncoding": "sealed-lattice-vss-public-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["sameSecretBridgeStatementSetRoot"] =
            json!(derive_canonical_object_hash(&statement_set,)?);

        Ok((statement_set, same_secret_consistency, same_secret_proofs))
    }

    fn same_secret_consistency_statement_set() -> CanonicalResult<Value> {
        let statement_records = (0..2_usize)
            .map(same_secret_consistency_statement_record)
            .collect::<CanonicalResult<Vec<_>>>()?;
        let trustee_secret_commitment_roots = statement_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, statement_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "trusteeSecretCommitmentRoot": statement_record["trusteeSecretCommitmentRoot"],
                })
            })
            .collect::<Vec<_>>();
        let statement_set_without_root = json!({
            "objectType": "SameSecretConsistencyStatementSet",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "thresholdDegree": 4,
            "vssCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "trusteeSecretCommitmentRoots": trustee_secret_commitment_roots,
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["sameSecretConsistencyRoot"] =
            json!(derive_canonical_object_hash(&statement_set,)?);

        Ok(statement_set)
    }

    fn same_secret_consistency_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let statement_without_root = json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": if trustee_roster_position == 0 {
                "a".repeat(128)
            } else {
                "b".repeat(128)
            },
            "constantCoefficientCommitmentRoots": [],
            "trusteeSecretCommitmentRoot": if trustee_roster_position == 0 {
                "e".repeat(128)
            } else {
                "f".repeat(128)
            },
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share"
            ],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        let mut statement = statement_without_root;
        statement["sameSecretStatementRoot"] = json!(derive_canonical_object_hash(&statement,)?);

        Ok(statement)
    }

    fn same_secret_proof_set(same_secret_consistency: &Value) -> CanonicalResult<Value> {
        let proof_records = (0..2_usize)
            .map(|trustee_roster_position| {
                same_secret_proof_record(
                    trustee_roster_position,
                    &same_secret_consistency["statementRecords"][trustee_roster_position],
                )
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let same_secret_proof_roots = proof_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, proof_record)| {
                json!({
                    "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
                    "trusteeRosterPosition": trustee_roster_position,
                    "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                })
            })
            .collect::<Vec<_>>();
        let proof_set_without_root = json!({
            "objectType": "SameSecretProofSet",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofAccountingHash": "d".repeat(128),
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "participantCount": 2,
            "rnsLimbCount": 2,
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "vssCoefficientCommitmentMaterialRoot": "e".repeat(128),
            "sameSecretProofRoots": same_secret_proof_roots,
            "proofRecords": proof_records,
        });
        let mut proof_set = proof_set_without_root;
        proof_set["sameSecretProofSetRoot"] = json!(derive_canonical_object_hash(&proof_set,)?);

        Ok(proof_set)
    }

    fn same_secret_proof_record(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
    ) -> CanonicalResult<Value> {
        let proof_record_without_root = json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupParametersHash": "3".repeat(128),
            "setupEpoch": "setup-epoch",
            "trusteeIdentity": format!("trustee-{trustee_roster_position}"),
            "trusteeRosterPosition": trustee_roster_position,
            "ringDegree": 8,
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "sameSecretProofFamilyBindingRoot": same_secret_statement["sameSecretProofFamilyBindingRoot"],
            "statementHash": if trustee_roster_position == 0 {
                "1".repeat(128)
            } else {
                "2".repeat(128)
            },
            "proofSizeBytes": 1,
            "proofBytesHash": crate::hashing::hash512_hex(
                super::SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN,
                &[&[0_u8]],
            ),
            "proofBytesHex": "00",
        });
        let mut proof_record = proof_record_without_root;
        proof_record["sameSecretProofRoot"] = json!(derive_canonical_object_hash(&proof_record,)?);

        Ok(proof_record)
    }

    fn same_secret_bridge_statement_record_from_evidence(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
        same_secret_proof: &Value,
    ) -> CanonicalResult<Value> {
        let mut statement = same_secret_bridge_statement_record(trustee_roster_position)?;
        statement["sameSecretStatementRoot"] =
            same_secret_statement["sameSecretStatementRoot"].clone();
        statement["sameSecretProofRoot"] = same_secret_proof["sameSecretProofRoot"].clone();
        statement["trusteeSecretCommitmentRoot"] =
            same_secret_statement["trusteeSecretCommitmentRoot"].clone();
        statement["sameSecretProofFamilyBindingRoot"] =
            same_secret_statement["sameSecretProofFamilyBindingRoot"].clone();
        rebind_bridge_statement_root(&mut statement)?;

        Ok(statement)
    }

    fn rebind_bridge_statement_root(statement: &mut Value) -> CanonicalResult<()> {
        statement["sameSecretBridgeStatementRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                statement,
                "sameSecretBridgeStatementRoot",
                "compact same-secret bridge statement",
            )?,)?);

        Ok(())
    }

    fn rebind_bridge_statement_set_root(statement_set: &mut Value) -> CanonicalResult<()> {
        statement_set["sameSecretBridgeStatementSetRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                statement_set,
                "sameSecretBridgeStatementSetRoot",
                "compact same-secret bridge statement set",
            )?,)?);

        Ok(())
    }

    fn move_same_secret_proof_bytes_to_transport(
        same_secret_proofs: &mut Value,
    ) -> CanonicalResult<Value> {
        let proof_records = same_secret_proofs["proofRecords"]
            .as_array_mut()
            .expect("same-secret proof records");
        let mut transported_proof_materials = Vec::new();
        for proof_record in proof_records.iter_mut() {
            let proof_bytes = crate::transcript_core::decode_hex(
                proof_record["proofBytesHex"]
                    .as_str()
                    .expect("embedded same-secret proof bytes"),
            )?;
            let chunks = vec![proof_bytes.clone()];
            let transport_hashes = setup_proof_material_transport_hashes(
                "same-secret-linkage-anchor",
                &chunks,
                SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
            )?;
            proof_record
                .as_object_mut()
                .expect("same-secret proof record object")
                .remove("proofBytesHex");
            proof_record["proofBytesEncoding"] = json!(SETUP_PROOF_MATERIAL_ENCODING);
            proof_record["proofChunkSizeBytes"] = json!(SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES);
            proof_record["proofChunkCount"] = json!(transport_hashes.chunk_hashes.len());
            proof_record["proofTotalByteLength"] = json!(transport_hashes.total_byte_length);
            proof_record["proofFullObjectHash"] = json!(transport_hashes.full_object_hash.clone());
            proof_record["proofChunkRoot"] = json!(transport_hashes.chunk_root.clone());
            proof_record["proofChunkHashes"] = json!(transport_hashes.chunk_hashes.clone());
            proof_record["proofMaterialRoot"] = json!(same_secret_anchor_proof_material_root(
                proof_record,
                &transport_hashes
            )?);
            proof_record["sameSecretProofRoot"] =
                json!(derive_canonical_object_hash(&value_without_root_field(
                    proof_record,
                    "sameSecretProofRoot",
                    "same-secret proof",
                )?,)?);

            transported_proof_materials.push(json!({
                "objectType": "SetupTransportedSameSecretProofMaterial",
                "objectVersion": 1,
                "proofFamily": "same-secret-linkage-anchor",
                "proofMaterialRoot": proof_record["proofMaterialRoot"],
                "chunkSizeBytes": SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
                "chunkCount": transport_hashes.chunk_hashes.len(),
                "totalByteLength": transport_hashes.total_byte_length,
                "fullObjectHash": transport_hashes.full_object_hash,
                "chunkHashes": transport_hashes.chunk_hashes,
                "chunkRoot": transport_hashes.chunk_root,
                "chunks": [{
                    "chunkIndex": 0,
                    "bytesBase64": crate::transcript_core::encode_standard_base64(&proof_bytes),
                }],
            }));
        }

        let same_secret_proof_roots = proof_records
            .iter()
            .enumerate()
            .map(|(trustee_roster_position, proof_record)| {
                json!({
                    "trusteeIdentity": proof_record["trusteeIdentity"],
                    "trusteeRosterPosition": trustee_roster_position,
                    "sameSecretProofRoot": proof_record["sameSecretProofRoot"],
                })
            })
            .collect::<Vec<_>>();
        same_secret_proofs["sameSecretProofRoots"] = json!(same_secret_proof_roots);
        same_secret_proofs["sameSecretProofSetRoot"] =
            json!(derive_canonical_object_hash(&value_without_root_field(
                same_secret_proofs,
                "sameSecretProofSetRoot",
                "same-secret proof set",
            )?,)?);

        Ok(json!({
            "objectType": "SetupTransportedSameSecretProofMaterialSet",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "proofMaterials": transported_proof_materials,
        }))
    }

    fn rebind_bridge_statement_set_to_same_secret_proofs(
        statement_set: &mut Value,
        same_secret_proofs: &Value,
    ) -> CanonicalResult<()> {
        let statement_records = statement_set["statementRecords"]
            .as_array_mut()
            .expect("compact same-secret bridge statement records");
        let proof_records = same_secret_proofs["proofRecords"]
            .as_array()
            .expect("same-secret proof records");
        for (statement_index, statement_record) in statement_records.iter_mut().enumerate() {
            statement_record["sameSecretProofRoot"] =
                proof_records[statement_index]["sameSecretProofRoot"].clone();
            rebind_bridge_statement_root(statement_record)?;
        }
        statement_set["sameSecretProofSetRoot"] =
            same_secret_proofs["sameSecretProofSetRoot"].clone();
        rebind_bridge_statement_set_root(statement_set)
    }
}
