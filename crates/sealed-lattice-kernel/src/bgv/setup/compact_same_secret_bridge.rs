use super::compact_vss_commitment::{
    COMPACT_VSS_COMMITMENT_BINARY_FORMAT, COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
    COMPACT_VSS_COMMITMENT_PROFILE_ID,
};
use super::setup_proof::{
    SETUP_PROOF_MATERIAL_ENCODING, SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
    SetupProofMaterialTransportHashes, setup_proof_material_transport_hashes,
    verified_setup_proof_material_chunks_from_request,
};
use super::*;
use std::collections::BTreeSet;

const SETUP_PROOF_PROFILE_ID: &str = "SealedLattice-SetupProof-v1";
const SAME_SECRET_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
const SAME_SECRET_ANCHOR_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1";
const SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE: &str =
    "SetupTransportedSameSecretProofMaterialSet";
const SAME_SECRET_PROOF_TRANSPORT_OBJECT_TYPE: &str = "SetupTransportedSameSecretProofMaterial";
const SAME_SECRET_RELATION: &str =
    "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs";
const COMPACT_VSS_SAME_SECRET_BRIDGE_RELATION: &str = "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof";
const COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY: &str = "restricted native compact same-secret bridge proof over target-basis compact constant commitments; not target-ready package proof evidence";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "compact-same-secret-bridge";
const COMPACT_SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/compact-same-secret-bridge/proof-bytes-v1";
const COMPACT_SAME_SECRET_BRIDGE_RESTRICTED_PROOF_VERIFIED_SCOPE: &str = "restricted compact same-secret bridge proof bytes were verified against supplied low-level native proof statements";
const COMPACT_SAME_SECRET_BRIDGE_RESTRICTED_PROOF_UNSUPPLIED_SCOPE: &str = "no restricted compact same-secret bridge proof statements were supplied; material-set verification checked binding roots and proof-byte hashes only";
const COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT: &str = "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb";
const COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION: &str = "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime";
const COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER: &str = "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime";
const SETUP_CONTEXT_FIELD_NAMES: [&str; 8] = [
    "ceremonyId",
    "manifestHash",
    "rosterHash",
    "setupProfileHash",
    "qShareHash",
    "carryAwareVssShareRelationProfileHash",
    "commitmentProfileHash",
    "setupEpoch",
];

pub(crate) fn verify_compact_vss_same_secret_bridge_statement_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    compare_required_string(
        string_at_path(statement_set, &["objectType"])?,
        "CompactVssSameSecretBridgeStatementSet",
        "compact VSS same-secret bridge statement set objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(statement_set, &["objectVersion"])?,
        1,
        "compact VSS same-secret bridge statement set objectVersion",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS same-secret bridge statement set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["compactCommitmentProfileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS same-secret bridge statement set compactCommitmentProfileId",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["developmentScope"])?,
        COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
        "compact VSS same-secret bridge statement set developmentScope",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["setupProofProfileId"])?,
        SETUP_PROOF_PROFILE_ID,
        "compact VSS same-secret bridge statement set setupProofProfileId",
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
    let setup_profile_hash = hash_at_path(statement_set, &["setupProfileHash"])?;
    let q_share_hash = hash_at_path(statement_set, &["qShareHash"])?;
    let carry_aware_vss_share_relation_profile_hash =
        hash_at_path(statement_set, &["carryAwareVssShareRelationProfileHash"])?;
    let commitment_profile_hash = hash_at_path(statement_set, &["commitmentProfileHash"])?;
    let target_basis_hash = hash_at_path(statement_set, &["targetBasisHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let compact_coefficient_commitment_root =
        hash_at_path(statement_set, &["compactCoefficientCommitmentRoot"])?;
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
        COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "compact VSS same-secret bridge statement set integerSupport",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["signedRepresentativeConvention"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compact VSS same-secret bridge statement set signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["compactCommitmentEncoding"])?,
        COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "compact VSS same-secret bridge statement set compactCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(statement_set, &["targetBasisLimbOrder"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
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
                statement_set: StatementSetBinding {
                    ceremony_id,
                    manifest_hash,
                    roster_hash,
                    setup_profile_hash,
                    q_share_hash,
                    carry_aware_vss_share_relation_profile_hash,
                    commitment_profile_hash,
                    setup_epoch,
                    target_basis_hash,
                    public_matrix_seed_hash,
                    same_secret_proof_family_binding_root,
                },
            },
        )?);
    }

    let expected_statement_set_root = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &json!({
            "objectType": "CompactVssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "developmentScope": COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": SAME_SECRET_PROOF_FAMILY,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "targetBasisHash": target_basis_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "participantCount": participant_count,
            "targetRnsLimbCount": target_rns_limb_count,
            "thresholdDegree": threshold_degree,
            "compactCoefficientCommitmentRoot": compact_coefficient_commitment_root,
            "sameSecretConsistencyRoot": same_secret_consistency_root,
            "sameSecretProofSetRoot": same_secret_proof_set_root,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "integerSupport": COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
            "signedRepresentativeConvention": COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
            "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
            "targetBasisLimbOrder": COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
            "statementRecords": verified_statement_records,
        }),
    )?;
    let statement_set_root =
        hash_at_path(statement_set, &["compactSameSecretBridgeStatementSetRoot"])?;
    if expected_statement_set_root != statement_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS same-secret bridge statement set root does not match its bound statements",
        ));
    }
    verify_optional_same_secret_evidence_sets(EvidenceSetVerificationInput {
        request,
        statement_set: StatementSetBinding {
            ceremony_id,
            manifest_hash,
            roster_hash,
            setup_profile_hash,
            q_share_hash,
            carry_aware_vss_share_relation_profile_hash,
            commitment_profile_hash,
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
        "operation": "verifyCompactVssSameSecretBridgeStatementSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compactSameSecretBridgeStatementSetRoot": statement_set_root,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "compactCoefficientCommitmentRoot": compact_coefficient_commitment_root,
        "sameSecretConsistencyRoot": same_secret_consistency_root,
        "sameSecretProofSetRoot": same_secret_proof_set_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "integerSupport": COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
    }))
}

pub(crate) fn verify_compact_vss_same_secret_bridge_proof_material_set_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let statement_set = value_at_path(request, &["statementSet"])?;
    let statement_verification =
        verify_compact_vss_same_secret_bridge_statement_set_request(request)?;
    let statement_set_root = hash_at_path(
        &statement_verification,
        &["compactSameSecretBridgeStatementSetRoot"],
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
    let threshold_degree = read_positive_usize_at_path(
        &statement_verification,
        &["thresholdDegree"],
        "compact same-secret bridge proof material statement thresholdDegree",
    )?;
    let proof_material_set = value_at_path(request, &["proofMaterialSet"])?;
    compare_required_string(
        string_at_path(proof_material_set, &["objectType"])?,
        "CompactVssSameSecretBridgeProofMaterialSet",
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
    let setup_profile_hash = hash_at_path(statement_set, &["setupProfileHash"])?;
    let q_share_hash = hash_at_path(statement_set, &["qShareHash"])?;
    let carry_aware_vss_share_relation_profile_hash =
        hash_at_path(statement_set, &["carryAwareVssShareRelationProfileHash"])?;
    let commitment_profile_hash = hash_at_path(statement_set, &["commitmentProfileHash"])?;
    let target_basis_hash = hash_at_path(statement_set, &["targetBasisHash"])?;
    let public_matrix_seed_hash = hash_at_path(statement_set, &["publicMatrixSeedHash"])?;
    let compact_coefficient_commitment_root =
        hash_at_path(statement_set, &["compactCoefficientCommitmentRoot"])?;
    let same_secret_consistency_root = hash_at_path(statement_set, &["sameSecretConsistencyRoot"])?;
    let same_secret_proof_set_root = hash_at_path(statement_set, &["sameSecretProofSetRoot"])?;
    let same_secret_proof_family_binding_root =
        hash_at_path(statement_set, &["sameSecretProofFamilyBindingRoot"])?;

    for (field_name, expected_value) in [
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        (
            "compactCommitmentProfileId",
            COMPACT_VSS_COMMITMENT_PROFILE_ID,
        ),
        ("developmentScope", COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
        ("proofFamily", COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY),
        (
            "proofBoundary",
            COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        ),
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
        ("setupProfileHash", setup_profile_hash),
        ("qShareHash", q_share_hash),
        (
            "carryAwareVssShareRelationProfileHash",
            carry_aware_vss_share_relation_profile_hash,
        ),
        ("commitmentProfileHash", commitment_profile_hash),
        ("targetBasisHash", target_basis_hash),
        ("publicMatrixSeedHash", public_matrix_seed_hash),
        (
            "compactCoefficientCommitmentRoot",
            compact_coefficient_commitment_root,
        ),
        ("sameSecretConsistencyRoot", same_secret_consistency_root),
        ("sameSecretProofSetRoot", same_secret_proof_set_root),
        (
            "sameSecretProofFamilyBindingRoot",
            same_secret_proof_family_binding_root,
        ),
        (
            "compactSameSecretBridgeStatementSetRoot",
            statement_set_root,
        ),
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
    let restricted_proof_statements = match request.get("restrictedProofStatements") {
        None => Vec::new(),
        Some(Value::Array(values)) => values.iter().collect::<Vec<_>>(),
        Some(_) => {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "restrictedProofStatements must be an array when supplied",
            ));
        }
    };
    let mut restricted_proof_statement_hashes = BTreeSet::new();
    for restricted_statement in &restricted_proof_statements {
        let proof_statement_hash = hash_at_path(restricted_statement, &["proofStatementHash"])?;
        if !restricted_proof_statement_hashes.insert(proof_statement_hash.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "restrictedProofStatements must not repeat proofStatementHash",
            ));
        }
    }

    let mut proof_statement_hashes = BTreeSet::new();
    let mut total_proof_byte_length = 0usize;
    let mut verified_restricted_proof_count = 0usize;
    let mut used_restricted_proof_statements = vec![false; restricted_proof_statements.len()];
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
            "CompactVssSameSecretBridgeProofRecord",
            "compact same-secret bridge proof record objectType",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_record, &["objectVersion"])?,
            1,
            "compact same-secret bridge proof record objectVersion",
        )?;
        compare_required_string(
            string_at_path(proof_record, &["proofFamily"])?,
            COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "compact same-secret bridge proof record proofFamily",
        )?;
        compare_required_string(
            string_at_path(proof_record, &["proofBoundary"])?,
            COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
            "compact same-secret bridge proof record proofBoundary",
        )?;
        let bridge_statement_root =
            hash_at_path(bridge_statement, &["compactSameSecretBridgeStatementRoot"])?;
        compare_required_string(
            hash_at_path(proof_record, &["compactSameSecretBridgeStatementRoot"])?,
            bridge_statement_root,
            "compact same-secret bridge proof record statement root",
        )?;
        let proof_statement_hash = hash_at_path(proof_record, &["proofStatementHash"])?;
        if !proof_statement_hashes.insert(proof_statement_hash.to_string()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "compact same-secret bridge proof records must not repeat proofStatementHash",
            ));
        }
        let proof_byte_length = read_positive_usize_at_path(
            proof_record,
            &["proofByteLength"],
            "compact same-secret bridge proof record proofByteLength",
        )?;
        let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
        let proof_bytes_hex = string_at_path(proof_record, &["proofBytesHex"])?;
        let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
        if proof_byte_length != proof_bytes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "compact same-secret bridge proof record proofByteLength must match proofBytesHex",
            ));
        }
        let expected_proof_bytes_hash = hash512_hex(
            COMPACT_SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        );
        compare_required_string(
            proof_bytes_hash,
            &expected_proof_bytes_hash,
            "compact same-secret bridge proof record proofBytesHash",
        )?;
        total_proof_byte_length = total_proof_byte_length
            .checked_add(proof_byte_length)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "compact same-secret bridge proof byte length overflowed",
                )
            })?;

        let proof_record_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeProofRecord",
            "objectVersion": 1,
            "proofFamily": COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
            "compactSameSecretBridgeStatementRoot": bridge_statement_root,
            "proofStatementHash": proof_statement_hash,
            "proofByteLength": proof_byte_length,
            "proofBytesHash": proof_bytes_hash,
            "proofBytesHex": proof_bytes_hex,
        });
        let proof_record_root = hash_at_path(proof_record, &["proofRecordRoot"])?;
        let expected_proof_record_root =
            derive_protocol_hash("SetupProofRecordBindingHash", &proof_record_without_root)?;
        if expected_proof_record_root != proof_record_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "compact same-secret bridge proof record root does not match its bound proof bytes",
            ));
        }

        if !restricted_proof_statements.is_empty() {
            let restricted_statement_index = matching_restricted_proof_statement_index(
                &restricted_proof_statements,
                &used_restricted_proof_statements,
                proof_statement_hash,
            )?;
            let restricted_statement = restricted_proof_statements[restricted_statement_index];
            verify_restricted_compact_same_secret_bridge_proof_statement(
                RestrictedCompactSameSecretBridgeProofStatementVerification {
                    restricted_statement,
                    bridge_statement,
                    statement_set: StatementSetBinding {
                        ceremony_id,
                        manifest_hash,
                        roster_hash,
                        setup_profile_hash,
                        q_share_hash,
                        carry_aware_vss_share_relation_profile_hash,
                        commitment_profile_hash,
                        setup_epoch,
                        target_basis_hash,
                        public_matrix_seed_hash,
                        same_secret_proof_family_binding_root,
                    },
                    expected_position,
                    proof_statement_hash,
                    proof_byte_length,
                    proof_bytes_hex,
                },
            )?;
            used_restricted_proof_statements[restricted_statement_index] = true;
            verified_restricted_proof_count += 1;
        }

        let mut verified_proof_record = proof_record_without_root;
        verified_proof_record["proofRecordRoot"] = json!(proof_record_root);
        verified_proof_records.push(verified_proof_record);
    }
    if used_restricted_proof_statements
        .iter()
        .any(|statement_was_used| !statement_was_used)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "every supplied restrictedProofStatements record must match a compact same-secret bridge proof record",
        ));
    }

    let proof_material_set_without_root = json!({
        "objectType": "CompactVssSameSecretBridgeProofMaterialSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "developmentScope": COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "targetBasisHash": target_basis_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": participant_count,
        "targetRnsLimbCount": target_rns_limb_count,
        "thresholdDegree": threshold_degree,
        "compactCoefficientCommitmentRoot": compact_coefficient_commitment_root,
        "sameSecretConsistencyRoot": same_secret_consistency_root,
        "sameSecretProofSetRoot": same_secret_proof_set_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "compactSameSecretBridgeStatementSetRoot": statement_set_root,
        "proofRecords": verified_proof_records,
    });
    let proof_material_set_root = hash_at_path(proof_material_set, &["proofMaterialSetRoot"])?;
    let expected_proof_material_set_root = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &proof_material_set_without_root,
    )?;
    if expected_proof_material_set_root != proof_material_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact same-secret bridge proof material set root does not match its bound proof records",
        ));
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyCompactVssSameSecretBridgeProofMaterialSet",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "proofFamily": COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "compactSameSecretBridgeStatementSetRoot": statement_set_root,
        "proofMaterialSetRoot": proof_material_set_root,
        "participantCount": participant_count,
        "proofRecordCount": proof_records.len(),
        "totalProofByteLength": total_proof_byte_length,
        "restrictedProofVerificationCount": verified_restricted_proof_count,
        "restrictedProofVerificationScope": if verified_restricted_proof_count > 0 {
            COMPACT_SAME_SECRET_BRIDGE_RESTRICTED_PROOF_VERIFIED_SCOPE
        } else {
            COMPACT_SAME_SECRET_BRIDGE_RESTRICTED_PROOF_UNSUPPLIED_SCOPE
        },
    }))
}

#[derive(Clone, Copy)]
struct StatementSetBinding<'a> {
    ceremony_id: &'a str,
    manifest_hash: &'a str,
    roster_hash: &'a str,
    setup_profile_hash: &'a str,
    q_share_hash: &'a str,
    carry_aware_vss_share_relation_profile_hash: &'a str,
    commitment_profile_hash: &'a str,
    setup_epoch: &'a str,
    target_basis_hash: &'a str,
    public_matrix_seed_hash: &'a str,
    same_secret_proof_family_binding_root: &'a str,
}

struct StatementRecordVerificationInput<'a> {
    statement_record: &'a Value,
    expected_position: usize,
    target_rns_limb_count: usize,
    statement_set: StatementSetBinding<'a>,
}

struct RestrictedCompactSameSecretBridgeProofStatementVerification<'a> {
    restricted_statement: &'a Value,
    bridge_statement: &'a Value,
    statement_set: StatementSetBinding<'a>,
    expected_position: usize,
    proof_statement_hash: &'a str,
    proof_byte_length: usize,
    proof_bytes_hex: &'a str,
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

fn matching_restricted_proof_statement_index(
    restricted_proof_statements: &[&Value],
    used_restricted_proof_statements: &[bool],
    proof_statement_hash: &str,
) -> CanonicalResult<usize> {
    for (restricted_statement_index, restricted_statement) in
        restricted_proof_statements.iter().enumerate()
    {
        if used_restricted_proof_statements[restricted_statement_index] {
            continue;
        }
        if hash_at_path(restricted_statement, &["proofStatementHash"])? == proof_statement_hash {
            return Ok(restricted_statement_index);
        }
    }

    Err(CanonicalError::new(
        CanonicalErrorCode::ProfileComponentMismatch,
        "compact same-secret bridge proof record has no matching restricted proof statement",
    ))
}

fn verify_restricted_compact_same_secret_bridge_proof_statement(
    input: RestrictedCompactSameSecretBridgeProofStatementVerification<'_>,
) -> CanonicalResult<()> {
    let restricted_context = value_at_path(input.restricted_statement, &["context"])?;
    compare_required_string(
        string_at_path(restricted_context, &["ceremonyId"])?,
        input.statement_set.ceremony_id,
        "restricted compact same-secret bridge proof context ceremonyId",
    )?;
    compare_required_string(
        hash_at_path(restricted_context, &["manifestHash"])?,
        input.statement_set.manifest_hash,
        "restricted compact same-secret bridge proof context manifestHash",
    )?;
    compare_required_string(
        hash_at_path(restricted_context, &["rosterHash"])?,
        input.statement_set.roster_hash,
        "restricted compact same-secret bridge proof context rosterHash",
    )?;
    compare_required_string(
        string_at_path(restricted_context, &["setupEpoch"])?,
        input.statement_set.setup_epoch,
        "restricted compact same-secret bridge proof context setupEpoch",
    )?;

    let trustee_identity = string_at_path(input.bridge_statement, &["trusteeIdentity"])?;
    compare_required_string(
        string_at_path(restricted_context, &["trusteeIdentity"])?,
        trustee_identity,
        "restricted compact same-secret bridge proof context trusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(restricted_context, &["trusteeRosterPosition"])?,
        input.expected_position as u64,
        "restricted compact same-secret bridge proof context trusteeRosterPosition",
    )?;

    let restricted_compact_statement =
        value_at_path(input.restricted_statement, &["compactSameSecretBridge"])?;
    compare_required_string(
        hash_at_path(
            restricted_compact_statement,
            &["compactSameSecretBridgeStatementRoot"],
        )?,
        hash_at_path(
            input.bridge_statement,
            &["compactSameSecretBridgeStatementRoot"],
        )?,
        "restricted compact same-secret bridge proof statement root",
    )?;
    compare_required_string(
        hash_at_path(restricted_compact_statement, &["sameSecretStatementRoot"])?,
        hash_at_path(input.bridge_statement, &["sameSecretStatementRoot"])?,
        "restricted compact same-secret bridge proof statement sameSecretStatementRoot",
    )?;
    compare_required_string(
        hash_at_path(restricted_compact_statement, &["sameSecretProofRoot"])?,
        hash_at_path(input.bridge_statement, &["sameSecretProofRoot"])?,
        "restricted compact same-secret bridge proof statement sameSecretProofRoot",
    )?;
    compare_required_string(
        hash_at_path(
            restricted_compact_statement,
            &["sameSecretProofFamilyBindingRoot"],
        )?,
        input.statement_set.same_secret_proof_family_binding_root,
        "restricted compact same-secret bridge proof statement sameSecretProofFamilyBindingRoot",
    )?;
    compare_required_string(
        string_at_path(restricted_compact_statement, &["sourceTrusteeIdentity"])?,
        trustee_identity,
        "restricted compact same-secret bridge proof statement sourceTrusteeIdentity",
    )?;
    compare_required_u64(
        unsigned_at_path(
            restricted_compact_statement,
            &["sourceTrusteeRosterPosition"],
        )?,
        input.expected_position as u64,
        "restricted compact same-secret bridge proof statement sourceTrusteeRosterPosition",
    )?;
    compare_required_string(
        hash_at_path(restricted_compact_statement, &["publicMatrixSeedHash"])?,
        input.statement_set.public_matrix_seed_hash,
        "restricted compact same-secret bridge proof statement publicMatrixSeedHash",
    )?;
    compare_required_string(
        hash_at_path(restricted_compact_statement, &["targetBasisHash"])?,
        input.statement_set.target_basis_hash,
        "restricted compact same-secret bridge proof statement targetBasisHash",
    )?;

    let target_rns_primes = array_at_path(restricted_compact_statement, &["targetRnsPrimes"])?;
    let target_constant_roots = array_at_path(
        restricted_compact_statement,
        &["targetConstantCommitmentRoots"],
    )?;
    let bridge_target_constant_roots = array_at_path(
        input.bridge_statement,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    if target_rns_primes.len() != bridge_target_constant_roots.len()
        || target_constant_roots.len() != bridge_target_constant_roots.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "restricted compact same-secret bridge proof target roots must match the bridge statement target basis",
        ));
    }
    for (target_rns_limb_index, bridge_target_root) in
        bridge_target_constant_roots.iter().enumerate()
    {
        compare_required_u64(
            unsigned_at_path(bridge_target_root, &["rnsLimbIndex"])?,
            target_rns_limb_index as u64,
            "compact same-secret bridge target root rnsLimbIndex",
        )?;
        compare_required_u64(
            unsigned_at_path(&target_rns_primes[target_rns_limb_index], &[])?,
            unsigned_at_path(bridge_target_root, &["rnsPrime"])?,
            "restricted compact same-secret bridge proof target prime",
        )?;
        compare_required_string(
            string_at_path(&target_constant_roots[target_rns_limb_index], &[])?,
            hash_at_path(bridge_target_root, &["coefficientCommitmentRoot"])?,
            "restricted compact same-secret bridge proof target commitment root",
        )?;
    }

    let mut proof_verification_request = input.restricted_statement.clone();
    let proof_verification_request_object =
        proof_verification_request.as_object_mut().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "restricted compact same-secret bridge proof statement must be an object",
            )
        })?;
    proof_verification_request_object.remove("proofStatementHash");
    proof_verification_request_object.insert(
        "proofBytesHex".to_string(),
        Value::String(input.proof_bytes_hex.to_string()),
    );
    let proof_verification =
        super::verify_compact_same_secret_bridge_proof_from_request(&proof_verification_request)?;
    compare_required_string(
        string_at_path(&proof_verification, &["proofFamily"])?,
        COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
        "restricted compact same-secret bridge proof verification proofFamily",
    )?;
    compare_required_string(
        string_at_path(&proof_verification, &["proofBoundary"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "restricted compact same-secret bridge proof verification proofBoundary",
    )?;
    compare_required_string(
        hash_at_path(&proof_verification, &["statementHash"])?,
        input.proof_statement_hash,
        "restricted compact same-secret bridge proof verification statementHash",
    )?;
    compare_required_u64(
        unsigned_at_path(&proof_verification, &["proofByteLength"])?,
        input.proof_byte_length as u64,
        "restricted compact same-secret bridge proof verification proofByteLength",
    )?;

    Ok(())
}

fn verify_optional_same_secret_evidence_sets(
    input: EvidenceSetVerificationInput<'_>,
) -> CanonicalResult<()> {
    match (
        input.request.get("sameSecretConsistency"),
        input.request.get("sameSecretProofs"),
    ) {
        (None, None) => Ok(()),
        (Some(same_secret_consistency), Some(same_secret_proofs)) => {
            let same_secret_statement_records =
                verify_same_secret_consistency_evidence(same_secret_consistency, &input)?;
            verify_same_secret_proof_evidence(
                same_secret_proofs,
                &input,
                &same_secret_statement_records,
            )
        }
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS same-secret bridge evidence verification requires both sameSecretConsistency and sameSecretProofs",
        )),
    }
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
        string_at_path(same_secret_consistency, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "same-secret consistency setupProfileId",
    )?;
    compare_required_string(
        string_at_path(same_secret_consistency, &["setupProofProfileId"])?,
        SETUP_PROOF_PROFILE_ID,
        "same-secret consistency setupProofProfileId",
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
    let expected_consistency_root = derive_protocol_hash(
        "SameSecretConsistencyRoot",
        &value_without_root_field(
            same_secret_consistency,
            "sameSecretConsistencyRoot",
            "same-secret consistency statement set",
        )?,
    )?;
    if expected_consistency_root != input.same_secret_consistency_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
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
    let trustee_secret_root_references =
        array_at_path(same_secret_consistency, &["trusteeSecretCommitmentRoots"])?;
    if trustee_secret_root_references.len() != input.participant_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret consistency trustee secret root references must cover every participant",
        ));
    }

    let mut verified_statement_records = Vec::with_capacity(statement_records.len());
    for expected_position in 0..input.participant_count {
        let statement_record = &statement_records[expected_position];
        let bridge_statement = &input.bridge_statement_records[expected_position];
        let trustee_secret_root_reference = &trustee_secret_root_references[expected_position];
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
        let expected_statement_root = derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &value_without_root_field(
                statement_record,
                "sameSecretStatementRoot",
                "same-secret consistency statement",
            )?,
        )?;
        if expected_statement_root != same_secret_statement_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "same-secret consistency statement root does not match its bound statement",
            ));
        }
        compare_required_string(
            string_at_path(trustee_secret_root_reference, &["trusteeIdentity"])?,
            trustee_identity,
            "same-secret trustee secret root reference trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(trustee_secret_root_reference, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret trustee secret root reference trusteeRosterPosition",
        )?;
        compare_required_string(
            hash_at_path(
                trustee_secret_root_reference,
                &["trusteeSecretCommitmentRoot"],
            )?,
            trustee_secret_commitment_root,
            "same-secret trustee secret root reference root",
        )?;
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
        string_at_path(same_secret_proofs, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "same-secret proof set setupProfileId",
    )?;
    compare_required_string(
        string_at_path(same_secret_proofs, &["setupProofProfileId"])?,
        SETUP_PROOF_PROFILE_ID,
        "same-secret proof set setupProofProfileId",
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
    let expected_proof_set_root = derive_protocol_hash(
        "SameSecretProofRoot",
        &value_without_root_field(
            same_secret_proofs,
            "sameSecretProofSetRoot",
            "same-secret proof set",
        )?,
    )?;
    if expected_proof_set_root != input.same_secret_proof_set_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "same-secret proof set root does not match its bound proof records",
        ));
    }

    let proof_records = array_at_path(same_secret_proofs, &["proofRecords"])?;
    let proof_root_references = array_at_path(same_secret_proofs, &["sameSecretProofRoots"])?;
    if proof_records.len() != input.participant_count
        || proof_root_references.len() != input.participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proof records and root references must cover every participant",
        ));
    }

    for expected_position in 0..input.participant_count {
        let proof_record = &proof_records[expected_position];
        let proof_root_reference = &proof_root_references[expected_position];
        let statement_record = &same_secret_statement_records[expected_position];
        let bridge_statement = &input.bridge_statement_records[expected_position];
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
        let expected_proof_root = derive_protocol_hash(
            "SameSecretProofRoot",
            &value_without_root_field(proof_record, "sameSecretProofRoot", "same-secret proof")?,
        )?;
        if expected_proof_root != same_secret_proof_root {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "same-secret proof root does not match its bound proof record",
            ));
        }
        compare_required_string(
            string_at_path(proof_root_reference, &["trusteeIdentity"])?,
            trustee_identity,
            "same-secret proof root reference trusteeIdentity",
        )?;
        compare_required_u64(
            unsigned_at_path(proof_root_reference, &["trusteeRosterPosition"])?,
            expected_position as u64,
            "same-secret proof root reference trusteeRosterPosition",
        )?;
        compare_required_string(
            hash_at_path(proof_root_reference, &["sameSecretProofRoot"])?,
            same_secret_proof_root,
            "same-secret proof root reference root",
        )?;
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
    let proof_size_bytes = read_positive_usize_at_path(
        proof_record,
        &["proofSizeBytes"],
        "same-secret proof record proofSizeBytes",
    )?;
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    if proof_record.get("proofBytesHex").is_some() {
        if proof_record.get("proofBytesEncoding").is_some()
            || same_secret_proof_has_transport_reference(proof_record)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "same-secret proof record must not mix embedded proofBytesHex with transported proof material",
            ));
        }
        let proof_bytes_hex = string_at_path(proof_record, &["proofBytesHex"])?;
        let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
        if proof_bytes.len() != proof_size_bytes {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "same-secret proof record proofBytesHex must match proofSizeBytes",
            ));
        }
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
            proof_size_bytes,
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
                CanonicalErrorCode::ProfileComponentMismatch,
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
                CanonicalErrorCode::ProfileComponentMismatch,
                "transportedSameSecretProofMaterial contains duplicate proofMaterialRoot entries",
            ));
        }
        let chunks = if proof_material.get("chunks").is_some() {
            transported_same_secret_proof_chunks(proof_material, proof_material_index)?
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
            &chunks,
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
            CanonicalErrorCode::ProfileComponentMismatch,
            "transportedSameSecretProofMaterial is missing the requested proofMaterialRoot",
        )
    })
}

fn verify_transported_same_secret_proof_material_set_header(value: &Value) -> CanonicalResult<()> {
    for (field_name, expected_value) in [
        ("objectType", SAME_SECRET_PROOF_TRANSPORT_SET_OBJECT_TYPE),
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
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
        ("setupProfileId", COLLECTIVE_BGV_SETUP_PROFILE_ID),
        ("setupProofProfileId", SETUP_PROOF_PROFILE_ID),
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
        chunks.push(crate::transcript_core::decode_hex(string_at_path(
            chunk_value,
            &["bytesHex"],
        )?)?);
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
    proof_size_bytes: usize,
    transport_hashes: &SetupProofMaterialTransportHashes,
) -> CanonicalResult<()> {
    let proof_size_bytes = u64::try_from(proof_size_bytes).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "same-secret proofSizeBytes does not fit u64",
        )
    })?;
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
    compare_required_u64(
        proof_size_bytes,
        transport_hashes.total_byte_length,
        "same-secret proof record proofSizeBytes",
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
    derive_protocol_hash(
        "SameSecretLinkageAnchorProofMaterialRoot",
        &json!({
            "objectType": "SameSecretLinkageAnchorProofMaterialReference",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
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
        }),
    )
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
        "CompactVssSameSecretBridgeStatement",
        "compact VSS same-secret bridge statement objectType",
    )?;
    compare_required_u64(
        unsigned_at_path(input.statement_record, &["objectVersion"])?,
        1,
        "compact VSS same-secret bridge statement objectVersion",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compact VSS same-secret bridge statement setupProfileId",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["compactCommitmentProfileId"])?,
        COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "compact VSS same-secret bridge statement compactCommitmentProfileId",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["developmentScope"])?,
        COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
        "compact VSS same-secret bridge statement developmentScope",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["setupProofProfileId"])?,
        SETUP_PROOF_PROFILE_ID,
        "compact VSS same-secret bridge statement setupProofProfileId",
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
        COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "compact VSS same-secret bridge statement integerSupport",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["signedRepresentativeConvention"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compact VSS same-secret bridge statement signedRepresentativeConvention",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["compactCommitmentEncoding"])?,
        COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "compact VSS same-secret bridge statement compactCommitmentEncoding",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["targetBasisLimbOrder"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "compact VSS same-secret bridge statement targetBasisLimbOrder",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["relation"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_RELATION,
        "compact VSS same-secret bridge statement relation",
    )?;
    compare_required_string(
        string_at_path(input.statement_record, &["proofBoundary"])?,
        COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "compact VSS same-secret bridge statement proofBoundary",
    )?;

    let target_constant_roots = array_at_path(
        input.statement_record,
        &["targetConstantCoefficientCommitmentRoots"],
    )?;
    if target_constant_roots.len() != input.target_rns_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "compact VSS same-secret bridge statement must bind one target constant root per target RNS limb",
        ));
    }
    let verified_target_constant_roots = target_constant_roots
        .iter()
        .enumerate()
        .map(|(expected_rns_limb_index, root_record)| {
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
                unsigned_at_path(root_record, &["shamirCoefficientIndex"])?,
                0,
                "compact VSS same-secret bridge target constant shamirCoefficientIndex",
            )?;
            let coefficient_commitment_root =
                hash_at_path(root_record, &["coefficientCommitmentRoot"])?;

            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "shamirCoefficientIndex": 0,
                "coefficientCommitmentRoot": coefficient_commitment_root,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let expected_statement_root = derive_protocol_hash(
        "SetupProofRecordBindingHash",
        &json!({
            "objectType": "CompactVssSameSecretBridgeStatement",
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
            "developmentScope": COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
            "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
            "proofFamily": SAME_SECRET_PROOF_FAMILY,
            "ceremonyId": input.statement_set.ceremony_id,
            "manifestHash": input.statement_set.manifest_hash,
            "rosterHash": input.statement_set.roster_hash,
            "setupProfileHash": input.statement_set.setup_profile_hash,
            "qShareHash": input.statement_set.q_share_hash,
            "carryAwareVssShareRelationProfileHash": input
                .statement_set
                .carry_aware_vss_share_relation_profile_hash,
            "commitmentProfileHash": input.statement_set.commitment_profile_hash,
            "setupEpoch": input.statement_set.setup_epoch,
            "targetBasisHash": input.statement_set.target_basis_hash,
            "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": input.expected_position,
            "sameSecretStatementRoot": same_secret_statement_root,
            "sameSecretProofRoot": same_secret_proof_root,
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "dataBasisRelation": SAME_SECRET_RELATION,
            "integerSupport": COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
            "signedRepresentativeConvention": COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
            "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
            "targetBasisLimbOrder": COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
            "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
            "relation": COMPACT_VSS_SAME_SECRET_BRIDGE_RELATION,
            "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        }),
    )?;
    let statement_root = hash_at_path(
        input.statement_record,
        &["compactSameSecretBridgeStatementRoot"],
    )?;
    if expected_statement_root != statement_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "compact VSS same-secret bridge statement root does not match its bound roots",
        ));
    }

    Ok(json!({
        "objectType": "CompactVssSameSecretBridgeStatement",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "compactCommitmentProfileId": COMPACT_VSS_COMMITMENT_PROFILE_ID,
        "developmentScope": COMPACT_VSS_COMMITMENT_DEVELOPMENT_SCOPE,
        "setupProofProfileId": SETUP_PROOF_PROFILE_ID,
        "proofFamily": SAME_SECRET_PROOF_FAMILY,
        "ceremonyId": input.statement_set.ceremony_id,
        "manifestHash": input.statement_set.manifest_hash,
        "rosterHash": input.statement_set.roster_hash,
        "setupProfileHash": input.statement_set.setup_profile_hash,
        "qShareHash": input.statement_set.q_share_hash,
        "carryAwareVssShareRelationProfileHash": input
            .statement_set
            .carry_aware_vss_share_relation_profile_hash,
        "commitmentProfileHash": input.statement_set.commitment_profile_hash,
        "setupEpoch": input.statement_set.setup_epoch,
        "targetBasisHash": input.statement_set.target_basis_hash,
        "publicMatrixSeedHash": input.statement_set.public_matrix_seed_hash,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": input.expected_position,
        "sameSecretStatementRoot": same_secret_statement_root,
        "sameSecretProofRoot": same_secret_proof_root,
        "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "dataBasisRelation": SAME_SECRET_RELATION,
        "integerSupport": COMPACT_VSS_SAME_SECRET_BRIDGE_INTEGER_SUPPORT,
        "signedRepresentativeConvention": COMPACT_VSS_SAME_SECRET_BRIDGE_SIGNED_REPRESENTATIVE_CONVENTION,
        "compactCommitmentEncoding": COMPACT_VSS_COMMITMENT_BINARY_FORMAT,
        "targetBasisLimbOrder": COMPACT_VSS_SAME_SECRET_BRIDGE_TARGET_BASIS_LIMB_ORDER,
        "targetConstantCoefficientCommitmentRoots": verified_target_constant_roots,
        "relation": COMPACT_VSS_SAME_SECRET_BRIDGE_RELATION,
        "proofBoundary": COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
        "compactSameSecretBridgeStatementRoot": statement_root,
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
            "setupProfileHash" => statement_set.setup_profile_hash,
            "qShareHash" => statement_set.q_share_hash,
            "carryAwareVssShareRelationProfileHash" => {
                statement_set.carry_aware_vss_share_relation_profile_hash
            }
            "commitmentProfileHash" => statement_set.commitment_profile_hash,
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
            "setupProfileHash" => statement_set.setup_profile_hash,
            "qShareHash" => statement_set.q_share_hash,
            "carryAwareVssShareRelationProfileHash" => {
                statement_set.carry_aware_vss_share_relation_profile_hash
            }
            "commitmentProfileHash" => statement_set.commitment_profile_hash,
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
            CanonicalErrorCode::ProfileComponentMismatch,
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
        value_without_root_field, verify_compact_vss_same_secret_bridge_proof_material_set_request,
        verify_compact_vss_same_secret_bridge_statement_set_request,
    };
    use crate::{
        encoding::CanonicalResult,
        hashing::{derive_protocol_hash, to_hex},
    };

    #[test]
    fn compact_same_secret_bridge_statement_set_verifies_bound_roots() -> CanonicalResult<()> {
        let statement_set = compact_same_secret_bridge_statement_set()?;
        let verification = verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyCompactVssSameSecretBridgeStatementSet",
            "statementSet": statement_set,
        }))?;

        assert_eq!(
            verification["operation"],
            "verifyCompactVssSameSecretBridgeStatementSet"
        );
        assert_eq!(
            verification["compactSameSecretBridgeStatementSetRoot"],
            statement_set["compactSameSecretBridgeStatementSetRoot"]
        );
        assert_eq!(verification["participantCount"], json!(2_u64));
        assert_eq!(verification["targetRnsLimbCount"], json!(2_u64));
        assert_eq!(
            verification["compactCommitmentEncoding"],
            "sealed-lattice-compact-vss-commitment-binary-v1"
        );

        let mut tampered_statement_set = statement_set;
        tampered_statement_set["statementRecords"][1]["targetConstantCoefficientCommitmentRoots"]
            [0]["coefficientCommitmentRoot"] = json!("c".repeat(128));
        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
                "statementSet": tampered_statement_set,
            }))
            .is_err(),
            "tampered compact same-secret bridge target constant root must reject"
        );

        let mut unsupported_convention_statement_set = compact_same_secret_bridge_statement_set()?;
        unsupported_convention_statement_set["signedRepresentativeConvention"] =
            json!("unsupported compact bridge signed representative convention");
        unsupported_convention_statement_set["compactSameSecretBridgeStatementSetRoot"] =
            json!(derive_protocol_hash(
                "SetupProofRecordBindingHash",
                &unsupported_convention_statement_set,
            )?);
        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
                "statementSet": unsupported_convention_statement_set,
            }))
            .is_err(),
            "unsupported signed-representative convention must reject"
        );

        Ok(())
    }

    #[test]
    fn compact_same_secret_bridge_evidence_sets_bind_same_secret_roots() -> CanonicalResult<()> {
        let (statement_set, same_secret_consistency, same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let verification = verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyCompactVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        let mut forged_statement_set = statement_set;
        forged_statement_set["statementRecords"][0]["sameSecretProofRoot"] = json!("0".repeat(128));
        rebind_bridge_statement_root(&mut forged_statement_set["statementRecords"][0])?;
        rebind_bridge_statement_set_root(&mut forged_statement_set)?;
        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
                "statementSet": forged_statement_set.clone(),
            }))
            .is_ok(),
            "statement-only verification remains a root-binding check"
        );
        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
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
    fn compact_same_secret_bridge_checks_transported_same_secret_proof_material()
    -> CanonicalResult<()> {
        let (mut statement_set, same_secret_consistency, mut same_secret_proofs) =
            compact_same_secret_bridge_statement_set_with_evidence()?;
        let transported_same_secret_proof_material =
            move_same_secret_proof_bytes_to_transport(&mut same_secret_proofs)?;
        rebind_bridge_statement_set_to_same_secret_proofs(&mut statement_set, &same_secret_proofs)?;

        let verification = verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
            "command": "VerifyCompactVssSameSecretBridgeStatementSet",
            "statementSet": statement_set.clone(),
            "sameSecretConsistency": same_secret_consistency.clone(),
            "sameSecretProofs": same_secret_proofs.clone(),
            "transportedSameSecretProofMaterial": transported_same_secret_proof_material.clone(),
        }))?;
        assert_eq!(verification["ok"], json!(true));

        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
                "statementSet": statement_set.clone(),
                "sameSecretConsistency": same_secret_consistency.clone(),
                "sameSecretProofs": same_secret_proofs.clone(),
            }))
            .is_err(),
            "transported same-secret proof records must require transported proof material"
        );

        let mut tampered_material = transported_same_secret_proof_material;
        tampered_material["proofMaterials"][0]["chunks"][0]["bytesHex"] = json!("ff");
        assert!(
            verify_compact_vss_same_secret_bridge_statement_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeStatementSet",
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
    fn compact_same_secret_bridge_proof_material_set_binds_proof_bytes() -> CanonicalResult<()> {
        let statement_set = compact_same_secret_bridge_statement_set()?;
        let proof_material_set =
            compact_same_secret_bridge_proof_material_set(&statement_set, ["aa", "bb"])?;

        let verification =
            verify_compact_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "proofMaterialSet": proof_material_set.clone(),
            }))?;
        assert_eq!(
            verification["operation"],
            "verifyCompactVssSameSecretBridgeProofMaterialSet"
        );
        assert_eq!(
            verification["compactSameSecretBridgeStatementSetRoot"],
            statement_set["compactSameSecretBridgeStatementSetRoot"]
        );
        assert_eq!(
            verification["proofMaterialSetRoot"],
            proof_material_set["proofMaterialSetRoot"]
        );
        assert_eq!(verification["proofRecordCount"], json!(2_u64));

        let mut tampered_proof_material_set = proof_material_set.clone();
        tampered_proof_material_set["proofRecords"][0]["proofBytesHash"] = json!("0".repeat(128));
        assert!(
            verify_compact_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set.clone(),
                "proofMaterialSet": tampered_proof_material_set,
            }))
            .is_err(),
            "proof material must reject a proofBytesHash that no longer matches proofBytesHex"
        );

        let mut wrong_statement_root_material_set = proof_material_set;
        wrong_statement_root_material_set["proofRecords"][1]["compactSameSecretBridgeStatementRoot"] =
            json!("0".repeat(128));
        assert!(
            verify_compact_vss_same_secret_bridge_proof_material_set_request(&json!({
                "command": "VerifyCompactVssSameSecretBridgeProofMaterialSet",
                "statementSet": statement_set,
                "proofMaterialSet": wrong_statement_root_material_set,
            }))
            .is_err(),
            "proof material must bind each proof record to its bridge statement root"
        );

        Ok(())
    }

    fn compact_same_secret_bridge_statement_set() -> CanonicalResult<Value> {
        let mut statement_records = Vec::new();
        for trustee_roster_position in 0..2_usize {
            statement_records.push(compact_same_secret_bridge_statement_record(
                trustee_roster_position,
            )?);
        }
        let statement_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 4,
            "compactCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretConsistencyRoot": "a".repeat(128),
            "sameSecretProofSetRoot": "b".repeat(128),
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement_set,
        )?);

        Ok(statement_set)
    }

    fn compact_same_secret_bridge_proof_material_set(
        statement_set: &Value,
        proof_bytes_hex_values: [&str; 2],
    ) -> CanonicalResult<Value> {
        let statement_records = statement_set["statementRecords"]
            .as_array()
            .expect("compact bridge statement records");
        let proof_records = statement_records
            .iter()
            .zip(proof_bytes_hex_values)
            .enumerate()
            .map(
                |(proof_record_index, (statement_record, proof_bytes_hex))| {
                    let proof_bytes = crate::transcript_core::decode_hex(proof_bytes_hex)?;
                    let proof_record_without_root = json!({
                        "objectType": "CompactVssSameSecretBridgeProofRecord",
                        "objectVersion": 1,
                        "proofFamily": super::COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
                        "proofBoundary": super::COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
                        "compactSameSecretBridgeStatementRoot": statement_record["compactSameSecretBridgeStatementRoot"],
                        "proofStatementHash": if proof_record_index == 0 {
                            "1".repeat(128)
                        } else {
                            "2".repeat(128)
                        },
                        "proofByteLength": proof_bytes.len(),
                        "proofBytesHash": crate::hashing::hash512_hex(
                            super::COMPACT_SAME_SECRET_BRIDGE_PROOF_BYTES_HASH_DOMAIN,
                            &[&proof_bytes],
                        ),
                        "proofBytesHex": proof_bytes_hex,
                    });
                    let mut proof_record = proof_record_without_root;
                    proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
                        "SetupProofRecordBindingHash",
                        &proof_record,
                    )?);
                    Ok(proof_record)
                },
            )
            .collect::<CanonicalResult<Vec<_>>>()?;
        let proof_material_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": super::COMPACT_SAME_SECRET_BRIDGE_PROOF_FAMILY,
            "proofBoundary": super::COMPACT_VSS_SAME_SECRET_BRIDGE_PROOF_BOUNDARY,
            "ceremonyId": statement_set["ceremonyId"],
            "manifestHash": statement_set["manifestHash"],
            "rosterHash": statement_set["rosterHash"],
            "setupProfileHash": statement_set["setupProfileHash"],
            "qShareHash": statement_set["qShareHash"],
            "carryAwareVssShareRelationProfileHash": statement_set["carryAwareVssShareRelationProfileHash"],
            "commitmentProfileHash": statement_set["commitmentProfileHash"],
            "setupEpoch": statement_set["setupEpoch"],
            "targetBasisHash": statement_set["targetBasisHash"],
            "publicMatrixSeedHash": statement_set["publicMatrixSeedHash"],
            "participantCount": statement_set["participantCount"],
            "targetRnsLimbCount": statement_set["targetRnsLimbCount"],
            "thresholdDegree": statement_set["thresholdDegree"],
            "compactCoefficientCommitmentRoot": statement_set["compactCoefficientCommitmentRoot"],
            "sameSecretConsistencyRoot": statement_set["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": statement_set["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": statement_set["sameSecretProofFamilyBindingRoot"],
            "compactSameSecretBridgeStatementSetRoot": statement_set["compactSameSecretBridgeStatementSetRoot"],
            "proofRecords": proof_records,
        });
        let mut proof_material_set = proof_material_set_without_root;
        proof_material_set["proofMaterialSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &proof_material_set,
        )?);

        Ok(proof_material_set)
    }

    fn compact_same_secret_bridge_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let target_constant_coefficient_commitment_roots = (0..2_usize)
            .map(|rns_limb_index| {
                json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": if rns_limb_index == 0 { 97 } else { 193 },
                    "shamirCoefficientIndex": 0,
                    "coefficientCommitmentRoot": if trustee_roster_position == 0 && rns_limb_index == 0 {
                        "d".repeat(128)
                    } else if trustee_roster_position == 0 {
                        "e".repeat(128)
                    } else if rns_limb_index == 0 {
                        "f".repeat(128)
                    } else {
                        "0".repeat(128)
                    },
                })
            })
            .collect::<Vec<_>>();
        let statement_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
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
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "targetConstantCoefficientCommitmentRoots": target_constant_coefficient_commitment_roots,
            "relation": "target-basis compact constant coefficient commitments bind to the same signed ternary trustee secret as the data-basis same-secret proof",
            "proofBoundary": "restricted native compact same-secret bridge proof over target-basis compact constant commitments; not target-ready package proof evidence",
        });
        let mut statement = statement_without_root;
        statement["compactSameSecretBridgeStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement,
        )?);

        Ok(statement)
    }

    fn compact_same_secret_bridge_statement_set_with_evidence()
    -> CanonicalResult<(Value, Value, Value)> {
        let same_secret_consistency = same_secret_consistency_statement_set()?;
        let same_secret_proofs = same_secret_proof_set(&same_secret_consistency)?;
        let mut statement_records = Vec::new();
        for trustee_roster_position in 0..2_usize {
            statement_records.push(compact_same_secret_bridge_statement_record_from_evidence(
                trustee_roster_position,
                &same_secret_consistency["statementRecords"][trustee_roster_position],
                &same_secret_proofs["proofRecords"][trustee_roster_position],
            )?);
        }
        let statement_set_without_root = json!({
            "objectType": "CompactVssSameSecretBridgeStatementSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "compactCommitmentProfileId": "SealedLattice-CompactLinearCommitment-Development-v1",
            "developmentScope": "development-only-not-certified-for-production-use",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
            "setupEpoch": "setup-epoch",
            "targetBasisHash": "7".repeat(128),
            "publicMatrixSeedHash": "8".repeat(128),
            "participantCount": 2,
            "targetRnsLimbCount": 2,
            "thresholdDegree": 4,
            "compactCoefficientCommitmentRoot": "9".repeat(128),
            "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
            "sameSecretProofSetRoot": same_secret_proofs["sameSecretProofSetRoot"],
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "integerSupport": "the bridge proof must show one centered ternary integer coefficient vector whose signed coefficients reduce into every bound data-basis and target-basis limb",
            "signedRepresentativeConvention": "coefficients are interpreted as signed representatives before reduction into each data-basis or target-basis RNS prime",
            "compactCommitmentEncoding": "sealed-lattice-compact-vss-commitment-binary-v1",
            "targetBasisLimbOrder": "target constant roots are ordered by contiguous target-basis rnsLimbIndex values starting at zero and bind the listed target-basis prime",
            "statementRecords": statement_records,
        });
        let mut statement_set = statement_set_without_root;
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &statement_set,
        )?);

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
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
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
        statement_set["sameSecretConsistencyRoot"] = json!(derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &statement_set,
        )?);

        Ok(statement_set)
    }

    fn same_secret_consistency_statement_record(
        trustee_roster_position: usize,
    ) -> CanonicalResult<Value> {
        let statement_without_root = json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
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
            "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
            "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
            "sameSecretProofFamilyBindingRoot": "c".repeat(128),
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        let mut statement = statement_without_root;
        statement["sameSecretStatementRoot"] = json!(derive_protocol_hash(
            "SameSecretConsistencyRoot",
            &statement,
        )?);

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
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "proofAccountingHash": "d".repeat(128),
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
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
        proof_set["sameSecretProofSetRoot"] =
            json!(derive_protocol_hash("SameSecretProofRoot", &proof_set,)?);

        Ok(proof_set)
    }

    fn same_secret_proof_record(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
    ) -> CanonicalResult<Value> {
        let proof_record_without_root = json!({
            "objectType": "SameSecretProof",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "commitmentProfileId": "SealedLattice-BDLOP-Commitment-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": "compact-vss-test",
            "manifestHash": "1".repeat(128),
            "rosterHash": "2".repeat(128),
            "setupProfileHash": "3".repeat(128),
            "qShareHash": "4".repeat(128),
            "carryAwareVssShareRelationProfileHash": "5".repeat(128),
            "commitmentProfileHash": "6".repeat(128),
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
        proof_record["sameSecretProofRoot"] =
            json!(derive_protocol_hash("SameSecretProofRoot", &proof_record,)?);

        Ok(proof_record)
    }

    fn compact_same_secret_bridge_statement_record_from_evidence(
        trustee_roster_position: usize,
        same_secret_statement: &Value,
        same_secret_proof: &Value,
    ) -> CanonicalResult<Value> {
        let mut statement = compact_same_secret_bridge_statement_record(trustee_roster_position)?;
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
        statement["compactSameSecretBridgeStatementRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &value_without_root_field(
                statement,
                "compactSameSecretBridgeStatementRoot",
                "compact same-secret bridge statement",
            )?,
        )?);

        Ok(())
    }

    fn rebind_bridge_statement_set_root(statement_set: &mut Value) -> CanonicalResult<()> {
        statement_set["compactSameSecretBridgeStatementSetRoot"] = json!(derive_protocol_hash(
            "SetupProofRecordBindingHash",
            &value_without_root_field(
                statement_set,
                "compactSameSecretBridgeStatementSetRoot",
                "compact same-secret bridge statement set",
            )?,
        )?);

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
            proof_record["sameSecretProofRoot"] = json!(derive_protocol_hash(
                "SameSecretProofRoot",
                &value_without_root_field(
                    proof_record,
                    "sameSecretProofRoot",
                    "same-secret proof",
                )?,
            )?);

            transported_proof_materials.push(json!({
                "objectType": "SetupTransportedSameSecretProofMaterial",
                "objectVersion": 1,
                "setupProfileId": "CollectiveBgvSetup-v1",
                "setupProofProfileId": "SealedLattice-SetupProof-v1",
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
                    "bytesHex": to_hex(&proof_bytes),
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
        same_secret_proofs["sameSecretProofSetRoot"] = json!(derive_protocol_hash(
            "SameSecretProofRoot",
            &value_without_root_field(
                same_secret_proofs,
                "sameSecretProofSetRoot",
                "same-secret proof set",
            )?,
        )?);

        Ok(json!({
            "objectType": "SetupTransportedSameSecretProofMaterialSet",
            "objectVersion": 1,
            "setupProfileId": "CollectiveBgvSetup-v1",
            "setupProofProfileId": "SealedLattice-SetupProof-v1",
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
