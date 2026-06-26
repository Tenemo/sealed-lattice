use std::collections::{BTreeMap, BTreeSet};

use super::*;

const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofMaterial";
const TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofRecord";

pub(super) struct TargetDecryptionShareProofMaterialGenerationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a Value,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_randomness_source: &'a str,
    pub(super) proof_randomness_seed_hex: &'a str,
    pub(super) proof_randomness_nonce_hex: &'a str,
}

pub(super) struct TargetDecryptionShareProofMaterialVerificationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_material: &'a Value,
}

pub(super) fn generate_target_decryption_share_proof_material_from_local_witness(
    input: TargetDecryptionShareProofMaterialGenerationInput<'_>,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.target_decryption_share,
    )?;
    let target_share_proof_statement_root =
        hash_at_path(input.proof_statement, &["proofStatementRoot"])?.to_string();
    let target_decryption_share_hash = hash_at_path(
        input.target_decryption_share,
        &["targetDecryptionShareHash"],
    )?
    .to_string();
    let share_root = hash_at_path(input.target_decryption_share, &["shareRoot"])?.to_string();
    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    let mut proof_records =
        Vec::with_capacity(TARGET_DECRYPTION_SMUDGING_ROLES.len() * active_limb_count);
    let mut proof_statements = Vec::with_capacity(proof_records.capacity());
    let mut total_proof_byte_length = 0_usize;

    for target_role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for target_rns_limb_index in 0..active_limb_count {
            let proof_slice_request =
                target_decryption_share_proof_slice_request_from_local_witness(
                    TargetDecryptionShareProofSliceRequestInput {
                        setup_binding: input.setup_binding,
                        target_accepted: input.target_accepted,
                        target_ciphertexts: input.target_ciphertexts,
                        target_share_profile: input.target_share_profile,
                        participant: input.participant,
                        local_target_share_witness: input.local_target_share_witness,
                        target_decryption_share: input.target_decryption_share,
                        proof_statement: input.proof_statement,
                        target_role,
                        target_rns_limb_index,
                        proof_randomness_source: input.proof_randomness_source,
                        proof_randomness_seed_hex: input.proof_randomness_seed_hex,
                        proof_randomness_nonce_hex: input.proof_randomness_nonce_hex,
                    },
                )?;
            let generated = crate::bgv::setup::generate_target_decryption_share_proof_from_request(
                &proof_slice_request,
            )?;
            let proof_slice_statement = proof_slice_statement_from_request(&proof_slice_request)?;
            let proof_statement_hash = hash_at_path(&generated, &["statementHash"])?.to_string();
            let proof_bytes_hex = string_at_path(&generated, &["proofBytesHex"])?.to_string();
            let proof_bytes = decode_hex(&proof_bytes_hex)?;
            let proof_byte_length = proof_bytes.len();
            total_proof_byte_length = total_proof_byte_length
                .checked_add(proof_byte_length)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target-decryption proof material byte length overflowed",
                    )
                })?;
            let proof_bytes_hash = hash512_hex(
                TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
                &[&proof_bytes],
            );
            let proof_record_without_root = json!({
                "objectType": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE,
                "objectVersion": 1,
                "proofFamily": TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
                "targetShareProofStatementRoot": target_share_proof_statement_root,
                "targetRole": target_role,
                "targetRnsLimbIndex": target_rns_limb_index,
                "proofStatementHash": proof_statement_hash,
                "proofByteLength": proof_byte_length,
                "proofBytesHash": proof_bytes_hash,
                "proofBytesHex": proof_bytes_hex,
            });
            let mut proof_record = proof_record_without_root;
            proof_record["proofRecordRoot"] = json!(derive_protocol_hash(
                "TargetDecryptionShareProofRecordRoot",
                &proof_record
            )?);

            let mut packaged_proof_statement = proof_slice_statement;
            packaged_proof_statement["proofStatementHash"] = json!(proof_statement_hash);
            proof_records.push(proof_record);
            proof_statements.push(packaged_proof_statement);
        }
    }

    let mut proof_material = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE,
        "objectVersion": 1,
        "targetShareProofStatementRoot": target_share_proof_statement_root,
        "targetDecryptionShareHash": target_decryption_share_hash,
        "shareRoot": share_root,
        "trusteeIdentity": input.participant.trustee_identity,
        "trusteeRosterPosition": input.participant.roster_position,
        "activeRnsLimbCount": active_limb_count,
        "targetRoleCount": TARGET_DECRYPTION_SMUDGING_ROLES.len(),
        "proofRecordCount": proof_records.len(),
        "totalProofByteLength": total_proof_byte_length,
        "proofRecords": proof_records,
        "proofStatements": proof_statements,
    });
    proof_material["proofMaterialRoot"] = json!(derive_protocol_hash(
        "TargetDecryptionShareProofMaterialRoot",
        &proof_material
    )?);

    Ok(proof_material)
}

pub(super) fn verify_target_decryption_share_proof_material(
    input: TargetDecryptionShareProofMaterialVerificationInput<'_>,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.target_decryption_share,
    )?;
    if string_at_path(input.proof_material, &["objectType"])?
        != TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE
        || unsigned_at_path(input.proof_material, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof material must be BgvTargetDecryptionShareProofMaterial version 1",
        ));
    }
    let mut material_without_root = input.proof_material.clone();
    material_without_root
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target-decryption proof material must be an object",
            )
        })?
        .remove("proofMaterialRoot")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target-decryption proof material must include proofMaterialRoot",
            )
        })?;
    let expected_material_root = derive_protocol_hash(
        "TargetDecryptionShareProofMaterialRoot",
        &material_without_root,
    )?;
    compare_hash_field(
        input.proof_material,
        "proofMaterialRoot",
        &expected_material_root,
        "target-decryption proof material root",
    )?;

    let target_share_proof_statement_root =
        hash_at_path(input.proof_statement, &["proofStatementRoot"])?;
    compare_hash_field(
        input.proof_material,
        "targetShareProofStatementRoot",
        target_share_proof_statement_root,
        "target-decryption proof material statement root",
    )?;
    compare_hash_field(
        input.proof_material,
        "targetDecryptionShareHash",
        hash_at_path(
            input.target_decryption_share,
            &["targetDecryptionShareHash"],
        )?,
        "target-decryption proof material share hash",
    )?;
    compare_hash_field(
        input.proof_material,
        "shareRoot",
        hash_at_path(input.target_decryption_share, &["shareRoot"])?,
        "target-decryption proof material share root",
    )?;
    compare_string_field(
        input.proof_material,
        "trusteeIdentity",
        &input.participant.trustee_identity,
        "target-decryption proof material trustee identity",
    )?;
    compare_unsigned_field(
        input.proof_material,
        "trusteeRosterPosition",
        input.participant.roster_position as u64,
        "target-decryption proof material trustee roster position",
    )?;
    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    compare_unsigned_field(
        input.proof_material,
        "activeRnsLimbCount",
        active_limb_count as u64,
        "target-decryption proof material active limb count",
    )?;
    compare_unsigned_field(
        input.proof_material,
        "targetRoleCount",
        TARGET_DECRYPTION_SMUDGING_ROLES.len() as u64,
        "target-decryption proof material role count",
    )?;

    let proof_records = array_at_path(input.proof_material, &["proofRecords"])?;
    let proof_statements = array_at_path(input.proof_material, &["proofStatements"])?;
    let expected_proof_count = TARGET_DECRYPTION_SMUDGING_ROLES
        .len()
        .checked_mul(active_limb_count)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption proof material expected proof count overflowed",
            )
        })?;
    if proof_records.len() != expected_proof_count || proof_statements.len() != expected_proof_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption proof material must include one proof record and statement per active role and limb",
        ));
    }
    compare_unsigned_field(
        input.proof_material,
        "proofRecordCount",
        proof_records.len() as u64,
        "target-decryption proof material record count",
    )?;

    let mut proof_statements_by_hash = BTreeMap::new();
    for proof_statement in proof_statements {
        let proof_statement_hash = hash_at_path(proof_statement, &["proofStatementHash"])?;
        if proof_statements_by_hash
            .insert(proof_statement_hash.to_string(), proof_statement)
            .is_some()
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target-decryption proof material statements must not repeat proofStatementHash",
            ));
        }
    }

    let mut covered_slices = BTreeSet::new();
    let mut total_proof_byte_length = 0_usize;
    for proof_record in proof_records {
        verify_target_decryption_share_proof_record(
            proof_record,
            &proof_statements_by_hash,
            target_share_proof_statement_root,
            active_limb_count,
            &mut covered_slices,
            &mut total_proof_byte_length,
        )?;
    }
    for target_role in TARGET_DECRYPTION_SMUDGING_ROLES {
        for target_rns_limb_index in 0..active_limb_count {
            if !covered_slices.contains(&(target_role.to_string(), target_rns_limb_index)) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption proof material is missing an active target role and limb",
                ));
            }
        }
    }
    compare_unsigned_field(
        input.proof_material,
        "totalProofByteLength",
        total_proof_byte_length as u64,
        "target-decryption proof material total proof byte length",
    )?;

    Ok(json!({
        "ok": true,
        "operation": "verifyBgvTargetDecryptionShareProofMaterial",
        "targetShareProofStatementRoot": target_share_proof_statement_root,
        "targetDecryptionShareHash": hash_at_path(input.target_decryption_share, &["targetDecryptionShareHash"])?,
        "proofMaterialRoot": expected_material_root,
        "verifiedProofCount": proof_records.len(),
        "totalProofByteLength": total_proof_byte_length,
    }))
}

fn verify_target_decryption_share_proof_record(
    proof_record: &Value,
    proof_statements_by_hash: &BTreeMap<String, &Value>,
    target_share_proof_statement_root: &str,
    active_limb_count: usize,
    covered_slices: &mut BTreeSet<(String, usize)>,
    total_proof_byte_length: &mut usize,
) -> CanonicalResult<()> {
    if string_at_path(proof_record, &["objectType"])?
        != TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE
        || unsigned_at_path(proof_record, &["objectVersion"])? != 1
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof record must be BgvTargetDecryptionShareProofRecord version 1",
        ));
    }
    compare_string_field(
        proof_record,
        "proofFamily",
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "target-decryption proof record proof family",
    )?;
    compare_hash_field(
        proof_record,
        "targetShareProofStatementRoot",
        target_share_proof_statement_root,
        "target-decryption proof record target statement root",
    )?;
    let target_role = string_at_path(proof_record, &["targetRole"])?;
    if !TARGET_DECRYPTION_SMUDGING_ROLES.contains(&target_role) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption proof record targetRole is not supported",
        ));
    }
    let target_rns_limb_index = usize_at_path(proof_record, &["targetRnsLimbIndex"])?;
    if target_rns_limb_index >= active_limb_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption proof record limb is outside the active target range",
        ));
    }
    if !covered_slices.insert((target_role.to_string(), target_rns_limb_index)) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption proof material repeats a target role and limb",
        ));
    }
    let proof_statement_hash = hash_at_path(proof_record, &["proofStatementHash"])?;
    let proof_statement = proof_statements_by_hash
        .get(proof_statement_hash)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target-decryption proof record has no matching packaged proof statement",
            )
        })?;
    compare_hash_field(
        value_at_path(proof_statement, &["context"])?,
        "targetShareProofStatementRoot",
        target_share_proof_statement_root,
        "target-decryption packaged proof statement context root",
    )?;
    let proof_statement_target_share = value_at_path(proof_statement, &["targetDecryptionShare"])?;
    compare_hash_field(
        proof_statement_target_share,
        "targetShareProofStatementRoot",
        target_share_proof_statement_root,
        "target-decryption packaged proof statement target root",
    )?;
    compare_string_field(
        proof_statement_target_share,
        "targetRole",
        target_role,
        "target-decryption packaged proof statement target role",
    )?;
    compare_unsigned_field(
        proof_statement_target_share,
        "targetRnsLimbIndex",
        target_rns_limb_index as u64,
        "target-decryption packaged proof statement limb",
    )?;
    let proof_bytes_hex = string_at_path(proof_record, &["proofBytesHex"])?;
    let proof_bytes = decode_hex(proof_bytes_hex)?;
    let proof_byte_length = usize_at_path(proof_record, &["proofByteLength"])?;
    if proof_byte_length != proof_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption proof record proofByteLength must match proofBytesHex",
        ));
    }
    let expected_proof_bytes_hash = hash512_hex(
        TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
        &[&proof_bytes],
    );
    compare_hash_field(
        proof_record,
        "proofBytesHash",
        &expected_proof_bytes_hash,
        "target-decryption proof record proofBytesHash",
    )?;
    let proof_record_without_root = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE,
        "objectVersion": 1,
        "proofFamily": TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "targetShareProofStatementRoot": target_share_proof_statement_root,
        "targetRole": target_role,
        "targetRnsLimbIndex": target_rns_limb_index,
        "proofStatementHash": proof_statement_hash,
        "proofByteLength": proof_byte_length,
        "proofBytesHash": expected_proof_bytes_hash,
        "proofBytesHex": proof_bytes_hex,
    });
    let expected_proof_record_root = derive_protocol_hash(
        "TargetDecryptionShareProofRecordRoot",
        &proof_record_without_root,
    )?;
    compare_hash_field(
        proof_record,
        "proofRecordRoot",
        &expected_proof_record_root,
        "target-decryption proof record root",
    )?;

    let mut proof_verification_request = (*proof_statement).clone();
    proof_verification_request
        .as_object_mut()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target-decryption packaged proof statement must be an object",
            )
        })?
        .remove("proofStatementHash");
    proof_verification_request["proofBytesHex"] = json!(proof_bytes_hex);
    let proof_verification = crate::bgv::setup::verify_target_decryption_share_proof_from_request(
        &proof_verification_request,
    )?;
    compare_string_field(
        &proof_verification,
        "proofFamily",
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "target-decryption proof verification proof family",
    )?;
    compare_hash_field(
        &proof_verification,
        "statementHash",
        proof_statement_hash,
        "target-decryption proof verification statement hash",
    )?;
    compare_string_field(
        &proof_verification,
        "targetRole",
        target_role,
        "target-decryption proof verification target role",
    )?;
    compare_unsigned_field(
        &proof_verification,
        "targetRnsLimbIndex",
        target_rns_limb_index as u64,
        "target-decryption proof verification limb",
    )?;
    compare_unsigned_field(
        &proof_verification,
        "proofByteLength",
        proof_byte_length as u64,
        "target-decryption proof verification proof byte length",
    )?;
    *total_proof_byte_length = total_proof_byte_length
        .checked_add(proof_byte_length)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption proof material byte length overflowed",
            )
        })?;

    Ok(())
}
