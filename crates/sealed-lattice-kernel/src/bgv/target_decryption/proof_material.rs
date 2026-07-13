use super::*;

const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofMaterial";
const TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofRecord";
const TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/target-decryption/share-proof/proof-bytes";

pub(super) struct TargetDecryptionShareProofMaterialGenerationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a Value,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
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

struct TargetDecryptionShareProofRecordVerificationInput<'a> {
    proof_record: &'a Value,
    proof_bytes: &'a crate::bgv::setup::BgvProofMaterialBytes,
    setup_binding: &'a SetupBinding,
    target_accepted: &'a TargetAcceptedBinding,
    target_ciphertexts: &'a TargetCiphertextPair,
    participant: &'a ParticipantBinding,
    target_decryption_share: &'a Value,
    target_share_proof_statement: &'a Value,
    active_limb_count: usize,
}

pub(super) struct TargetProofMaterialEvictionGuard {
    proof_material_root: String,
}

pub(super) fn target_proof_material_eviction_guard_for_request(
    request: &Value,
) -> Option<TargetProofMaterialEvictionGuard> {
    request
        .get("proofMaterial")
        .and_then(|proof_material| proof_material.get("proofMaterialRoot"))
        .and_then(Value::as_str)
        .map(|proof_material_root| TargetProofMaterialEvictionGuard {
            proof_material_root: proof_material_root.to_string(),
        })
}

impl Drop for TargetProofMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_proof_materials(std::slice::from_ref(
            &self.proof_material_root,
        ));
    }
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
    let proof_slice_request =
        target_decryption_share_all_active_limbs_proof_request_from_local_witness(
            TargetDecryptionShareAllActiveLimbsProofRequestInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                target_share_profile: input.target_share_profile,
                participant: input.participant,
                local_target_share_witness: input.local_target_share_witness,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.proof_statement,
                proof_randomness_seed_hex: input.proof_randomness_seed_hex,
                proof_randomness_nonce_hex: input.proof_randomness_nonce_hex,
            },
        )?;
    let generated = crate::bgv::setup::generate_target_decryption_share_proof_bytes_from_request(
        &proof_slice_request,
    )?;
    let expected_target_roles = expected_target_roles();
    if generated.target_roles != expected_target_roles {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption proof material generator returned noncanonical target-role coverage",
        ));
    }
    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    let expected_target_rns_limb_indices = (0..active_limb_count).collect::<Vec<_>>();
    if generated.target_rns_limb_indices != expected_target_rns_limb_indices {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target-decryption proof material generator returned noncanonical active-limb coverage",
        ));
    }
    let proof_bytes = generated.proof_bytes;
    let proof_bytes_hash = hash512_hex(
        TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
        &[&proof_bytes],
    );
    let proof_record = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE,
        "proofBytesHash": proof_bytes_hash,
    });

    let mut proof_material = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE,
        "proofRecords": [proof_record],
    });
    let proof_material_root = derive_canonical_object_hash(
        &target_decryption_share_proof_material_root_preimage(&proof_material)?,
    )?;
    proof_material["proofMaterialRoot"] = json!(&proof_material_root);
    crate::bgv::setup::retain_generated_canonical_proof_material(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        proof_material_root,
        proof_bytes,
    )?;

    Ok(proof_material)
}

pub(super) fn verify_target_decryption_share_proof_material(
    input: TargetDecryptionShareProofMaterialVerificationInput<'_>,
) -> CanonicalResult<Value> {
    let supplied_material_root = hash_at_path(input.proof_material, &["proofMaterialRoot"])?;
    let _material_eviction_guard = TargetProofMaterialEvictionGuard {
        proof_material_root: supplied_material_root.to_string(),
    };
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
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof material must use the current target proof-material layout",
        ));
    }
    let expected_material_root = derive_canonical_object_hash(
        &target_decryption_share_proof_material_root_preimage(input.proof_material)?,
    )?;
    compare_hash_field(
        input.proof_material,
        "proofMaterialRoot",
        &expected_material_root,
        "target-decryption proof material root",
    )?;

    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    let proof_records = array_at_path(input.proof_material, &["proofRecords"])?;
    if proof_records.len() != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption proof material must include one all-active-limb proof record",
        ));
    }
    let proof_bytes = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        &expected_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target-decryption proof material is missing its canonical stream-authenticated bytes",
        )
    })?;

    for proof_record in proof_records {
        verify_target_decryption_share_proof_record(
            TargetDecryptionShareProofRecordVerificationInput {
                proof_record,
                proof_bytes: &proof_bytes,
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                target_share_proof_statement: input.proof_statement,
                active_limb_count,
            },
        )?;
    }

    Ok(json!({
        "proofMaterialRoot": expected_material_root,
    }))
}

fn verify_target_decryption_share_proof_record(
    input: TargetDecryptionShareProofRecordVerificationInput<'_>,
) -> CanonicalResult<()> {
    let proof_record = input.proof_record;
    if string_at_path(proof_record, &["objectType"])?
        != TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof record must use the current target proof-record layout",
        ));
    }
    let expected_target_rns_limb_indices = (0..input.active_limb_count).collect::<Vec<_>>();
    let expected_target_roles = expected_target_roles();
    let proof_bytes_hash = hash_at_path(proof_record, &["proofBytesHash"])?;
    let recomputed_proof_bytes_hash = crate::hashing::hash512_hex_streamed_part(
        TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
        input.proof_bytes.len(),
        input.proof_bytes.chunks(),
    )?;
    if proof_bytes_hash != recomputed_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proofBytesHash does not match the authenticated proof bytes",
        ));
    }
    let proof_verification_request =
        target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
            TargetDecryptionShareAllActiveLimbsProofStatementInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.target_share_proof_statement,
            },
        )?;
    let proof_verification =
        crate::bgv::setup::verify_target_decryption_share_proof_source_from_request(
            &proof_verification_request,
            input.proof_bytes.as_ref(),
        )?;
    compare_string_field(
        &proof_verification,
        "proofFamily",
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "target-decryption proof verification proof family",
    )?;
    compare_target_roles_field(
        &proof_verification,
        &expected_target_roles,
        "target-decryption proof verification target roles",
    )?;
    compare_target_limb_indices_field(
        &proof_verification,
        &expected_target_rns_limb_indices,
        "target-decryption proof verification target limbs",
    )?;
    compare_unsigned_field(
        &proof_verification,
        "proofByteLength",
        input.proof_bytes.len() as u64,
        "target-decryption proof verification proof byte length",
    )?;

    Ok(())
}

fn expected_target_roles() -> Vec<String> {
    TARGET_DECRYPTION_SMUDGING_ROLES
        .iter()
        .map(|target_role| (*target_role).to_string())
        .collect()
}

fn compare_target_roles_field(
    value: &Value,
    expected_target_roles: &[String],
    field_description: &str,
) -> CanonicalResult<()> {
    let actual_target_roles = array_at_path(value, &["targetRoles"])?;
    if actual_target_roles.len() != expected_target_roles.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{field_description} count does not match"),
        ));
    }
    for (actual_role, expected_role) in actual_target_roles.iter().zip(expected_target_roles) {
        if actual_role.as_str() != Some(expected_role.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("{field_description} do not match"),
            ));
        }
    }

    Ok(())
}

fn compare_target_limb_indices_field(
    value: &Value,
    expected_target_rns_limb_indices: &[usize],
    field_description: &str,
) -> CanonicalResult<()> {
    let actual_target_rns_limb_indices = array_at_path(value, &["targetRnsLimbIndices"])?;
    if actual_target_rns_limb_indices.len() != expected_target_rns_limb_indices.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            format!("{field_description} count does not match"),
        ));
    }
    for (actual_target_rns_limb_index, expected_target_rns_limb_index) in
        actual_target_rns_limb_indices
            .iter()
            .zip(expected_target_rns_limb_indices)
    {
        if actual_target_rns_limb_index.as_u64() != Some(*expected_target_rns_limb_index as u64) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                format!("{field_description} do not match"),
            ));
        }
    }

    Ok(())
}

fn target_decryption_share_proof_material_root_preimage(
    proof_material: &Value,
) -> CanonicalResult<Value> {
    let mut root_preimage = proof_material.clone();
    let root_preimage_object = root_preimage.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof material root preimage must be an object",
        )
    })?;
    root_preimage_object.remove("proofMaterialRoot");
    Ok(root_preimage)
}
