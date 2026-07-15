use super::*;

const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofMaterial";
const TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/target-decryption/share-proof/proof-bytes";

pub(super) struct VerifiedLocalTargetDecryptionShareProofMaterialGenerationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a LocalTargetDecryptionShareWitness,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_randomness_seed_hex: &'a str,
}

pub(super) struct TargetDecryptionShareProofMaterialVerificationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_material: &'a Value,
}

pub(super) struct TargetProofMaterialEvictionGuard {
    proof_bytes_hash: String,
}

pub(super) fn target_proof_material_eviction_guard_for_request(
    request: &Value,
) -> Option<TargetProofMaterialEvictionGuard> {
    request
        .get("proofMaterial")
        .and_then(|proof_material| proof_material.get("proofBytesHash"))
        .and_then(Value::as_str)
        .map(|proof_bytes_hash| TargetProofMaterialEvictionGuard {
            proof_bytes_hash: proof_bytes_hash.to_string(),
        })
}

impl Drop for TargetProofMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_proof_materials(std::slice::from_ref(
            &self.proof_bytes_hash,
        ));
    }
}

pub(super) fn generate_target_decryption_share_proof_material_from_verified_local_witness(
    input: VerifiedLocalTargetDecryptionShareProofMaterialGenerationInput<'_>,
) -> CanonicalResult<Value> {
    let proof_slice_request =
        target_decryption_share_all_active_limbs_proof_request_from_verified_local_witness(
            VerifiedLocalTargetDecryptionShareAllActiveLimbsProofRequestInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                local_target_share_witness: input.local_target_share_witness,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.proof_statement,
                proof_randomness_seed_hex: input.proof_randomness_seed_hex,
            },
        )?;
    generate_and_retain_target_decryption_share_proof_material(&proof_slice_request)
}

fn generate_and_retain_target_decryption_share_proof_material(
    proof_slice_request: &Value,
) -> CanonicalResult<Value> {
    let proof_bytes = crate::bgv::setup::generate_target_decryption_share_proof_bytes_from_request(
        proof_slice_request,
    )?;
    let proof_bytes_hash = hash512_hex(
        TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
        &[&proof_bytes],
    );
    let proof_material = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE,
        "proofBytesHash": &proof_bytes_hash,
    });
    crate::bgv::setup::retain_generated_canonical_proof_material(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
        proof_bytes,
    )?;

    Ok(proof_material)
}

pub(super) fn verify_target_decryption_share_proof_material(
    input: TargetDecryptionShareProofMaterialVerificationInput<'_>,
) -> CanonicalResult<()> {
    let supplied_proof_bytes_hash = hash_at_path(input.proof_material, &["proofBytesHash"])?;
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
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
    let proof_bytes = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        supplied_proof_bytes_hash,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target-decryption proof material is missing its canonical stream-authenticated bytes",
        )
    })?;

    let recomputed_proof_bytes_hash = crate::hashing::hash512_hex_streamed_part(
        TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
        proof_bytes.len(),
        proof_bytes.chunks(),
    )?;
    if supplied_proof_bytes_hash != recomputed_proof_bytes_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proofBytesHash does not match the authenticated proof bytes",
        ));
    }
    let proof_verification_request =
        target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
            TargetDecryptionShareAllActiveLimbsProofStatementInput {
                setup_binding: input.setup_binding,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.proof_statement,
            },
        )?;
    crate::bgv::setup::verify_target_decryption_share_proof_source_from_request(
        &proof_verification_request,
        proof_bytes.as_ref(),
    )?;

    Ok(())
}
