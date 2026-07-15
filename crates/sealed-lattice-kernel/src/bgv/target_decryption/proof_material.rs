use super::*;

const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofMaterial";
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

pub(super) struct TargetProofMaterialAttemptGuard {
    proof_bytes_hash: String,
}

pub(super) fn target_proof_material_attempt_guard(
    request: &Value,
) -> Option<TargetProofMaterialAttemptGuard> {
    request
        .get("proofMaterial")
        .and_then(|proof_material| proof_material.get("proofBytesHash"))
        .and_then(Value::as_str)
        .map(|proof_bytes_hash| TargetProofMaterialAttemptGuard {
            proof_bytes_hash: proof_bytes_hash.to_string(),
        })
}

impl Drop for TargetProofMaterialAttemptGuard {
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
    _proof_slice_request: &Value,
) -> CanonicalResult<Value> {
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "target-decryption share generation requires schema 0x1621 to be proved by the common proof suite",
    ))
}

pub(super) fn verify_target_decryption_share_proof_material(
    input: TargetDecryptionShareProofMaterialVerificationInput<'_>,
) -> CanonicalResult<()> {
    let proof_bytes_hash = hash_at_path(input.proof_material, &["proofBytesHash"])?;
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
    // Transfer the authenticated bytes out of the store for the one-shot proof
    // verification. A verifier refusal drops them, while the surrounding
    // active-attempt guard also clears material on earlier validation errors.
    let _proof_material_bytes = crate::bgv::setup::take_verified_canonical_proof_material_bytes(
        crate::bgv::setup::TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        &proof_bytes_hash,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target-decryption share proof material is missing canonical stream-authenticated bytes",
        )
    })?;
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "target-decryption share verification requires schema 0x1621 to be verified by the common proof suite",
    ))
}
