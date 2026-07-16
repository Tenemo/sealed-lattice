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
    pub(super) proof_material_attempt: TargetDecryptionShareProofMaterialAttempt,
}

pub(super) struct TargetDecryptionShareProofMaterialAttempt {
    proof_bytes: crate::bgv::setup::BgvProofMaterialBytes,
}

pub(super) fn take_target_decryption_share_proof_material_for_active_attempt(
    target_share_proof: &Value,
) -> CanonicalResult<TargetDecryptionShareProofMaterialAttempt> {
    let proof_material = value_at_path(target_share_proof, &["proofMaterial"])?;
    let proof_bytes_hash = hash_at_path(proof_material, &["proofBytesHash"])?;
    // Crossing this boundary transfers the family-scoped authenticated bytes
    // out of the store. Every later refusal aborts the active release session,
    // and a retry must authenticate the proof stream again.
    let proof_bytes = crate::bgv::setup::take_authenticated_canonical_proof_material_bytes(
        crate::bgv::setup::TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        proof_bytes_hash,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "target-decryption share proof material is missing canonical stream-authenticated bytes",
        )
    })?;

    Ok(TargetDecryptionShareProofMaterialAttempt { proof_bytes })
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
            CanonicalErrorCode::InvalidProtocolObject,
            "target-decryption proof material must use the current target proof-material layout",
        ));
    }
    // Keep the one-shot bytes owned by this verification call. The common
    // proof-suite verifier will consume this source once schema 0x1621 lands.
    let _proof_material_bytes = input.proof_material_attempt.proof_bytes;
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "target-decryption share verification requires schema 0x1621 to be verified by the common proof suite",
    ))
}
