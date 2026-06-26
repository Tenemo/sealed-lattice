use super::*;

pub(crate) fn generate_bgv_target_decryption_share_from_local_share_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;
    let local_witness = read_local_target_decryption_share_witness(
        value_at_path(request, &["localTargetShareWitness"])?,
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        participant,
    )?;

    generate_target_decryption_share_from_secret_share(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        participant,
        &local_witness.secret_share_by_limb,
        &local_witness.smudging_polynomial_openings,
    )
}

pub(crate) fn derive_bgv_target_decryption_share_proof_statement_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;

    derive_target_decryption_share_proof_statement(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        participant,
        value_at_path(request, &["localTargetShareWitness"])?,
        value_at_path(request, &["targetDecryptionShare"])?,
    )
}

pub(crate) fn verify_bgv_target_decryption_share_proof_statement_binding_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let proof_statement = value_at_path(request, &["proofStatement"])?;
    let trustee_identity = string_at_path(proof_statement, &["trusteeIdentity"])?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;

    verify_target_decryption_share_proof_statement_binding(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_profile,
        participant,
        value_at_path(request, &["targetDecryptionShare"])?,
        proof_statement,
    )
}

pub(crate) fn generate_bgv_target_decryption_share_proof_slice_from_local_witness_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;
    let proof_request = target_decryption_share_proof_slice_request_from_local_witness(
        TargetDecryptionShareProofSliceRequestInput {
            setup_binding: &setup_binding,
            target_accepted: &target_accepted,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile,
            participant,
            local_target_share_witness: value_at_path(request, &["localTargetShareWitness"])?,
            target_decryption_share: value_at_path(request, &["targetDecryptionShare"])?,
            proof_statement: value_at_path(request, &["proofStatement"])?,
            target_role: required_string_field(request, "targetRole")?,
            target_rns_limb_index: usize_at_path(request, &["targetRnsLimbIndex"])?,
            proof_randomness_source: required_string_field(request, "proofRandomnessSource")?,
            proof_randomness_seed_hex: required_string_field(request, "proofRandomnessSeedHex")?,
            proof_randomness_nonce_hex: required_string_field(request, "proofRandomnessNonceHex")?,
        },
    )?;
    let generated =
        crate::bgv::setup::generate_target_decryption_share_proof_from_request(&proof_request)?;
    let proof_bytes_hex = required_string_field(&generated, "proofBytesHex")?;
    let proof_bytes = decode_hex(proof_bytes_hex)?;
    let proof_slice_statement = proof_slice_statement_from_request(&proof_request)?;

    Ok(json!({
        "ok": true,
        "operation": "generateBgvTargetDecryptionShareProofSliceFromLocalWitness",
        "proofFamily": generated["proofFamily"],
        "statementHash": generated["statementHash"],
        "targetRole": generated["targetRole"],
        "targetRnsLimbIndex": generated["targetRnsLimbIndex"],
        "proofByteLength": generated["proofByteLength"],
        "proofBytesHash": hash512_hex(
            TARGET_DECRYPTION_SHARE_PROOF_BYTES_HASH_DOMAIN,
            &[&proof_bytes],
        ),
        "proofBytesHex": proof_bytes_hex,
        "proofSliceStatement": proof_slice_statement,
    }))
}

pub(crate) fn generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;

    generate_target_decryption_share_proof_material_from_local_witness(
        TargetDecryptionShareProofMaterialGenerationInput {
            setup_binding: &setup_binding,
            target_accepted: &target_accepted,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile,
            participant,
            local_target_share_witness: value_at_path(request, &["localTargetShareWitness"])?,
            target_decryption_share: value_at_path(request, &["targetDecryptionShare"])?,
            proof_statement: value_at_path(request, &["proofStatement"])?,
            proof_randomness_source: required_string_field(request, "proofRandomnessSource")?,
            proof_randomness_seed_hex: required_string_field(request, "proofRandomnessSeedHex")?,
            proof_randomness_nonce_hex: required_string_field(request, "proofRandomnessNonceHex")?,
        },
    )
}

pub(crate) fn verify_bgv_target_decryption_share_proof_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let proof_statement = value_at_path(request, &["proofStatement"])?;
    let trustee_identity = string_at_path(proof_statement, &["trusteeIdentity"])?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_identity)?;

    verify_target_decryption_share_proof_material(
        TargetDecryptionShareProofMaterialVerificationInput {
            setup_binding: &setup_binding,
            target_accepted: &target_accepted,
            target_ciphertexts: &target_ciphertexts,
            target_share_profile: &target_share_profile,
            participant,
            target_decryption_share: value_at_path(request, &["targetDecryptionShare"])?,
            proof_statement,
            proof_material: value_at_path(request, &["proofMaterial"])?,
        },
    )
}

pub(crate) fn verify_and_recombine_bgv_target_decryption_shares_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_package = value_at_path(request, &["setupPackage"])?;
    let setup_binding = read_setup_binding(setup_package)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    let target_share_profile = read_target_share_profile(
        value_at_path(request, &["targetShareProfile"])?,
        &setup_binding,
    )?;
    let target_decryption_shares = array_at_path(request, &["targetDecryptionShares"])?;
    let proof_statements = array_at_path(request, &["proofStatements"])?;
    let proof_materials = array_at_path(request, &["proofMaterials"])?;
    if target_decryption_shares.len() != proof_statements.len()
        || target_decryption_shares.len() != proof_materials.len()
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target recombination requires matching share, proof statement, and proof material arrays",
        ));
    }
    let proof_bundles = target_decryption_shares
        .iter()
        .zip(proof_statements.iter())
        .zip(proof_materials.iter())
        .map(
            |((target_decryption_share, proof_statement), proof_material)| {
                TargetDecryptionShareProofBundle {
                    target_decryption_share,
                    proof_statement,
                    proof_material,
                }
            },
        )
        .collect::<Vec<_>>();

    verify_and_recombine_target_decryption_shares(TargetDecryptionRecombinationInput {
        setup_binding: &setup_binding,
        target_accepted: &target_accepted,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
        proof_bundles,
    })
}

fn read_target_decryption_participant<'a>(
    setup_binding: &'a SetupBinding,
    trustee_identity: &str,
) -> CanonicalResult<&'a ParticipantBinding> {
    setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption trusteeIdentity is not part of the setup roster",
            )
        })
}
