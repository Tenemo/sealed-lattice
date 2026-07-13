use super::*;

struct AggregateOpeningMaterialEvictionGuard {
    material_roots: Vec<String>,
}

impl AggregateOpeningMaterialEvictionGuard {
    fn for_request(request: &Value) -> Self {
        let material_roots = request
            .get("localTargetShareWitness")
            .and_then(|witness| witness.get("aggregateOpening"))
            .and_then(|opening| opening.get("aggregateOpeningCredentials"))
            .and_then(Value::as_array)
            .map(|credentials| {
                credentials
                    .iter()
                    .filter_map(|credential| {
                        credential
                            .get("aggregateOpeningRoot")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { material_roots }
    }
}

impl Drop for AggregateOpeningMaterialEvictionGuard {
    fn drop(&mut self) {
        crate::bgv::setup::evict_verified_canonical_proof_materials(&self.material_roots);
    }
}

pub(crate) fn generate_bgv_target_decryption_share_from_local_share_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let _aggregate_opening_material_guard =
        AggregateOpeningMaterialEvictionGuard::for_request(request);
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
    let _aggregate_opening_material_guard =
        AggregateOpeningMaterialEvictionGuard::for_request(request);
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

pub(crate) fn generate_bgv_target_decryption_share_proof_material_from_local_witness_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let _aggregate_opening_material_guard =
        AggregateOpeningMaterialEvictionGuard::for_request(request);
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
            proof_randomness_seed_hex: required_string_field(request, "proofRandomnessSeedHex")?,
            proof_randomness_nonce_hex: required_string_field(request, "proofRandomnessNonceHex")?,
        },
    )
}

pub(crate) fn verify_bgv_target_decryption_share_proof_material_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let _material_eviction_guard = target_proof_material_eviction_guard_for_request(request);
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

pub(crate) fn derive_bgv_target_decryption_result_release_setup_context_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    target_result_release_setup_context_from_setup_package(value_at_path(
        request,
        &["setupPackage"],
    )?)
}

pub(crate) fn begin_bgv_target_decryption_result_release_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_binding = read_target_result_release_setup_context(value_at_path(
        request,
        &["releaseSetupContext"],
    )?)?;
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

    begin_target_decryption_result_release(TargetDecryptionResultReleaseBeginInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
        setup_binding: &setup_binding,
        target_accepted: &target_accepted,
        target_ciphertexts: &target_ciphertexts,
        target_share_profile: &target_share_profile,
    })
}

pub(crate) fn absorb_bgv_target_decryption_result_release_share_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    absorb_target_decryption_result_release_share(TargetDecryptionResultReleaseShareInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
        target_share_proof: value_at_path(request, &["targetShareProof"])?,
    })
}

pub(crate) fn finish_bgv_target_decryption_result_release_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    finish_target_decryption_result_release(TargetDecryptionResultReleaseFinishInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
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
