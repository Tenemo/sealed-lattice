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
        crate::bgv::setup::evict_authenticated_canonical_proof_materials(&self.material_roots);
    }
}

struct TargetDecryptionRequestContext {
    setup_binding: SetupBinding,
    target_accepted: TargetAcceptedBinding,
    target_ciphertexts: TargetCiphertextPair,
}

impl TargetDecryptionRequestContext {
    fn parse(request: &Value) -> CanonicalResult<Self> {
        let setup_binding = read_setup_binding(value_at_path(request, &["setupPackage"])?)?;
        Self::parse_target_inputs(request, setup_binding)
    }

    fn parse_target_inputs(request: &Value, setup_binding: SetupBinding) -> CanonicalResult<Self> {
        let target_accepted = read_target_accepted_binding(
            value_at_path(request, &["targetAcceptedRecord"])?,
            &setup_binding,
        )?;
        let target_ciphertexts = read_target_ciphertext_pair(
            value_at_path(request, &["targetCiphertexts"])?,
            value_at_path(request, &["targetCiphertextBinding"])?,
            &target_accepted,
        )?;
        Ok(Self {
            setup_binding,
            target_accepted,
            target_ciphertexts,
        })
    }
}

pub(crate) fn generate_bgv_target_decryption_share_from_local_share_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let _aggregate_opening_material_guard =
        AggregateOpeningMaterialEvictionGuard::for_request(request);
    let TargetDecryptionRequestContext {
        setup_binding,
        target_accepted,
        target_ciphertexts,
    } = TargetDecryptionRequestContext::parse(request)?;
    let trustee_roster_position = usize_field(request, "trusteeRosterPosition")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_roster_position)?;
    let local_witness = read_local_target_decryption_share_witness(
        value_at_path(request, &["localTargetShareWitness"])?,
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        participant,
    )?;

    generate_target_decryption_share_from_secret_share(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        participant,
        &local_witness.secret_share_by_limb,
        &local_witness.flooding_noise_openings,
    )
}

pub(crate) fn derive_bgv_target_decryption_share_proof_statement_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let _aggregate_opening_material_guard =
        AggregateOpeningMaterialEvictionGuard::for_request(request);
    let TargetDecryptionRequestContext {
        setup_binding,
        target_accepted,
        target_ciphertexts,
    } = TargetDecryptionRequestContext::parse(request)?;
    let trustee_roster_position = usize_field(request, "trusteeRosterPosition")?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_roster_position)?;

    derive_target_decryption_share_proof_statement(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        participant,
        value_at_path(request, &["localTargetShareWitness"])?,
        value_at_path(request, &["targetDecryptionShare"])?,
    )
}

pub(crate) fn verify_bgv_target_decryption_share_proof_statement_binding_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let TargetDecryptionRequestContext {
        setup_binding,
        target_accepted,
        target_ciphertexts,
    } = TargetDecryptionRequestContext::parse(request)?;
    let proof_statement = value_at_path(request, &["proofStatement"])?;
    let trustee_roster_position = usize_at_path(proof_statement, &["trusteeRosterPosition"])?;
    let participant = read_target_decryption_participant(&setup_binding, trustee_roster_position)?;

    verify_target_decryption_share_proof_statement_binding(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        participant,
        value_at_path(request, &["targetDecryptionShare"])?,
        proof_statement,
    )
}

pub(crate) fn begin_bgv_target_decryption_result_release_for_test(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_binding = read_setup_binding(value_at_path(request, &["setupPackage"])?)?;
    let target_accepted = read_target_accepted_binding(
        value_at_path(request, &["targetAcceptedRecord"])?,
        &setup_binding,
    )?;
    let target_ciphertexts = read_target_ciphertext_pair(
        value_at_path(request, &["targetCiphertexts"])?,
        value_at_path(request, &["targetCiphertextBinding"])?,
        &target_accepted,
    )?;
    begin_target_decryption_result_release(TargetDecryptionResultReleaseBeginInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
        setup_binding: &setup_binding,
        target_accepted: &target_accepted,
        target_ciphertexts: &target_ciphertexts,
    })
}

pub(crate) fn absorb_bgv_target_decryption_result_release_share_for_test(
    request: &Value,
) -> CanonicalResult<Value> {
    absorb_target_decryption_result_release_share(TargetDecryptionResultReleaseShareInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
        target_share_proof: value_at_path(request, &["targetShareProof"])?,
    })
}

pub(crate) fn finish_bgv_target_decryption_result_release_for_test(
    request: &Value,
) -> CanonicalResult<Value> {
    finish_target_decryption_result_release(TargetDecryptionResultReleaseFinishInput {
        release_verification_id: required_string_field(request, "releaseVerificationId")?,
    })
}

fn read_target_decryption_participant(
    setup_binding: &SetupBinding,
    trustee_roster_position: usize,
) -> CanonicalResult<&ParticipantBinding> {
    setup_binding
        .participants
        .get(trustee_roster_position)
        .filter(|candidate| candidate.roster_position == trustee_roster_position)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target decryption trustee roster position is not part of the setup roster",
            )
        })
}
