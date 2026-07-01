use super::*;

pub(crate) fn generate_bgv_target_decryption_share_from_request(
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
    let target_share_parameters = read_target_share_parameters(
        value_at_path(request, &["targetShareParameters"])?,
        &setup_binding,
    )?;
    let trustee_identity = required_string_field(request, "trusteeIdentity")?;
    let participant = setup_binding
        .participants
        .iter()
        .find(|candidate| candidate.trustee_identity == trustee_identity)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption trusteeIdentity is not part of the setup roster",
            )
        })?;
    let private_setup_seed = string_at_path(request, &["setupPrivateWitness", "setupSeed"])?;
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, private_setup_seed)?;

    generate_target_decryption_share(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_parameters,
        participant,
        &evaluator_key,
        private_setup_seed,
    )
}

pub(crate) fn recombine_bgv_target_decryption_shares_from_request(
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
    let target_share_parameters = read_target_share_parameters(
        value_at_path(request, &["targetShareParameters"])?,
        &setup_binding,
    )?;
    let share_records = request
        .get("decryptionShares")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "decryptionShares must be an array",
            )
        })?;
    let shares = share_records
        .iter()
        .map(|share| {
            read_partial_decryption_share(
                share,
                &setup_binding,
                &target_accepted,
                &target_ciphertexts,
                &target_share_parameters,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    recombine_target_decryption_shares(
        &setup_binding,
        &target_accepted,
        &target_ciphertexts,
        &target_share_parameters,
        shares,
    )
}
