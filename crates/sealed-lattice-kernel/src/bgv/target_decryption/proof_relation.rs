use super::*;

pub(super) fn verify_target_decryption_relation_from_local_witness(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    local_target_share_witness: &Value,
    target_decryption_share: &Value,
) -> CanonicalResult<LocalTargetDecryptionShareWitness> {
    read_partial_decryption_share(
        target_decryption_share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
    )?;
    let local_witness = read_local_target_decryption_share_witness(
        local_target_share_witness,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
    )?;
    let expected_share = generate_target_decryption_share_from_secret_share(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        &local_witness.secret_share_by_limb,
        &local_witness.flooding_noise_openings,
    )?;

    if value_at_path(target_decryption_share, &["sharePayload"])?
        != value_at_path(&expected_share, &["sharePayload"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "target decryption share payload does not satisfy the restored local witness relation",
        ));
    }
    Ok(local_witness)
}
