use super::*;

pub(super) fn verify_target_decryption_relation_from_local_witness(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    local_target_share_witness: &Value,
    target_decryption_share: &Value,
) -> CanonicalResult<LocalTargetDecryptionShareWitness> {
    read_partial_decryption_share(
        target_decryption_share,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
    )?;
    let local_witness = read_local_target_decryption_share_witness(
        local_target_share_witness,
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
    )?;
    let expected_share = generate_target_decryption_share_from_secret_share(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &local_witness.secret_share_by_limb,
        &local_witness.smudging_polynomial_openings,
    )?;

    if value_at_path(target_decryption_share, &["sharePayload"])?
        != value_at_path(&expected_share, &["sharePayload"])?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target decryption share payload does not satisfy the restored local witness relation",
        ));
    }
    let expected_share_root = hash_at_path(&expected_share, &["shareRoot"])?;
    compare_hash_field(
        target_decryption_share,
        "shareRoot",
        expected_share_root,
        "target decryption share root restored from local witness",
    )?;
    let expected_share_hash = hash_at_path(&expected_share, &["targetDecryptionShareHash"])?;
    compare_hash_field(
        target_decryption_share,
        "targetDecryptionShareHash",
        expected_share_hash,
        "target decryption share hash restored from local witness",
    )?;

    Ok(local_witness)
}
