use super::*;

pub(super) fn generate_target_decryption_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    evaluator_key: &DevelopmentBgvKey,
    private_setup_seed: &str,
) -> CanonicalResult<Value> {
    let level = target_ciphertexts.target_id.level;
    let secret_share = derive_threshold_secret_share_by_limb(
        evaluator_key,
        &setup_binding.setup_package_hash,
        &target_share_profile.hash,
        private_setup_seed,
        participant.interpolation_point,
        target_share_profile.minimum_shares_for_interpolation,
        level,
    )?;
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, &secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, &secret_share)?;
    let payload = share_payload(level, &target_id_partials, &target_order_partials)?;
    let share_root = derive_protocol_hash("BgvTargetDecryptionShareRoot", &payload)?;
    let record_hash_input = share_record_hash_input(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        participant,
        &share_root,
    );
    let target_decryption_share_hash =
        derive_protocol_hash("BgvTargetDecryptionShareHash", &record_hash_input)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShare",
        "objectVersion": 1,
        "targetDecryptionShareHash": target_decryption_share_hash,
        "setupPackageHash": setup_binding.setup_package_hash,
        "ceremonyId": setup_binding.ceremony_id,
        "electionManifestHash": setup_binding.election_manifest_hash,
        "trusteeIdentity": participant.trustee_identity,
        "rosterPosition": participant.roster_position,
        "boardPosition": participant.board_position,
        "interpolationPoint": participant.interpolation_point,
        "recoveryEpoch": participant.recovery_epoch,
        "deviceEpoch": participant.device_epoch,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetProposalHash": target_accepted.target_proposal_hash,
        "targetPreimageHash": target_accepted.target_preimage_hash,
        "targetFinalityRecordHash": target_accepted.target_finality_record_hash,
        "targetFinalityCheckpointHash": target_accepted.target_finality_checkpoint_hash,
        "evaluatorReplayRecordHash": target_accepted.evaluator_replay_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetDecryptionCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "targetCiphertextBindingHash": target_ciphertexts.target_ciphertext_binding_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "targetDecryptionProfileBindingHash": setup_binding.target_decryption_profile_binding_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "thresholdShareVerificationKeyRoot": setup_binding.threshold_verification.threshold_share_verification_key_root,
        "thresholdShareVerificationKeyHash": setup_binding.threshold_verification.threshold_share_verification_key_hash,
        "trusteeThresholdVerificationKeyHash": participant.trustee_threshold_verification_key_hash,
        "shareEquation": TARGET_SHARE_EQUATION,
        "shareRoot": share_root,
        "sharePayload": payload,
        "statusLabels": [
            "TargetBoundPartDecComputed",
            "AcceptedTargetContextBound",
            "ShareProofCertificationPending"
        ],
    }))
}

pub(super) fn derive_threshold_secret_share_by_limb(
    evaluator_key: &DevelopmentBgvKey,
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    level: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let secret = evaluator_key.secret();

    #[cfg(not(target_arch = "wasm32"))]
    {
        DATA_PRIMES[..=level]
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        DATA_PRIMES[..=level]
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                derive_threshold_secret_share_limb(
                    secret,
                    setup_package_hash,
                    target_share_profile_hash,
                    private_setup_seed,
                    interpolation_point,
                    minimum_shares_for_interpolation,
                    limb_index,
                    *modulus,
                )
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
// Development-only dealer: this reshares the actual secret coefficient (Shamir constant term) with a per-prime degree-(t-1) polynomial derived deterministically from private_setup_seed, so reconstruction at x=0 returns s. This is a centralized dealer simulating a DKG, not a real distributed key generation; the shares are only as private as the seed.
pub(super) fn derive_threshold_secret_share_limb(
    secret: &[i64],
    setup_package_hash: &str,
    target_share_profile_hash: &str,
    private_setup_seed: &str,
    interpolation_point: u64,
    minimum_shares_for_interpolation: usize,
    limb_index: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut share = secret
        .iter()
        .map(|coefficient| signed_residue(*coefficient, modulus))
        .collect::<Vec<_>>();
    let evaluation_point = interpolation_point % modulus;
    let mut evaluation_point_power = evaluation_point;
    let limb_index_bytes = (limb_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    for polynomial_degree in 1..minimum_shares_for_interpolation {
        let degree_bytes = (polynomial_degree as u64).to_le_bytes();
        let mut sampler = DeterministicSampler::new(
            "sealed-lattice-bgv-rns/target-decryption-shamir-polynomial-v1",
            &[
                private_setup_seed.as_bytes(),
                setup_package_hash.as_bytes(),
                target_share_profile_hash.as_bytes(),
                &limb_index_bytes,
                &modulus_bytes,
                &degree_bytes,
            ],
        );
        let coefficients = sampler.uniform_residues(modulus, POLYNOMIAL_DEGREE);
        for (share_coefficient, polynomial_coefficient) in share.iter_mut().zip(coefficients) {
            let term = mul_mod_fast(polynomial_coefficient, evaluation_point_power, modulus);
            *share_coefficient = add_mod_fast(*share_coefficient, term, modulus);
        }
        evaluation_point_power = mul_mod(evaluation_point_power, evaluation_point, modulus)?;
    }

    Ok(share)
}

// PROTOTYPE GAP (labeled, not a hidden flaw): partial shares are released as bare c1*s_i with no smudging / noise-flooding term. Threshold-BGV simulation security requires adding flooding noise E_i super-polynomially larger than the decryption noise; without it the released shares leak c1*s_i exactly. This is gated: read_setup_binding in bindings.rs refuses to run unless targetC1C4StatusAccepted is false, and share records carry ShareProofCertificationPending. The C1-C4 smudging/noise closure is the open work.
pub(super) fn partial_decryption_by_limb(
    ciphertext: &Ciphertext,
    secret_share_by_limb: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    if ciphertext.components.len() != 2 || secret_share_by_limb.len() != ciphertext.primes().len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target PartDec requires a two-component ciphertext and one secret-share limb per active prime",
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        ciphertext
            .primes()
            .par_iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        ciphertext
            .primes()
            .iter()
            .enumerate()
            .map(|(limb_index, modulus)| {
                negacyclic_mul(
                    &ciphertext.components[1][limb_index],
                    &secret_share_by_limb[limb_index],
                    *modulus,
                )
            })
            .collect()
    }
}
