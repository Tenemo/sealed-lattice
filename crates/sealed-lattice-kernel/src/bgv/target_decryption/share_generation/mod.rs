use super::*;

mod smudging;
mod witness;
pub(super) use self::smudging::*;
pub(super) use self::witness::*;

pub(super) struct LocalTargetDecryptionShareWitness {
    pub(super) secret_share_by_limb: Vec<Vec<u64>>,
    pub(super) private_flooding_seed_hex: String,
    pub(super) flooding_noise_openings: Vec<TargetDecryptionFloodingNoiseOpening>,
    pub(super) active_credential_bindings: Vec<AggregateOpeningCredentialBinding>,
}

pub(super) struct AggregateOpeningCredentialBinding {
    pub(super) aggregate_commitment_root: String,
    pub(super) aggregate_opening_root: String,
}

pub(super) struct TargetDecryptionFloodingNoiseOpening {
    pub(super) coefficients: Vec<i64>,
}

struct TargetDecryptionSmudgingCommitmentOpening {
    message_coefficients: Vec<u64>,
    material_seed_hex: String,
    commitment_context: Value,
}

pub(super) fn generate_target_decryption_share_from_secret_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    participant: &ParticipantBinding,
    secret_share: &[Vec<u64>],
    flooding_noise_openings: &[TargetDecryptionFloodingNoiseOpening],
) -> CanonicalResult<Value> {
    let participant_count = u64::try_from(setup_binding.participants.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption participant count does not fit u64",
        )
    })?;
    let denominator_clearing_factor =
        target_decryption_interpolation_denominator_clearing_factor(participant_count)?;
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, secret_share)?;
    let target_id_partials = apply_plaintext_multiple_flooding_noise(
        flooding_noise_openings,
        "targetId",
        &target_id_partials,
        denominator_clearing_factor,
    )?;
    let target_order_partials = apply_plaintext_multiple_flooding_noise(
        flooding_noise_openings,
        "targetOrder",
        &target_order_partials,
        denominator_clearing_factor,
    )?;
    let payload = share_payload(&target_id_partials, &target_order_partials)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShare",
        "trusteeRosterPosition": participant.roster_position,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "sharePayload": payload,
    }))
}

pub(super) fn derive_threshold_secret_share_by_limb(
    evaluator_key: &DevelopmentBgvKey,
    setup_context_hash: &str,
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
                    setup_context_hash,
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
                    setup_context_hash,
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
pub(super) fn derive_threshold_secret_share_limb(
    secret: &[i64],
    setup_context_hash: &str,
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
            "sealed-lattice-bgv-rns/target-decryption-shamir-polynomial",
            &[
                private_setup_seed.as_bytes(),
                setup_context_hash.as_bytes(),
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
