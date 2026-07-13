use super::*;

mod smudging;
mod witness;
pub(super) use self::smudging::*;
pub(super) use self::witness::*;

pub(super) struct LocalTargetDecryptionShareWitness {
    pub(super) secret_share_by_limb: Vec<Vec<u64>>,
    pub(super) smudging_seed_hex: String,
    pub(super) smudging_polynomial_openings: Vec<TargetDecryptionSmudgingPolynomialOpening>,
    pub(super) active_credential_bindings: Vec<AggregateOpeningCredentialBinding>,
}

pub(super) struct AggregateOpeningCredentialBinding {
    pub(super) limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) aggregate_commitment_root: String,
    pub(super) aggregate_commitment_context_hash: String,
    pub(super) aggregate_opening_root: String,
    pub(super) aggregate_commitment_message_values: Vec<u64>,
    pub(super) aggregate_material_seed_hex: String,
}

pub(super) struct TargetDecryptionSmudgingPolynomialOpening {
    pub(super) role: String,
    pub(super) rns_limb_index: usize,
    pub(super) rns_prime: u64,
    pub(super) polynomial_degree: usize,
    pub(super) polynomial_coefficients: Vec<i64>,
}

struct TargetDecryptionSmudgingCommitmentOpening {
    #[cfg(test)]
    rns_limb_index: usize,
    #[cfg(test)]
    rns_prime: u64,
    message_coefficients: Vec<u64>,
    material_seed_hex: String,
    commitment_context: Value,
}

pub(super) struct TargetDecryptionSmudgingProofOpening {
    pub(super) message_coefficients: Vec<u64>,
    pub(super) material_seed_hex: String,
    pub(super) commitment_context_hash: String,
}

pub(super) fn generate_target_decryption_share_from_secret_share(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    participant: &ParticipantBinding,
    secret_share: &[Vec<u64>],
    smudging_polynomial_openings: &[TargetDecryptionSmudgingPolynomialOpening],
) -> CanonicalResult<Value> {
    let target_id_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_id, secret_share)?;
    let target_order_partials =
        partial_decryption_by_limb(&target_ciphertexts.target_order, secret_share)?;
    let target_id_partials = apply_plaintext_multiple_zero_share_smudging(
        target_share_profile,
        participant,
        smudging_polynomial_openings,
        "targetId",
        &target_id_partials,
    )?;
    let target_order_partials = apply_plaintext_multiple_zero_share_smudging(
        target_share_profile,
        participant,
        smudging_polynomial_openings,
        "targetOrder",
        &target_order_partials,
    )?;
    let payload = share_payload(&target_id_partials, &target_order_partials)?;
    let share_root = derive_canonical_object_hash(&payload)?;
    let record_hash_input = share_record_hash_input(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        participant,
        &share_root,
    );
    let target_decryption_share_hash = derive_canonical_object_hash(&record_hash_input)?;

    Ok(json!({
        "objectType": "BgvTargetDecryptionShare",
        "targetDecryptionShareHash": target_decryption_share_hash,
        "setupPackageHash": setup_binding.setup_package_hash,
        "trusteeIdentity": participant.trustee_identity,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetCiphertextHash": target_ciphertexts.target_ciphertext_hash,
        "shareRoot": share_root,
        "sharePayload": payload,
    }))
}

#[cfg(test)]
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
#[cfg(test)]
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
