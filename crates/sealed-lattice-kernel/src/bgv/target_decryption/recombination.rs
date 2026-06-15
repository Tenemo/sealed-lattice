use super::*;

pub(super) fn recombine_target_decryption_shares(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    mut shares: Vec<PartialDecryptionShare>,
) -> CanonicalResult<Value> {
    if shares.len() < target_share_profile.minimum_shares_for_interpolation {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target recombination requires at least minimumSharesForInterpolation valid shares",
        ));
    }
    let mut identities = BTreeSet::new();
    let mut roster_positions = BTreeSet::new();
    let mut board_positions = BTreeSet::new();
    for share in &shares {
        let trustee_identity = string_at_path(&share.record, &["trusteeIdentity"])?.to_string();
        if !identities.insert(trustee_identity)
            || !roster_positions.insert(share.roster_position)
            || !board_positions.insert(share.board_position)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "target recombination rejects duplicate trustee, roster-position, or board-position shares",
            ));
        }
    }
    // Shares are selected deterministically by board position, but interpolation uses the roster-derived abscissa; the triple dedup prevents a trustee from re-submitting under a different board/roster slot.
    shares.sort_by_key(|share| share.board_position);
    let selected = shares
        .into_iter()
        .take(target_share_profile.minimum_shares_for_interpolation)
        .collect::<Vec<_>>();
    let selected_roster_positions = selected
        .iter()
        .map(|share| share.roster_position)
        .collect::<Vec<_>>();
    let selected_board_positions = selected
        .iter()
        .map(|share| share.board_position)
        .collect::<Vec<_>>();
    let target_id_slots =
        recombine_ciphertext_slots(&target_ciphertexts.target_id, &selected, |share| {
            &share.target_id_partials
        })?;
    let target_order_slots =
        recombine_ciphertext_slots(&target_ciphertexts.target_order, &selected, |share| {
            &share.target_order_partials
        })?;
    let decoded_target_ids = packed_target_values(&target_id_slots);
    let decoded_target_orders = packed_target_values(&target_order_slots);
    let target_result_root = derive_protocol_hash(
        "TargetDecryptionResultHash",
        &json!({
            "objectType": "TargetDecryptionResult",
            "objectVersion": 1,
            "setupPackageHash": setup_binding.setup_package_hash,
            "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
            "targetContextHash": target_accepted.target_context_hash,
            "targetCiphertextHash": target_accepted.target_ciphertext_hash,
            "targetShareProfileHash": target_share_profile.hash,
            "selectedBoardPositions": selected_board_positions,
            "selectedRosterPositions": selected_roster_positions,
            "decodedTargetIds": decoded_target_ids,
            "decodedTargetOrders": decoded_target_orders,
        }),
    )?;

    Ok(json!({
        "ok": true,
        "operation": "recombineBgvTargetDecryptionShares",
        "targetDecryptionResultHash": target_result_root,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetDecryptionProfileHash": target_accepted.target_decryption_profile_hash,
        "shareEquation": TARGET_SHARE_EQUATION,
        "recombinationEquation": "c0 + sum(lambda_i * PartDec_i(C_target)) over every active BGV data prime",
        "selectedShareRule": SELECTED_SHARE_RULE,
        "minimumSharesForInterpolation": target_share_profile.minimum_shares_for_interpolation,
        "decryptionThreshold": target_share_profile.decryption_threshold,
        "decryptionShareQuorum": target_share_profile.decryption_share_quorum,
        "selectedBoardPositions": selected_board_positions,
        "selectedRosterPositions": selected_roster_positions,
        "decodedTargetIds": decoded_target_ids,
        "decodedTargetOrders": decoded_target_orders,
        "decryptScaling": 1,
    }))
}

pub(super) fn recombine_ciphertext_slots<F>(
    ciphertext: &Ciphertext,
    shares: &[PartialDecryptionShare],
    partials: F,
) -> CanonicalResult<Vec<u64>>
where
    F: Fn(&PartialDecryptionShare) -> &[Vec<u64>],
{
    // c0 is the message-bearing component; adding the sum of lambda_i * (c1*s_i) reconstructs c0 + c1*s = m + p*e, then centered reduction mod p recovers m.
    let mut accumulator = ciphertext.components[0].clone();
    for (limb_index, modulus) in ciphertext.primes().iter().enumerate() {
        let coefficients = lagrange_coefficients_at_zero_mod(shares, *modulus)?;
        for (share, lagrange_coefficient) in shares.iter().zip(coefficients) {
            let share_partials = partials(share);
            for coefficient_index in 0..POLYNOMIAL_DEGREE {
                let weighted = mul_mod(
                    share_partials[limb_index][coefficient_index],
                    lagrange_coefficient,
                    *modulus,
                )?;
                accumulator[limb_index][coefficient_index] = add_mod(
                    accumulator[limb_index][coefficient_index],
                    weighted,
                    *modulus,
                )?;
            }
        }
    }
    let coefficients = decryption_accumulator_to_coefficients(ciphertext, &accumulator)?;

    forward_negacyclic_ntt(&coefficients, crate::bgv::profile::PLAINTEXT_MODULUS)
}

// Interpolation is per RNS prime field, so abscissae must stay distinct mod each prime; the reduction is identity for the tiny roster points but the check is required in general.
pub(super) fn lagrange_coefficients_at_zero_mod(
    shares: &[PartialDecryptionShare],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut coefficients = Vec::with_capacity(shares.len());
    for (share_index, share) in shares.iter().enumerate() {
        let x_i = share.interpolation_point % modulus;
        if x_i == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target decryption interpolation point must be non-zero modulo the data prime",
            ));
        }
        let mut numerator = 1_u64;
        let mut denominator = 1_u64;
        for (other_index, other_share) in shares.iter().enumerate() {
            if other_index == share_index {
                continue;
            }
            let x_j = other_share.interpolation_point % modulus;
            if x_j == 0 || x_i == x_j {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::ProfileComponentMismatch,
                    "target decryption interpolation points must be non-zero and distinct",
                ));
            }
            numerator = mul_mod(numerator, modulus - x_j, modulus)?;
            let difference = if x_i >= x_j {
                x_i - x_j
            } else {
                modulus - (x_j - x_i)
            };
            denominator = mul_mod(denominator, difference, modulus)?;
        }
        coefficients.push(mul_mod(
            numerator,
            inverse_mod(denominator, modulus)?,
            modulus,
        )?);
    }

    Ok(coefficients)
}

pub(super) fn packed_target_values(slots: &[u64]) -> Vec<u64> {
    (0..MAXIMUM_OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}
