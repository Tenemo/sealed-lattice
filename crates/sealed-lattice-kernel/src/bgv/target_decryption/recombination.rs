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
    let recombination_input_report = recombination_input_report_value(
        setup_binding,
        target_accepted,
        target_ciphertexts,
        target_share_profile,
        &selected,
        &decoded_target_ids,
        &decoded_target_orders,
    )?;
    let recombination_input_report_hash = derive_protocol_hash(
        "TargetDecryptionRecombinationInputReportHash",
        &recombination_input_report,
    )?;
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
            "recombinationInputReportHash": recombination_input_report_hash,
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
        "recombinationInputReport": recombination_input_report,
        "recombinationInputReportHash": recombination_input_report_hash,
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

fn recombination_input_report_value(
    setup_binding: &SetupBinding,
    target_accepted: &TargetAcceptedBinding,
    target_ciphertexts: &TargetCiphertextPair,
    target_share_profile: &TargetShareProfile,
    selected_shares: &[PartialDecryptionShare],
    decoded_target_ids: &[u64],
    decoded_target_orders: &[u64],
) -> CanonicalResult<Value> {
    let selected_share_records = selected_shares
        .iter()
        .map(|share| {
            Ok(json!({
                "trusteeIdentity": string_at_path(&share.record, &["trusteeIdentity"])?,
                "rosterPosition": share.roster_position,
                "boardPosition": share.board_position,
                "interpolationPoint": share.interpolation_point,
                "shareRoot": hash_at_path(&share.record, &["shareRoot"])?,
                "targetDecryptionShareHash": hash_at_path(&share.record, &["targetDecryptionShareHash"])?,
                "smudgingInputReportHash": share.smudging_input_report_hash.as_str(),
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let active_rns_limb_reports = target_ciphertexts
        .target_id
        .primes()
        .iter()
        .enumerate()
        .map(|(rns_limb_index, rns_prime)| {
            let lagrange_terms =
                lagrange_coefficient_terms_at_zero_mod(selected_shares, *rns_prime)?
                    .iter()
                    .map(lagrange_coefficient_term_value)
                    .collect::<Vec<_>>();
            Ok(json!({
                "rnsLimbIndex": rns_limb_index,
                "rnsPrime": rns_prime,
                "lagrangeTerms": lagrange_terms,
            }))
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let maximum_decoded_value = decoded_target_ids
        .iter()
        .chain(decoded_target_orders.iter())
        .copied()
        .max()
        .unwrap_or(0);
    let centered_positive_limit = (crate::bgv::profile::PLAINTEXT_MODULUS - 1) / 2;
    if maximum_decoded_value > centered_positive_limit {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target decryption decoded values exceed the centered plaintext decoding margin",
        ));
    }

    Ok(json!({
        "objectType": "TargetDecryptionRecombinationInputReport",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "setupPackageHash": setup_binding.setup_package_hash,
        "targetAcceptedRecordHash": target_accepted.target_accepted_record_hash,
        "targetContextHash": target_accepted.target_context_hash,
        "targetCiphertextHash": target_accepted.target_ciphertext_hash,
        "targetShareProfileHash": target_share_profile.hash,
        "targetBasisHash": target_accepted.target_basis_hash,
        "targetIdRoot": target_ciphertexts.target_id_root,
        "targetOrderRoot": target_ciphertexts.target_order_root,
        "minimumSharesForInterpolation": target_share_profile.minimum_shares_for_interpolation,
        "decryptionThreshold": target_share_profile.decryption_threshold,
        "selectedShareCount": selected_shares.len(),
        "selectedShares": selected_share_records,
        "smudgingProfileId": TARGET_DECRYPTION_SMUDGING_PROFILE_ID,
        "smudgingDevelopmentScope": TARGET_DECRYPTION_SMUDGING_DEVELOPMENT_SCOPE,
        "smudgingCombinationRule": TARGET_DECRYPTION_SMUDGING_ZERO_SHARING_RULE,
        "smudgingProofBoundary": TARGET_DECRYPTION_SMUDGING_PROOF_BOUNDARY,
        "activeRnsLimbCount": active_rns_limb_reports.len(),
        "activeRnsLimbReports": active_rns_limb_reports,
        "recombinationCoefficientEquation": "denominatorProductModuloPrime * lagrangeCoefficientModuloPrime = numeratorProductModuloPrime mod rnsPrime",
        "decodingMargin": {
            "plaintextModulus": crate::bgv::profile::PLAINTEXT_MODULUS,
            "centeredPositiveLimit": centered_positive_limit,
            "maximumDecodedTargetValue": maximum_decoded_value,
            "centeredPositiveMargin": centered_positive_limit - maximum_decoded_value,
            "marginRule": "decoded target id and order residues must remain in the nonnegative centered plaintext range after recombination",
        },
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
    Ok(lagrange_coefficient_terms_at_zero_mod(shares, modulus)?
        .iter()
        .map(|term| term.lagrange_coefficient_modulo_prime)
        .collect())
}

struct LagrangeCoefficientTerm {
    selected_share_index: usize,
    roster_position: usize,
    board_position: usize,
    interpolation_point: u64,
    numerator_product_modulo_prime: u64,
    denominator_product_modulo_prime: u64,
    denominator_inverse_modulo_prime: u64,
    lagrange_coefficient_modulo_prime: u64,
}

fn lagrange_coefficient_terms_at_zero_mod(
    shares: &[PartialDecryptionShare],
    modulus: u64,
) -> CanonicalResult<Vec<LagrangeCoefficientTerm>> {
    let mut terms = Vec::with_capacity(shares.len());
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
        let denominator_inverse = inverse_mod(denominator, modulus)?;
        terms.push(LagrangeCoefficientTerm {
            selected_share_index: share_index,
            roster_position: share.roster_position,
            board_position: share.board_position,
            interpolation_point: share.interpolation_point,
            numerator_product_modulo_prime: numerator,
            denominator_product_modulo_prime: denominator,
            denominator_inverse_modulo_prime: denominator_inverse,
            lagrange_coefficient_modulo_prime: mul_mod(numerator, denominator_inverse, modulus)?,
        });
    }

    Ok(terms)
}

fn lagrange_coefficient_term_value(term: &LagrangeCoefficientTerm) -> Value {
    json!({
        "selectedShareIndex": term.selected_share_index,
        "rosterPosition": term.roster_position,
        "boardPosition": term.board_position,
        "interpolationPoint": term.interpolation_point,
        "numeratorProductModuloPrime": term.numerator_product_modulo_prime,
        "denominatorProductModuloPrime": term.denominator_product_modulo_prime,
        "denominatorInverseModuloPrime": term.denominator_inverse_modulo_prime,
        "lagrangeCoefficientModuloPrime": term.lagrange_coefficient_modulo_prime,
    })
}

pub(super) fn packed_target_values(slots: &[u64]) -> Vec<u64> {
    (0..MAXIMUM_OPTION_COUNT)
        .map(|option| slots[packed_score_slot(option)])
        .collect()
}
