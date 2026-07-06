use super::super::*;
use super::*;
use num_bigint::BigInt;

// Combined linkage lincheck vectors for one commitment field. For every
// relation (commitment l, row k) and repetition r with Fiat-Shamir weight
// alpha_{l,k,r}, the transposed matrix action of row k lands on each witness
// column; combining across rows and repetitions yields one public vector per
// witness column, in SumcheckPublicEvaluations linkage order (secret link,
// negative indicator, then each opening-randomness column). The returned
// scalar is the alpha-weighted sum of the public commitment-row linchecks,
// which joins the combined sumcheck claim.
pub(crate) fn build_linkage_public_vectors(
    linkage: &SameSecretLinkageStatement,
    commitment_field: usize,
    tower: &ChallengeExtensionTower,
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    linkage_alpha: &[ChallengeExtensionElement],
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let modulus = tower.modulus;
    let ring_degree = linkage.commitments[0].ring_degree;
    let commitment_count = linkage.commitments.len();
    debug_assert_eq!(
        linkage_alpha.len(),
        commitment_count * SETUP_COMMITMENT_ROW_COUNT * LINCHECK_REPETITIONS
    );
    let mut linkage_claim = ChallengeExtensionTower::zero();
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    let mut secret_link = extension_zero_vector();
    let mut negative_indicator = extension_zero_vector();
    let mut randomness_vectors =
        vec![extension_zero_vector(); commitment_count * SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let add_base_scaled = |target: &mut [ChallengeExtensionElement],
                           source: &[ChallengeExtensionElement],
                           scale: u64| {
        for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
            *target_value = tower.add(target_value, &tower.scale_base(source_value, scale));
        }
    };
    for (commitment_index, commitment) in linkage.commitments.iter().enumerate() {
        let source_modulus_residue = commitment.source_message_modulus % modulus;
        let limb = &commitment.limbs[commitment_field];
        for row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            // Repetition-combined challenge vector for this relation.
            let mut combined_u = extension_zero_vector();
            for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
                let alpha_value = &linkage_alpha[(commitment_index * SETUP_COMMITMENT_ROW_COUNT
                    + row_index)
                    * LINCHECK_REPETITIONS
                    + repetition];
                for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
                    *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
                }
            }
            // Public side: alpha-weighted lincheck sums of the commitment row.
            let mut row_sum = ChallengeExtensionTower::zero();
            for (u_value, row_value) in combined_u.iter().zip(limb.rows[row_index].iter()) {
                row_sum = tower.add(&row_sum, &tower.scale_base(u_value, *row_value));
            }
            linkage_claim = tower.add(&linkage_claim, &row_sum);
            // Message row: the lifted secret message s + neg * q_l.
            if row_index == SETUP_COMMITMENT_MODULE_RANK {
                add_base_scaled(&mut secret_link, &combined_u, 1);
                add_base_scaled(&mut negative_indicator, &combined_u, source_modulus_residue);
            }
            for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                let target = &mut randomness_vectors
                    [commitment_index * SETUP_COMMITMENT_RANDOMNESS_WIDTH + randomness_column];
                match structural_matrix_polynomial_kind(row_index, randomness_column) {
                    Some(StructuralMatrixPolynomial::One) => {
                        add_base_scaled(target, &combined_u, 1);
                    }
                    Some(StructuralMatrixPolynomial::Zero) => {}
                    None => {
                        let matrix_polynomial = setup_commitment_matrix_coefficients_cached(
                            &linkage.public_matrix_seed_hash,
                            commitment.source_rns_limb_index,
                            commitment_field,
                            row_index,
                            randomness_column,
                            ring_degree,
                            modulus,
                        )?;
                        let transposed = negacyclic_transpose_product_extension(
                            &matrix_polynomial,
                            &combined_u,
                            modulus,
                        )?;
                        add_base_scaled(target, &transposed, 1);
                    }
                }
            }
        }
    }
    let mut vectors = Vec::with_capacity(2 + randomness_vectors.len());
    vectors.push(secret_link);
    vectors.push(negative_indicator);
    vectors.extend(randomness_vectors);

    Ok((linkage_claim, vectors))
}

// Combined private VSS lincheck vectors for one commitment field. The vector
// order matches the private VSS logical witness columns: every hidden Shamir
// coefficient message, the hidden carry vector, then every opening-randomness
// column by coefficient and randomness-column index.
pub(crate) fn build_private_vss_public_vectors(
    statement: &PrivateVssShareStatement,
    commitment_field: usize,
    tower: &ChallengeExtensionTower,
    u_power_vectors: &[Vec<ChallengeExtensionElement>],
    relation_alpha: &[ChallengeExtensionElement],
) -> CanonicalResult<(
    ChallengeExtensionElement,
    Vec<Vec<ChallengeExtensionElement>>,
)> {
    let modulus = tower.modulus;
    let ring_degree = statement.share_values.len();
    let coefficient_count = statement.coefficient_commitments.len();
    debug_assert_eq!(
        relation_alpha.len(),
        (coefficient_count * SETUP_COMMITMENT_ROW_COUNT + 1) * LINCHECK_REPETITIONS
    );
    let extension_zero_vector = || vec![ChallengeExtensionTower::zero(); ring_degree];
    let mut relation_claim = ChallengeExtensionTower::zero();
    let mut message_vectors = vec![extension_zero_vector(); coefficient_count];
    let mut carry_vector = extension_zero_vector();
    let mut randomness_vectors =
        vec![extension_zero_vector(); coefficient_count * SETUP_COMMITMENT_RANDOMNESS_WIDTH];
    let add_base_scaled = |target: &mut [ChallengeExtensionElement],
                           source: &[ChallengeExtensionElement],
                           scale: u64| {
        for (target_value, source_value) in target.iter_mut().zip(source.iter()) {
            *target_value = tower.add(target_value, &tower.scale_base(source_value, scale));
        }
    };

    for (coefficient_index, commitment) in statement.coefficient_commitments.iter().enumerate() {
        let limb = &commitment.limbs[commitment_field];
        for row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            let relation_index = coefficient_index * SETUP_COMMITMENT_ROW_COUNT + row_index;
            let mut combined_u = extension_zero_vector();
            for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
                let alpha_value =
                    &relation_alpha[relation_index * LINCHECK_REPETITIONS + repetition];
                for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
                    *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
                }
            }
            let mut row_sum = ChallengeExtensionTower::zero();
            for (u_value, row_value) in combined_u.iter().zip(limb.rows[row_index].iter()) {
                row_sum = tower.add(&row_sum, &tower.scale_base(u_value, *row_value));
            }
            relation_claim = tower.add(&relation_claim, &row_sum);
            if row_index == SETUP_COMMITMENT_MODULE_RANK {
                add_base_scaled(&mut message_vectors[coefficient_index], &combined_u, 1);
            }
            for randomness_column in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                let target = &mut randomness_vectors
                    [coefficient_index * SETUP_COMMITMENT_RANDOMNESS_WIDTH + randomness_column];
                match structural_matrix_polynomial_kind(row_index, randomness_column) {
                    Some(StructuralMatrixPolynomial::One) => {
                        add_base_scaled(target, &combined_u, 1);
                    }
                    Some(StructuralMatrixPolynomial::Zero) => {}
                    None => {
                        let matrix_polynomial = setup_commitment_matrix_coefficients_cached(
                            &statement.public_matrix_seed_hash,
                            statement.source_rns_limb_index,
                            commitment_field,
                            row_index,
                            randomness_column,
                            ring_degree,
                            modulus,
                        )?;
                        let transposed = negacyclic_transpose_product_extension(
                            &matrix_polynomial,
                            &combined_u,
                            modulus,
                        )?;
                        add_base_scaled(target, &transposed, 1);
                    }
                }
            }
        }
    }

    let share_relation_index = coefficient_count * SETUP_COMMITMENT_ROW_COUNT;
    let trustee_point = canonical_trustee_point(
        usize::try_from(statement.recipient_roster_position).map_err(|_| {
            invalid_succinct_setup_proof("private VSS recipient roster position does not fit usize")
        })?,
        statement.source_message_modulus,
    )?;
    let mut trustee_point_powers = Vec::with_capacity(coefficient_count);
    let mut trustee_point_power = 1_u128;
    for _ in 0..coefficient_count {
        trustee_point_powers.push((trustee_point_power % u128::from(modulus)) as u64);
        trustee_point_power = trustee_point_power
            .checked_mul(u128::from(trustee_point))
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS trustee point overflowed"))?;
    }
    let source_modulus_residue = statement.source_message_modulus % modulus;
    let negated_source_modulus = if source_modulus_residue == 0 {
        0
    } else {
        modulus - source_modulus_residue
    };
    for (repetition, u_powers) in u_power_vectors.iter().enumerate() {
        let alpha_value = &relation_alpha[share_relation_index * LINCHECK_REPETITIONS + repetition];
        let mut combined_u = extension_zero_vector();
        for (target_value, source_value) in combined_u.iter_mut().zip(u_powers.iter()) {
            *target_value = tower.add(target_value, &tower.mul(alpha_value, source_value));
        }
        let mut share_sum = ChallengeExtensionTower::zero();
        for (u_value, share_value) in combined_u.iter().zip(statement.share_values.iter()) {
            share_sum = tower.add(
                &share_sum,
                &tower.scale_base(u_value, *share_value % modulus),
            );
        }
        relation_claim = tower.add(&relation_claim, &share_sum);
        for (coefficient_index, power) in trustee_point_powers.iter().enumerate() {
            add_base_scaled(&mut message_vectors[coefficient_index], &combined_u, *power);
        }
        add_base_scaled(&mut carry_vector, &combined_u, negated_source_modulus);
    }

    let mut vectors = Vec::with_capacity(coefficient_count + 1 + randomness_vectors.len());
    vectors.extend(message_vectors);
    vectors.push(carry_vector);
    vectors.extend(randomness_vectors);

    Ok((relation_claim, vectors))
}

// Centered bound for a published masked consistency claim: the clear sum is
// bounded by max witness magnitude * ring degree * (2^bits - 1), and the
// smudging mask lies in the family-selected base-3 range.
// Family-aware clear bound: private VSS masks only the carry and ternary
// opening-randomness columns. Share-linkage masks per-item carries and
// message digits; carry claims use the lifted carry bound and digit
// claims use the digit bound. Every other family uses 2
// (centered-binomial magnitude).
// The mask is one-sided in [0, CLAIM_MASK_RADIX^mask_digit_count), so the centered claim
// lies in [-clear_bound, mask_bound + clear_bound]. The disclosed smudging
// figure in accounting.rs recomputes from this same family-aware bound, so the
// relation bound and the disclosed leakage figure agree by construction. The
// carry's range bound here is essential to the global sharing-soundness
// argument: it keeps the pinned evaluation a bounded centered lift.
pub(crate) fn claim_mask_digit_count_for_global_claim(
    statement: &TrusteeEvaluationKeyStatement,
    global_claim_id: u64,
) -> usize {
    let family_shape = statement
        .family_shape()
        .expect("statement shape validated before claim masking");
    let consistency_repetitions = family_shape.consistency_repetitions();
    if statement.target_decryption_share.is_some() {
        let global_vector_index = global_claim_id as usize / consistency_repetitions;
        let target_message_digit_vector_count =
            statement.target_decryption_total_message_digit_count();
        if global_vector_index < target_message_digit_vector_count {
            let global_message_index = global_vector_index
                / crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
            match statement
                .target_decryption_message_claim_kind(global_message_index)
                .expect("target-decryption message claim id is in range")
            {
                TargetDecryptionMessageClaimKind::AggregateOpening => {
                    TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT
                }
                TargetDecryptionMessageClaimKind::SmudgingOpening => {
                    TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT
                }
            }
        } else {
            unreachable!("target-decryption global claims only carry message digits")
        }
    } else if let Some(vss_share_linkage) = &statement.vss_share_linkage {
        // Carry vectors occupy the first item_count vector slots; the message
        // digit vectors follow. Mask selection must pair with the same
        // carry-versus-digit split the claim bounds use, so multi-item
        // statements mask their additional carry claims as carries.
        let global_vector_index = global_claim_id as usize / consistency_repetitions;
        if global_vector_index < vss_share_linkage.item_count() {
            VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT
        } else {
            VSS_PUBLIC_DIGIT_CLAIM_MASK_DIGIT_COUNT
        }
    } else if let Some(same_secret_bridge) = &statement.same_secret_bridge {
        let global_vector_index = global_claim_id as usize / consistency_repetitions;
        let total_error_vectors = statement
            .keys
            .iter()
            .map(|key| key.digit_count())
            .sum::<usize>();
        let bridge_digit_start = 1 + total_error_vectors + 1;
        let bridge_digit_vector_count = same_secret_bridge.target_rns_primes.len()
            * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
        if (bridge_digit_start..bridge_digit_start + bridge_digit_vector_count)
            .contains(&global_vector_index)
        {
            VSS_PUBLIC_DIGIT_CLAIM_MASK_DIGIT_COUNT
        } else {
            family_shape.claim_mask_digit_count()
        }
    } else {
        family_shape.claim_mask_digit_count()
    }
}

pub(crate) fn claim_mask_bound_for_digit_count(mask_digit_count: usize) -> CanonicalResult<BigInt> {
    let exponent = u32::try_from(mask_digit_count)
        .map_err(|_| invalid_succinct_setup_proof("claim mask digit count overflowed"))?;

    Ok(BigInt::from(CLAIM_MASK_RADIX).pow(exponent))
}

pub(crate) fn masked_claim_bounds_for_global_claim(
    statement: &TrusteeEvaluationKeyStatement,
    global_claim_id: u64,
) -> CanonicalResult<(BigInt, BigInt)> {
    let family_shape = statement.family_shape()?;
    let ring_degree = statement
        .vss_share_linkage
        .as_ref()
        .map(|share_linkage| share_linkage.packed_ring_degree(statement.ring_degree))
        .transpose()?
        .unwrap_or(statement.ring_degree);
    let consistency_repetitions = family_shape.consistency_repetitions();
    let coefficient_bound = (1_i128 << family_shape.consistency_coefficient_bits()) - 1;
    let witness_bound = match &statement.private_vss_share {
        Some(private_vss_share) => {
            // The message (Shamir coefficient) columns carry no masked
            // consistency claim (their cross-field consistency is argued globally
            // via the carry consistency, the public share, and >= t honest
            // recipients; see consistency_vector_count), so the published masked
            // claims range only over the carry and the ternary opening-randomness
            // columns. The lifted carry bound dominates the magnitude-one
            // randomness, so it is the witness bound.
            let carry_bound = private_vss_share_lifted_carry_bound(
                private_vss_share.recipient_roster_position,
                private_vss_share.coefficient_commitments.len(),
            )?;
            carry_bound.max(1)
        }
        None => match &statement.vss_share_linkage {
            Some(vss_share_linkage) => {
                let global_vector_index = global_claim_id as usize / consistency_repetitions;
                if global_vector_index < vss_share_linkage.item_count() {
                    let carry_bound = if global_vector_index == 0 {
                        private_vss_share_lifted_carry_bound(
                            vss_share_linkage.recipient_roster_position,
                            vss_share_linkage.coefficient_commitments.len(),
                        )?
                    } else {
                        let item =
                            &vss_share_linkage.additional_linkage_items[global_vector_index - 1];
                        private_vss_share_lifted_carry_bound(
                            item.recipient_roster_position,
                            item.coefficient_commitments.len(),
                        )?
                    };
                    carry_bound.max(1)
                } else {
                    i128::from(crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_BASE - 1)
                }
            }
            None => {
                if let Some(same_secret_bridge) = &statement.same_secret_bridge {
                    let global_vector_index = global_claim_id as usize / consistency_repetitions;
                    let total_error_vectors = statement
                        .keys
                        .iter()
                        .map(|key| key.digit_count())
                        .sum::<usize>();
                    let bridge_digit_start = 1 + total_error_vectors + 1;
                    let bridge_digit_vector_count = same_secret_bridge.target_rns_primes.len()
                        * crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
                    if (bridge_digit_start..bridge_digit_start + bridge_digit_vector_count)
                        .contains(&global_vector_index)
                    {
                        i128::from(
                            crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_BASE - 1,
                        )
                    } else {
                        2
                    }
                } else if statement.target_decryption_share.is_some() {
                    let global_vector_index = global_claim_id as usize / consistency_repetitions;
                    let target_message_digit_vector_count =
                        statement.target_decryption_total_message_digit_count();
                    if global_vector_index < target_message_digit_vector_count {
                        let global_message_index = global_vector_index
                            / crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
                        let digit_index = global_vector_index
                            % crate::bgv::setup::vss_commitment::VSS_PUBLIC_MESSAGE_DIGIT_COUNT;
                        let digit_bound = statement
                            .target_decryption_message_digit_bound(
                                global_message_index,
                                digit_index,
                            )
                            .expect("target-decryption digit claim id is in range");
                        i128::from(digit_bound.saturating_sub(1))
                    } else {
                        unreachable!("target-decryption global claims only carry message digits")
                    }
                } else {
                    2
                }
            }
        },
    };
    let clear_bound = witness_bound
        .checked_mul(coefficient_bound)
        .and_then(|bound| bound.checked_mul(ring_degree as i128))
        .ok_or_else(|| invalid_succinct_setup_proof("masked claim bound overflowed"))?;
    let mask_digit_count = claim_mask_digit_count_for_global_claim(statement, global_claim_id);
    let mask_bound = claim_mask_bound_for_digit_count(mask_digit_count)?;
    let clear_bound = BigInt::from(clear_bound);

    Ok((-&clear_bound, mask_bound + clear_bound))
}

pub(crate) fn masked_claim_lift_residue_count_for_moduli(
    moduli: impl IntoIterator<Item = u64>,
    lower_bound: &BigInt,
    upper_bound: &BigInt,
) -> usize {
    let lower_magnitude = -lower_bound;
    let maximum_magnitude = if lower_magnitude > *upper_bound {
        lower_magnitude
    } else {
        upper_bound.clone()
    };
    let required_product = maximum_magnitude * BigInt::from(2_u8);
    let mut product = BigInt::from(1_u8);
    let mut residue_count = 0_usize;
    for modulus in moduli {
        residue_count += 1;
        product *= BigInt::from(modulus);
        if product > required_product {
            return residue_count;
        }
    }

    residue_count + 1
}

pub(crate) fn private_vss_share_lifted_carry_bound(
    recipient_roster_position: u64,
    coefficient_count: usize,
) -> CanonicalResult<i128> {
    let trustee_point = recipient_roster_position
        .checked_add(1)
        .ok_or_else(|| invalid_succinct_setup_proof("private VSS trustee point overflowed"))?;
    let mut power = 1_i128;
    let mut bound = 0_i128;
    for _ in 0..coefficient_count {
        bound = bound
            .checked_add(power)
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS carry bound overflowed"))?;
        power = power
            .checked_mul(i128::from(trustee_point))
            .ok_or_else(|| invalid_succinct_setup_proof("private VSS carry bound overflowed"))?;
    }

    Ok(bound)
}
