use super::super::*;
use super::*;

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
// smudging mask lies in [0, 2^CLAIM_MASK_DIGIT_COUNT).
// Family-aware clear bound: the private-VSS family masks only the carry and the
// ternary opening-randomness columns (its message columns carry no consistency
// claim; see consistency_vector_count for why the message is pinned globally
// rather than by a per-claim mask), so its witness bound is the lifted carry
// bound (about 2^11); every other family uses 2 (centered-binomial magnitude).
// The mask is one-sided in [0, 2^CLAIM_MASK_DIGIT_COUNT), so the centered claim
// lies in [-clear_bound, mask_bound + clear_bound]. The disclosed smudging
// figure in accounting.rs recomputes from this same carry-driven family bound,
// so the relation bound and the disclosed leakage figure agree by construction.
// The carry's range bound here is essential to the global sharing-soundness
// argument: it keeps the pinned evaluation a bounded centered lift.
pub(crate) fn masked_claim_bounds(
    statement: &TrusteeEvaluationKeyStatement,
) -> CanonicalResult<(i128, i128)> {
    let ring_degree = statement.ring_degree;
    let coefficient_bound = (1_i128 << CONSISTENCY_COEFFICIENT_BITS) - 1;
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
        None => match &statement.compact_vss_share_linkage {
            Some(compact_vss_share_linkage) => {
                let carry_bound = private_vss_share_lifted_carry_bound(
                    compact_vss_share_linkage.recipient_roster_position,
                    compact_vss_share_linkage.coefficient_commitments.len(),
                )?;
                carry_bound.max(1)
            }
            None => 2,
        },
    };
    let clear_bound = witness_bound
        .checked_mul(coefficient_bound)
        .and_then(|bound| bound.checked_mul(ring_degree as i128))
        .ok_or_else(|| invalid_succinct_setup_proof("masked claim bound overflowed"))?;
    let mask_bound = 1_i128 << CLAIM_MASK_DIGIT_COUNT;

    Ok((-clear_bound, mask_bound + clear_bound))
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
