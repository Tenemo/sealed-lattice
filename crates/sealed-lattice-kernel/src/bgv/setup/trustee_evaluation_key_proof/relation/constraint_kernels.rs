use super::super::*;
use super::*;

// Column value domain for the composition functions: the prover evaluates
// them over base-field committed column values, the verifier re-evaluates the
// same expressions over extension-valued out-of-domain evaluations. One
// generic implementation keeps the constraint enumeration identical on both
// sides; the challenges always live in the extension.
pub(crate) trait CompositionColumnDomain {
    type Value: Copy;

    fn tower(&self) -> &ChallengeExtensionTower;
    fn value_mul(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub_base(&self, left: &Self::Value, right: u64) -> Self::Value;
    // challenge * value, landing in the extension.
    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &Self::Value,
    ) -> ChallengeExtensionElement;
}

pub(crate) struct BaseColumnDomain {
    pub(crate) tower: ChallengeExtensionTower,
}

impl CompositionColumnDomain for BaseColumnDomain {
    type Value = u64;

    fn tower(&self) -> &ChallengeExtensionTower {
        &self.tower
    }

    fn value_mul(&self, left: &u64, right: &u64) -> u64 {
        mul_mod_fast(*left, *right, self.tower.modulus)
    }

    fn value_sub(&self, left: &u64, right: &u64) -> u64 {
        sub_mod_fast(*left, *right, self.tower.modulus)
    }

    fn value_sub_base(&self, left: &u64, right: u64) -> u64 {
        sub_mod_fast(*left, right % self.tower.modulus, self.tower.modulus)
    }

    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &u64,
    ) -> ChallengeExtensionElement {
        self.tower.scale_base(challenge, *value)
    }
}

pub(crate) struct ExtensionColumnDomain {
    pub(crate) tower: ChallengeExtensionTower,
}

impl CompositionColumnDomain for ExtensionColumnDomain {
    type Value = ChallengeExtensionElement;

    fn tower(&self) -> &ChallengeExtensionTower {
        &self.tower
    }

    fn value_mul(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.mul(left, right)
    }

    fn value_sub(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.sub(left, right)
    }

    fn value_sub_base(
        &self,
        left: &ChallengeExtensionElement,
        right: u64,
    ) -> ChallengeExtensionElement {
        self.tower
            .sub(left, &self.tower.embed_base(right % self.tower.modulus))
    }

    fn challenge_times(
        &self,
        challenge: &ChallengeExtensionElement,
        value: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        self.tower.mul(challenge, value)
    }
}

// The batched row-check value sum_k beta_k * C_k at one point, given the
// phase-one physical column values at that point in layout order. One
// constraint per physical column:
//   secret halves:        S^3 - S            (ternary support)
//   error halves:         E (E2 - 1)(E2 - 4) (centered binomial support)
//   error-square halves:  E2 - E^2           (helper well-formedness)
//   mask halves:          M^2 - M            (binary digits)
pub(crate) fn batched_row_check_value<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    beta: &[ChallengeExtensionElement],
    layout: &LimbColumnLayout,
) -> ChallengeExtensionElement {
    debug_assert_eq!(column_values.len(), layout.phase_one_physical_count());
    debug_assert_eq!(beta.len(), layout.row_check_constraint_count());
    let tower = *domain.tower();
    let mut accumulated = ChallengeExtensionTower::zero();
    let mut constraint_index = 0_usize;
    let mut absorb = |value: &Domain::Value, accumulated: &mut ChallengeExtensionElement| {
        *accumulated = tower.add(
            accumulated,
            &domain.challenge_times(&beta[constraint_index], value),
        );
        constraint_index += 1;
    };
    if layout.private_vss_active() {
        for randomness_position in 0..layout.private_vss_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness = column_values
                    [layout.physical_private_vss_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
        for mask_column in 0..layout.mask_column_count {
            for half in 0..TRACE_SPLIT {
                let mask = column_values[layout.physical_mask(mask_column, half)];
                absorb(
                    &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                    &mut accumulated,
                );
            }
        }

        return accumulated;
    }
    if layout.compact_vss_active() {
        for randomness_position in 0..layout.compact_vss_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness = column_values
                    [layout.physical_compact_vss_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
        for mask_column in 0..layout.mask_column_count {
            for half in 0..TRACE_SPLIT {
                let mask = column_values[layout.physical_mask(mask_column, half)];
                absorb(
                    &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                    &mut accumulated,
                );
            }
        }

        return accumulated;
    }
    if layout.target_decryption_active() {
        for randomness_position in 0..layout.target_decryption_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness = column_values
                    [layout.physical_target_decryption_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
        for mask_column in 0..layout.mask_column_count {
            for half in 0..TRACE_SPLIT {
                let mask = column_values[layout.physical_mask(mask_column, half)];
                absorb(
                    &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                    &mut accumulated,
                );
            }
        }

        return accumulated;
    }
    for half in 0..TRACE_SPLIT {
        let secret = column_values[layout.physical_secret(half)];
        let cube = domain.value_mul(&domain.value_mul(&secret, &secret), &secret);
        absorb(&domain.value_sub(&cube, &secret), &mut accumulated);
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            let range_polynomial = domain.value_mul(
                &domain.value_sub_base(&error_square, 1),
                &domain.value_sub_base(&error_square, 4),
            );
            absorb(
                &domain.value_mul(&error, &range_polynomial),
                &mut accumulated,
            );
        }
    }
    for error_position in 0..layout.total_error_columns {
        for half in 0..TRACE_SPLIT {
            let error = column_values[layout.physical_error(error_position, half)];
            let error_square = column_values[layout.physical_error_square(error_position, half)];
            absorb(
                &domain.value_sub(&error_square, &domain.value_mul(&error, &error)),
                &mut accumulated,
            );
        }
    }
    if layout.linkage_active() {
        for half in 0..TRACE_SPLIT {
            let indicator = column_values[layout.physical_negative_indicator(half)];
            absorb(
                &domain.value_sub(&domain.value_mul(&indicator, &indicator), &indicator),
                &mut accumulated,
            );
        }
        for randomness_position in 0..layout.linkage_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness =
                    column_values[layout.physical_linkage_randomness(randomness_position, half)];
                let cube =
                    domain.value_mul(&domain.value_mul(&randomness, &randomness), &randomness);
                absorb(&domain.value_sub(&cube, &randomness), &mut accumulated);
            }
        }
    }
    for mask_column in 0..layout.mask_column_count {
        for half in 0..TRACE_SPLIT {
            let mask = column_values[layout.physical_mask(mask_column, half)];
            absorb(
                &domain.value_sub(&domain.value_mul(&mask, &mask), &mask),
                &mut accumulated,
            );
        }
    }

    accumulated
}

// The per-point public evaluations the batched sumcheck integrand consumes:
// for each lincheck repetition the per-half combined secret-factor vector and
// the power vector, for each consistency repetition the per-half coefficient
// vector, and for each mask column the per-half selector combination.
pub(crate) struct SumcheckPublicEvaluations<ColumnValue> {
    // [repetition][half]
    pub(crate) secret_factor: Vec<[ChallengeExtensionElement; 2]>,
    pub(crate) u_power: Vec<[ChallengeExtensionElement; 2]>,
    // [consistency repetition][half]; the consistency vectors are public
    // bounded integers, so their evaluations stay in the column value domain.
    pub(crate) consistency: Vec<[ColumnValue; 2]>,
    // [mask column][half]
    pub(crate) mask_selector: Vec<[ChallengeExtensionElement; 2]>,
    // Linkage pair vectors in fixed order: the secret-link vector, the
    // negative-indicator vector, then one combined vector per opening
    // randomness column. Empty outside the commitment fields.
    pub(crate) linkage: Vec<[ChallengeExtensionElement; 2]>,
}

// Scalar weights for the error contribution of the lincheck: weight of error
// column position p at repetition r is alpha_{key(p), r} * gamma_{key(p)}^j(p).
pub(crate) struct SumcheckErrorWeights {
    // [repetition][error position]
    pub(crate) weights: Vec<Vec<ChallengeExtensionElement>>,
}

// The batched sumcheck integrand at one point:
//   sum_r [ SecretFactor_r * S - p * U_r * (sum_p weight_{r,p} * E_p) ]
// + sum_{c,t} alpha'_{c,t} * P_t * W_c
// + sum_i CombSel_i * Mask_i
// with every product summed over both halves.
#[allow(clippy::too_many_arguments)]
pub(crate) fn batched_sumcheck_value<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    publics: &SumcheckPublicEvaluations<Domain::Value>,
    error_weights: &SumcheckErrorWeights,
    consistency_alpha: &[ChallengeExtensionElement],
    layout: &LimbColumnLayout,
) -> ChallengeExtensionElement {
    let tower = *domain.tower();
    let plaintext_modulus = (PLAINTEXT_MODULUS_I64 as u64) % tower.modulus;
    let mut accumulated = ChallengeExtensionTower::zero();
    if layout.private_vss_active() {
        let mut claim_alpha_index = 0_usize;
        for consistency_vector in 0..layout.consistency_vector_count() {
            for repetition in 0..CONSISTENCY_REPETITIONS {
                let alpha_value = &consistency_alpha[claim_alpha_index];
                claim_alpha_index += 1;
                for half in 0..TRACE_SPLIT {
                    // Consistency vectors are [carry, opening-randomness...]; the
                    // message columns carry no consistency claim (see
                    // consistency_vector_count), so index zero is the carry and
                    // the rest are the opening-randomness columns. This order must
                    // match the prover's signed_vectors in global_claim_integers.
                    let witness_value = if consistency_vector == 0 {
                        column_values[layout.physical_private_vss_carry(half)]
                    } else {
                        column_values
                            [layout.physical_private_vss_randomness(consistency_vector - 1, half)]
                    };
                    let consistency_product =
                        domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                    accumulated = tower.add(
                        &accumulated,
                        &domain.challenge_times(alpha_value, &consistency_product),
                    );
                }
            }
        }
        for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(
                        &mask_selector[half],
                        &column_values[layout.physical_mask(mask_column, half)],
                    ),
                );
            }
        }
        debug_assert_eq!(publics.linkage.len(), layout.private_vss_logical_columns());
        for (column_index, relation_values) in publics.linkage.iter().enumerate() {
            for (half, relation_value) in relation_values.iter().enumerate().take(TRACE_SPLIT) {
                let column_value =
                    private_vss_column_value::<Domain>(column_values, layout, column_index, half);
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(relation_value, &column_value),
                );
            }
        }

        return accumulated;
    }
    if layout.compact_vss_active() {
        let mut claim_alpha_index = 0_usize;
        for consistency_vector in 0..layout.consistency_vector_count() {
            for repetition in 0..CONSISTENCY_REPETITIONS {
                let alpha_value = &consistency_alpha[claim_alpha_index];
                claim_alpha_index += 1;
                for half in 0..TRACE_SPLIT {
                    let witness_value = if consistency_vector == 0 {
                        column_values[layout.physical_compact_vss_carry(half)]
                    } else {
                        column_values
                            [layout.physical_compact_vss_randomness(consistency_vector - 1, half)]
                    };
                    let consistency_product =
                        domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                    accumulated = tower.add(
                        &accumulated,
                        &domain.challenge_times(alpha_value, &consistency_product),
                    );
                }
            }
        }
        for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(
                        &mask_selector[half],
                        &column_values[layout.physical_mask(mask_column, half)],
                    ),
                );
            }
        }
        debug_assert_eq!(publics.linkage.len(), layout.compact_vss_logical_columns());
        for (column_index, relation_values) in publics.linkage.iter().enumerate() {
            for (half, relation_value) in relation_values.iter().enumerate().take(TRACE_SPLIT) {
                let column_value =
                    compact_vss_column_value::<Domain>(column_values, layout, column_index, half);
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(relation_value, &column_value),
                );
            }
        }

        return accumulated;
    }
    if layout.target_decryption_active() {
        let mut claim_alpha_index = 0_usize;
        for consistency_vector in 0..layout.consistency_vector_count() {
            for repetition in 0..CONSISTENCY_REPETITIONS {
                let alpha_value = &consistency_alpha[claim_alpha_index];
                claim_alpha_index += 1;
                for half in 0..TRACE_SPLIT {
                    let witness_value =
                        if consistency_vector < layout.target_decryption_message_columns {
                            column_values[layout
                                .physical_target_decryption_message(consistency_vector, half)]
                        } else {
                            column_values[layout.physical_target_decryption_randomness(
                                consistency_vector - layout.target_decryption_message_columns,
                                half,
                            )]
                        };
                    let consistency_product =
                        domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                    accumulated = tower.add(
                        &accumulated,
                        &domain.challenge_times(alpha_value, &consistency_product),
                    );
                }
            }
        }
        for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(
                        &mask_selector[half],
                        &column_values[layout.physical_mask(mask_column, half)],
                    ),
                );
            }
        }
        debug_assert_eq!(
            publics.linkage.len(),
            layout.target_decryption_logical_columns()
        );
        for (column_index, relation_values) in publics.linkage.iter().enumerate() {
            for (half, relation_value) in relation_values.iter().enumerate().take(TRACE_SPLIT) {
                let column_value = target_decryption_column_value::<Domain>(
                    column_values,
                    layout,
                    column_index,
                    half,
                );
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(relation_value, &column_value),
                );
            }
        }

        return accumulated;
    }
    for (repetition, (secret_factor, u_power)) in publics
        .secret_factor
        .iter()
        .zip(publics.u_power.iter())
        .enumerate()
    {
        for half in 0..TRACE_SPLIT {
            let secret = column_values[layout.physical_secret(half)];
            accumulated = tower.add(
                &accumulated,
                &domain.challenge_times(&secret_factor[half], &secret),
            );
            let mut weighted_error = ChallengeExtensionTower::zero();
            for error_position in 0..layout.total_error_columns {
                weighted_error = tower.add(
                    &weighted_error,
                    &domain.challenge_times(
                        &error_weights.weights[repetition][error_position],
                        &column_values[layout.physical_error(error_position, half)],
                    ),
                );
            }
            accumulated = tower.sub(
                &accumulated,
                &tower.scale_base(
                    &tower.mul(&u_power[half], &weighted_error),
                    plaintext_modulus,
                ),
            );
        }
    }
    let mut claim_alpha_index = 0_usize;
    for consistency_vector in 0..layout.consistency_vector_count() {
        for repetition in 0..CONSISTENCY_REPETITIONS {
            let alpha_value = &consistency_alpha[claim_alpha_index];
            claim_alpha_index += 1;
            for half in 0..TRACE_SPLIT {
                let witness_value = if consistency_vector == 0 {
                    column_values[layout.physical_secret(half)]
                } else if consistency_vector <= layout.total_error_columns {
                    column_values[layout.physical_error(consistency_vector - 1, half)]
                } else if consistency_vector == layout.total_error_columns + 1 {
                    column_values[layout.physical_negative_indicator(half)]
                } else {
                    column_values[layout.physical_linkage_randomness(
                        consistency_vector - layout.total_error_columns - 2,
                        half,
                    )]
                };
                let consistency_product =
                    domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(alpha_value, &consistency_product),
                );
            }
        }
    }
    for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
        for half in 0..TRACE_SPLIT {
            accumulated = tower.add(
                &accumulated,
                &domain.challenge_times(
                    &mask_selector[half],
                    &column_values[layout.physical_mask(mask_column, half)],
                ),
            );
        }
    }
    if layout.linkage_active() {
        debug_assert_eq!(publics.linkage.len(), 2 + layout.linkage_randomness_columns);
        for (linkage_position, linkage_values) in publics.linkage.iter().enumerate() {
            for half in 0..TRACE_SPLIT {
                let column_value = if linkage_position == 0 {
                    column_values[layout.physical_secret(half)]
                } else if linkage_position == 1 {
                    column_values[layout.physical_negative_indicator(half)]
                } else {
                    column_values[layout.physical_linkage_randomness(linkage_position - 2, half)]
                };
                accumulated = tower.add(
                    &accumulated,
                    &domain.challenge_times(&linkage_values[half], &column_value),
                );
            }
        }
    }

    accumulated
}

fn private_vss_column_value<Domain: CompositionColumnDomain>(
    column_values: &[Domain::Value],
    layout: &LimbColumnLayout,
    vector_index: usize,
    half: usize,
) -> Domain::Value {
    if vector_index < layout.private_vss_coefficient_columns {
        column_values[layout.physical_private_vss_message(vector_index, half)]
    } else if vector_index == layout.private_vss_coefficient_columns {
        column_values[layout.physical_private_vss_carry(half)]
    } else {
        column_values[layout.physical_private_vss_randomness(
            vector_index - layout.private_vss_coefficient_columns - 1,
            half,
        )]
    }
}

fn compact_vss_column_value<Domain: CompositionColumnDomain>(
    column_values: &[Domain::Value],
    layout: &LimbColumnLayout,
    vector_index: usize,
    half: usize,
) -> Domain::Value {
    if vector_index < layout.compact_vss_coefficient_columns {
        column_values[layout.physical_compact_vss_message(vector_index, half)]
    } else if vector_index == layout.compact_vss_coefficient_columns {
        column_values[layout.physical_compact_vss_recipient_message(half)]
    } else if vector_index == layout.compact_vss_coefficient_columns + 1 {
        column_values[layout.physical_compact_vss_carry(half)]
    } else {
        column_values[layout.physical_compact_vss_randomness(
            vector_index - layout.compact_vss_coefficient_columns - 2,
            half,
        )]
    }
}

fn target_decryption_column_value<Domain: CompositionColumnDomain>(
    column_values: &[Domain::Value],
    layout: &LimbColumnLayout,
    vector_index: usize,
    half: usize,
) -> Domain::Value {
    if vector_index < layout.target_decryption_message_columns {
        column_values[layout.physical_target_decryption_message(vector_index, half)]
    } else {
        column_values[layout.physical_target_decryption_randomness(
            vector_index - layout.target_decryption_message_columns,
            half,
        )]
    }
}
