use super::super::*;
use super::*;

pub(crate) trait CompositionColumnDomain {
    type Value: Copy;

    fn tower(&self) -> &ChallengeExtensionTower;
    fn value_mul(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub(&self, left: &Self::Value, right: &Self::Value) -> Self::Value;
    fn value_sub_base(&self, left: &Self::Value, right: u64) -> Self::Value;
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
    let trinary_constraint = |value: &Domain::Value| {
        let cube = domain.value_mul(&domain.value_mul(value, value), value);
        domain.value_sub(&cube, value)
    };
    let mask_digit_constraint = |value: &Domain::Value| {
        let value_minus_one = domain.value_sub_base(value, 1);
        let value_minus_two = domain.value_sub_base(value, 2);
        domain.value_mul(&domain.value_mul(value, &value_minus_one), &value_minus_two)
    };

    if layout.private_vss_active() {
        for randomness_position in 0..layout.private_vss_randomness_columns {
            for half in 0..TRACE_SPLIT {
                let randomness = column_values
                    [layout.physical_private_vss_randomness(randomness_position, half)];
                absorb(&trinary_constraint(&randomness), &mut accumulated);
            }
        }
        for mask_column in 0..layout.mask_column_count {
            for half in 0..TRACE_SPLIT {
                let mask = column_values[layout.physical_mask(mask_column, half)];
                absorb(&mask_digit_constraint(&mask), &mut accumulated);
            }
        }
        return accumulated;
    }

    for half in 0..TRACE_SPLIT {
        let secret = column_values[layout.physical_secret(half)];
        absorb(&trinary_constraint(&secret), &mut accumulated);
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
                absorb(&trinary_constraint(&randomness), &mut accumulated);
            }
        }
    }
    for mask_column in 0..layout.mask_column_count {
        for half in 0..TRACE_SPLIT {
            let mask = column_values[layout.physical_mask(mask_column, half)];
            absorb(&mask_digit_constraint(&mask), &mut accumulated);
        }
    }
    accumulated
}

pub(crate) struct SumcheckPublicEvaluations<ColumnValue> {
    pub(crate) secret_factor: Vec<[ChallengeExtensionElement; 2]>,
    pub(crate) u_power: Vec<[ChallengeExtensionElement; 2]>,
    pub(crate) consistency: Vec<[ColumnValue; 2]>,
    pub(crate) mask_selector: Vec<[ChallengeExtensionElement; 2]>,
    pub(crate) linkage: Vec<[ChallengeExtensionElement; 2]>,
}

pub(crate) struct SumcheckErrorWeights {
    pub(crate) weights: Vec<Vec<ChallengeExtensionElement>>,
}

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
            for repetition in 0..layout.consistency_repetitions {
                let alpha_value = &consistency_alpha[claim_alpha_index];
                claim_alpha_index += 1;
                for half in 0..TRACE_SPLIT {
                    let witness_value = if consistency_vector == 0 {
                        column_values[layout.physical_private_vss_carry(half)]
                    } else {
                        column_values
                            [layout.physical_private_vss_randomness(consistency_vector - 1, half)]
                    };
                    let product =
                        domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                    accumulated =
                        tower.add(&accumulated, &domain.challenge_times(alpha_value, &product));
                }
            }
        }
        absorb_mask_columns(domain, column_values, publics, layout, &mut accumulated);
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
        for repetition in 0..layout.consistency_repetitions {
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
                let product =
                    domain.value_mul(&publics.consistency[repetition][half], &witness_value);
                accumulated =
                    tower.add(&accumulated, &domain.challenge_times(alpha_value, &product));
            }
        }
    }
    absorb_mask_columns(domain, column_values, publics, layout, &mut accumulated);
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

fn absorb_mask_columns<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    publics: &SumcheckPublicEvaluations<Domain::Value>,
    layout: &LimbColumnLayout,
    accumulated: &mut ChallengeExtensionElement,
) {
    let tower = *domain.tower();
    for (mask_column, mask_selector) in publics.mask_selector.iter().enumerate() {
        for half in 0..TRACE_SPLIT {
            *accumulated = tower.add(
                accumulated,
                &domain.challenge_times(
                    &mask_selector[half],
                    &column_values[layout.physical_mask(mask_column, half)],
                ),
            );
        }
    }
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
