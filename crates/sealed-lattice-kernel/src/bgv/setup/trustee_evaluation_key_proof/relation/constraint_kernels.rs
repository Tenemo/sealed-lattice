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

#[cfg(test)]
pub(crate) struct BaseColumnDomain {
    pub(crate) tower: ChallengeExtensionTower,
}

#[cfg(test)]
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
    let ternary_constraint = |value: &Domain::Value| {
        let cube = domain.value_mul(&domain.value_mul(value, value), value);
        domain.value_sub(&cube, value)
    };
    let mask_digit_constraint = |value: &Domain::Value| {
        let value_minus_one = domain.value_sub_base(value, 1);
        let value_minus_two = domain.value_sub_base(value, 2);
        domain.value_mul(&domain.value_mul(value, &value_minus_one), &value_minus_two)
    };

    for randomness_position in 0..layout.private_vss_randomness_columns {
        for half in 0..TRACE_SPLIT {
            let randomness =
                column_values[layout.physical_private_vss_randomness(randomness_position, half)];
            absorb(&ternary_constraint(&randomness), &mut accumulated);
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
    pub(crate) consistency: Vec<[ColumnValue; 2]>,
    pub(crate) mask_selector: Vec<[ChallengeExtensionElement; 2]>,
    pub(crate) private_vss_relation: Vec<[ChallengeExtensionElement; 2]>,
}

pub(crate) fn batched_sumcheck_value<Domain: CompositionColumnDomain>(
    domain: &Domain,
    column_values: &[Domain::Value],
    publics: &SumcheckPublicEvaluations<Domain::Value>,
    consistency_alpha: &[ChallengeExtensionElement],
    layout: &LimbColumnLayout,
) -> ChallengeExtensionElement {
    let tower = *domain.tower();
    let mut accumulated = ChallengeExtensionTower::zero();
    debug_assert_eq!(consistency_alpha.len(), layout.claim_count());
    for (repetition, alpha_value) in consistency_alpha.iter().enumerate() {
        for half in 0..TRACE_SPLIT {
            let witness_value = column_values[layout.physical_private_vss_carry(half)];
            let product = domain.value_mul(&publics.consistency[repetition][half], &witness_value);
            accumulated = tower.add(&accumulated, &domain.challenge_times(alpha_value, &product));
        }
    }
    absorb_mask_columns(domain, column_values, publics, layout, &mut accumulated);
    debug_assert_eq!(
        publics.private_vss_relation.len(),
        layout.private_vss_logical_columns()
    );
    for (column_index, relation_values) in publics.private_vss_relation.iter().enumerate() {
        for (half, relation_value) in relation_values.iter().enumerate().take(TRACE_SPLIT) {
            let column_value =
                private_vss_column_value::<Domain>(column_values, layout, column_index, half);
            accumulated = tower.add(
                &accumulated,
                &domain.challenge_times(relation_value, &column_value),
            );
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
