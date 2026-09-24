use crate::parameters::ZERO_PRODUCTS as DISJOINT_PAIRS;
use crate::{
    field::{self, Element, MODULUS, Transform, ZERO, base},
    linear::LinearOracle,
    oracles::{self, FirstOracle, SecondOracle, Witness},
    parameters::*,
    transcript::challenge,
};

struct Weights {
    coefficients: Vec<Element>,
    powers: Vec<Vec<u128>>,
    classes: Vec<usize>,
}
impl Weights {
    fn new(message: &[u8], coset: u128) -> Self {
        let degrees = degrees();
        let mut unique = degrees.clone();
        unique.sort_unstable();
        unique.dedup();
        let powers = unique
            .iter()
            .map(|degree| {
                let shift = MAX_DEGREE - *degree;
                let mut value = base::power(coset, shift as u128);
                let step = base::power(field::root(SYSTEMATIC), shift as u128);
                (0..SYSTEMATIC)
                    .map(|_| {
                        let previous = value;
                        value = base::multiply(value, step);
                        previous
                    })
                    .collect()
            })
            .collect();
        Self {
            coefficients: (0..2 * ORACLES)
                .map(|index| challenge(message, index, false))
                .collect(),
            powers,
            classes: degrees
                .iter()
                .map(|degree| unique.binary_search(degree).unwrap())
                .collect(),
        }
    }
    fn value(&self, oracle: usize, position: usize) -> Element {
        field::add(
            self.coefficients[2 * oracle],
            field::scale(
                self.coefficients[2 * oracle + 1],
                self.powers[self.classes[oracle]][position],
            ),
        )
    }
    fn add_base(&self, output: &mut [Element], oracle: usize, values: &[u128]) {
        for (position, (sum, value)) in output.iter_mut().zip(values).enumerate() {
            *sum = field::add(*sum, field::scale(self.value(oracle, position), *value));
        }
    }
    fn add_extension(&self, output: &mut [Element], oracle: usize, values: &[Element]) {
        for (position, (sum, value)) in output.iter_mut().zip(values).enumerate() {
            *sum = field::add(*sum, field::multiply(self.value(oracle, position), *value));
        }
    }
    fn add_lookup(
        &self,
        output: &mut [Element],
        lookup_index: usize,
        beta: Element,
        inverse_vanishing: u128,
        words: &[u128],
        reciprocals: &[Element],
    ) {
        let inverse_oracle = COLUMNS + 1 + lookup_index;
        let residual_oracle = COLUMNS + LOOKUPS + 4 + BOOLEANS + DISJOINT_PAIRS + lookup_index;
        let (_, factor) = lookup(lookup_index);
        let residual_constant =
            field::scale(self.coefficients[2 * residual_oracle], inverse_vanishing);
        let residual_shifted = field::scale(
            self.coefficients[2 * residual_oracle + 1],
            inverse_vanishing,
        );
        let constant = field::add(
            self.coefficients[2 * inverse_oracle],
            field::multiply(beta, residual_constant),
        );
        let challenge_shifted = field::multiply(beta, residual_shifted);
        let word_constant = field::scale(residual_constant, factor);
        let word_shifted = field::scale(residual_shifted, factor);
        // Collect both occurrences of the reciprocal before multiplying it.
        // The verifier still evaluates the original inverse and quotient rows.
        for (position, ((sum, word), reciprocal)) in
            output.iter_mut().zip(words).zip(reciprocals).enumerate()
        {
            let inverse_power = self.powers[self.classes[inverse_oracle]][position];
            let residual_power = self.powers[self.classes[residual_oracle]][position];
            let coefficient = field::subtract(
                field::add(
                    constant,
                    field::add(
                        field::scale(self.coefficients[2 * inverse_oracle + 1], inverse_power),
                        field::scale(challenge_shifted, residual_power),
                    ),
                ),
                field::scale(
                    field::add(word_constant, field::scale(word_shifted, residual_power)),
                    *word,
                ),
            );
            *sum = field::add(
                *sum,
                field::subtract(
                    field::multiply(coefficient, *reciprocal),
                    field::add(
                        residual_constant,
                        field::scale(residual_shifted, residual_power),
                    ),
                ),
            );
        }
    }
}
pub fn polynomial(
    witness: &Witness,
    first: &FirstOracle,
    second: &SecondOracle,
    linear: &LinearOracle,
    beta: Element,
    inverses: &[Element],
    message: &[u8],
) -> Vec<Element> {
    let transform = Transform::new(SYSTEMATIC);
    // Every honest combined oracle has degree below twice the systematic size.
    // Interpolate on that many points; the verifier still checks the full domain.
    let shifts = [oracles::coset(0), oracles::coset(2)];
    let weights = shifts.map(|coset| Weights::new(message, coset));
    let inverse_vanishing = shifts.map(|coset| {
        base::power(
            base::subtract(base::power(coset, SYSTEMATIC as u128), 1),
            MODULUS - 2,
        )
    });
    let mut outputs =
        shifts.map(|coset| oracles::extension_values(&first.degree_mask, coset, &transform));
    let mut positive: [Option<Vec<u128>>; 2] = [None, None];
    // Both cosets use the same inverse transform. Retain just this column's
    // coefficients while computing their different forward evaluations.
    for column in 0..COLUMNS {
        let mut coefficients: Vec<u128> = witness.columns[column]
            .iter()
            .map(|value| u128::from(*value))
            .collect();
        transform.base(&mut coefficients, true);
        let values = shifts.map(|coset| {
            oracles::masked_base_coefficients(
                coefficients.clone(),
                &first.masks[column],
                coset,
                &transform,
                None,
            )
        });
        for coset in 0..2 {
            weights[coset].add_base(&mut outputs[coset], column, &values[coset]);
        }
        if column < WORDS {
            for lookup_index in 0..LOOKUPS {
                let (source, factor) = lookup(lookup_index);
                if source != column {
                    continue;
                }
                let raw = witness.columns[column]
                    .iter()
                    .map(|value| inverses[usize::from(*value) * factor as usize])
                    .collect();
                let coefficients = oracles::masked_extension_coefficients(
                    raw,
                    &second.masks[lookup_index],
                    &transform,
                );
                for coset in 0..2 {
                    let reciprocal =
                        oracles::extension_values(&coefficients, shifts[coset], &transform);
                    weights[coset].add_lookup(
                        &mut outputs[coset],
                        lookup_index,
                        beta,
                        inverse_vanishing[coset],
                        &values[coset],
                        &reciprocal,
                    );
                }
            }
        } else {
            for coset in 0..2 {
                let values = &values[coset];
                let residuals: Vec<u128> = values
                    .iter()
                    .map(|value| {
                        base::multiply(
                            base::multiply(*value, base::subtract(*value, 1)),
                            inverse_vanishing[coset],
                        )
                    })
                    .collect();
                weights[coset].add_base(
                    &mut outputs[coset],
                    COLUMNS + LOOKUPS + 4 + column - WORDS,
                    &residuals,
                );
                if column < WORDS + 2 * DISJOINT_PAIRS {
                    if (column - WORDS).is_multiple_of(2) {
                        positive[coset] = Some(values.clone());
                    } else {
                        let positive = positive[coset].take().unwrap();
                        let residuals: Vec<u128> = positive
                            .iter()
                            .zip(values)
                            .map(|(first, second)| {
                                base::multiply(
                                    base::multiply(*first, *second),
                                    inverse_vanishing[coset],
                                )
                            })
                            .collect();
                        weights[coset].add_base(
                            &mut outputs[coset],
                            COLUMNS + LOOKUPS + 4 + BOOLEANS + (column - WORDS) / 2,
                            &residuals,
                        );
                    }
                }
            }
        }
    }
    let mut count_coefficients = witness.counts.clone();
    transform.base(&mut count_coefficients, true);
    let raw = witness
        .counts
        .iter()
        .zip(inverses)
        .map(|(count, inverse)| field::scale(*inverse, *count))
        .collect();
    let coefficients =
        oracles::masked_extension_coefficients(raw, &second.masks[LOOKUPS], &transform);
    for coset_index in 0..2 {
        let coset = shifts[coset_index];
        let weights = &weights[coset_index];
        let output = &mut outputs[coset_index];
        let inverse_vanishing = inverse_vanishing[coset_index];
        let multiplicity = oracles::masked_base_coefficients(
            count_coefficients.clone(),
            &first.masks[COLUMNS],
            coset,
            &transform,
            None,
        );
        weights.add_base(output, COLUMNS, &multiplicity);
        let table_inverse = oracles::extension_values(&coefficients, coset, &transform);
        weights.add_extension(output, COLUMNS + 1 + LOOKUPS, &table_inverse);
        let table = oracles::masked_base(
            &(0..SYSTEMATIC)
                .map(|value| value as u128)
                .collect::<Vec<_>>(),
            &[],
            coset,
            &transform,
        );
        let residuals: Vec<Element> = table_inverse
            .iter()
            .zip(&table)
            .zip(&multiplicity)
            .map(|((inverse, table), multiplicity)| {
                field::scale(
                    field::subtract(
                        field::multiply(field::subtract(beta, [*table, 0, 0]), *inverse),
                        [*multiplicity, 0, 0],
                    ),
                    inverse_vanishing,
                )
            })
            .collect();
        weights.add_extension(output, ORACLES - 2, &residuals);
        weights.add_extension(
            output,
            COLUMNS + LOOKUPS + 2,
            &oracles::extension_values(&second.sum_mask, coset, &transform),
        );
        weights.add_extension(
            output,
            COLUMNS + LOOKUPS + 3,
            &oracles::extension_values(&linear.quotient, coset, &transform),
        );
        weights.add_extension(
            output,
            ORACLES - 1,
            &oracles::extension_values(&linear.remainder, coset, &transform),
        );
        #[cfg(not(target_arch = "wasm32"))]
        println!("Combined oracle coset {coset_index}");
    }
    let mut evaluations = vec![ZERO; 2 * SYSTEMATIC];
    for (coset, output) in outputs.into_iter().enumerate() {
        for (position, value) in output.into_iter().enumerate() {
            evaluations[coset + 2 * position] = value;
        }
    }
    Transform::new(2 * SYSTEMATIC).extension(&mut evaluations, true);
    let inverse_coset = base::power(7, MODULUS - 2);
    let mut power = 1;
    for value in &mut evaluations {
        *value = field::scale(*value, power);
        power = base::multiply(power, inverse_coset);
    }
    evaluations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ONE;
    #[test]
    fn collected_reciprocal_terms_equal_the_direct_constraint_for_both_lookup_scales() {
        let mut state = 0x935ac307125aec91u128;
        let mut sample = || {
            state ^= state << 23;
            state ^= state >> 31;
            state ^= state << 17;
            state % MODULUS
        };
        let weights = Weights {
            coefficients: (0..2 * ORACLES)
                .map(|_| [sample(), sample(), sample()])
                .collect(),
            powers: vec![vec![0, 1, MODULUS - 1, 37], vec![11, 0, 2, MODULUS - 1]],
            classes: (0..ORACLES).map(|index| index % 2).collect(),
        };
        let words = [0, 1, MODULUS - 1, sample()];
        let reciprocals = [
            [0, 0, 0],
            [1, 0, 0],
            [MODULUS - 1; 3],
            [sample(), sample(), sample()],
        ];
        for lookup_index in [0, 1, WORDS - 1, WORDS, LOOKUPS - 1] {
            for beta in [ZERO, ONE, [0, 0, 1], [sample(), sample(), sample()]] {
                for inverse_vanishing in [0, 1, MODULUS - 1, sample()] {
                    let mut actual = vec![ONE; words.len()];
                    weights.add_lookup(
                        &mut actual,
                        lookup_index,
                        beta,
                        inverse_vanishing,
                        &words,
                        &reciprocals,
                    );
                    for position in 0..words.len() {
                        let inverse_oracle = COLUMNS + 1 + lookup_index;
                        let residual_oracle =
                            COLUMNS + LOOKUPS + 4 + BOOLEANS + DISJOINT_PAIRS + lookup_index;
                        let residue = field::scale(
                            field::subtract(
                                field::multiply(
                                    reciprocals[position],
                                    field::subtract(
                                        beta,
                                        [
                                            base::multiply(words[position], lookup(lookup_index).1),
                                            0,
                                            0,
                                        ],
                                    ),
                                ),
                                ONE,
                            ),
                            inverse_vanishing,
                        );
                        let expected = field::add(
                            ONE,
                            field::add(
                                field::multiply(
                                    weights.value(inverse_oracle, position),
                                    reciprocals[position],
                                ),
                                field::multiply(weights.value(residual_oracle, position), residue),
                            ),
                        );
                        assert_eq!(actual[position], expected);
                    }
                }
            }
        }
    }
}
