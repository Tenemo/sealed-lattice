pub use crate::linear_oracle::LinearOracle;
use crate::{
    field::{self, Element, ONE, ZERO},
    linear_oracle::{self, Public},
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    sums::Sums,
};
use parallel_work::share;
use zeroize::Zeroizing;

/// A public polynomial of an affine operator: its values sit at every
/// (SYSTEMATIC / degree)-th row of a column, with zeros between them.
pub enum PublicColumn {
    /// The first `degree` powers of the operator's challenge.
    Powers(usize),
    /// `degree` ones.
    Ones(usize),
    /// Public values, as many as the degree.
    Values(Vec<Element>),
}
impl PublicColumn {
    /// The sum of the values the column places.
    pub fn sum(&self, alpha: Element) -> Element {
        match self {
            Self::Powers(degree) => powers(alpha, *degree).into_iter().fold(ZERO, field::add),
            Self::Ones(degree) => [*degree as u128, 0, 0],
            Self::Values(values) => values.iter().copied().fold(ZERO, field::add),
        }
    }
}
/// A public column and the weight with which it enters each relation
/// column it names.
pub struct Term {
    pub public: PublicColumn,
    pub weights: Vec<(usize, Element)>,
}
/// An affine operator at a challenge: each relation column is the weighted
/// sum of the public columns of the terms that name it.
pub struct Operator {
    pub alpha: Element,
    pub terms: Vec<Term>,
    pub target: Element,
    pub lookup_weight: Element,
}
fn powers(alpha: Element, degree: usize) -> Vec<Element> {
    let mut current = ONE;
    (0..degree)
        .map(|_| {
            let previous = current;
            current = field::multiply(current, alpha);
            previous
        })
        .collect()
}
impl Operator {
    /// The values of the relation's columns at the queries, column after
    /// column. The query evaluation is linear, so each column's values are
    /// the weighted sums of its public columns' values, and ones on every
    /// row are one at every query.
    pub fn at_queries(
        self,
        columns: usize,
        queries: &[u32],
    ) -> Result<Vec<Element>, setup_stream_kernel::Error> {
        let count = queries.len();
        let mut output = vec![ZERO; columns * count];
        let mut evaluated = Vec::new();
        let mut weights = Vec::new();
        for term in self.terms {
            if term.weights.is_empty() {
                continue;
            }
            let values = match term.public {
                PublicColumn::Ones(degree) if degree == SYSTEMATIC => {
                    for (column, weight) in term.weights {
                        for value in &mut output[column * count..(column + 1) * count] {
                            *value = field::add(*value, weight);
                        }
                    }
                    continue;
                }
                PublicColumn::Powers(degree) => powers(self.alpha, degree),
                PublicColumn::Ones(degree) => vec![ONE; degree],
                PublicColumn::Values(values) => values,
            };
            evaluated.push(values);
            weights.push(term.weights);
        }
        let values = setup_stream_kernel::evaluate_public_columns(evaluated, queries)?;
        for (weights, values) in weights.iter().zip(values.chunks(count)) {
            for (column, weight) in weights {
                for (target, value) in output[column * count..(column + 1) * count]
                    .iter_mut()
                    .zip(values)
                {
                    *target = field::add(*target, field::multiply(*weight, *value));
                }
            }
        }
        Ok(output)
    }
    /// Every row of the relation's columns.
    #[cfg(test)]
    pub fn columns(&self, columns: usize) -> Vec<Vec<Element>> {
        let mut output = vec![vec![ZERO; SYSTEMATIC]; columns];
        for term in &self.terms {
            let values = match &term.public {
                PublicColumn::Powers(degree) => powers(self.alpha, *degree),
                PublicColumn::Ones(degree) => vec![ONE; *degree],
                PublicColumn::Values(values) => values.clone(),
            };
            let stride = SYSTEMATIC / values.len();
            for (column, weight) in &term.weights {
                for (index, value) in values.iter().enumerate() {
                    let target = &mut output[*column][stride * index];
                    *target = field::add(*target, field::multiply(*weight, *value));
                }
            }
        }
        output
    }
}

impl LinearOracle {
    pub fn create(
        role: &[u8],
        witness: &Witness,
        first: &FirstOracle,
        second: &SecondOracle,
        operator: Operator,
        mask_challenge: Element,
        adversarial: bool,
    ) -> Self {
        let mut sums = Sums::new(DOMAIN);
        let alpha = operator.alpha;
        // Each term adds the products of its public polynomial with the
        // weighted sum of the committed columns it names.
        for term in &operator.terms {
            let columns: Vec<_> = term
                .weights
                .iter()
                .copied()
                .filter(|(_, weight)| *weight != ZERO)
                .collect();
            if columns.is_empty() {
                continue;
            }
            let geometric = |degree, constant| Public::Geometric {
                alpha,
                degree,
                automorphism: 1,
                shift: 0,
                constant,
            };
            let values: parallel_work::Shared;
            let public = match &term.public {
                PublicColumn::Powers(degree) => geometric(*degree, false),
                PublicColumn::Ones(degree) => geometric(*degree, true),
                PublicColumn::Values(elements) => {
                    let mut bytes = Zeroizing::new(Vec::with_capacity(48 * elements.len()));
                    for value in elements {
                        bytes.extend(field::encode(*value));
                    }
                    values = share(bytes);
                    Public::Adjoint {
                        values: &values,
                        count: elements.len(),
                    }
                }
            };
            linear_oracle::products(
                &mut sums,
                mask_challenge,
                public,
                &columns,
                &witness.columns,
                &first.masks,
            );
        }
        linear_oracle::term(
            &mut sums,
            field::multiply(mask_challenge, operator.lookup_weight),
            &second.lookup_coefficients,
        );
        linear_oracle::term(&mut sums, ONE, &second.sum_mask);
        let mut evaluations = sums.finish();
        Self::from_evaluations(
            role,
            std::mem::take(&mut *evaluations),
            operator.target,
            operator.lookup_weight,
            mask_challenge,
            second.mask_sum,
            adversarial,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::MODULUS;

    fn element(seed: usize) -> Element {
        let value = |offset: usize| {
            (seed as u128 * 0x9e37_79b9_7f4a_7c15 + offset as u128 * 0x632b_e59b_d9b4_e019)
                % MODULUS
        };
        [value(1), value(2), value(3)]
    }

    // Every kind of public column, at full and reduced degrees, gives each
    // relation column the values at the queries that evaluating the column's
    // every row gives; a column no term names is zero.
    #[test]
    fn terms_give_every_column_the_values_of_its_rows() {
        let reduced = SYSTEMATIC / 16;
        let terms = vec![
            (PublicColumn::Powers(SYSTEMATIC), vec![0, 1, 3]),
            (PublicColumn::Powers(reduced), vec![1, 4]),
            (PublicColumn::Ones(SYSTEMATIC), vec![2, 3]),
            (PublicColumn::Ones(reduced), vec![0, 4]),
            (
                PublicColumn::Values((0..SYSTEMATIC).map(|row| element(row + 7)).collect()),
                vec![3, 5],
            ),
            (
                PublicColumn::Values((0..reduced).map(|row| element(row + 3)).collect()),
                vec![1, 5],
            ),
        ];
        let operator = Operator {
            alpha: element(1),
            terms: terms
                .into_iter()
                .enumerate()
                .map(|(term, (public, columns))| Term {
                    public,
                    weights: columns
                        .into_iter()
                        .map(|column| (column, element(100 * term + column)))
                        .collect(),
                })
                .collect(),
            target: ZERO,
            lookup_weight: ZERO,
        };
        let queries = [0, 1, 2, 3, 17, 1000, SYSTEMATIC as u32, DOMAIN as u32 - 1];
        let columns = operator.columns(7);
        assert!(columns[6].iter().all(|value| *value == ZERO));
        let expected = setup_stream_kernel::evaluate_public_columns(columns, &queries).unwrap();
        assert_eq!(operator.at_queries(7, &queries).unwrap(), expected);
    }

    // A column's sum is the sum of the values it places.
    #[test]
    fn public_column_sums_add_their_values() {
        let alpha = element(5);
        let mut current = ONE;
        let mut expected = ZERO;
        for _ in 0..SYSTEMATIC / 16 {
            expected = field::add(expected, current);
            current = field::multiply(current, alpha);
        }
        assert_eq!(PublicColumn::Powers(SYSTEMATIC / 16).sum(alpha), expected);
        assert_eq!(PublicColumn::Ones(4096).sum(alpha), [4096, 0, 0]);
        assert_eq!(
            PublicColumn::Values(vec![element(1), element(2)]).sum(alpha),
            field::add(element(1), element(2))
        );
    }
}
