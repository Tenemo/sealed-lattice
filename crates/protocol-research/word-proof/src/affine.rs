use crate::{
    field::{self, Element, ONE, ZERO},
    linear_oracle::{AffineValues, LinearOracle, Public},
    oracles::{FirstOracle, SecondOracle, Witness},
};
use parallel_work::share;
use supported_profile::relation::*;
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
    ) -> Result<Vec<Element>, statement_stream::Error> {
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
        let values = statement_stream::evaluate_public_columns(evaluated, queries)?;
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
    #[cfg(any(test, feature = "test-support"))]
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
        let mut values = AffineValues::new();
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
            let shared: parallel_work::Shared;
            let public = match &term.public {
                PublicColumn::Powers(degree) => geometric(*degree, false),
                PublicColumn::Ones(degree) => geometric(*degree, true),
                PublicColumn::Values(elements) => {
                    let mut bytes = Zeroizing::new(Vec::with_capacity(48 * elements.len()));
                    for value in elements {
                        bytes.extend(field::encode(*value));
                    }
                    shared = share(bytes);
                    Public::Adjoint {
                        values: &shared,
                        count: elements.len(),
                    }
                }
            };
            values.products(
                mask_challenge,
                public,
                &columns,
                &witness.columns,
                &first.masks,
            );
        }
        values.term(
            field::multiply(mask_challenge, operator.lookup_weight),
            &second.lookup_coefficients,
        );
        values.term(ONE, &second.sum_mask);
        let mut evaluations = values.finish();
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
#[path = "affine-tests.rs"]
mod tests;
