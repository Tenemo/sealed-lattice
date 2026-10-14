use crate::{
    field::{self, Element, ONE, ZERO},
    linear_oracle::{AffineValues, LinearOracle, Public},
    oracles::{FirstOracle, SecondOracle, Witness},
};
use parallel_work::share;
use statement_stream::affine::{Operator, PublicColumn};
use zeroize::Zeroizing;

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
            mask_challenge,
            second.mask_sum,
            adversarial,
        )
    }
}
