pub use crate::linear_oracle::LinearOracle;
use crate::{
    field::{self, Element, ONE},
    linear_oracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    statement::Operator,
    sums::Sums,
};

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
        for column in 0..witness.relation.columns() {
            linear_oracle::column(
                &mut sums,
                mask_challenge,
                &operator.coefficients[column],
                &first.masks[column],
                &witness.columns[column],
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
