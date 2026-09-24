pub use crate::linear_oracle::LinearOracle;
use crate::{
    field::{self, Element, Transform, ZERO, base},
    oracles::{FirstOracle, SecondOracle, Witness, extension_values, masked_base},
    parameters::*,
    statement::Operator,
};
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
        let transform = Transform::new(SYSTEMATIC);
        let coefficients: Vec<Vec<Element>> = operator
            .coefficients
            .into_iter()
            .map(|mut values| {
                transform.extension(&mut values, true);
                values
            })
            .collect();
        let raw = Zeroizing::new(
            witness
                .columns
                .iter()
                .map(|column| column.iter().map(|value| u128::from(*value)).collect())
                .collect::<Vec<Vec<u128>>>(),
        );
        let mut evaluations = Zeroizing::new(vec![ZERO; DOMAIN]);
        for coset in 0..4 {
            let twist = base::multiply(7, base::power(field::root(DOMAIN), coset as u128));
            for column in 0..COLUMNS {
                let public = extension_values(&coefficients[column], twist, &transform);
                let values = Zeroizing::new(masked_base(
                    &raw[column],
                    &first.masks[column],
                    twist,
                    &transform,
                ));
                for (index, (coefficient, value)) in public.iter().zip(values.iter()).enumerate() {
                    let position = coset + 4 * index;
                    evaluations[position] =
                        field::add(evaluations[position], field::scale(*coefficient, *value));
                }
            }
            let lookup = Zeroizing::new(extension_values(
                &second.lookup_coefficients,
                twist,
                &transform,
            ));
            let mask = Zeroizing::new(extension_values(&second.sum_mask, twist, &transform));
            for (index, (lookup, mask)) in lookup.iter().zip(mask.iter()).enumerate() {
                let position = coset + 4 * index;
                evaluations[position] = field::add(
                    field::multiply(
                        mask_challenge,
                        field::add(
                            evaluations[position],
                            field::multiply(operator.lookup_weight, *lookup),
                        ),
                    ),
                    *mask,
                );
            }
        }
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
