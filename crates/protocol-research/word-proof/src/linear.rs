use crate::{
    field::{self, Element, ONE, ZERO},
    linear_oracle::{self, Public},
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::*,
    sums::Sums,
};
use parallel_work::share;
use setup_stream_kernel::prover_operator_plan;
use std::collections::BTreeMap;
use supported_profile::Profile;
use zeroize::Zeroizing;

pub use crate::linear_oracle::LinearOracle;
pub struct Challenges {
    pub alpha: Element,
    pub mask: Element,
}
pub enum PreparedPolynomial {
    Value(Element),
    Adjoint(Vec<Element>),
}
impl LinearOracle {
    pub fn create_prepared(
        profile: Profile,
        role: &[u8],
        witness: &Witness,
        first: &FirstOracle,
        second: &SecondOracle,
        challenges: Challenges,
        mut polynomials: impl Iterator<Item = PreparedPolynomial>,
    ) -> Self {
        let Challenges {
            alpha,
            mask: mask_challenge,
        } = challenges;
        let relation = &witness.relation;
        let polynomial_count = profile.setup_polynomials();
        let plan = prover_operator_plan(profile, alpha).unwrap();
        let mut target = plan.target_offset;
        let mut sums = Sums::new(DOMAIN);
        let mut groups: BTreeMap<(usize, usize, usize, bool), Vec<Element>> = BTreeMap::new();
        for term in &plan.fixed_terms {
            let group = groups
                .entry((term.degree, term.automorphism, term.shift, term.constant))
                .or_insert_with(|| vec![ZERO; relation.columns()]);
            for (column, weight) in &term.columns {
                group[*column] = field::add(group[*column], *weight);
            }
        }
        for ((degree, automorphism, shift, constant), weights) in groups {
            let columns: Vec<_> = weights
                .into_iter()
                .enumerate()
                .filter(|(_, weight)| *weight != ZERO)
                .collect();
            if columns.is_empty() {
                continue;
            }
            linear_oracle::products(
                &mut sums,
                mask_challenge,
                Public::Geometric {
                    alpha,
                    degree,
                    automorphism,
                    shift,
                    constant,
                },
                &columns,
                &witness.columns,
                &first.masks,
            );
        }
        #[cfg(not(target_arch = "wasm32"))]
        println!("Started fixed affine bases");
        for index in 0..polynomial_count {
            let polynomial = polynomials.next().unwrap();
            if plan.common_columns[index].is_empty() {
                let PreparedPolynomial::Value(value) = polynomial else {
                    panic!("Expected public value");
                };
                target = field::subtract(target, field::multiply(plan.value_weights[index], value));
            } else {
                let PreparedPolynomial::Adjoint(values) = polynomial else {
                    panic!("Expected public adjoint");
                };
                let count = values.len();
                let mut bytes = Zeroizing::new(Vec::with_capacity(48 * count));
                for value in &values {
                    bytes.extend(field::encode(*value));
                }
                let values = share(bytes);
                linear_oracle::products(
                    &mut sums,
                    mask_challenge,
                    Public::Adjoint {
                        values: &values,
                        count,
                    },
                    &plan.common_columns[index],
                    &witness.columns,
                    &first.masks,
                );
            }
            if index % 14 == 0 {
                #[cfg(not(target_arch = "wasm32"))]
                println!("Started public polynomial {index}");
            }
        }
        assert!(polynomials.next().is_none());
        linear_oracle::term(
            &mut sums,
            field::multiply(mask_challenge, plan.lookup_weight),
            &second.lookup_coefficients,
        );
        linear_oracle::term(&mut sums, ONE, &second.sum_mask);
        let mut evaluations = sums.finish();
        Self::from_evaluations(
            role,
            std::mem::take(&mut *evaluations),
            target,
            plan.lookup_weight,
            mask_challenge,
            second.mask_sum,
            false,
        )
    }
}
