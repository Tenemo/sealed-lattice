use crate::{
    field::{self, Element, ONE, ZERO},
    linear_oracle::{AffineValues, Public},
    oracles::{FirstOracle, SecondOracle, Witness},
};
use parallel_work::share;
use setup_stream_kernel::{ProverOperatorPlan, prover_operator_plan};
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
/// The masked affine sum of a setup proof. Its fixed bases' jobs start with
/// it and each public polynomial's jobs start as the polynomial arrives, so
/// the prover keeps no prepared polynomial after its jobs start.
pub struct AffineSum {
    plan: ProverOperatorPlan,
    mask: Element,
    target: Element,
    values: AffineValues,
    next: usize,
}
impl AffineSum {
    /// Starts the jobs of the fixed affine bases.
    pub fn begin(
        profile: Profile,
        witness: &Witness,
        first: &FirstOracle,
        challenges: Challenges,
    ) -> Self {
        let Challenges { alpha, mask } = challenges;
        let plan = prover_operator_plan(profile, alpha).unwrap();
        let mut values = AffineValues::new();
        let mut groups: BTreeMap<(usize, usize, usize, bool), Vec<Element>> = BTreeMap::new();
        for term in &plan.fixed_terms {
            let group = groups
                .entry((term.degree, term.automorphism, term.shift, term.constant))
                .or_insert_with(|| vec![ZERO; witness.relation.columns()]);
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
            values.products(
                mask,
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
        Self {
            target: plan.target_offset,
            plan,
            mask,
            values,
            next: 0,
        }
    }
    /// The index of the next public polynomial.
    pub fn next(&self) -> usize {
        self.next
    }
    /// Whether the next public polynomial arrives as its adjoint, since it
    /// has common columns, rather than as its value.
    pub fn next_is_adjoint(&self) -> bool {
        !self.plan.common_columns[self.next].is_empty()
    }
    /// Adds the next public polynomial: its weighted value leaves the
    /// target, or the jobs of its adjoint's products start.
    pub fn polynomial(
        &mut self,
        witness: &Witness,
        first: &FirstOracle,
        polynomial: PreparedPolynomial,
    ) {
        let index = self.next;
        match (self.next_is_adjoint(), polynomial) {
            (false, PreparedPolynomial::Value(value)) => {
                self.target = field::subtract(
                    self.target,
                    field::multiply(self.plan.value_weights[index], value),
                );
            }
            (true, PreparedPolynomial::Adjoint(values)) => {
                let count = values.len();
                let mut bytes = Zeroizing::new(Vec::with_capacity(48 * count));
                for value in &values {
                    bytes.extend(field::encode(*value));
                }
                drop(values);
                let values = share(bytes);
                self.values.products(
                    self.mask,
                    Public::Adjoint {
                        values: &values,
                        count,
                    },
                    &self.plan.common_columns[index],
                    &witness.columns,
                    &first.masks,
                );
            }
            _ => panic!("Public polynomial kind"),
        }
        if index.is_multiple_of(14) {
            #[cfg(not(target_arch = "wasm32"))]
            println!("Started public polynomial {index}");
        }
        self.next += 1;
    }
    /// The linear oracle once every public polynomial has arrived.
    pub fn finish(self, role: &[u8], second: &SecondOracle) -> LinearOracle {
        let Self {
            plan,
            mask,
            target,
            mut values,
            next,
        } = self;
        assert_eq!(next, plan.common_columns.len());
        values.term(
            field::multiply(mask, plan.lookup_weight),
            &second.lookup_coefficients,
        );
        values.term(ONE, &second.sum_mask);
        let mut evaluations = values.finish();
        LinearOracle::from_evaluations(
            role,
            std::mem::take(&mut *evaluations),
            target,
            plan.lookup_weight,
            mask,
            second.mask_sum,
            false,
        )
    }
}
