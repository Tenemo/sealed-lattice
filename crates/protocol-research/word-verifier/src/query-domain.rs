use super::{Challenges, Element, FOLDS, Shape, add, root, scale};
use statement_stream::proof_field::{
    MODULUS, multiply as multiply_base, power as power_base, subtract as subtract_base,
};
use std::sync::OnceLock;
use supported_profile::relation::{
    EVALUATION_DOMAIN_SIZE, MAXIMUM_DEGREE, SYSTEMATIC, WITNESS_DEGREE,
};

/// The degrees whose corrections raise an oracle to the largest degree.
pub(super) const CORRECTED_DEGREES: [usize; 4] = [
    WITNESS_DEGREE,
    WITNESS_DEGREE - 1,
    2 * WITNESS_DEGREE - SYSTEMATIC,
    SYSTEMATIC - 2,
];
/// The low bits of an exponent of the domain's root, which index the table
/// of its first powers.
const LOW_BITS: usize = 9;

/// The proof domain is the coset of the shift seven by the subgroup of the
/// domain's root w. Every queried point's values follow from constants this
/// instance computes once: the powers of w as two tables, the shift's
/// inverse, the systematic vanishing polynomial's values on the coset and
/// their inverses, which repeat with the index modulo four because w^SYSTEMATIC has
/// order four, and the shift's power at each degree correction. Each fold
/// round's points follow from the shift's inverse raised to that round's
/// power of two.
pub(super) struct Coset {
    pub(super) low: Vec<u128>,
    pub(super) high: Vec<u128>,
    pub(super) inverse_shift: u128,
    pub(super) vanishing: [u128; 4],
    pub(super) inverse_vanishing: [u128; 4],
    pub(super) shifts: [u128; 4],
    pub(super) inverse_fold_shifts: [u128; FOLDS],
    pub(super) half: u128,
    pub(super) inverse_systematic: u128,
}
impl Coset {
    pub(super) fn get() -> &'static Self {
        static COSET: OnceLock<Coset> = OnceLock::new();
        COSET.get_or_init(|| {
            let root = root(EVALUATION_DOMAIN_SIZE);
            let powers = |step: u128, count: usize| {
                let mut value = 1;
                (0..count)
                    .map(|_| {
                        let current = value;
                        value = multiply_base(value, step);
                        current
                    })
                    .collect()
            };
            let order_four = power_base(root, SYSTEMATIC as u128);
            let shifted = power_base(7, SYSTEMATIC as u128);
            let vanishing: [u128; 4] = std::array::from_fn(|residue| {
                subtract_base(
                    multiply_base(shifted, power_base(order_four, residue as u128)),
                    1,
                )
            });
            let inverse_shift = power_base(7, MODULUS - 2);
            Self {
                low: powers(root, 1 << LOW_BITS),
                high: powers(
                    power_base(root, 1 << LOW_BITS),
                    EVALUATION_DOMAIN_SIZE >> LOW_BITS,
                ),
                inverse_shift,
                inverse_vanishing: vanishing.map(|value| power_base(value, MODULUS - 2)),
                vanishing,
                shifts: CORRECTED_DEGREES
                    .map(|degree| power_base(7, (MAXIMUM_DEGREE - degree) as u128)),
                inverse_fold_shifts: std::array::from_fn(|round| {
                    power_base(inverse_shift, 1 << round)
                }),
                half: power_base(2, MODULUS - 2),
                inverse_systematic: power_base(SYSTEMATIC as u128, MODULUS - 2),
            }
        })
    }
    /// The inverse of a fold round's point 7^(2^round) w^(index 2^round).
    pub(super) fn inverse_fold_point(&self, round: usize, index: usize) -> u128 {
        multiply_base(
            self.inverse_fold_shifts[round],
            self.root_power(EVALUATION_DOMAIN_SIZE as u64 - ((index as u64) << round)),
        )
    }
    /// w to the exponent modulo the domain's size.
    fn root_power(&self, exponent: u64) -> u128 {
        let exponent = (exponent % EVALUATION_DOMAIN_SIZE as u64) as usize;
        multiply_base(
            self.high[exponent >> LOW_BITS],
            self.low[exponent & ((1 << LOW_BITS) - 1)],
        )
    }
}

pub(super) struct Point {
    pub(super) value: u128,
    pub(super) inverse: u128,
    pub(super) vanishing: u128,
    pub(super) inverse_vanishing: u128,
    pub(super) powers: [u128; 4],
    pub(super) table: u128,
}
impl Point {
    /// The values at the point 7 w^index: its inverse 7^-1 w^(EVALUATION_DOMAIN_SIZE - index),
    /// the vanishing polynomial's value, and 7^e w^(index e) for each
    /// correction exponent e.
    pub(super) fn new(index: usize, table: u128) -> Self {
        let coset = Coset::get();
        let index = index as u64;
        Self {
            value: multiply_base(7, coset.root_power(index)),
            inverse: multiply_base(
                coset.inverse_shift,
                coset.root_power(EVALUATION_DOMAIN_SIZE as u64 - index),
            ),
            vanishing: coset.vanishing[index as usize % 4],
            inverse_vanishing: coset.inverse_vanishing[index as usize % 4],
            powers: std::array::from_fn(|correction| {
                multiply_base(
                    coset.shifts[correction],
                    coset.root_power(
                        index * (MAXIMUM_DEGREE - CORRECTED_DEGREES[correction]) as u64,
                    ),
                )
            }),
            table,
        }
    }
    pub(super) fn weight(&self, shape: &Shape, challenges: &Challenges, index: usize) -> Element {
        if index >= shape.word_oracles {
            let shift = multiply_base(
                super::add_base(self.vanishing, 1),
                if (index - shape.word_oracles).is_multiple_of(2) {
                    1
                } else {
                    self.value
                },
            );
            return add(
                challenges.combination[2 * index],
                scale(challenges.combination[2 * index + 1], shift),
            );
        }
        let class = if index < shape.original - 1 {
            0
        } else if index == shape.original - 1 || index == shape.word_oracles - 2 {
            1
        } else if index == shape.word_oracles - 1 {
            3
        } else {
            2
        };
        add(
            challenges.combination[2 * index],
            scale(challenges.combination[2 * index + 1], self.powers[class]),
        )
    }
}
