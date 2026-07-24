//! Minimal canonical Goldilocks arithmetic for the browser diagnostic.
//!
//! The extension is `F_p[X] / (X^5 - 3)`, matching the degree-five
//! `BinomialExtensionField<Goldilocks, 5>` used by the real bakeoff arm. This
//! module exists so the bounded arithmetic experiment also compiles when the
//! native-only proof backend is unavailable.

use super::arena::GOLDILOCKS_MODULUS;

#[inline]
pub(crate) fn add(left: u64, right: u64) -> u64 {
    reduce128(u128::from(left) + u128::from(right))
}

#[inline]
pub(crate) fn sub(left: u64, right: u64) -> u64 {
    reduce128(u128::from(left) + u128::from(GOLDILOCKS_MODULUS) - u128::from(right))
}

#[inline]
pub(crate) fn mul(left: u64, right: u64) -> u64 {
    reduce128(u128::from(left) * u128::from(right))
}

#[inline]
fn reduce128(value: u128) -> u64 {
    u64::try_from(value % u128::from(GOLDILOCKS_MODULUS))
        .expect("a reduced Goldilocks value fits in u64")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtensionFieldElement {
    pub(crate) coefficients: [u64; 5],
}

impl ExtensionFieldElement {
    pub(crate) const ZERO: Self = Self {
        coefficients: [0; 5],
    };
    pub(crate) const ONE: Self = Self {
        coefficients: [1, 0, 0, 0, 0],
    };

    pub(crate) const fn from_base(value: u64) -> Self {
        Self {
            coefficients: [value, 0, 0, 0, 0],
        }
    }

    pub(crate) fn add(self, other: Self) -> Self {
        Self {
            coefficients: core::array::from_fn(|index| {
                add(self.coefficients[index], other.coefficients[index])
            }),
        }
    }

    pub(crate) fn sub(self, other: Self) -> Self {
        Self {
            coefficients: core::array::from_fn(|index| {
                sub(self.coefficients[index], other.coefficients[index])
            }),
        }
    }

    pub(crate) fn mul(self, other: Self) -> Self {
        let mut convolution = [0_u64; 9];
        for left_index in 0..5 {
            for right_index in 0..5 {
                let product = mul(
                    self.coefficients[left_index],
                    other.coefficients[right_index],
                );
                convolution[left_index + right_index] =
                    add(convolution[left_index + right_index], product);
            }
        }
        for degree in (5..=8).rev() {
            let reduced = mul(3, convolution[degree]);
            convolution[degree - 5] = add(convolution[degree - 5], reduced);
        }
        Self {
            coefficients: convolution[..5]
                .try_into()
                .expect("the reduced polynomial has five coefficients"),
        }
    }

    pub(crate) fn mul_base(self, base: u64) -> Self {
        Self {
            coefficients: self.coefficients.map(|coefficient| mul(coefficient, base)),
        }
    }

    pub(crate) fn to_canonical_bytes(self) -> [u8; 40] {
        let mut bytes = [0_u8; 40];
        for (index, coefficient) in self.coefficients.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&coefficient.to_le_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_arch = "wasm32"))]
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
    #[cfg(not(target_arch = "wasm32"))]
    use p3_goldilocks::Goldilocks;

    #[cfg(not(target_arch = "wasm32"))]
    type PinnedChallengeField = p3_field::extension::BinomialExtensionField<Goldilocks, 5>;

    #[test]
    fn extension_reduces_x_to_the_fifth_to_three() {
        let x = ExtensionFieldElement {
            coefficients: [0, 1, 0, 0, 0],
        };
        let x_squared = x.mul(x);
        let x_fourth = x_squared.mul(x_squared);
        assert_eq!(x_fourth.mul(x), ExtensionFieldElement::from_base(3));
    }

    #[test]
    fn extension_distributivity_holds_on_nontrivial_values() {
        let left = ExtensionFieldElement {
            coefficients: [1, 2, 3, 4, 5],
        };
        let middle = ExtensionFieldElement {
            coefficients: [6, 7, 8, 9, 10],
        };
        let right = ExtensionFieldElement {
            coefficients: [11, 12, 13, 14, 15],
        };
        assert_eq!(
            left.mul(middle.add(right)),
            left.mul(middle).add(left.mul(right))
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn extension_arithmetic_matches_the_pinned_plonky3_field() {
        for sample_index in 0_u64..64 {
            let left = ExtensionFieldElement {
                coefficients: core::array::from_fn(|coefficient_index| {
                    sample_index
                        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                        .rotate_left((coefficient_index * 11) as u32)
                        % GOLDILOCKS_MODULUS
                }),
            };
            let right = ExtensionFieldElement {
                coefficients: core::array::from_fn(|coefficient_index| {
                    sample_index
                        .wrapping_add((coefficient_index + 1) as u64)
                        .wrapping_mul(0xbf58_476d_1ce4_e5b9)
                        % GOLDILOCKS_MODULUS
                }),
            };
            let to_pinned = |value: ExtensionFieldElement| {
                PinnedChallengeField::from_basis_coefficients_fn(|coefficient_index| {
                    Goldilocks::from_u64(value.coefficients[coefficient_index])
                })
            };
            let pinned_product = to_pinned(left) * to_pinned(right);
            let pinned_coefficients: [u64; 5] = core::array::from_fn(|coefficient_index| {
                <PinnedChallengeField as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(
                    &pinned_product,
                )[coefficient_index]
                    .as_canonical_u64()
            });
            assert_eq!(left.mul(right).coefficients, pinned_coefficients);
        }
    }
}
