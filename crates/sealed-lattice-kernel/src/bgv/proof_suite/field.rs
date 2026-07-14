use num_bigint::BigUint;
use num_traits::{One, Zero};

/// The Goldilocks prime `2^64 - 2^32 + 1`.
pub(crate) const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// A generator of the order-`2^32` subgroup of the Goldilocks field.
pub(crate) const GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR: u64 = 0x1856_29dc_da58_878c;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Goldilocks(u64);

impl Goldilocks {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);
    pub(crate) const TWO: Self = Self(2);
    pub(crate) const THREE: Self = Self(3);

    pub(crate) const fn from_canonical_u64(value: u64) -> Option<Self> {
        if value < GOLDILOCKS_MODULUS {
            Some(Self(value))
        } else {
            None
        }
    }

    pub(crate) fn from_reduced_u128(value: u128) -> Self {
        Self((value % u128::from(GOLDILOCKS_MODULUS)) as u64)
    }

    pub(crate) fn add(self, right: Self) -> Self {
        Self::from_reduced_u128(u128::from(self.0) + u128::from(right.0))
    }

    pub(crate) fn subtract(self, right: Self) -> Self {
        if self.0 >= right.0 {
            Self(self.0 - right.0)
        } else {
            Self(GOLDILOCKS_MODULUS - (right.0 - self.0))
        }
    }

    pub(crate) fn negate(self) -> Self {
        if self == Self::ZERO {
            Self::ZERO
        } else {
            Self(GOLDILOCKS_MODULUS - self.0)
        }
    }

    pub(crate) fn multiply(self, right: Self) -> Self {
        Self::from_reduced_u128(u128::from(self.0) * u128::from(right.0))
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    pub(crate) fn pow_u64(self, mut exponent: u64) -> Self {
        let mut result = Self::ONE;
        let mut power = self;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.multiply(power);
            }
            power = power.square();
            exponent >>= 1;
        }
        result
    }

    pub(crate) fn inverse(self) -> Option<Self> {
        (self != Self::ZERO).then(|| self.pow_u64(GOLDILOCKS_MODULUS - 2))
    }

    pub(crate) fn canonical_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub(crate) fn decode_canonical(bytes: [u8; 8]) -> Option<Self> {
        Self::from_canonical_u64(u64::from_le_bytes(bytes))
    }
}

/// The challenge field `F_p[Y] / (Y^5 - 3)` in constant-first order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GoldilocksQuintic([Goldilocks; 5]);

impl GoldilocksQuintic {
    pub(crate) const ZERO: Self = Self([Goldilocks::ZERO; 5]);
    pub(crate) const ONE: Self = Self([
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);

    pub(crate) const fn from_coefficients(coefficients: [Goldilocks; 5]) -> Self {
        Self(coefficients)
    }

    pub(crate) fn multiply(self, right: Self) -> Self {
        let mut product = [Goldilocks::ZERO; 9];
        for left_index in 0..5 {
            for right_index in 0..5 {
                let product_index = left_index + right_index;
                product[product_index] =
                    product[product_index].add(self.0[left_index].multiply(right.0[right_index]));
            }
        }
        // Y^5 = 3. Products have degree at most eight, so one descending
        // reduction pass is sufficient and cannot create another term >= 5.
        for product_index in (5..=8).rev() {
            product[product_index - 5] =
                product[product_index - 5].add(product[product_index].multiply(Goldilocks::THREE));
        }
        Self(core::array::from_fn(|index| product[index]))
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    pub(crate) fn pow_biguint(self, exponent: &BigUint) -> Self {
        let mut result = Self::ONE;
        let mut power = self;
        let mut remaining = exponent.clone();
        while !remaining.is_zero() {
            if (&remaining & BigUint::one()) == BigUint::one() {
                result = result.multiply(power);
            }
            power = power.square();
            remaining >>= 1_usize;
        }
        result
    }

    pub(crate) fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        let field_order = BigUint::from(GOLDILOCKS_MODULUS).pow(5);
        Some(self.pow_biguint(&(field_order - BigUint::from(2_u8))))
    }

    pub(crate) fn canonical_bytes(self) -> [u8; 40] {
        let mut bytes = [0_u8; 40];
        for (coefficient_index, coefficient) in self.0.into_iter().enumerate() {
            let start = coefficient_index * 8;
            bytes[start..start + 8].copy_from_slice(&coefficient.canonical_bytes());
        }
        bytes
    }

    pub(crate) fn decode_canonical(bytes: [u8; 40]) -> Option<Self> {
        let mut coefficients = [Goldilocks::ZERO; 5];
        for (coefficient_index, coefficient) in coefficients.iter_mut().enumerate() {
            let start = coefficient_index * 8;
            let mut coefficient_bytes = [0_u8; 8];
            coefficient_bytes.copy_from_slice(&bytes[start..start + 8]);
            *coefficient = Goldilocks::decode_canonical(coefficient_bytes)?;
        }
        Some(Self(coefficients))
    }
}

/// Checks the Kummer irreducibility criterion for `Y^5 - 3`.
///
/// The Goldilocks field contains the fifth roots of unity because `5 | p-1`.
/// For prime degree five, `Y^5-a` is irreducible exactly when `a` is not a
/// fifth power. Euler's criterion tests that condition without trusting a
/// backend-specific extension type.
pub(crate) fn quintic_polynomial_is_irreducible() -> bool {
    (GOLDILOCKS_MODULUS - 1).is_multiple_of(5)
        && Goldilocks::THREE.pow_u64((GOLDILOCKS_MODULUS - 1) / 5) != Goldilocks::ONE
}

pub(crate) fn maximum_two_adic_generator_has_exact_order() -> bool {
    let generator = Goldilocks::from_canonical_u64(GOLDILOCKS_MAXIMUM_TWO_ADIC_GENERATOR)
        .expect("the stored two-adic generator is canonical");
    generator
        .inverse()
        .is_some_and(|inverse| generator.multiply(inverse) == Goldilocks::ONE)
        && generator.pow_u64(1_u64 << 32) == Goldilocks::ONE
        && generator.pow_u64(1_u64 << 31) != Goldilocks::ONE
}

/// Cross-checks the implemented challenge-field arithmetic against the
/// selected polynomial and canonical coordinate encoding. Suite generation
/// calls this before publishing the field profile, so an arithmetic or codec
/// regression cannot produce a new suite identifier.
pub(crate) fn quintic_implementation_matches_polynomial() -> bool {
    let indeterminate = GoldilocksQuintic::from_coefficients([
        Goldilocks::ZERO,
        Goldilocks::ONE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);
    let indeterminate_fifth_power = indeterminate.square().square().multiply(indeterminate);
    let expected_fifth_power = GoldilocksQuintic::from_coefficients([
        Goldilocks::THREE,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
        Goldilocks::ZERO,
    ]);
    let test_element = GoldilocksQuintic::from_coefficients([
        Goldilocks::TWO,
        Goldilocks::ONE,
        Goldilocks::THREE,
        Goldilocks::from_canonical_u64(5).expect("five is canonical"),
        Goldilocks::from_canonical_u64(8).expect("eight is canonical"),
    ]);
    indeterminate_fifth_power == expected_fifth_power
        && Goldilocks::TWO.subtract(Goldilocks::THREE) == Goldilocks::ONE.negate()
        && GoldilocksQuintic::decode_canonical(test_element.canonical_bytes()) == Some(test_element)
        && test_element
            .inverse()
            .is_some_and(|inverse| test_element.multiply(inverse) == GoldilocksQuintic::ONE)
}
