//! Canonical arithmetic for the common transparent-proof field.
//!
//! The first production profile uses the Goldilocks prime and the quintic
//! extension defined by `Y^5 - 3`. Profile validation independently checks the
//! prime, the exact maximum two-adic root order, and polynomial
//! irreducibility; the constants are not trusted merely because they compile.

use std::sync::OnceLock;

pub(crate) const PROOF_BASE_FIELD_MODULUS: u64 = 18_446_744_069_414_584_321;
pub(crate) const PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR: u64 = 1_753_635_133_440_165_772;
pub(crate) const PROOF_CHALLENGE_EXTENSION_DEGREE: usize = 5;
pub(crate) const PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS: [u64;
    PROOF_CHALLENGE_EXTENSION_DEGREE] = [PROOF_BASE_FIELD_MODULUS - 3, 0, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofFieldError {
    CompositeBaseModulus,
    InvalidTwoAdicGenerator,
    InvalidExtensionPolynomial,
    NonCanonicalElement,
    DivisionByZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProofBaseFieldElement(u64);

impl ProofBaseFieldElement {
    pub(crate) const ZERO: Self = Self(0);
    pub(crate) const ONE: Self = Self(1);

    pub(crate) fn from_canonical(value: u64) -> Result<Self, ProofFieldError> {
        if value >= PROOF_BASE_FIELD_MODULUS {
            return Err(ProofFieldError::NonCanonicalElement);
        }
        Ok(Self(value))
    }

    pub(crate) fn from_reduced(value: u128) -> Self {
        Self((value % u128::from(PROOF_BASE_FIELD_MODULUS)) as u64)
    }

    pub(crate) const fn canonical(self) -> u64 {
        self.0
    }

    pub(crate) fn add(self, other: Self) -> Self {
        Self::from_reduced(u128::from(self.0) + u128::from(other.0))
    }

    pub(crate) fn subtract(self, other: Self) -> Self {
        if self.0 >= other.0 {
            Self(self.0 - other.0)
        } else {
            Self(PROOF_BASE_FIELD_MODULUS - (other.0 - self.0))
        }
    }

    pub(crate) fn negate(self) -> Self {
        if self == Self::ZERO {
            self
        } else {
            Self(PROOF_BASE_FIELD_MODULUS - self.0)
        }
    }

    pub(crate) fn multiply(self, other: Self) -> Self {
        Self::from_reduced(u128::from(self.0) * u128::from(other.0))
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    pub(crate) fn power(self, mut exponent: u64) -> Self {
        let mut result = Self::ONE;
        let mut running_power = self;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.multiply(running_power);
            }
            running_power = running_power.square();
            exponent >>= 1;
        }
        result
    }

    pub(crate) fn inverse(self) -> Result<Self, ProofFieldError> {
        if self == Self::ZERO {
            return Err(ProofFieldError::DivisionByZero);
        }
        Ok(self.power(PROOF_BASE_FIELD_MODULUS - 2))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProofChallengeExtensionElement {
    coordinates: [ProofBaseFieldElement; PROOF_CHALLENGE_EXTENSION_DEGREE],
}

impl ProofChallengeExtensionElement {
    pub(crate) const ZERO: Self = Self {
        coordinates: [ProofBaseFieldElement::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE],
    };
    pub(crate) const ONE: Self = Self {
        coordinates: [
            ProofBaseFieldElement::ONE,
            ProofBaseFieldElement::ZERO,
            ProofBaseFieldElement::ZERO,
            ProofBaseFieldElement::ZERO,
            ProofBaseFieldElement::ZERO,
        ],
    };

    pub(crate) fn from_canonical_coordinates(
        coordinates: [u64; PROOF_CHALLENGE_EXTENSION_DEGREE],
    ) -> Result<Self, ProofFieldError> {
        let mut canonical = [ProofBaseFieldElement::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
        for (destination, source) in canonical.iter_mut().zip(coordinates) {
            *destination = ProofBaseFieldElement::from_canonical(source)?;
        }
        Ok(Self {
            coordinates: canonical,
        })
    }

    pub(crate) fn from_base(value: ProofBaseFieldElement) -> Self {
        let mut coordinates = [ProofBaseFieldElement::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
        coordinates[0] = value;
        Self { coordinates }
    }

    pub(crate) fn canonical_coordinates(self) -> [u64; PROOF_CHALLENGE_EXTENSION_DEGREE] {
        self.coordinates.map(ProofBaseFieldElement::canonical)
    }

    pub(crate) fn is_zero(self) -> bool {
        self == Self::ZERO
    }

    pub(crate) fn multiply_base(self, scalar: ProofBaseFieldElement) -> Self {
        let mut result = Self::ZERO;
        for coordinate_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
            result.coordinates[coordinate_index] =
                self.coordinates[coordinate_index].multiply(scalar);
        }
        result
    }

    pub(crate) fn add(self, other: Self) -> Self {
        let mut result = Self::ZERO;
        for coordinate_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
            result.coordinates[coordinate_index] =
                self.coordinates[coordinate_index].add(other.coordinates[coordinate_index]);
        }
        result
    }

    pub(crate) fn subtract(self, other: Self) -> Self {
        let mut result = Self::ZERO;
        for coordinate_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
            result.coordinates[coordinate_index] =
                self.coordinates[coordinate_index].subtract(other.coordinates[coordinate_index]);
        }
        result
    }

    pub(crate) fn negate(self) -> Self {
        let mut result = Self::ZERO;
        for coordinate_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
            result.coordinates[coordinate_index] = self.coordinates[coordinate_index].negate();
        }
        result
    }

    pub(crate) fn multiply(self, other: Self) -> Self {
        let mut unreduced = [ProofBaseFieldElement::ZERO; 2 * PROOF_CHALLENGE_EXTENSION_DEGREE - 1];
        for left_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
            for right_index in 0..PROOF_CHALLENGE_EXTENSION_DEGREE {
                let product = self.coordinates[left_index].multiply(other.coordinates[right_index]);
                unreduced[left_index + right_index] =
                    unreduced[left_index + right_index].add(product);
            }
        }

        // Y^5 = 3. Descending reduction is required because a coefficient
        // above degree nine in a future profile could itself reduce again.
        for degree in (PROOF_CHALLENGE_EXTENSION_DEGREE..unreduced.len()).rev() {
            let coefficient = unreduced[degree];
            unreduced[degree - PROOF_CHALLENGE_EXTENSION_DEGREE] = unreduced
                [degree - PROOF_CHALLENGE_EXTENSION_DEGREE]
                .add(coefficient.multiply(ProofBaseFieldElement(3)));
        }

        let mut coordinates = [ProofBaseFieldElement::ZERO; PROOF_CHALLENGE_EXTENSION_DEGREE];
        coordinates.copy_from_slice(&unreduced[..PROOF_CHALLENGE_EXTENSION_DEGREE]);
        Self { coordinates }
    }

    pub(crate) fn square(self) -> Self {
        self.multiply(self)
    }

    pub(crate) fn inverse(self) -> Result<Self, ProofFieldError> {
        if self.is_zero() {
            return Err(ProofFieldError::DivisionByZero);
        }

        // In F_(p^5), the product of all five Frobenius conjugates is the
        // base-field norm.  Multiplying conjugates one through four and then
        // dividing by that norm avoids a wide p^5 - 2 exponent.
        let mut conjugate_product = Self::ONE;
        for conjugate_index in 1..PROOF_CHALLENGE_EXTENSION_DEGREE {
            conjugate_product = conjugate_product.multiply(self.frobenius(conjugate_index as u16));
        }
        let norm = self.multiply(conjugate_product);
        if norm.coordinates[1..]
            .iter()
            .any(|coordinate| *coordinate != ProofBaseFieldElement::ZERO)
        {
            return Err(ProofFieldError::InvalidExtensionPolynomial);
        }
        Ok(conjugate_product.multiply_base(norm.coordinates[0].inverse()?))
    }

    pub(crate) fn divide(self, divisor: Self) -> Result<Self, ProofFieldError> {
        Ok(self.multiply(divisor.inverse()?))
    }

    pub(crate) fn power(self, mut exponent: u64) -> Self {
        let mut result = Self::ONE;
        let mut running_power = self;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result.multiply(running_power);
            }
            running_power = running_power.square();
            exponent >>= 1;
        }
        result
    }

    pub(crate) fn frobenius(self, conjugate_index: u16) -> Self {
        let mut result = self;
        for _ in 0..usize::from(conjugate_index) % PROOF_CHALLENGE_EXTENSION_DEGREE {
            result = result.power(PROOF_BASE_FIELD_MODULUS);
        }
        result
    }
}

pub(crate) fn validate_proof_field_profile() -> Result<(), ProofFieldError> {
    static VALIDATION: OnceLock<Result<(), ProofFieldError>> = OnceLock::new();
    *VALIDATION.get_or_init(|| {
        if !is_prime_u64(PROOF_BASE_FIELD_MODULUS) {
            return Err(ProofFieldError::CompositeBaseModulus);
        }
        validate_maximum_two_adic_generator(
            PROOF_BASE_FIELD_MODULUS,
            PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
        )?;
        if !is_irreducible_monic_polynomial(
            PROOF_BASE_FIELD_MODULUS,
            &PROOF_CHALLENGE_EXTENSION_POLYNOMIAL_COEFFICIENTS,
        ) {
            return Err(ProofFieldError::InvalidExtensionPolynomial);
        }
        Ok(())
    })
}

fn validate_maximum_two_adic_generator(
    modulus: u64,
    generator: u64,
) -> Result<(), ProofFieldError> {
    if generator == 0 || generator >= modulus {
        return Err(ProofFieldError::InvalidTwoAdicGenerator);
    }
    let two_adicity = (modulus - 1).trailing_zeros();
    if two_adicity == 0 {
        return Err(ProofFieldError::InvalidTwoAdicGenerator);
    }
    let order = 1_u64
        .checked_shl(two_adicity)
        .ok_or(ProofFieldError::InvalidTwoAdicGenerator)?;
    if modular_power(generator, order, modulus) != 1
        || modular_power(generator, order / 2, modulus) != modulus - 1
    {
        return Err(ProofFieldError::InvalidTwoAdicGenerator);
    }
    Ok(())
}

fn is_prime_u64(candidate: u64) -> bool {
    if candidate < 2 {
        return false;
    }
    for small_prime in [2_u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if candidate == small_prime {
            return true;
        }
        if candidate.is_multiple_of(small_prime) {
            return false;
        }
    }

    let mut odd_component = candidate - 1;
    let power_of_two = odd_component.trailing_zeros();
    odd_component >>= power_of_two;
    for witness in [2_u64, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022] {
        let witness = witness % candidate;
        if witness == 0 {
            continue;
        }
        let mut value = modular_power(witness, odd_component, candidate);
        if value == 1 || value == candidate - 1 {
            continue;
        }
        let mut found_negative_one = false;
        for _ in 1..power_of_two {
            value = modular_multiply(value, value, candidate);
            if value == candidate - 1 {
                found_negative_one = true;
                break;
            }
        }
        if !found_negative_one {
            return false;
        }
    }
    true
}

fn modular_multiply(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_power(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1_u64;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = modular_multiply(result, base, modulus);
        }
        base = modular_multiply(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn is_irreducible_monic_polynomial(modulus: u64, coefficients: &[u64]) -> bool {
    let degree = coefficients.len();
    if degree == 0
        || coefficients
            .iter()
            .any(|coefficient| *coefficient >= modulus)
    {
        return false;
    }

    let mut defining_polynomial = coefficients.to_vec();
    defining_polynomial.push(1);
    let indeterminate = vec![0, 1];
    let mut frobenius_power = indeterminate.clone();
    let degree_prime_factors = distinct_prime_factors(degree);

    for iteration in 1..=degree {
        frobenius_power =
            polynomial_power_mod(&frobenius_power, modulus, &defining_polynomial, modulus);
        if degree_prime_factors
            .iter()
            .any(|factor| iteration == degree / factor)
        {
            let difference = polynomial_subtract(&frobenius_power, &indeterminate, modulus);
            if polynomial_degree(&polynomial_gcd(
                difference,
                defining_polynomial.clone(),
                modulus,
            )) > 0
            {
                return false;
            }
        }
    }

    polynomial_is_zero(&polynomial_subtract(
        &frobenius_power,
        &indeterminate,
        modulus,
    ))
}

fn distinct_prime_factors(mut value: usize) -> Vec<usize> {
    let mut factors = Vec::new();
    let mut candidate = 2_usize;
    while candidate <= value / candidate {
        if value.is_multiple_of(candidate) {
            factors.push(candidate);
            while value.is_multiple_of(candidate) {
                value /= candidate;
            }
        }
        candidate += 1;
    }
    if value > 1 {
        factors.push(value);
    }
    factors
}

fn polynomial_power_mod(
    base: &[u64],
    mut exponent: u64,
    defining_polynomial: &[u64],
    modulus: u64,
) -> Vec<u64> {
    let mut result = vec![1];
    let mut running_power = polynomial_remainder(base.to_vec(), defining_polynomial, modulus);
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = polynomial_remainder(
                polynomial_multiply(&result, &running_power, modulus),
                defining_polynomial,
                modulus,
            );
        }
        running_power = polynomial_remainder(
            polynomial_multiply(&running_power, &running_power, modulus),
            defining_polynomial,
            modulus,
        );
        exponent >>= 1;
    }
    result
}

fn polynomial_multiply(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    if polynomial_is_zero(left) || polynomial_is_zero(right) {
        return vec![0];
    }
    let mut product = vec![0_u64; left.len() + right.len() - 1];
    for (left_index, left_coefficient) in left.iter().copied().enumerate() {
        for (right_index, right_coefficient) in right.iter().copied().enumerate() {
            let term = modular_multiply(left_coefficient, right_coefficient, modulus);
            product[left_index + right_index] =
                modular_add(product[left_index + right_index], term, modulus);
        }
    }
    trim_polynomial(&mut product);
    product
}

fn polynomial_subtract(left: &[u64], right: &[u64], modulus: u64) -> Vec<u64> {
    let mut difference = vec![0_u64; left.len().max(right.len())];
    for (index, output) in difference.iter_mut().enumerate() {
        let left_value = left.get(index).copied().unwrap_or(0);
        let right_value = right.get(index).copied().unwrap_or(0);
        *output = modular_subtract(left_value, right_value, modulus);
    }
    trim_polynomial(&mut difference);
    difference
}

fn polynomial_remainder(mut dividend: Vec<u64>, divisor: &[u64], modulus: u64) -> Vec<u64> {
    trim_polynomial(&mut dividend);
    let divisor_degree = polynomial_degree(divisor);
    let divisor_leading_inverse = modular_power(divisor[divisor_degree], modulus - 2, modulus);
    while !polynomial_is_zero(&dividend) && polynomial_degree(&dividend) >= divisor_degree {
        let dividend_degree = polynomial_degree(&dividend);
        let degree_difference = dividend_degree - divisor_degree;
        let scale = modular_multiply(dividend[dividend_degree], divisor_leading_inverse, modulus);
        for (divisor_index, divisor_coefficient) in divisor.iter().copied().enumerate() {
            let destination = divisor_index + degree_difference;
            dividend[destination] = modular_subtract(
                dividend[destination],
                modular_multiply(scale, divisor_coefficient, modulus),
                modulus,
            );
        }
        trim_polynomial(&mut dividend);
    }
    dividend
}

fn polynomial_gcd(mut left: Vec<u64>, mut right: Vec<u64>, modulus: u64) -> Vec<u64> {
    trim_polynomial(&mut left);
    trim_polynomial(&mut right);
    while !polynomial_is_zero(&right) {
        let remainder = polynomial_remainder(left, &right, modulus);
        left = right;
        right = remainder;
    }
    if polynomial_is_zero(&left) {
        return left;
    }
    let leading = left[polynomial_degree(&left)];
    let inverse = modular_power(leading, modulus - 2, modulus);
    for coefficient in &mut left {
        *coefficient = modular_multiply(*coefficient, inverse, modulus);
    }
    left
}

fn polynomial_degree(polynomial: &[u64]) -> usize {
    polynomial
        .iter()
        .rposition(|coefficient| *coefficient != 0)
        .unwrap_or(0)
}

fn polynomial_is_zero(polynomial: &[u64]) -> bool {
    polynomial.iter().all(|coefficient| *coefficient == 0)
}

fn trim_polynomial(polynomial: &mut Vec<u64>) {
    while polynomial.len() > 1 && polynomial.last() == Some(&0) {
        polynomial.pop();
    }
    if polynomial.is_empty() {
        polynomial.push(0);
    }
}

fn modular_add(left: u64, right: u64, modulus: u64) -> u64 {
    ((u128::from(left) + u128::from(right)) % u128::from(modulus)) as u64
}

fn modular_subtract(left: u64, right: u64, modulus: u64) -> u64 {
    if left >= right {
        left - right
    } else {
        modulus - (right - left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_profile_passes_independent_parameter_checks() {
        assert_eq!(validate_proof_field_profile(), Ok(()));
        assert_eq!(PROOF_BASE_FIELD_MODULUS - 1, 0xffff_ffff_0000_0000);
        assert_eq!(
            modular_power(
                PROOF_BASE_FIELD_MAXIMUM_TWO_ADIC_GENERATOR,
                1_u64 << 31,
                PROOF_BASE_FIELD_MODULUS,
            ),
            PROOF_BASE_FIELD_MODULUS - 1,
        );
    }

    #[test]
    fn profile_checks_reject_wrong_roots_and_reducible_polynomials() {
        assert_eq!(
            validate_maximum_two_adic_generator(PROOF_BASE_FIELD_MODULUS, 1),
            Err(ProofFieldError::InvalidTwoAdicGenerator),
        );
        assert!(!is_irreducible_monic_polynomial(
            PROOF_BASE_FIELD_MODULUS,
            &[0, 0],
        ));
        assert!(!is_irreducible_monic_polynomial(
            PROOF_BASE_FIELD_MODULUS,
            &[PROOF_BASE_FIELD_MODULUS],
        ));
    }

    #[test]
    fn base_arithmetic_handles_values_near_the_word_boundary() {
        let largest = ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS - 1)
            .expect("the largest canonical residue is valid");
        let seven = ProofBaseFieldElement::from_canonical(7).expect("seven is canonical");
        assert_eq!(
            largest.add(ProofBaseFieldElement::ONE),
            ProofBaseFieldElement::ZERO
        );
        assert_eq!(largest.multiply(largest), ProofBaseFieldElement::ONE);
        assert_eq!(
            seven.multiply(seven.inverse().expect("seven is nonzero")),
            ProofBaseFieldElement::ONE
        );
        assert_eq!(
            ProofBaseFieldElement::from_canonical(PROOF_BASE_FIELD_MODULUS),
            Err(ProofFieldError::NonCanonicalElement),
        );
    }

    #[test]
    fn quintic_arithmetic_obeys_the_defining_relation_and_field_axioms() {
        let indeterminate =
            ProofChallengeExtensionElement::from_canonical_coordinates([0, 1, 0, 0, 0])
                .expect("the indeterminate is canonical");
        assert_eq!(
            indeterminate.power(5),
            ProofChallengeExtensionElement::from_base(
                ProofBaseFieldElement::from_canonical(3).expect("three is canonical"),
            ),
        );

        let left = ProofChallengeExtensionElement::from_canonical_coordinates([
            1,
            2,
            3,
            4,
            PROOF_BASE_FIELD_MODULUS - 1,
        ])
        .expect("coordinates are canonical");
        let right = ProofChallengeExtensionElement::from_canonical_coordinates([17, 0, 11, 9, 5])
            .expect("coordinates are canonical");
        let third = ProofChallengeExtensionElement::from_canonical_coordinates([2, 7, 0, 1, 13])
            .expect("coordinates are canonical");
        assert_eq!(
            left.multiply(right).multiply(third),
            left.multiply(right.multiply(third)),
        );
        assert_eq!(
            left.multiply(right.add(third)),
            left.multiply(right).add(left.multiply(third)),
        );
        assert_eq!(
            left.add(left.negate()),
            ProofChallengeExtensionElement::ZERO
        );
    }

    #[test]
    fn frobenius_has_exact_quintic_cycle_and_preserves_products() {
        let value = ProofChallengeExtensionElement::from_canonical_coordinates([3, 5, 8, 13, 21])
            .expect("coordinates are canonical");
        let other =
            ProofChallengeExtensionElement::from_canonical_coordinates([34, 55, 89, 144, 233])
                .expect("coordinates are canonical");
        assert_eq!(value.frobenius(5), value);
        assert_eq!(value.frobenius(10), value);
        assert_eq!(
            value.multiply(other).frobenius(3),
            value.frobenius(3).multiply(other.frobenius(3)),
        );
        assert_eq!(
            value.multiply(value.inverse().expect("a nonzero value is invertible")),
            ProofChallengeExtensionElement::ONE,
        );
        assert_eq!(
            ProofChallengeExtensionElement::ZERO.inverse(),
            Err(ProofFieldError::DivisionByZero),
        );
    }
}
