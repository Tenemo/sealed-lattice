use crate::bgv::modular_arithmetic::{
    add_mod_fast, inverse_mod, mul_mod_fast, pow_mod, sub_mod_fast,
};
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

// Challenge extension field for the succinct trustee evaluation-key argument.
//
// The committed columns stay in the base limb field, but every
// post-commitment verifier challenge (consistency, lincheck, batching,
// out-of-domain points, fold challenges) is drawn from the degree-four
// extension of that limb field, so each challenge round's soundness error is
// governed by the extension size (around 188 bits for the 47-bit data
// primes) instead of the base field size. The tower is
// F_{p^2} = F_p[s] / (s^2 - quadratic_non_residue) and
// F_{p^4} = F_{p^2}[t] / (t^2 - quartic_seed), with both non-residues found
// deterministically per prime, so prover and verifier always agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ChallengeExtensionTower {
    pub(super) modulus: u64,
    // s^2 in the base field.
    pub(super) quadratic_non_residue: u64,
    // t^2 as an F_{p^2} element (constant term, s coefficient).
    pub(super) quartic_seed: [u64; 2],
}

// One F_{p^4} element as coefficients of {1, s, t, s*t}.
pub(super) type ChallengeExtensionElement = [u64; 4];

pub(super) const CHALLENGE_EXTENSION_DEGREE: usize = 4;

fn is_quadratic_residue(value: u64, modulus: u64) -> CanonicalResult<bool> {
    // Euler criterion; the data primes are odd.
    // Zero is reported as a residue by convention so the seed search's norm
    // != 0 guard, not this predicate, is what rejects a degenerate zero norm.
    Ok(value == 0 || pow_mod(value, (modulus - 1) / 2, modulus)? == 1)
}

impl ChallengeExtensionTower {
    pub(super) fn for_modulus(modulus: u64) -> CanonicalResult<Self> {
        if modulus < 3 || modulus.is_multiple_of(2) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "challenge extension tower requires an odd prime modulus",
            ));
        }
        let mut quadratic_non_residue = 0;
        for candidate in 2..modulus {
            if !is_quadratic_residue(candidate, modulus)? {
                quadratic_non_residue = candidate;
                break;
            }
        }
        if quadratic_non_residue == 0 {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "no quadratic non-residue exists below the modulus",
            ));
        }
        // t^2 = seed must be a non-square in F_{p^2}. An element is a square
        // in F_{p^2} exactly when its F_{p^2}-norm is a square in F_p, so we
        // search constant + s * 1 seeds and test norm = constant^2 -
        // quadratic_non_residue for non-residuosity.
        for constant_term in 0..modulus {
            let norm = sub_mod_fast(
                mul_mod_fast(constant_term, constant_term, modulus),
                quadratic_non_residue,
                modulus,
            );
            // An element of F_{p^2} is a square iff its F_p-norm is a square
            // (the norm map is 2-to-1 onto squares), so a non-square norm makes
            // the seed a non-square and t^2 - seed irreducible; this is what
            // makes the degree-4 tower a field.
            if norm != 0 && !is_quadratic_residue(norm, modulus)? {
                return Ok(Self {
                    modulus,
                    quadratic_non_residue,
                    quartic_seed: [constant_term, 1],
                });
            }
        }

        Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "no quartic tower seed exists for the modulus",
        ))
    }

    pub(super) fn zero() -> ChallengeExtensionElement {
        [0; 4]
    }

    pub(super) fn one() -> ChallengeExtensionElement {
        [1, 0, 0, 0]
    }

    pub(super) fn embed_base(&self, value: u64) -> ChallengeExtensionElement {
        [value % self.modulus, 0, 0, 0]
    }

    pub(super) fn is_zero(element: &ChallengeExtensionElement) -> bool {
        element.iter().all(|coefficient| *coefficient == 0)
    }

    pub(super) fn add(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        [
            add_mod_fast(left[0], right[0], self.modulus),
            add_mod_fast(left[1], right[1], self.modulus),
            add_mod_fast(left[2], right[2], self.modulus),
            add_mod_fast(left[3], right[3], self.modulus),
        ]
    }

    pub(super) fn sub(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        [
            sub_mod_fast(left[0], right[0], self.modulus),
            sub_mod_fast(left[1], right[1], self.modulus),
            sub_mod_fast(left[2], right[2], self.modulus),
            sub_mod_fast(left[3], right[3], self.modulus),
        ]
    }

    // F_{p^2} helpers over (constant, s) pairs.
    fn quadratic_mul(&self, left: &[u64; 2], right: &[u64; 2]) -> [u64; 2] {
        let cross = add_mod_fast(
            mul_mod_fast(left[0], right[1], self.modulus),
            mul_mod_fast(left[1], right[0], self.modulus),
            self.modulus,
        );
        let constant = add_mod_fast(
            mul_mod_fast(left[0], right[0], self.modulus),
            mul_mod_fast(
                mul_mod_fast(left[1], right[1], self.modulus),
                self.quadratic_non_residue,
                self.modulus,
            ),
            self.modulus,
        );

        [constant, cross]
    }

    fn quadratic_add(&self, left: &[u64; 2], right: &[u64; 2]) -> [u64; 2] {
        [
            add_mod_fast(left[0], right[0], self.modulus),
            add_mod_fast(left[1], right[1], self.modulus),
        ]
    }

    fn quadratic_sub(&self, left: &[u64; 2], right: &[u64; 2]) -> [u64; 2] {
        [
            sub_mod_fast(left[0], right[0], self.modulus),
            sub_mod_fast(left[1], right[1], self.modulus),
        ]
    }

    fn quadratic_inverse(&self, value: &[u64; 2]) -> CanonicalResult<[u64; 2]> {
        // (c0 + c1 s)^-1 = (c0 - c1 s) / (c0^2 - non_residue * c1^2).
        let norm = sub_mod_fast(
            mul_mod_fast(value[0], value[0], self.modulus),
            mul_mod_fast(
                mul_mod_fast(value[1], value[1], self.modulus),
                self.quadratic_non_residue,
                self.modulus,
            ),
            self.modulus,
        );
        let norm_inverse = inverse_mod(norm, self.modulus)?;

        Ok([
            mul_mod_fast(value[0], norm_inverse, self.modulus),
            mul_mod_fast(
                sub_mod_fast(0, value[1], self.modulus),
                norm_inverse,
                self.modulus,
            ),
        ])
    }

    pub(super) fn mul(
        &self,
        left: &ChallengeExtensionElement,
        right: &ChallengeExtensionElement,
    ) -> ChallengeExtensionElement {
        // Elements are A + B t with A, B in F_{p^2}:
        // (A + B t)(C + D t) = (AC + BD * seed) + (AD + BC) t.
        let left_low = [left[0], left[1]];
        let left_high = [left[2], left[3]];
        let right_low = [right[0], right[1]];
        let right_high = [right[2], right[3]];
        let low = self.quadratic_add(
            &self.quadratic_mul(&left_low, &right_low),
            &self.quadratic_mul(
                &self.quadratic_mul(&left_high, &right_high),
                &self.quartic_seed,
            ),
        );
        let high = self.quadratic_add(
            &self.quadratic_mul(&left_low, &right_high),
            &self.quadratic_mul(&left_high, &right_low),
        );

        [low[0], low[1], high[0], high[1]]
    }

    pub(super) fn inverse(
        &self,
        value: &ChallengeExtensionElement,
    ) -> CanonicalResult<ChallengeExtensionElement> {
        if Self::is_zero(value) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "zero has no challenge extension inverse",
            ));
        }
        // (A + B t)^-1 = (A - B t) / (A^2 - B^2 * seed) over F_{p^2}.
        let low = [value[0], value[1]];
        let high = [value[2], value[3]];
        let norm = self.quadratic_sub(
            &self.quadratic_mul(&low, &low),
            &self.quadratic_mul(&self.quadratic_mul(&high, &high), &self.quartic_seed),
        );
        let norm_inverse = self.quadratic_inverse(&norm)?;
        let low_part = self.quadratic_mul(&low, &norm_inverse);
        let high_part = self.quadratic_mul(&self.quadratic_sub(&[0, 0], &high), &norm_inverse);

        Ok([low_part[0], low_part[1], high_part[0], high_part[1]])
    }

    // Multiply an extension element by a base-field scalar; used when folding
    // base-field-committed leaf values against extension challenges.
    pub(super) fn scale_base(
        &self,
        element: &ChallengeExtensionElement,
        scalar: u64,
    ) -> ChallengeExtensionElement {
        [
            mul_mod_fast(element[0], scalar, self.modulus),
            mul_mod_fast(element[1], scalar, self.modulus),
            mul_mod_fast(element[2], scalar, self.modulus),
            mul_mod_fast(element[3], scalar, self.modulus),
        ]
    }

    pub(super) fn pow(
        &self,
        base: &ChallengeExtensionElement,
        exponent: u64,
    ) -> ChallengeExtensionElement {
        let mut result = Self::one();
        let mut square = *base;
        let mut remaining = exponent;
        while remaining > 0 {
            if remaining & 1 == 1 {
                result = self.mul(&result, &square);
            }
            square = self.mul(&square, &square);
            remaining >>= 1;
        }

        result
    }

    // Montgomery batch inversion: one extension inverse plus three
    // multiplications per element. Rejects any zero element.
    pub(super) fn batch_inverse(
        &self,
        elements: &[ChallengeExtensionElement],
    ) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
        if elements.is_empty() {
            return Ok(Vec::new());
        }
        let mut running_products = Vec::with_capacity(elements.len());
        let mut accumulated = Self::one();
        for element in elements {
            if Self::is_zero(element) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "challenge extension batch inversion requires nonzero elements",
                ));
            }
            running_products.push(accumulated);
            accumulated = self.mul(&accumulated, element);
        }
        let mut suffix_inverse = self.inverse(&accumulated)?;
        let mut inverses = vec![Self::zero(); elements.len()];
        for index in (0..elements.len()).rev() {
            inverses[index] = self.mul(&suffix_inverse, &running_products[index]);
            suffix_inverse = self.mul(&suffix_inverse, &elements[index]);
        }

        Ok(inverses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::profile::DATA_PRIMES;

    #[test]
    fn tower_constants_exist_for_every_data_prime_and_define_a_field() {
        for &prime in DATA_PRIMES.iter() {
            let tower = ChallengeExtensionTower::for_modulus(prime).expect("tower");
            assert!(!is_quadratic_residue(tower.quadratic_non_residue, prime).expect("euler"));

            // A deterministic non-trivial sample element.
            let sample: ChallengeExtensionElement =
                [5, prime - 3, 17, prime - 11].map(|value| value % prime);
            let inverse = tower.inverse(&sample).expect("inverse");
            assert_eq!(tower.mul(&sample, &inverse), ChallengeExtensionTower::one());

            // s * s lands on the quadratic non-residue, t * t on the seed.
            let s_element: ChallengeExtensionElement = [0, 1, 0, 0];
            assert_eq!(
                tower.mul(&s_element, &s_element),
                [tower.quadratic_non_residue, 0, 0, 0]
            );
            let t_element: ChallengeExtensionElement = [0, 0, 1, 0];
            assert_eq!(
                tower.mul(&t_element, &t_element),
                [tower.quartic_seed[0], tower.quartic_seed[1], 0, 0]
            );
        }
    }

    #[test]
    fn arithmetic_matches_field_axioms_on_sampled_elements() {
        let prime = DATA_PRIMES[0];
        let tower = ChallengeExtensionTower::for_modulus(prime).expect("tower");
        let first: ChallengeExtensionElement = [123, 456, 789, 1011];
        let second: ChallengeExtensionElement = [2222, 1, 0, prime - 1];
        let third: ChallengeExtensionElement = [9, 8, 7, 6];

        // Commutativity and associativity of multiplication.
        assert_eq!(tower.mul(&first, &second), tower.mul(&second, &first));
        assert_eq!(
            tower.mul(&tower.mul(&first, &second), &third),
            tower.mul(&first, &tower.mul(&second, &third))
        );
        // Distributivity.
        assert_eq!(
            tower.mul(&first, &tower.add(&second, &third)),
            tower.add(&tower.mul(&first, &second), &tower.mul(&first, &third))
        );
        // Subtraction inverts addition; base scaling matches base embedding.
        assert_eq!(tower.sub(&tower.add(&first, &second), &second), first);
        assert_eq!(
            tower.scale_base(&first, 4242),
            tower.mul(&first, &tower.embed_base(4242))
        );
        // Zero has no inverse.
        assert!(tower.inverse(&ChallengeExtensionTower::zero()).is_err());
    }
}
