//! Fixed-width Montgomery arithmetic over the digit-atom proof fields.
//!
//! Both selected proof primes are generalized Fermat primes p = b^64 + 1
//! with even b, which makes them simultaneously NTT-friendly (2^16 divides
//! p - 1, so the full negacyclic domain for ring degree 32768 exists) and
//! base-b digit-encodable for lattice commitment messages. Elements are
//! little-endian limb arrays kept in Montgomery form; the word-level
//! Montgomery constant is -p^{-1} mod 2^64, which is exactly u64::MAX here
//! because p = 1 mod 2^64 for every even-base generalized Fermat prime with
//! exponent 64.

use super::wide_unsigned::{is_less_than, shift_right_one_in_place, subtract_in_place};

/// Field parameters plus derived Montgomery constants. `LIMB_COUNT` is the
/// number of 64-bit limbs; the modulus must satisfy p < 2^(64 * LIMB_COUNT).
#[derive(Clone)]
pub(crate) struct ProofFieldParameters<const LIMB_COUNT: usize> {
    pub(crate) modulus: [u64; LIMB_COUNT],
    pub(crate) modulus_half_floor: [u64; LIMB_COUNT],
    montgomery_radix_squared: [u64; LIMB_COUNT],
    negated_modulus_inverse_word: u64,
    pub(crate) primitive_65536th_root: [u64; LIMB_COUNT],
}

/// The 16-limb-group proof field: p = 4166^64 + 1 (770 bits, 13 limbs).
/// Large enough for the limb-group integer relation over the full active
/// level-15 group (16 data primes) at ring degree 32768.
pub(crate) const SIXTEEN_LIMB_GROUP_FIELD_LIMBS: usize = 13;

pub(crate) fn sixteen_limb_group_field_parameters()
-> ProofFieldParameters<SIXTEEN_LIMB_GROUP_FIELD_LIMBS> {
    ProofFieldParameters::from_constants(
        [
            0x0000000000000001,
            0x82731d5e74859501,
            0x075c24f4d58d407c,
            0xdf4a4c20216d9c9c,
            0xd3fd57973581a77e,
            0x3d7fcac04acd1761,
            0xb8dc0caa77805159,
            0xf87f06c7de7d06d0,
            0x442608f7238a98f8,
            0x9b406bf40a4f59f8,
            0xbce342be4e3064b4,
            0xf53eaa9ea6474f9d,
            0x0000000000000002,
        ],
        [
            0x91c245069dfba39b,
            0xd9a5a0d4e169eea8,
            0xc02c3f4a544b6b99,
            0x82dcfdcefbca2749,
            0xa5990b42b2e016ab,
            0x2ddfa71617c39e86,
            0x07a7479a15aa0fdf,
            0x7d7147d518c2029d,
            0x6bbadf0f644acae9,
            0x234200afc4e2dd5b,
            0xed9651061b666512,
            0x24bb89c5a26b3a89,
            0x0000000000000002,
        ],
        [
            0x15c836f0deeb867e,
            0x9a12275561b6ef53,
            0x1824df66e7e7f9ad,
            0xb038288e5085e59c,
            0x18b4c808a0b6bfdf,
            0x7ffb81c0d565eb81,
            0x9ea15bb4bf4836ac,
            0x66e5f6cf5a3a74f6,
            0x7a7fc0c8d5e37f4b,
            0x479fbbd8a3d07e54,
            0xb0e2cbea862873ca,
            0x793e56009bdb41af,
            0x0000000000000000,
        ],
    )
}

/// The 8-limb-group proof field: p = 102^64 + 1 (428 bits, 7 limbs). Large
/// enough for an 8-prime limb-group congruence at ring degree 32768.
#[cfg(test)]
pub(crate) const EIGHT_LIMB_GROUP_FIELD_LIMBS: usize = 7;

#[cfg(test)]
pub(crate) fn eight_limb_group_field_parameters()
-> ProofFieldParameters<EIGHT_LIMB_GROUP_FIELD_LIMBS> {
    ProofFieldParameters::from_constants(
        [
            0x0000000000000001,
            0x8a2e248d00f6a101,
            0x972e680f93aed9ca,
            0xe27674d6198ffd72,
            0xbc0a251347e9c851,
            0x39c2a46178e955b6,
            0x000008329d783210,
        ],
        [
            0x10766dd000724f2c,
            0x3f8e8e749a2ee733,
            0x9676b082d05e5d21,
            0xd15379a677566f24,
            0xbd90d0ce4891dfef,
            0x0c71e7a5e84c8cc1,
            0x000006e063c8b9e3,
        ],
        [
            0x2c67fc7ef66c667e,
            0x1db9afd6f095712a,
            0xfad539958e3b33b0,
            0xaa612a7e364af750,
            0x88e9e8ca95955040,
            0x1ba4e83925867d3d,
            0x000005c2d0c5f121,
        ],
    )
}

/// Constructs single-limb parameters at runtime for word-sized NTT-friendly
/// moduli (used by the commitment ring).
#[cfg(test)]
pub(crate) fn single_limb_field_parameters(
    modulus: u64,
    primitive_65536th_root: u64,
) -> ProofFieldParameters<1> {
    let radix_remainder = ((1_u128 << 64) % u128::from(modulus)) as u64;
    let radix_squared =
        ((u128::from(radix_remainder) * u128::from(radix_remainder)) % u128::from(modulus)) as u64;
    ProofFieldParameters::from_constants([modulus], [radix_squared], [primitive_65536th_root])
}

impl<const LIMB_COUNT: usize> ProofFieldParameters<LIMB_COUNT> {
    fn from_constants(
        modulus: [u64; LIMB_COUNT],
        montgomery_radix_squared: [u64; LIMB_COUNT],
        primitive_65536th_root: [u64; LIMB_COUNT],
    ) -> Self {
        let mut modulus_half_floor = modulus;
        shift_right_one_in_place(&mut modulus_half_floor);
        Self {
            modulus,
            modulus_half_floor,
            montgomery_radix_squared,
            negated_modulus_inverse_word: negated_inverse_word(modulus[0]),
            primitive_65536th_root,
        }
    }

    pub(crate) fn zero(&self) -> [u64; LIMB_COUNT] {
        [0; LIMB_COUNT]
    }

    pub(crate) fn one(&self) -> [u64; LIMB_COUNT] {
        self.unsigned_word_to_element(1)
    }

    /// Converts a canonical residue (little-endian limbs, value < p) into
    /// Montgomery form.
    pub(crate) fn raw_value_to_element(&self, raw: &[u64; LIMB_COUNT]) -> [u64; LIMB_COUNT] {
        self.multiply(raw, &self.montgomery_radix_squared)
    }

    /// Converts a Montgomery-form element back to its canonical residue.
    pub(crate) fn to_raw_value(&self, element: &[u64; LIMB_COUNT]) -> [u64; LIMB_COUNT] {
        let mut one_raw = [0_u64; LIMB_COUNT];
        one_raw[0] = 1;
        self.multiply(element, &one_raw)
    }

    pub(crate) fn unsigned_word_to_element(&self, value: u64) -> [u64; LIMB_COUNT] {
        let mut raw = [0_u64; LIMB_COUNT];
        raw[0] = value;
        self.raw_value_to_element(&raw)
    }

    /// Maps a signed word to its centered residue: negative values become
    /// p - |value|.
    pub(crate) fn signed_word_to_element(&self, value: i64) -> [u64; LIMB_COUNT] {
        if value >= 0 {
            return self.unsigned_word_to_element(value as u64);
        }
        self.negate(&self.unsigned_word_to_element(value.unsigned_abs()))
    }

    pub(crate) fn add(
        &self,
        left: &[u64; LIMB_COUNT],
        right: &[u64; LIMB_COUNT],
    ) -> [u64; LIMB_COUNT] {
        let mut sum = *left;
        let mut carry = 0_u64;
        for index in 0..LIMB_COUNT {
            let total = u128::from(sum[index]) + u128::from(right[index]) + u128::from(carry);
            sum[index] = total as u64;
            carry = (total >> 64) as u64;
        }
        if carry > 0 || !is_less_than(&sum, &self.modulus) {
            subtract_in_place(&mut sum, &self.modulus);
        }
        sum
    }

    pub(crate) fn subtract(
        &self,
        left: &[u64; LIMB_COUNT],
        right: &[u64; LIMB_COUNT],
    ) -> [u64; LIMB_COUNT] {
        let mut difference = *left;
        if subtract_in_place(&mut difference, right) != 0 {
            let mut carry = 0_u64;
            for (difference_word, modulus_word) in difference.iter_mut().zip(self.modulus.iter()) {
                let total =
                    u128::from(*difference_word) + u128::from(*modulus_word) + u128::from(carry);
                *difference_word = total as u64;
                carry = (total >> 64) as u64;
            }
        }
        difference
    }

    pub(crate) fn negate(&self, element: &[u64; LIMB_COUNT]) -> [u64; LIMB_COUNT] {
        if element.iter().all(|limb| *limb == 0) {
            return *element;
        }
        let mut negated = self.modulus;
        subtract_in_place(&mut negated, element);
        negated
    }

    /// CIOS Montgomery multiplication. Inputs and output stay in Montgomery
    /// form and below the modulus. The high accumulator is widened to u128
    /// so the loop stays correct for any modulus below the limb radix.
    pub(crate) fn multiply(
        &self,
        left: &[u64; LIMB_COUNT],
        right: &[u64; LIMB_COUNT],
    ) -> [u64; LIMB_COUNT] {
        let mut accumulator = [0_u64; LIMB_COUNT];
        let mut accumulator_high: u128 = 0;
        for left_word in left {
            let mut carry = 0_u64;
            for (accumulator_word, right_word) in accumulator.iter_mut().zip(right.iter()) {
                let sum = u128::from(*accumulator_word)
                    + u128::from(*left_word) * u128::from(*right_word)
                    + u128::from(carry);
                *accumulator_word = sum as u64;
                carry = (sum >> 64) as u64;
            }
            accumulator_high += u128::from(carry);

            let reducer = accumulator[0].wrapping_mul(self.negated_modulus_inverse_word);
            let first =
                u128::from(accumulator[0]) + u128::from(reducer) * u128::from(self.modulus[0]);
            let mut carry = (first >> 64) as u64;
            for (modulus_index, modulus_word) in self.modulus.iter().enumerate().skip(1) {
                let sum = u128::from(accumulator[modulus_index])
                    + u128::from(reducer) * u128::from(*modulus_word)
                    + u128::from(carry);
                accumulator[modulus_index - 1] = sum as u64;
                carry = (sum >> 64) as u64;
            }
            let shifted = accumulator_high + u128::from(carry);
            accumulator[LIMB_COUNT - 1] = shifted as u64;
            accumulator_high = shifted >> 64;
        }
        if accumulator_high > 0 || !is_less_than(&accumulator, &self.modulus) {
            subtract_in_place(&mut accumulator, &self.modulus);
        }
        accumulator
    }

    /// Exponentiation by a little-endian limb exponent, in Montgomery form.
    pub(crate) fn power(
        &self,
        base: &[u64; LIMB_COUNT],
        exponent: &[u64; LIMB_COUNT],
    ) -> [u64; LIMB_COUNT] {
        let mut result = self.one();
        let mut running = *base;
        for exponent_limb in exponent {
            let mut bits = *exponent_limb;
            for _ in 0..64 {
                if bits & 1 == 1 {
                    result = self.multiply(&result, &running);
                }
                running = self.multiply(&running, &running);
                bits >>= 1;
            }
        }
        result
    }

    /// Multiplicative inverse via Fermat exponentiation (cold paths only).
    pub(crate) fn inverse(&self, element: &[u64; LIMB_COUNT]) -> [u64; LIMB_COUNT] {
        let mut exponent = self.modulus;
        let mut two = [0_u64; LIMB_COUNT];
        two[0] = 2;
        subtract_in_place(&mut exponent, &two);
        self.power(element, &exponent)
    }

    /// Lifts a Montgomery element to its centered integer representative,
    /// returned as (is_negative, magnitude limbs).
    pub(crate) fn centered_raw(&self, element: &[u64; LIMB_COUNT]) -> (bool, [u64; LIMB_COUNT]) {
        let raw = self.to_raw_value(element);
        if is_less_than(&self.modulus_half_floor, &raw) {
            let mut magnitude = self.modulus;
            subtract_in_place(&mut magnitude, &raw);
            (true, magnitude)
        } else {
            (false, raw)
        }
    }
}

/// Newton iteration for -modulus^{-1} mod 2^64; requires an odd modulus word.
fn negated_inverse_word(modulus_word: u64) -> u64 {
    let mut inverse = 1_u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2_u64.wrapping_sub(modulus_word.wrapping_mul(inverse)));
    }
    inverse.wrapping_neg()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn to_biguint<const LIMB_COUNT: usize>(value: &[u64; LIMB_COUNT]) -> BigUint {
        let mut result = BigUint::from(0_u32);
        for index in (0..LIMB_COUNT).rev() {
            result = (result << 64) | BigUint::from(value[index]);
        }
        result
    }

    fn from_biguint<const LIMB_COUNT: usize>(value: &BigUint) -> [u64; LIMB_COUNT] {
        let mut limbs = [0_u64; LIMB_COUNT];
        for (index, digit) in value.to_u64_digits().into_iter().enumerate() {
            limbs[index] = digit;
        }
        limbs
    }

    #[test]
    fn selected_fields_match_their_generalized_fermat_shapes() {
        let sixteen = sixteen_limb_group_field_parameters();
        assert_eq!(
            to_biguint(&sixteen.modulus),
            BigUint::from(4166_u32).pow(64) + BigUint::from(1_u32)
        );
        assert_eq!(sixteen.negated_modulus_inverse_word, u64::MAX);
        let eight = eight_limb_group_field_parameters();
        assert_eq!(
            to_biguint(&eight.modulus),
            BigUint::from(102_u32).pow(64) + BigUint::from(1_u32)
        );
        assert_eq!(eight.negated_modulus_inverse_word, u64::MAX);
    }

    #[test]
    fn multiplication_matches_known_answer_vectors() {
        let parameters = sixteen_limb_group_field_parameters();
        let x = [
            0x951a8aa3f3473c7c,
            0x9b6f52b584ed5d51,
            0xcdbaf5f01bc544d4,
            0xbc09b8a3d299a17c,
            0xd3baa39ad214b0d3,
            0x7d10d746fddfff44,
            0xf41f3707df32a0dc,
            0x11576ba9d00bcb52,
            0xc600e809642262d0,
            0xee4e7fcfbb97d18f,
            0x5d4ef1be960c62d1,
            0xda34dab2fe830b90,
            0x0000000000000002,
        ];
        let y = [
            0x731094ccc084ec38,
            0xc38cc0b2c3862e4f,
            0x574229b11d493174,
            0x6d63a7077bf89840,
            0x2bfee46550cd62b3,
            0x1e465902379e31c8,
            0x8669dee01a292f29,
            0x698d6ffefb077ca3,
            0xbb63ae05d35daf55,
            0x55987f9b02e01e4d,
            0xdaf6400681990bfa,
            0xe59ae26d9a79e773,
            0x0000000000000001,
        ];
        let expected_product = [
            0x20ad2acd077f50de,
            0xc2d8e3d23d8a0362,
            0x65dd0746823670e8,
            0x0a71cad1df9d6be3,
            0x694655818389848b,
            0x7fb32a00e4371701,
            0x21e38249f7f01b53,
            0x76f56dbf475c2163,
            0x05473c3d8ee6183d,
            0x4d94ae53cb25268d,
            0x2f301d03a769c425,
            0xc161912a5182954e,
            0x0000000000000002,
        ];
        let product = parameters.to_raw_value(&parameters.multiply(
            &parameters.raw_value_to_element(&x),
            &parameters.raw_value_to_element(&y),
        ));
        assert_eq!(product, expected_product);
    }

    fn check_multiplication_against_bigint<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) {
        let modulus = to_biguint(&parameters.modulus);
        let mut seed = BigUint::from(0x1234_5678_9abc_def1_u64);
        for _ in 0..24 {
            seed = (&seed * &seed + BigUint::from(12_345_u32)) % &modulus;
            let left = seed.clone();
            seed = (&seed * &seed + BigUint::from(98_765_u32)) % &modulus;
            let right = seed.clone();
            let expected = (&left * &right) % &modulus;
            let product = parameters.to_raw_value(&parameters.multiply(
                &parameters.raw_value_to_element(&from_biguint(&left)),
                &parameters.raw_value_to_element(&from_biguint(&right)),
            ));
            assert_eq!(to_biguint(&product), expected);
        }
    }

    #[test]
    fn multiplication_matches_bigint_reference() {
        check_multiplication_against_bigint(&sixteen_limb_group_field_parameters());
        check_multiplication_against_bigint(&eight_limb_group_field_parameters());
    }

    fn check_field_axioms<const LIMB_COUNT: usize>(parameters: &ProofFieldParameters<LIMB_COUNT>) {
        let a = parameters.unsigned_word_to_element(0xdead_beef_cafe_f00d);
        let b = parameters.signed_word_to_element(-31_337);
        let c = parameters.unsigned_word_to_element(65_537);
        let left = parameters.multiply(&parameters.multiply(&a, &b), &c);
        let right = parameters.multiply(&a, &parameters.multiply(&b, &c));
        assert_eq!(left, right);
        let distributed = parameters.multiply(&a, &parameters.add(&b, &c));
        let expanded = parameters.add(&parameters.multiply(&a, &b), &parameters.multiply(&a, &c));
        assert_eq!(distributed, expanded);
        let inverse = parameters.inverse(&a);
        assert_eq!(parameters.multiply(&a, &inverse), parameters.one());
        assert_eq!(
            parameters.add(&b, &parameters.negate(&b)),
            parameters.zero()
        );
    }

    #[test]
    fn field_axioms_hold_for_structured_values() {
        check_field_axioms(&sixteen_limb_group_field_parameters());
        check_field_axioms(&eight_limb_group_field_parameters());
    }

    fn check_primitive_root_order<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
    ) {
        let root = parameters.raw_value_to_element(&parameters.primitive_65536th_root);
        let mut exponent = [0_u64; LIMB_COUNT];
        exponent[0] = 32_768;
        let half_order = parameters.power(&root, &exponent);
        assert_eq!(half_order, parameters.negate(&parameters.one()));
    }

    #[test]
    fn primitive_root_has_exact_order_65536() {
        check_primitive_root_order(&sixteen_limb_group_field_parameters());
        check_primitive_root_order(&eight_limb_group_field_parameters());
    }

    fn check_centered_lift<const LIMB_COUNT: usize>(parameters: &ProofFieldParameters<LIMB_COUNT>) {
        for value in [-70_000_i64, -1, 0, 1, 32_769, 131_074] {
            let (is_negative, magnitude) =
                parameters.centered_raw(&parameters.signed_word_to_element(value));
            assert_eq!(is_negative, value < 0);
            assert_eq!(magnitude[0], value.unsigned_abs());
            assert!(magnitude[1..].iter().all(|limb| *limb == 0));
        }
    }

    #[test]
    fn centered_lift_round_trips_signed_words() {
        check_centered_lift(&sixteen_limb_group_field_parameters());
        check_centered_lift(&eight_limb_group_field_parameters());
    }

    #[test]
    fn single_limb_parameters_agree_with_u128_arithmetic() {
        let modulus = 2_305_843_009_214_414_849_u64;
        let parameters = single_limb_field_parameters(modulus, 1_324_459_744_473_789_483);
        for (left, right) in [
            (3_u64, 5_u64),
            (modulus - 1, modulus - 1),
            (0xffff_ffff, 0x1234_5678_9abc),
        ] {
            let product = parameters.to_raw_value(&parameters.multiply(
                &parameters.unsigned_word_to_element(left),
                &parameters.unsigned_word_to_element(right),
            ));
            let expected = ((u128::from(left) * u128::from(right)) % u128::from(modulus)) as u64;
            assert_eq!(product[0], expected);
        }
    }
}
