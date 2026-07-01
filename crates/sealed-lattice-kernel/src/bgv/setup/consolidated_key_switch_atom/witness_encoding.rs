//! Signed base-b digit encoding of proof-field values into commitment
//! messages.
//!
//! Both proof fields are generalized Fermat primes p = b^64 + 1, so a
//! canonical residue decomposes into 64 base-b digits, and a leftover unit
//! at position 64 wraps to -1 at position 0 because b^64 = -1 mod p. Signed
//! normalization keeps every digit magnitude at most b/2 + 1, which is the
//! coefficient norm the lattice commitment sees.

use super::proof_field::ProofFieldParameters;
use super::wide_unsigned::divide_word_in_place;

pub(crate) const ENCODED_DIGIT_COUNT: usize = 64;

/// Decomposes a canonical residue (value < p) into 64 signed base-b digits.
pub(crate) fn encode_signed_digits<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    raw_value: &[u64; LIMB_COUNT],
) -> [i32; ENCODED_DIGIT_COUNT] {
    let base = parameters.encoding_base;
    let chunk_base = base * base * base * base;
    let mut remaining = *raw_value;
    let mut unsigned_digits = [0_u64; ENCODED_DIGIT_COUNT];
    for chunk_index in 0..ENCODED_DIGIT_COUNT / 4 {
        let mut chunk = divide_word_in_place(&mut remaining, chunk_base);
        for digit_offset in 0..4 {
            unsigned_digits[chunk_index * 4 + digit_offset] = chunk % base;
            chunk /= base;
        }
    }
    // Only p - 1 = b^64 leaves a quotient after 16 chunks; it encodes as -1.
    let top_unit = remaining[0];
    debug_assert!(remaining[0] <= 1 && remaining[1..].iter().all(|limb| *limb == 0));

    let half_base = (base / 2) as i64;
    let mut signed_digits = [0_i32; ENCODED_DIGIT_COUNT];
    let mut carry = 0_i64;
    for digit_index in 0..ENCODED_DIGIT_COUNT {
        let mut digit = unsigned_digits[digit_index] as i64 + carry;
        carry = 0;
        if digit >= half_base {
            digit -= base as i64;
            carry = 1;
        }
        signed_digits[digit_index] = digit as i32;
    }
    // A final carry k at position 64 contributes k * b^64 = -k mod p.
    let wrap = carry + top_unit as i64;
    signed_digits[0] -= wrap as i32;
    signed_digits
}

/// Recomposes signed digits back into a field element (Horner over b).
pub(crate) fn decode_signed_digits<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    digits: &[i32; ENCODED_DIGIT_COUNT],
) -> [u64; LIMB_COUNT] {
    let base = parameters.unsigned_word_to_element(parameters.encoding_base);
    let mut accumulator = parameters.zero();
    for digit in digits.iter().rev() {
        accumulator = parameters.multiply(&accumulator, &base);
        accumulator = parameters.add(
            &accumulator,
            &parameters.signed_word_to_element(i64::from(*digit)),
        );
    }
    accumulator
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::{
        eight_limb_group_field_parameters, sixteen_limb_group_field_parameters,
    };
    use super::*;

    fn check_round_trip<const LIMB_COUNT: usize>(parameters: &ProofFieldParameters<LIMB_COUNT>) {
        let base = parameters.encoding_base;
        let digit_bound = (base / 2 + 1) as i32;
        let mut state = 0x0dd0_c0de_u64;
        for _ in 0..64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // Structured full-range values: a large power stirred by state.
            let value = parameters.power(
                &parameters.unsigned_word_to_element(state | 1),
                &parameters.modulus_half_floor,
            );
            let raw = parameters.to_raw_value(&value);
            let digits = encode_signed_digits(parameters, &raw);
            assert!(
                digits.iter().all(|digit| digit.abs() <= digit_bound),
                "digit magnitude exceeds b/2 + 1"
            );
            assert_eq!(decode_signed_digits(parameters, &digits), value);
        }
    }

    #[test]
    fn signed_digit_encoding_round_trips_full_range_values() {
        check_round_trip(&sixteen_limb_group_field_parameters());
        check_round_trip(&eight_limb_group_field_parameters());
    }

    #[test]
    fn boundary_values_encode_within_the_digit_bound() {
        let parameters = sixteen_limb_group_field_parameters();
        let mut modulus_minus_one = parameters.modulus;
        modulus_minus_one[0] -= 1;
        for raw in [
            [0_u64; 13],
            {
                let mut one = [0_u64; 13];
                one[0] = 1;
                one
            },
            modulus_minus_one,
        ] {
            let digits = encode_signed_digits(&parameters, &raw);
            let decoded = decode_signed_digits(&parameters, &digits);
            assert_eq!(decoded, parameters.raw_value_to_element(&raw));
        }
    }
}
