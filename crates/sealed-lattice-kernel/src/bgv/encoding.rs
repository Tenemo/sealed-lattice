use std::sync::OnceLock;

#[cfg(test)]
use crate::bgv::{
    base_conversion::lift_plaintext_coefficients_to_basis, parameters::BgvBasisKind,
    rns::RnsPolynomial,
};
use crate::{
    bgv::{
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt_in_place},
        parameters::{LOGICAL_SLOT_GENERATOR, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

static LOGICAL_TO_NATURAL_TRANSFORM_INDEX: OnceLock<Vec<usize>> = OnceLock::new();

#[cfg(test)]
pub(crate) struct EncodedBatchPlaintext {
    pub(crate) coefficients_mod_plaintext: Vec<u64>,
    pub(crate) polynomial: RnsPolynomial,
}

// Logical slots follow the suite generator order, while the NTT implementation
// exposes evaluations in ascending odd-exponent order. The suite arithmetic
// derivation owns the permutation between those two orders.
#[cfg(test)]
pub(crate) fn encode_batch_plaintext_slots(
    supplied_slots: &[u64],
    target_level: usize,
) -> CanonicalResult<EncodedBatchPlaintext> {
    let coefficients_mod_plaintext =
        encode_logical_slots_to_plaintext_coefficients(supplied_slots)?;
    let polynomial = lift_plaintext_coefficients_to_basis(
        &coefficients_mod_plaintext,
        BgvBasisKind::Data,
        target_level,
    )?;

    Ok(EncodedBatchPlaintext {
        coefficients_mod_plaintext,
        polynomial,
    })
}

pub(super) fn encode_logical_slots_to_plaintext_coefficients(
    supplied_slots: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if supplied_slots.len() > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV batch encoder received more slots than the selected polynomial degree",
        ));
    }
    if supplied_slots.iter().any(|slot| *slot >= PLAINTEXT_MODULUS) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV batch encoder slot value is outside the selected plaintext field",
        ));
    }
    let mut padded_slots = vec![0_u64; POLYNOMIAL_DEGREE];
    padded_slots[..supplied_slots.len()].copy_from_slice(supplied_slots);
    let mut coefficients_mod_plaintext = logical_slots_to_natural_transform_order(&padded_slots)?;
    inverse_negacyclic_ntt_in_place(&mut coefficients_mod_plaintext, PLAINTEXT_MODULUS)?;

    Ok(coefficients_mod_plaintext)
}

pub(super) fn decode_plaintext_coefficients_to_logical_slots(
    coefficients_mod_plaintext: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if coefficients_mod_plaintext.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV scalar decoder coefficient count must match the selected polynomial degree",
        ));
    }
    let natural_transform_slots =
        forward_negacyclic_ntt(coefficients_mod_plaintext, PLAINTEXT_MODULUS)?;
    natural_transform_slots_to_logical_order(&natural_transform_slots)
}

fn logical_slots_to_natural_transform_order(logical_slots: &[u64]) -> CanonicalResult<Vec<u64>> {
    let mut natural_transform_slots = vec![0_u64; logical_slots.len()];
    for (logical_slot, natural_transform_index) in logical_slots
        .iter()
        .zip(logical_to_natural_transform_indexes())
    {
        natural_transform_slots[*natural_transform_index] = *logical_slot;
    }

    Ok(natural_transform_slots)
}

fn natural_transform_slots_to_logical_order(
    natural_transform_slots: &[u64],
) -> CanonicalResult<Vec<u64>> {
    Ok(logical_to_natural_transform_indexes()
        .iter()
        .map(|natural_transform_index| natural_transform_slots[*natural_transform_index])
        .collect())
}

fn logical_to_natural_transform_indexes() -> &'static [usize] {
    LOGICAL_TO_NATURAL_TRANSFORM_INDEX.get_or_init(|| {
        let ring_order = 2 * POLYNOMIAL_DEGREE;
        let positive_slot_count = POLYNOMIAL_DEGREE / 2;
        let logical_slot_generator = LOGICAL_SLOT_GENERATOR;
        let mut positive_exponents = Vec::with_capacity(positive_slot_count);
        let mut exponent = 1_usize;
        for _ in 0..positive_slot_count {
            positive_exponents.push(exponent);
            exponent = exponent * logical_slot_generator % ring_order;
        }

        positive_exponents
            .iter()
            .copied()
            .chain(
                positive_exponents
                    .iter()
                    .map(|positive_exponent| ring_order - positive_exponent),
            )
            .map(|slot_exponent| (slot_exponent - 1) / 2)
            .collect()
    })
}

#[cfg(test)]
fn logical_slot_exponent(logical_slot_index: usize) -> usize {
    2 * logical_to_natural_transform_indexes()[logical_slot_index] + 1
}

// Decoding is the inverse of encoding: recover the plaintext coefficients from
// any limb, evaluate in natural NTT order, then apply the suite permutation.
#[cfg(test)]
pub(crate) fn decode_batch_plaintext_polynomial(
    polynomial: &RnsPolynomial,
) -> CanonicalResult<Vec<u64>> {
    polynomial.validate()?;
    let first_limb = polynomial.residues_by_modulus.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV plaintext object has no residue limbs",
        )
    })?;
    let coefficients_mod_plaintext = first_limb
        .iter()
        .map(|coefficient| coefficient % PLAINTEXT_MODULUS)
        .collect::<Vec<_>>();
    for (limb_index, limb) in polynomial.residues_by_modulus.iter().enumerate().skip(1) {
        for (coefficient_index, coefficient) in limb.iter().enumerate() {
            if coefficient % PLAINTEXT_MODULUS != coefficients_mod_plaintext[coefficient_index] {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    format!(
                        "BGV plaintext limb {limb_index} coefficient {coefficient_index} is not a consistent plaintext lift",
                    ),
                ));
            }
        }
    }

    decode_plaintext_coefficients_to_logical_slots(&coefficients_mod_plaintext)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_batch_plaintext_polynomial, decode_plaintext_coefficients_to_logical_slots,
        encode_batch_plaintext_slots, logical_slot_exponent, logical_to_natural_transform_indexes,
    };
    use crate::{
        bgv::{
            base_conversion::lift_plaintext_coefficients_to_basis,
            ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
            parameters::{
                BgvBasisKind, DATA_PRIMES, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, ROOT_PARAMETERS,
            },
        },
        encoding::CanonicalErrorCode,
    };

    #[test]
    fn batch_encoder_round_trips_boundary_slots() {
        let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
        slots[0] = PLAINTEXT_MODULUS - 1;
        slots[1] = 1;
        slots[2] = 2;
        slots[17] = 32_768;
        slots[POLYNOMIAL_DEGREE / 2 - 1] = PLAINTEXT_MODULUS - 2;
        slots[POLYNOMIAL_DEGREE / 2] = 31_337;
        slots[POLYNOMIAL_DEGREE - 1] = 99;
        let encoded = encode_batch_plaintext_slots(&slots, 0).expect("encode");
        let decoded = decode_batch_plaintext_polynomial(&encoded.polynomial).expect("decode");

        assert_eq!(decoded, slots);
        assert_eq!(encoded.polynomial.residues_by_modulus.len(), 1);
    }

    #[test]
    fn batch_encoder_round_trips_deterministic_full_slot_patterns() {
        for (pattern_index, seed) in [0_u64, 1, u64::MAX, 0xa076_1d64_78bd_642f]
            .into_iter()
            .enumerate()
        {
            let slots = deterministic_residue_vector(seed);
            let target_level = pattern_index % DATA_PRIMES.len();
            let encoded =
                encode_batch_plaintext_slots(&slots, target_level).expect("encode pattern");
            let decoded =
                decode_batch_plaintext_polynomial(&encoded.polynomial).expect("decode pattern");

            assert_eq!(decoded, slots, "pattern {pattern_index}");
        }
    }

    #[test]
    fn decoder_matches_direct_evaluation_for_deterministic_coefficient_patterns() {
        let sampled_logical_indexes = [
            0,
            1,
            2,
            POLYNOMIAL_DEGREE / 2 - 1,
            POLYNOMIAL_DEGREE / 2,
            POLYNOMIAL_DEGREE - 1,
        ];

        for seed in [0_u64, u64::MAX, 0xe703_7ed1_a0b4_28db] {
            let coefficients = deterministic_residue_vector(seed);
            let natural_transform =
                forward_negacyclic_ntt(&coefficients, PLAINTEXT_MODULUS).expect("forward NTT");
            let expected_logical_slots = logical_to_natural_transform_indexes()
                .iter()
                .map(|natural_transform_index| natural_transform[*natural_transform_index])
                .collect::<Vec<_>>();
            let polynomial =
                lift_plaintext_coefficients_to_basis(&coefficients, BgvBasisKind::Data, 1)
                    .expect("lift coefficients");
            let decoded =
                decode_batch_plaintext_polynomial(&polynomial).expect("decode coefficients");

            assert_eq!(decoded, expected_logical_slots);
            for logical_index in sampled_logical_indexes {
                let evaluation_point = modular_power(
                    ROOT_PARAMETERS[0].negacyclic_root,
                    logical_slot_exponent(logical_index) as u64,
                    PLAINTEXT_MODULUS,
                );
                assert_eq!(
                    decoded[logical_index],
                    evaluate_polynomial(&coefficients, evaluation_point),
                    "seed {seed}, logical slot {logical_index}",
                );
            }
        }
    }

    #[test]
    fn encoder_rejects_the_previous_natural_index_slot_assumption() {
        let logical_slot_index = 2;
        let slot_exponent = logical_slot_exponent(logical_slot_index);
        let natural_transform_index = logical_to_natural_transform_indexes()[logical_slot_index];
        assert_eq!(slot_exponent, 9);
        assert_eq!(natural_transform_index, 4);
        let evaluation_point = modular_power(
            ROOT_PARAMETERS[0].negacyclic_root,
            slot_exponent as u64,
            PLAINTEXT_MODULUS,
        );

        let mut logical_slots = vec![0_u64; POLYNOMIAL_DEGREE];
        logical_slots[logical_slot_index] = 42_424;
        let encoded = encode_batch_plaintext_slots(&logical_slots, 0).expect("encode logical slot");
        let previous_natural_order_coefficients =
            inverse_negacyclic_ntt(&logical_slots, PLAINTEXT_MODULUS)
                .expect("previous natural-order encoding");

        assert_ne!(
            encoded.coefficients_mod_plaintext,
            previous_natural_order_coefficients,
        );
        assert_eq!(
            evaluate_polynomial(&encoded.coefficients_mod_plaintext, evaluation_point,),
            42_424,
        );

        let previous_natural_exponent = (2 * logical_slot_index + 1) as u64;
        let previous_natural_point = modular_power(
            ROOT_PARAMETERS[0].negacyclic_root,
            previous_natural_exponent,
            PLAINTEXT_MODULUS,
        );
        assert_eq!(
            evaluate_polynomial(&encoded.coefficients_mod_plaintext, previous_natural_point),
            0,
        );
        assert_eq!(
            evaluate_polynomial(&previous_natural_order_coefficients, previous_natural_point),
            42_424,
        );
        assert_eq!(
            evaluate_polynomial(&previous_natural_order_coefficients, evaluation_point,),
            0,
        );
    }

    #[test]
    fn batch_encoder_round_trips_all_zero_and_all_max_slots() {
        for slots in [
            vec![0_u64; POLYNOMIAL_DEGREE],
            vec![PLAINTEXT_MODULUS - 1; POLYNOMIAL_DEGREE],
        ] {
            let encoded = encode_batch_plaintext_slots(&slots, 1).expect("encode");
            let decoded = decode_batch_plaintext_polynomial(&encoded.polynomial).expect("decode");

            assert_eq!(decoded, slots);
            assert_eq!(encoded.polynomial.residues_by_modulus.len(), 2);
        }
    }

    #[test]
    fn batch_encoder_rejects_bad_slot_values_and_levels() {
        assert!(encode_batch_plaintext_slots(&[PLAINTEXT_MODULUS], 0).is_err());
        assert!(encode_batch_plaintext_slots(&vec![0_u64; POLYNOMIAL_DEGREE + 1], 0).is_err());
        assert!(encode_batch_plaintext_slots(&[0], DATA_PRIMES.len()).is_err());

        for wrong_coefficient_count in [0, POLYNOMIAL_DEGREE / 2, POLYNOMIAL_DEGREE + 1] {
            let error =
                decode_plaintext_coefficients_to_logical_slots(&vec![0; wrong_coefficient_count])
                    .expect_err("wrong coefficient count must reject");
            assert_eq!(error.code, CanonicalErrorCode::MalformedLength);
        }
    }

    #[test]
    fn decoder_rejects_inconsistent_plaintext_lift_limbs() {
        let encoded = encode_batch_plaintext_slots(&[1, 2, 3], 1).expect("encode");
        let mut mutated_polynomial = encoded.polynomial;
        mutated_polynomial.residues_by_modulus[1][17] += 1;

        let error = decode_batch_plaintext_polynomial(&mutated_polynomial)
            .expect_err("inconsistent lift should reject");

        assert!(error.message.contains("consistent plaintext lift"));
    }

    fn deterministic_residue_vector(seed: u64) -> Vec<u64> {
        let mut state = seed;
        (0..POLYNOMIAL_DEGREE)
            .map(|coefficient_index| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407)
                    ^ (coefficient_index as u64).rotate_left(17);
                state % PLAINTEXT_MODULUS
            })
            .collect()
    }

    fn evaluate_polynomial(coefficients: &[u64], point: u64) -> u64 {
        coefficients
            .iter()
            .rev()
            .fold(0_u64, |accumulated_value, coefficient| {
                ((u128::from(accumulated_value) * u128::from(point) + u128::from(*coefficient))
                    % u128::from(PLAINTEXT_MODULUS)) as u64
            })
    }

    fn modular_power(base: u64, mut exponent: u64, modulus: u64) -> u64 {
        let mut result = 1_u64;
        let mut power = base;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = ((u128::from(result) * u128::from(power)) % u128::from(modulus)) as u64;
            }
            power = ((u128::from(power) * u128::from(power)) % u128::from(modulus)) as u64;
            exponent >>= 1;
        }
        result
    }
}
