#[cfg(test)]
use crate::bgv::{
    base_conversion::lift_plaintext_coefficients_to_basis, parameters::BgvBasisKind,
    rns::RnsPolynomial,
};
#[cfg(test)]
use crate::bgv::{
    direct_ballots::{PAIR_CHARACTER_LANE_DEGREE, pair_character_lane_idempotent_coefficients},
    modular_arithmetic::{add_mod, mul_mod},
};
use crate::{
    bgv::{
        direct_ballots::{PAIR_CHARACTER_LANE_COUNT, pair_character_lane_value},
        parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[cfg(test)]
pub(crate) struct EncodedBatchPlaintext {
    pub(crate) coefficients_mod_plaintext: Vec<u64>,
    pub(crate) polynomial: RnsPolynomial,
}

/// Encodes one base-field scalar in each of the 128 selected degree-256
/// plaintext lanes. This is the only scalar-lane embedding used by evaluator
/// development tests and target decoding; arbitrary extension-field lane
/// values stay in coefficient form.
#[cfg(test)]
pub(super) fn encode_scalar_lanes_to_plaintext_coefficients(
    supplied_lanes: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if supplied_lanes.len() > PAIR_CHARACTER_LANE_COUNT {
        return Err(encoding_error(
            CanonicalErrorCode::MalformedLength,
            "BGV scalar-lane encoder received more lanes than the selected plaintext algebra",
        ));
    }
    if supplied_lanes.iter().any(|lane| *lane >= PLAINTEXT_MODULUS) {
        return Err(encoding_error(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV scalar-lane encoder received a noncanonical plaintext value",
        ));
    }

    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (lane_ordinal, lane_value) in supplied_lanes.iter().copied().enumerate() {
        if lane_value == 0 {
            continue;
        }
        for (lane_coefficient_ordinal, idempotent_coefficient) in
            pair_character_lane_idempotent_coefficients(lane_ordinal)?
                .into_iter()
                .enumerate()
        {
            let coefficient_ordinal = lane_coefficient_ordinal
                .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                .ok_or_else(|| {
                    encoding_error(
                        CanonicalErrorCode::InvalidProtocolObject,
                        "BGV scalar-lane coefficient index overflowed",
                    )
                })?;
            let contribution = mul_mod(lane_value, idempotent_coefficient, PLAINTEXT_MODULUS)?;
            coefficients[coefficient_ordinal] = add_mod(
                coefficients[coefficient_ordinal],
                contribution,
                PLAINTEXT_MODULUS,
            )?;
        }
    }
    Ok(coefficients)
}

/// Test-only reference encoder for arbitrary values in every selected
/// degree-256 plaintext lane. Production pair-character encoding retains its
/// sparse specialized path; this helper exists to validate that path against
/// the complete extension algebra without adding browser work.
#[cfg(test)]
pub(super) fn encode_extension_lanes_to_plaintext_coefficients(
    supplied_lanes: &[[u64; PAIR_CHARACTER_LANE_DEGREE]],
) -> CanonicalResult<Vec<u64>> {
    if supplied_lanes.len() > PAIR_CHARACTER_LANE_COUNT {
        return Err(encoding_error(
            CanonicalErrorCode::MalformedLength,
            "BGV extension-lane encoder received more lanes than the selected plaintext algebra",
        ));
    }
    if supplied_lanes
        .iter()
        .flatten()
        .any(|coordinate| *coordinate >= PLAINTEXT_MODULUS)
    {
        return Err(encoding_error(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV extension-lane encoder received a noncanonical plaintext coordinate",
        ));
    }

    let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
    for (lane_ordinal, lane_value) in supplied_lanes.iter().enumerate() {
        let nonzero_coordinates = lane_value
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coordinate)| *coordinate != 0)
            .collect::<Vec<_>>();
        if nonzero_coordinates.is_empty() {
            continue;
        }
        let idempotent = pair_character_lane_idempotent_coefficients(lane_ordinal)?;
        for (residue_exponent, lane_coordinate) in nonzero_coordinates {
            for (lane_block_ordinal, idempotent_coefficient) in
                idempotent.iter().copied().enumerate()
            {
                let coefficient_ordinal = lane_block_ordinal
                    .checked_mul(PAIR_CHARACTER_LANE_DEGREE)
                    .and_then(|block_start| block_start.checked_add(residue_exponent))
                    .ok_or_else(|| {
                        encoding_error(
                            CanonicalErrorCode::InvalidProtocolObject,
                            "BGV extension-lane coefficient index overflowed",
                        )
                    })?;
                let contribution =
                    mul_mod(lane_coordinate, idempotent_coefficient, PLAINTEXT_MODULUS)?;
                coefficients[coefficient_ordinal] = add_mod(
                    coefficients[coefficient_ordinal],
                    contribution,
                    PLAINTEXT_MODULUS,
                )?;
            }
        }
    }
    Ok(coefficients)
}

#[cfg(test)]
pub(super) fn decode_plaintext_coefficients_to_extension_lanes(
    coefficients: &[u64],
) -> CanonicalResult<Vec<[u64; PAIR_CHARACTER_LANE_DEGREE]>> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(encoding_error(
            CanonicalErrorCode::MalformedLength,
            "BGV extension-lane decoder coefficient count does not match the selected ring degree",
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
    {
        return Err(encoding_error(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV extension-lane decoder received a noncanonical plaintext coefficient",
        ));
    }
    (0..PAIR_CHARACTER_LANE_COUNT)
        .map(|lane_ordinal| pair_character_lane_value(coefficients, lane_ordinal))
        .collect()
}

/// Decodes the base-field scalar subspace of the selected 128 extension
/// lanes. A target with a nonconstant extension component is malformed rather
/// than silently projected onto its constant coefficient.
pub(super) fn decode_plaintext_coefficients_to_scalar_lanes(
    coefficients: &[u64],
) -> CanonicalResult<Vec<u64>> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(encoding_error(
            CanonicalErrorCode::MalformedLength,
            "BGV scalar-lane decoder coefficient count does not match the selected ring degree",
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
    {
        return Err(encoding_error(
            CanonicalErrorCode::InvalidProtocolObject,
            "BGV scalar-lane decoder received a noncanonical plaintext coefficient",
        ));
    }

    (0..PAIR_CHARACTER_LANE_COUNT)
        .map(|lane_ordinal| {
            let lane = pair_character_lane_value(coefficients, lane_ordinal)?;
            if lane[1..].iter().any(|coefficient| *coefficient != 0) {
                return Err(encoding_error(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "BGV scalar-lane decoder received a nonconstant extension-lane value",
                ));
            }
            Ok(lane[0])
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn encode_batch_plaintext_lanes(
    supplied_lanes: &[u64],
    target_level: usize,
) -> CanonicalResult<EncodedBatchPlaintext> {
    let coefficients_mod_plaintext = encode_scalar_lanes_to_plaintext_coefficients(supplied_lanes)?;
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

fn encoding_error(code: CanonicalErrorCode, message: &'static str) -> CanonicalError {
    CanonicalError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::parameters::plaintext_extension_lane_root;

    #[test]
    fn selected_scalar_lanes_round_trip_boundaries_and_dense_values() {
        let lanes = (0..PAIR_CHARACTER_LANE_COUNT)
            .map(|lane_ordinal| {
                u64::try_from(37 * lane_ordinal + 256).expect("small lane value")
                    % PLAINTEXT_MODULUS
            })
            .collect::<Vec<_>>();
        let coefficients =
            encode_scalar_lanes_to_plaintext_coefficients(&lanes).expect("encode lanes");
        assert_eq!(
            decode_plaintext_coefficients_to_scalar_lanes(&coefficients).expect("decode lanes"),
            lanes
        );
    }

    #[test]
    fn selected_scalar_lane_codec_rejects_wrong_geometry_and_extension_values() {
        assert!(
            encode_scalar_lanes_to_plaintext_coefficients(&vec![0; PAIR_CHARACTER_LANE_COUNT + 1])
                .is_err()
        );
        assert!(encode_scalar_lanes_to_plaintext_coefficients(&[PLAINTEXT_MODULUS]).is_err());
        assert!(
            decode_plaintext_coefficients_to_scalar_lanes(&vec![0; POLYNOMIAL_DEGREE - 1]).is_err()
        );

        let mut extension_value = vec![0_u64; POLYNOMIAL_DEGREE];
        extension_value[1] = 1;
        assert!(decode_plaintext_coefficients_to_scalar_lanes(&extension_value).is_err());
    }

    #[test]
    fn selected_scalar_lane_plaintext_lift_retains_every_coefficient() {
        let encoded =
            encode_batch_plaintext_lanes(&[0, 1, 256, 17, 99], 0).expect("encode and lift lanes");
        assert_eq!(encoded.polynomial.level, 0);
        assert_eq!(
            encoded.polynomial.residues_by_modulus[0]
                .iter()
                .map(|coefficient| coefficient % PLAINTEXT_MODULUS)
                .collect::<Vec<_>>(),
            encoded.coefficients_mod_plaintext
        );
    }

    #[test]
    fn selected_extension_lanes_round_trip_dense_and_sparse_values() {
        let dense_lanes = (0..PAIR_CHARACTER_LANE_COUNT)
            .map(|lane_ordinal| {
                core::array::from_fn(|coordinate_ordinal| {
                    u64::try_from(37 * lane_ordinal + 19 * coordinate_ordinal + lane_ordinal % 11)
                        .expect("selected extension coordinate fits u64")
                        % PLAINTEXT_MODULUS
                })
            })
            .collect::<Vec<[u64; PAIR_CHARACTER_LANE_DEGREE]>>();
        let dense_coefficients = encode_extension_lanes_to_plaintext_coefficients(&dense_lanes)
            .expect("encode dense extension lanes");
        assert_eq!(
            decode_plaintext_coefficients_to_extension_lanes(&dense_coefficients)
                .expect("decode dense extension lanes"),
            dense_lanes
        );

        let mut sparse_lanes = vec![[0_u64; PAIR_CHARACTER_LANE_DEGREE]; PAIR_CHARACTER_LANE_COUNT];
        for (lane_ordinal, coordinate_ordinal, value) in [
            (0, 0, 1),
            (0, PAIR_CHARACTER_LANE_DEGREE - 1, 256),
            (63, 1, 19),
            (64, 127, 211),
            (127, PAIR_CHARACTER_LANE_DEGREE - 1, 1),
        ] {
            sparse_lanes[lane_ordinal][coordinate_ordinal] = value;
        }
        let sparse_coefficients = encode_extension_lanes_to_plaintext_coefficients(&sparse_lanes)
            .expect("encode sparse extension lanes");
        assert_eq!(
            decode_plaintext_coefficients_to_extension_lanes(&sparse_coefficients)
                .expect("decode sparse extension lanes"),
            sparse_lanes
        );
    }

    #[test]
    fn selected_extension_lane_codec_rejects_wrong_geometry_and_noncanonical_values() {
        assert!(
            encode_extension_lanes_to_plaintext_coefficients(&vec![
                [0; PAIR_CHARACTER_LANE_DEGREE];
                PAIR_CHARACTER_LANE_COUNT + 1
            ])
            .is_err()
        );
        let mut noncanonical_lane = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        noncanonical_lane[PAIR_CHARACTER_LANE_DEGREE - 1] = PLAINTEXT_MODULUS;
        assert!(encode_extension_lanes_to_plaintext_coefficients(&[noncanonical_lane]).is_err());
        assert!(
            decode_plaintext_coefficients_to_extension_lanes(&vec![0; POLYNOMIAL_DEGREE - 1])
                .is_err()
        );
        let mut noncanonical_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        noncanonical_coefficients[POLYNOMIAL_DEGREE - 1] = PLAINTEXT_MODULUS;
        assert!(
            decode_plaintext_coefficients_to_extension_lanes(&noncanonical_coefficients).is_err()
        );
    }

    #[test]
    fn sparse_full_ring_product_matches_every_extension_lane_product() {
        let mut left_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        let mut right_coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        for (coefficient_ordinal, value) in [
            (0, 256),
            (1, 17),
            (255, 91),
            (256, 33),
            (16_511, 201),
            (32_767, 7),
        ] {
            left_coefficients[coefficient_ordinal] = value;
        }
        for (coefficient_ordinal, value) in [
            (0, 13),
            (2, 256),
            (254, 99),
            (257, 41),
            (16_384, 77),
            (32_766, 5),
        ] {
            right_coefficients[coefficient_ordinal] = value;
        }
        let product_coefficients =
            sparse_negacyclic_product(&left_coefficients, &right_coefficients);

        for lane_ordinal in 0..PAIR_CHARACTER_LANE_COUNT {
            let lane_root = plaintext_extension_lane_root(lane_ordinal)
                .expect("selected extension lane root derives");
            let left_lane = evaluate_sparse_ring_in_lane(&left_coefficients, lane_root);
            let right_lane = evaluate_sparse_ring_in_lane(&right_coefficients, lane_root);
            let expected_product =
                multiply_extension_lane_values(&left_lane, &right_lane, lane_root);
            let observed_product = evaluate_sparse_ring_in_lane(&product_coefficients, lane_root);
            assert_eq!(observed_product, expected_product, "lane {lane_ordinal}");

            if [0, 1, 63, 64, 127].contains(&lane_ordinal) {
                assert_eq!(
                    pair_character_lane_value(&product_coefficients, lane_ordinal)
                        .expect("production lane decoder accepts the sparse product"),
                    observed_product,
                    "production decoder drifted in lane {lane_ordinal}",
                );
            }
        }
    }

    fn sparse_negacyclic_product(left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut product = vec![0_u64; POLYNOMIAL_DEGREE];
        for (left_ordinal, left_value) in left
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, value)| *value != 0)
        {
            for (right_ordinal, right_value) in right
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, value)| *value != 0)
            {
                let exponent = left_ordinal + right_ordinal;
                let (coefficient_ordinal, contribution) = if exponent >= POLYNOMIAL_DEGREE {
                    (
                        exponent - POLYNOMIAL_DEGREE,
                        modular_negation_for_test(modular_product_for_test(
                            left_value,
                            right_value,
                        )),
                    )
                } else {
                    (exponent, modular_product_for_test(left_value, right_value))
                };
                product[coefficient_ordinal] =
                    modular_sum_for_test(product[coefficient_ordinal], contribution);
            }
        }
        product
    }

    fn evaluate_sparse_ring_in_lane(
        coefficients: &[u64],
        lane_root: u64,
    ) -> [u64; PAIR_CHARACTER_LANE_DEGREE] {
        let mut lane = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        for (coefficient_ordinal, coefficient) in coefficients
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, coefficient)| *coefficient != 0)
        {
            let lane_block_ordinal = coefficient_ordinal / PAIR_CHARACTER_LANE_DEGREE;
            let residue_exponent = coefficient_ordinal % PAIR_CHARACTER_LANE_DEGREE;
            let root_power = modular_power_for_test(
                lane_root,
                u64::try_from(lane_block_ordinal).expect("lane block ordinal fits u64"),
            );
            lane[residue_exponent] = modular_sum_for_test(
                lane[residue_exponent],
                modular_product_for_test(coefficient, root_power),
            );
        }
        lane
    }

    fn multiply_extension_lane_values(
        left: &[u64; PAIR_CHARACTER_LANE_DEGREE],
        right: &[u64; PAIR_CHARACTER_LANE_DEGREE],
        lane_root: u64,
    ) -> [u64; PAIR_CHARACTER_LANE_DEGREE] {
        let mut product = [0_u64; PAIR_CHARACTER_LANE_DEGREE];
        for (left_exponent, left_value) in left
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, value)| *value != 0)
        {
            for (right_exponent, right_value) in right
                .iter()
                .copied()
                .enumerate()
                .filter(|(_, value)| *value != 0)
            {
                let exponent = left_exponent + right_exponent;
                let (reduced_exponent, reduction_factor) = if exponent >= PAIR_CHARACTER_LANE_DEGREE
                {
                    (exponent - PAIR_CHARACTER_LANE_DEGREE, lane_root)
                } else {
                    (exponent, 1)
                };
                let contribution = modular_product_for_test(
                    modular_product_for_test(left_value, right_value),
                    reduction_factor,
                );
                product[reduced_exponent] =
                    modular_sum_for_test(product[reduced_exponent], contribution);
            }
        }
        product
    }

    fn modular_power_for_test(mut base: u64, mut exponent: u64) -> u64 {
        let mut result = 1_u64;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = modular_product_for_test(result, base);
            }
            base = modular_product_for_test(base, base);
            exponent >>= 1;
        }
        result
    }

    fn modular_product_for_test(left: u64, right: u64) -> u64 {
        u64::try_from((u128::from(left) * u128::from(right)) % u128::from(PLAINTEXT_MODULUS))
            .expect("plaintext product fits u64")
    }

    fn modular_sum_for_test(left: u64, right: u64) -> u64 {
        (left + right) % PLAINTEXT_MODULUS
    }

    fn modular_negation_for_test(value: u64) -> u64 {
        if value == 0 {
            0
        } else {
            PLAINTEXT_MODULUS - value
        }
    }
}
