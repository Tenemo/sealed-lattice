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
}
